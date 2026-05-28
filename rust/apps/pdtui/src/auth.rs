//! M3 SRP authentication against Proton's /core/v4/auth endpoints.
//!
//! Flow: auth/info → SRP exchange (via proton-drive-crypto) → auth →
//! verify server proof → fetch key salts → derive mailbox password.
//!
//! Tokens are persisted in the OS keyring (secret-service on Linux,
//! Keychain on macOS). A session.json is also written so the existing
//! manual-bearer path keeps working without any changes.

use std::io::{self, Write as _};
use std::sync::Arc;

use base64::Engine as _;
use proton_drive::{
    ProtonDriveHttpClient, RpgpCrypto, SrpModule,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    auth::{AuthInfoRequest, AuthInfoResponse, AuthRequest, AuthResponse, KeySaltsResponse},
    common::{self, ResponseEnvelope},
};
use proton_drive_crypto::CryptoError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq as _;
use tracing::debug;
use zeroize::Zeroizing;

use crate::session::{SessionManager, SessionManagerError};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("http: {0}")]
    Http(proton_drive::Error),
    #[error("api error {code}: {message}")]
    Api { code: u32, message: String },
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("server proof mismatch — possible MITM")]
    ServerProofMismatch,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no non-empty key salt in /keys/salts response")]
    NoKeySalt,
    #[error("2FA is enabled — not yet supported; use scripts/configure-session.sh instead")]
    TwoFactorRequired,
    #[error("session: {0}")]
    Session(#[from] SessionManagerError),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Validated credentials after a successful SRP exchange.
///
/// `access_token`, `refresh_token`, and `key_password` are wrapped in
/// `Zeroizing` so their heap storage is wiped on drop (ADR-0011).
#[allow(dead_code)] // user_id + key_password consumed in M7 TUI wiring
pub struct Credentials {
    pub username: String,
    pub uid: String,
    pub user_id: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    /// Full bcrypt string ($2y$10…) — passphrase for unlocking the user's PGP key.
    pub key_password: Zeroizing<String>,
}

/// Perform the full SRP login flow and return validated credentials.
pub async fn login(
    http: &dyn ProtonDriveHttpClient,
    username: &str,
    password: &str,
) -> Result<Credentials, AuthError> {
    debug!(%username, "POST auth/info");
    let info: AuthInfoResponse = api_post(
        http,
        "/core/v4/auth/info",
        &AuthInfoRequest {
            username: username.to_owned(),
        },
        &[],
    )
    .await?;

    debug!(srp_version = info.version, "running SRP exchange");
    let crypto = RpgpCrypto::new();
    let exchange = crypto
        .get_srp(
            info.version,
            &info.modulus,
            &info.server_ephemeral,
            &info.salt,
            password,
        )
        .await?;

    debug!("POST auth");
    let auth_resp: AuthResponse = api_post(
        http,
        "/core/v4/auth",
        &AuthRequest {
            username: username.to_owned(),
            client_ephemeral: exchange.client_ephemeral.clone(),
            client_proof: exchange.client_proof.clone(),
            srp_session: info.srp_session,
        },
        &[],
    )
    .await?;

    // Constant-time comparison to avoid timing side-channel (ADR-0011).
    let proofs_match: bool = auth_resp
        .server_proof
        .as_bytes()
        .ct_eq(exchange.expected_server_proof.as_bytes())
        .into();
    if !proofs_match {
        return Err(AuthError::ServerProofMismatch);
    }

    if auth_resp.two_factor.enabled != 0 {
        return Err(AuthError::TwoFactorRequired);
    }

    let bearer_headers = vec![
        (
            "Authorization".to_owned(),
            format!("Bearer {}", auth_resp.access_token),
        ),
        ("x-pm-uid".to_owned(), auth_resp.uid.clone()),
    ];

    debug!("GET keys/salts");
    let salts: KeySaltsResponse = api_get(http, "/core/v4/keys/salts", &bearer_headers).await?;

    let key_salt_b64 = salts
        .key_salts
        .into_iter()
        .find(|s| !s.key_salt.is_empty())
        .map(|s| s.key_salt)
        .ok_or(AuthError::NoKeySalt)?;

    let salt_bytes = base64::engine::general_purpose::STANDARD.decode(&key_salt_b64)?;
    let key_password = crypto
        .compute_key_password(
            password,
            &base64::engine::general_purpose::STANDARD.encode(&salt_bytes),
        )
        .await?;

    Ok(Credentials {
        username: username.to_owned(),
        uid: auth_resp.uid,
        user_id: auth_resp.user_id,
        access_token: Zeroizing::new(auth_resp.access_token),
        refresh_token: Zeroizing::new(auth_resp.refresh_token),
        key_password: Zeroizing::new(key_password),
    })
}

/// Prompt for credentials interactively, run the full auth flow, and persist
/// the session through [`SessionManager::from_login`] — the single source of
/// truth for the keyring (uid-keyed, with `key_password`) and `session.json`
/// (with expiry). This is the same persistence path the TUI uses, so a session
/// created here can later be resumed via [`SessionManager::from_keyring`].
pub async fn login_interactive(base_url: &str, app_version: &str) -> Result<(), AuthError> {
    let username = prompt("Email: ")?;
    let password = rpassword::prompt_password("Password: ").map_err(AuthError::Io)?;

    let http: Arc<dyn ProtonDriveHttpClient> = Arc::new(
        crate::http::ReqwestHttpClient::new(base_url, app_version).map_err(AuthError::Http)?,
    );

    eprintln!("Authenticating…");
    let creds = login(&*http, &username, &password).await?;
    let username = creds.username.clone();

    // Proton returns no explicit expiry on login; 30 min matches the refresh path.
    SessionManager::from_login(
        Arc::clone(&http),
        creds.uid,
        creds.access_token,
        creds.refresh_token,
        creds.key_password,
        30 * 60,
    )
    .await?;

    eprintln!("✓ session persisted (keyring + session.json)");
    eprintln!("✓ logged in as {username}");
    Ok(())
}

fn prompt(label: &str) -> Result<String, AuthError> {
    print!("{label}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_owned())
}

async fn api_post<Req, Resp>(
    http: &dyn ProtonDriveHttpClient,
    path: &str,
    body: &Req,
    extra_headers: &[(String, String)],
) -> Result<Resp, AuthError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let body_bytes = serde_json::to_vec(body)?;
    let req = JsonRequest {
        method: HttpMethod::Post,
        path: path.to_owned(),
        query: vec![],
        headers: extra_headers.to_vec(),
        body: Some(body_bytes),
    };
    let resp = http.request_json(req).await.map_err(AuthError::Http)?;
    parse_envelope(&resp.body)
}

async fn api_get<Resp>(
    http: &dyn ProtonDriveHttpClient,
    path: &str,
    extra_headers: &[(String, String)],
) -> Result<Resp, AuthError>
where
    Resp: DeserializeOwned,
{
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: extra_headers.to_vec(),
        body: None,
    };
    let resp = http.request_json(req).await.map_err(AuthError::Http)?;
    parse_envelope(&resp.body)
}

fn parse_envelope<Resp: DeserializeOwned>(body: &[u8]) -> Result<Resp, AuthError> {
    let env: ResponseEnvelope<Resp> = serde_json::from_slice(body)?;
    if env.code != common::CODE_OK {
        return Err(AuthError::Api {
            code: env.code,
            message: env.error.unwrap_or_else(|| "unknown API error".into()),
        });
    }
    Ok(env.inner)
}
