//! Real [`ProtonDriveAccount`] implementation backed by the live Proton
//! Account API.
//!
//! # Key-unlock chain
//!
//! Login (`auth.rs`) yields a bcrypt-derived mailbox password (`$2y$10…`).
//! Resolving an address's private key follows the Proton key hierarchy:
//!
//! 1. `GET /core/v4/users` → `User.Keys[]`. Each armored `PrivateKey` is
//!    unlocked **directly** with the mailbox password.
//! 2. `GET /core/v4/addresses` → `Addresses[].Keys[]`. Each address key has a
//!    `Token` (an armored PGP message) encrypted to one of the user keys.
//!    Decrypting the Token with an unlocked user key yields the address-key
//!    passphrase, which in turn unlocks the address `PrivateKey`.
//! 3. The unlocked address keys are cached by email.
//!
//! Token signature verification against the SignedKeyList is **deferred** for
//! MVP — we decrypt only (see step 2 below).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use proton_drive::{
    Error, ProtonDriveAccount, ProtonDriveHttpClient, Result,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    addresses::{Address, GetAddressesResponse},
    common::{self, ResponseEnvelope},
    user::{GetUserResponse, User},
};
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey};
use serde::de::DeserializeOwned;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A live account context. Unlocked address keys are resolved once at
/// [`PdtuiAccount::bootstrap`] and cached by lowercased email.
pub struct PdtuiAccount {
    user_id: String,
    key_password: Zeroizing<String>,
    /// Address with the lowest `Order` (the primary).
    primary_email: String,
    /// Unlocked address private keys, keyed by lowercased email.
    address_keys: HashMap<String, PrivateKey>,
}

impl PdtuiAccount {
    /// Fetch the user + addresses and unlock every address key.
    ///
    /// `http` must already inject auth headers (use `SessionAwareHttpClient`).
    pub async fn bootstrap(
        http: Arc<dyn ProtonDriveHttpClient>,
        crypto: Arc<dyn OpenPgpCrypto>,
        user_id: String,
        key_password: Zeroizing<String>,
    ) -> Result<Self> {
        // Step 1: fetch user keys and unlock each directly with the mailbox
        // password.
        let user_resp: GetUserResponse = api_get(&*http, "/core/v4/users").await?;
        let user = user_resp.user;
        debug!(user_id = %user.id, key_count = user.keys.len(), "fetched user keys");

        let user_keys = unlock_user_keys(&*crypto, &user, &key_password).await?;
        if user_keys.is_empty() {
            return Err(Error::Decryption(
                "no user key could be unlocked with the mailbox password".to_owned(),
            ));
        }

        // Step 2: fetch addresses and unlock each address key via its Token.
        let addr_resp: GetAddressesResponse = api_get(&*http, "/core/v4/addresses").await?;
        debug!(count = addr_resp.addresses.len(), "fetched addresses");

        let mut address_keys: HashMap<String, PrivateKey> = HashMap::new();
        for address in &addr_resp.addresses {
            match unlock_address_key(&*crypto, address, &user_keys).await {
                Ok(key) => {
                    address_keys.insert(address.email.to_ascii_lowercase(), key);
                }
                Err(e) => {
                    // A user may have addresses we cannot unlock (disabled,
                    // external, legacy layouts). Skip them rather than abort —
                    // we only need the primary address for MVP.
                    warn!(email = %address.email, "skipping address: {e}");
                }
            }
        }

        if address_keys.is_empty() {
            return Err(Error::Decryption(
                "no address key could be unlocked".to_owned(),
            ));
        }

        // primary_email = address with the lowest Order (fall back to first).
        let primary_email = addr_resp
            .addresses
            .iter()
            .filter(|a| address_keys.contains_key(&a.email.to_ascii_lowercase()))
            .min_by_key(|a| a.order)
            .map(|a| a.email.clone())
            .or_else(|| addr_resp.addresses.first().map(|a| a.email.clone()))
            .ok_or_else(|| Error::Internal("no addresses returned for user".to_owned()))?;

        debug!(%primary_email, unlocked = address_keys.len(), "account bootstrap complete");

        Ok(Self {
            user_id,
            key_password,
            primary_email,
            address_keys,
        })
    }
}

#[async_trait]
impl ProtonDriveAccount for PdtuiAccount {
    fn user_id(&self) -> &str {
        &self.user_id
    }

    fn primary_email(&self) -> &str {
        &self.primary_email
    }

    async fn address_private_key(&self, email: &str) -> Result<PrivateKey> {
        self.address_keys
            .get(&email.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| Error::Internal(format!("no unlocked address private key for {email}")))
    }

    async fn key_password(&self) -> Result<String> {
        Ok(self.key_password.as_str().to_owned())
    }
}

// ---------------------------------------------------------------------------
// Key-unlock helpers
// ---------------------------------------------------------------------------

/// Unlock every user key directly with the mailbox password. Keys that fail to
/// unlock (e.g. hardware-backed) are skipped.
async fn unlock_user_keys(
    crypto: &dyn OpenPgpCrypto,
    user: &User,
    key_password: &str,
) -> Result<Vec<PrivateKey>> {
    let mut out = Vec::new();
    for key in &user.keys {
        match crypto.decrypt_key(&key.private_key, key_password).await {
            Ok(unlocked) => out.push(unlocked),
            Err(e) => warn!(key_id = %key.id, "user key did not unlock: {e}"),
        }
    }
    Ok(out)
}

/// Unlock one address's primary private key.
///
/// The address key `Token` is an armored PGP message encrypted to one of the
/// user keys; its plaintext is the passphrase that unlocks the address
/// `PrivateKey`.
///
/// Token signature verification against the SignedKeyList is deferred for MVP
/// — we decrypt only.
async fn unlock_address_key(
    crypto: &dyn OpenPgpCrypto,
    address: &Address,
    user_keys: &[PrivateKey],
) -> Result<PrivateKey> {
    // Prefer the primary address key; fall back to the first.
    let addr_key = address
        .keys
        .iter()
        .find(|k| k.primary == 1)
        .or_else(|| address.keys.first())
        .ok_or_else(|| Error::Internal(format!("address {} has no keys", address.email)))?;

    let token = addr_key.token.as_deref().ok_or_else(|| {
        Error::Decryption(format!(
            "address {} key {} has no Token (unsupported key layout)",
            address.email, addr_key.id
        ))
    })?;

    // The Token is an ASCII-armored PGP message. `decrypt_session_key` parses
    // raw binary packets (it does not de-armor), so convert to binary first.
    // `decrypt_and_verify` de-armors internally, but we feed it the same binary
    // for consistency.
    let token_bytes = dearmor_pgp(token)?;

    // Recover the session key from the Token's PKESK using any user key, then
    // decrypt the SEIPD body — the plaintext IS the address-key passphrase.
    let session_key = crypto
        .decrypt_session_key(&token_bytes, user_keys)
        .await
        .map_err(|e| Error::Decryption(format!("address token session key: {e}")))?;
    let (passphrase_bytes, _status) = crypto
        .decrypt_and_verify(&token_bytes, &session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("address token plaintext: {e}")))?;

    let passphrase = std::str::from_utf8(&passphrase_bytes)
        .map_err(|e| Error::Internal(format!("address passphrase not utf-8: {e}")))?;

    crypto
        .decrypt_key(&addr_key.private_key, passphrase)
        .await
        .map_err(|e| Error::Decryption(format!("unlock address private key: {e}")))
}

// ---------------------------------------------------------------------------
// Armor handling
// ---------------------------------------------------------------------------

/// De-armor an ASCII-armored PGP message into its binary packet stream.
///
/// `OpenPgpCrypto::decrypt_session_key` parses raw binary packets and does not
/// de-armor, so armored Tokens must be converted first. We strip the
/// `-----BEGIN/END-----` lines, the blank header-separator, optional armor
/// headers (`Key: value`), and the trailing `=CRC` checksum, then base64-decode
/// the remaining body.
fn dearmor_pgp(armored: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    let trimmed = armored.trim();
    if !trimmed.contains("-----BEGIN PGP") {
        // Not armored — assume it is already binary/base64 of binary.
        return base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| Error::Internal(format!("token base64: {e}")));
    }

    let mut body = String::new();
    let mut in_body = false;
    let mut seen_blank = false;
    for line in trimmed.lines() {
        let line = line.trim_end();
        if line.starts_with("-----BEGIN PGP") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END PGP") {
            break;
        }
        if !in_body {
            continue;
        }
        // Armor headers precede a blank line; skip until the blank separator.
        if !seen_blank {
            if line.is_empty() {
                seen_blank = true;
            }
            continue;
        }
        // The CRC-24 checksum line begins with '='.
        if line.starts_with('=') {
            continue;
        }
        if !line.is_empty() {
            body.push_str(line);
        }
    }

    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| Error::Internal(format!("token armor base64: {e}")))
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async fn api_get<T: DeserializeOwned>(http: &dyn ProtonDriveHttpClient, path: &str) -> Result<T> {
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Internal(format!("JSON parse {path}: {e}")))?;
    if env.code != common::CODE_OK {
        return Err(Error::Internal(format!(
            "API error {} on {path}: {}",
            env.code,
            env.error.unwrap_or_default()
        )));
    }
    Ok(env.inner)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use bytes::Bytes;
    use proton_drive::{
        Result as DriveResult, RpgpCrypto,
        http::{BlobRequest, JsonResponse},
    };
    use proton_drive_crypto::{EncryptOptions, PublicKey, SessionKey};

    // ── Mock HTTP that replays a fixed response per path -----------------------

    struct PathMock {
        responses: Mutex<VecDeque<(String, String)>>,
    }

    impl PathMock {
        fn new(responses: Vec<(&str, String)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(p, b)| (p.to_owned(), b))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for PathMock {
        async fn request_json(&self, req: JsonRequest) -> DriveResult<JsonResponse> {
            let body = {
                let mut q = self.responses.lock().unwrap();
                // Find a queued response whose path matches; else pop front.
                let idx = q.iter().position(|(p, _)| req.path.contains(p.as_str()));
                match idx {
                    Some(i) => q.remove(i).map(|(_, b)| b).unwrap_or_default(),
                    None => q.pop_front().map(|(_, b)| b).unwrap_or_default(),
                }
            };
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from(body.into_bytes()),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> DriveResult<JsonResponse> {
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::new(),
            })
        }
    }

    /// RFC 4880 ASCII-armor a binary PGP message (PKESK + SEIPD) the way Proton
    /// serves address-key Tokens. Includes the CRC-24 checksum trailer.
    fn armor_message(data: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let mut out = String::from("-----BEGIN PGP MESSAGE-----\n\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        let crc = crc24(data);
        let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
        out.push('=');
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(crc_bytes));
        out.push('\n');
        out.push_str("-----END PGP MESSAGE-----\n");
        out
    }

    /// CRC-24 over `data` (RFC 4880 §6.1).
    fn crc24(data: &[u8]) -> u32 {
        let mut crc: u32 = 0x00B7_04CE;
        for &byte in data {
            crc ^= (byte as u32) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x0100_0000 != 0 {
                    crc ^= 0x0186_4CFB;
                }
            }
        }
        crc & 0x00FF_FFFF
    }

    /// Build a PGP message wrapping `plaintext`, encrypted to `recipient_pub`.
    /// Used to fabricate a realistic address-key Token.
    async fn make_token(
        crypto: &RpgpCrypto,
        recipient_pub: &PublicKey,
        signing_key: &PrivateKey,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let session_key: SessionKey = crypto
            .generate_session_key(
                std::slice::from_ref(recipient_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(recipient_pub),
                signing_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap()
    }

    /// Full key-unlock orchestration using the real RpgpCrypto: generate a user
    /// key, an address key locked with a random passphrase, and a Token that
    /// wraps that passphrase encrypted to the user key. Bootstrap must resolve
    /// the address private key.
    #[tokio::test]
    async fn bootstrap_unlocks_address_key_via_token() {
        let crypto = RpgpCrypto::new();
        let mailbox_pw = "$2y$10$mailboxpasswordforuserkey";

        // 1. User key, locked with the mailbox password.
        let (user_priv, user_pub_armored) = crypto
            .generate_key(mailbox_pw, EncryptOptions::default())
            .await
            .unwrap();
        let user_pub = PublicKey {
            armored: user_pub_armored,
            fingerprint_hex: user_priv.fingerprint_hex.clone(),
        };

        // 2. Address key, locked with a random passphrase.
        let addr_passphrase = "address-key-passphrase-xyz";
        let (addr_priv, _addr_pub) = crypto
            .generate_key(addr_passphrase, EncryptOptions::default())
            .await
            .unwrap();

        // 3. Token = addr_passphrase encrypted to the user key, ASCII-armored
        // the way Proton serves it.
        let token_bytes =
            make_token(&crypto, &user_pub, &user_priv, addr_passphrase.as_bytes()).await;
        let token_armored = armor_message(&token_bytes);

        // Sanity: dearmor + crypto round-trip recovers the passphrase.
        let unlocked_user = crypto
            .decrypt_key(&user_priv.armored, mailbox_pw)
            .await
            .unwrap();
        let dearmored = dearmor_pgp(&token_armored).expect("dearmor token");
        assert_eq!(dearmored, token_bytes, "dearmor must match original binary");
        let sk = crypto
            .decrypt_session_key(&dearmored, std::slice::from_ref(&unlocked_user))
            .await
            .expect("token session key");
        let (pt, _) = crypto
            .decrypt_and_verify(&dearmored, &sk, &[])
            .await
            .expect("token plaintext");
        assert_eq!(pt, addr_passphrase.as_bytes());

        let users_body = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "user-123",
                "Name": "tester",
                "Email": "tester@proton.me",
                "Keys": [{ "ID": "uk1", "Primary": 1, "PrivateKey": user_priv.armored }]
            }
        })
        .to_string();

        let addresses_body = serde_json::json!({
            "Code": 1000,
            "Addresses": [{
                "ID": "addr-1",
                "Email": "tester@proton.me",
                "Order": 1,
                "Keys": [{
                    "ID": "ak1",
                    "Primary": 1,
                    "PrivateKey": addr_priv.armored,
                    "Token": token_armored
                }]
            }]
        })
        .to_string();

        let http = Arc::new(PathMock::new(vec![
            ("/core/v4/users", users_body),
            ("/core/v4/addresses", addresses_body),
        ])) as Arc<dyn ProtonDriveHttpClient>;
        let crypto_arc = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let account = PdtuiAccount::bootstrap(
            http,
            crypto_arc,
            "user-123".to_owned(),
            Zeroizing::new(mailbox_pw.to_owned()),
        )
        .await
        .expect("bootstrap should succeed");

        assert_eq!(account.user_id(), "user-123");
        assert_eq!(account.primary_email(), "tester@proton.me");

        let resolved = account
            .address_private_key("tester@proton.me")
            .await
            .expect("primary address key resolves");
        assert_eq!(resolved.fingerprint_hex, addr_priv.fingerprint_hex);
        // Case-insensitive lookup.
        assert!(
            account
                .address_private_key("TESTER@PROTON.ME")
                .await
                .is_ok()
        );
        // Unknown email is an error.
        assert!(
            account
                .address_private_key("nobody@proton.me")
                .await
                .is_err()
        );
        assert_eq!(account.key_password().await.unwrap(), mailbox_pw);
    }

    #[tokio::test]
    async fn bootstrap_fails_when_user_key_does_not_unlock() {
        let crypto = RpgpCrypto::new();
        let (user_priv, _) = crypto
            .generate_key("correct-password", EncryptOptions::default())
            .await
            .unwrap();

        let users_body = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "u",
                "Name": "n",
                "Email": "e@proton.me",
                "Keys": [{ "ID": "uk1", "Primary": 1, "PrivateKey": user_priv.armored }]
            }
        })
        .to_string();

        let http = Arc::new(PathMock::new(vec![("/core/v4/users", users_body)]))
            as Arc<dyn ProtonDriveHttpClient>;
        let crypto_arc = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let result = PdtuiAccount::bootstrap(
            http,
            crypto_arc,
            "u".to_owned(),
            Zeroizing::new("wrong-password".to_owned()),
        )
        .await;
        assert!(
            result.is_err(),
            "wrong mailbox password must fail bootstrap"
        );
    }

    // -----------------------------------------------------------------------
    // Live end-to-end (ignored). Requires a persisted session + keyring entry
    // produced by `pdtui login`. Run manually:
    //   cargo test -p pdtui --bin pdtui account::tests::live_bootstrap -- --ignored
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "hits the live Proton API; requires a logged-in session"]
    async fn live_bootstrap_resolves_primary_address_key() {
        use crate::http::{ReqwestHttpClient, SessionAwareHttpClient};
        use crate::session::SessionManager;

        let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
        let transport: Arc<dyn ProtonDriveHttpClient> =
            Arc::new(ReqwestHttpClient::new("https://drive.proton.me/api", &app_version).unwrap());
        let session = Arc::new(
            SessionManager::from_keyring(Arc::clone(&transport))
                .await
                .expect("a persisted session is required (run `pdtui login` first)"),
        );
        let key_password = session.key_password().await;
        let http: Arc<dyn ProtonDriveHttpClient> =
            Arc::new(SessionAwareHttpClient::new(transport, Arc::clone(&session)));
        let crypto = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let account = PdtuiAccount::bootstrap(http, crypto, String::new(), key_password)
            .await
            .expect("live bootstrap should succeed");

        let email = account.primary_email().to_owned();
        assert!(!email.is_empty(), "primary email must be populated");
        account
            .address_private_key(&email)
            .await
            .expect("primary address key must resolve");
    }
}
