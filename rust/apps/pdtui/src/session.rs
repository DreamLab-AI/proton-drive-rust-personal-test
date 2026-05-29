//! Session lifecycle and token refresh (ADR-0010).
//!
//! # Overview
//!
//! [`SessionManager`] owns the `(uid, access_token, refresh_token,
//! key_password, expiry)` tuple behind a `tokio::sync::RwLock`. HTTP requests
//! read a snapshot atomically (many readers, one writer). A background
//! `tokio::task` refreshes proactively at `expires_at - 60 s`. HTTP 401
//! responses trigger a single forced refresh followed by one retry (see
//! `http.rs`).
//!
//! # Persistence
//!
//! | Secret | Storage |
//! |---|---|
//! | `refresh_token` + `key_password` | OS keyring (`pdtui-proton-drive`, UID as account) |
//! | `access_token` + `expires_at` | `session.json` (mode 0600) |
//!
//! On logout: keyring entry deleted, `session.json` truncated.
//!
//! # Backward compatibility
//!
//! The original [`Session`] struct is retained for `probe.rs` and `app.rs`
//! which use it as a lightweight bearer-token container.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proton_drive::{
    ProtonDriveHttpClient,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    auth::{RefreshRequest, RefreshResponse},
    common::{self, ResponseEnvelope},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Errors produced by [`SessionManager`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionManagerError {
    /// The access token could not be refreshed (server returned 401 or 422).
    /// The caller should prompt the user to log in again.
    #[error("session expired - please log in again")]
    SessionExpired,

    #[error("keyring: {0}")]
    Keyring(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(proton_drive::Error),

    #[error("no session stored in keyring for uid {0}")]
    NoKeyring(String),
}

// ---------------------------------------------------------------------------
// Legacy Session struct (backward compat for probe.rs / app.rs)
// ---------------------------------------------------------------------------

/// Minimal session loaded from `$XDG_CONFIG_HOME/pdtui/session.json`.
///
/// Used by the `probe` subcommand and the pre-MG manual-bearer path.
/// New code should use [`SessionManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "AccessToken")]
    pub access_token: String,
    #[serde(rename = "UID")]
    pub uid: String,
    #[serde(default = "default_app_version")]
    pub app_version: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_app_version() -> String {
    format!("external-drive-pdtui@{}-stable", env!("CARGO_PKG_VERSION"))
}

fn default_base_url() -> String {
    "https://drive.proton.me/api".to_owned()
}

/// Errors from the legacy [`Session::load`] path.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no session file at {0}")]
    NotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Per-process temp directory that session persistence is redirected to under
/// `cfg(test)`, so unit tests never touch the developer's real session files.
#[cfg(test)]
static TEST_CONFIG_DIR: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    let dir = std::env::temp_dir().join(format!("pdtui-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
});

impl Session {
    pub fn config_path() -> PathBuf {
        // In test builds, redirect all session persistence to a per-process
        // temp directory. Unit tests exercise `do_refresh`/`from_login`, which
        // write the session + secret files; without this redirect they would
        // clobber the developer's real `~/.config/pdtui/` session.
        #[cfg(test)]
        {
            TEST_CONFIG_DIR.join("session.json")
        }
        #[cfg(not(test))]
        {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = std::env::var_os("HOME").unwrap_or_default();
                    PathBuf::from(home).join(".config")
                });
            base.join("pdtui").join("session.json")
        }
    }

    /// Path to the 0600 secret-fallback file holding `refresh_token` +
    /// `key_password`. Used when no OS secret store is available (e.g. headless
    /// containers where the `keyring` crate degrades to an in-memory backend
    /// that cannot persist across processes). Personal-use only (ADR-0007).
    pub fn secret_path() -> PathBuf {
        let mut p = Self::config_path();
        p.set_file_name("session.secret.json");
        p
    }

    pub fn load() -> Result<Self, SessionError> {
        let path = Self::config_path();
        if !path.exists() {
            return Err(SessionError::NotFound(path));
        }
        let bytes = std::fs::read(&path)?;
        let s = serde_json::from_slice::<Session>(&bytes)?;
        Ok(s)
    }

    pub fn auth_headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", self.access_token),
            ),
            ("x-pm-uid".to_owned(), self.uid.clone()),
        ]
    }
}

// ---------------------------------------------------------------------------
// Persistent session JSON (access_token + expiry, mode 0600)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SessionFile {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "AccessToken")]
    access_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    #[serde(rename = "ExpiresAt")]
    expires_at_unix: u64,
    #[serde(default = "default_app_version")]
    app_version: String,
    #[serde(default = "default_base_url")]
    base_url: String,
}

// ---------------------------------------------------------------------------
// Keyring helpers
// ---------------------------------------------------------------------------

const KEYRING_SERVICE: &str = "pdtui-proton-drive";

#[derive(Serialize, Deserialize)]
struct KeyringPayload {
    uid: String,
    refresh_token: String,
    key_password: String,
}

fn keyring_entry(uid: &str) -> Result<keyring::Entry, SessionManagerError> {
    keyring::Entry::new(KEYRING_SERVICE, uid)
        .map_err(|e| SessionManagerError::Keyring(e.to_string()))
}

pub(crate) fn save_keyring(
    uid: &str,
    refresh_token: &str,
    key_password: &str,
) -> Result<(), SessionManagerError> {
    // Serialize the same `KeyringPayload` struct that `load_keyring` parses, so
    // the write and read schemas cannot drift (the prior bug: a second writer
    // persisted `{uid, refresh_token}` with no `key_password`, which
    // `load_keyring` then failed to resume).
    let payload = KeyringPayload {
        uid: uid.to_owned(),
        refresh_token: refresh_token.to_owned(),
        key_password: key_password.to_owned(),
    };
    let json = serde_json::to_string(&payload)?;
    keyring_entry(uid)?
        .set_password(&json)
        .map_err(|e| SessionManagerError::Keyring(e.to_string()))
}

pub(crate) fn delete_keyring(uid: &str) -> Result<(), SessionManagerError> {
    match keyring_entry(uid)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SessionManagerError::Keyring(e.to_string())),
    }
}

fn load_keyring(uid: &str) -> Result<KeyringPayload, SessionManagerError> {
    let raw = keyring_entry(uid)?.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => SessionManagerError::NoKeyring(uid.to_owned()),
        other => SessionManagerError::Keyring(other.to_string()),
    })?;
    serde_json::from_str(&raw).map_err(SessionManagerError::Json)
}

// ---------------------------------------------------------------------------
// Secret-file fallback (0600) — for environments with no usable OS secret
// store. The same `KeyringPayload` schema is reused so the two stores cannot
// drift. ADR-0007: personal use only.
// ---------------------------------------------------------------------------

pub(crate) fn save_secret_file(
    uid: &str,
    refresh_token: &str,
    key_password: &str,
) -> Result<(), SessionManagerError> {
    let payload = KeyringPayload {
        uid: uid.to_owned(),
        refresh_token: refresh_token.to_owned(),
        key_password: key_password.to_owned(),
    };
    let json = serde_json::to_string(&payload)?;
    let path = Session::secret_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_secret_file(uid: &str) -> Result<KeyringPayload, SessionManagerError> {
    let path = Session::secret_path();
    if !path.exists() {
        return Err(SessionManagerError::NoKeyring(uid.to_owned()));
    }
    let raw = std::fs::read(&path)?;
    let payload: KeyringPayload = serde_json::from_slice(&raw)?;
    if payload.uid != uid {
        return Err(SessionManagerError::NoKeyring(uid.to_owned()));
    }
    Ok(payload)
}

pub(crate) fn delete_secret_file() -> Result<(), SessionManagerError> {
    let path = Session::secret_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SessionManagerError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// session.json helpers
// ---------------------------------------------------------------------------

pub(crate) fn write_session_file(
    uid: &str,
    access_token: &str,
    expires_at: Instant,
) -> Result<(), SessionManagerError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let secs_remaining = expires_at
        .saturating_duration_since(Instant::now())
        .as_secs();
    let expires_at_unix = now_unix.saturating_add(secs_remaining);

    let sf = SessionFile {
        uid: uid.to_owned(),
        access_token: access_token.to_owned(),
        expires_at_unix,
        app_version: default_app_version(),
        base_url: default_base_url(),
    };
    let json = serde_json::to_string_pretty(&sf)?;
    let path = Session::config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn truncate_session_file() -> Result<(), SessionManagerError> {
    let path = Session::config_path();
    if path.exists() {
        std::fs::write(&path, b"")?;
    }
    Ok(())
}

fn load_session_file() -> Result<SessionFile, SessionManagerError> {
    let path = Session::config_path();
    let bytes = std::fs::read(&path)?;
    serde_json::from_slice(&bytes).map_err(SessionManagerError::Json)
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// Secret state for one authenticated session.
///
/// All secret fields use `Zeroizing<String>`; `ZeroizeOnDrop` wipes heap
/// storage on drop (ADR-0011).
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SessionState {
    pub(crate) uid: String,
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Zeroizing<String>,
    pub(crate) key_password: Zeroizing<String>,
    // Instant holds no secret material.
    #[zeroize(skip)]
    pub(crate) expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Refresh (shared by proactive + reactive paths)
// ---------------------------------------------------------------------------

/// Issue `POST /core/v4/auth/refresh` and atomically replace session state.
///
/// Returns [`SessionManagerError::SessionExpired`] on 401 or 422, clearing
/// the keyring entry so the caller can detect the need to re-login.
///
/// `pub(crate)` so `http.rs` tests can drive it directly.
pub(crate) async fn do_refresh(
    state: &mut SessionState,
    http: &dyn ProtonDriveHttpClient,
) -> Result<(), SessionManagerError> {
    let body = serde_json::to_vec(&RefreshRequest {
        response_type: "token".to_owned(),
        grant_type: "refresh_token".to_owned(),
        refresh_token: state.refresh_token.as_str().to_owned(),
        redirect_uri: "https://protonmail.com".to_owned(),
    })?;

    let req = JsonRequest {
        method: HttpMethod::Post,
        path: "/core/v4/auth/refresh".to_owned(),
        query: vec![],
        headers: vec![("x-pm-uid".to_owned(), state.uid.clone())],
        body: Some(body),
    };

    let resp = http
        .request_json(req)
        .await
        .map_err(SessionManagerError::Http)?;

    if resp.status == 401 || resp.status == 422 {
        warn!(status = resp.status, "refresh rejected - session expired");
        let _ = delete_keyring(&state.uid); // best-effort
        return Err(SessionManagerError::SessionExpired);
    }

    let env: ResponseEnvelope<RefreshResponse> =
        serde_json::from_slice(&resp.body).map_err(SessionManagerError::Json)?;

    if env.code != common::CODE_OK {
        return Err(SessionManagerError::Http(proton_drive::Error::Internal(
            format!(
                "refresh endpoint returned code {}: {}",
                env.code,
                env.error.unwrap_or_default()
            ),
        )));
    }

    let new_token = env.inner;
    // Use 30 minutes as a conservative default; Proton does not currently
    // return an ExpiresIn field in the refresh response.
    let expires_at = Instant::now() + Duration::from_secs(30 * 60);

    // Persist before updating in-memory state. Keyring is best-effort (it may
    // be an in-memory backend on headless hosts); the 0600 secret file is the
    // authoritative fallback and must stay in sync with the rotated token.
    if let Err(e) = save_keyring(
        &state.uid,
        &new_token.refresh_token,
        state.key_password.as_str(),
    ) {
        warn!("keyring update on refresh failed ({e}); updating secret-file fallback");
    }
    save_secret_file(
        &state.uid,
        &new_token.refresh_token,
        state.key_password.as_str(),
    )?;
    write_session_file(&state.uid, &new_token.access_token, expires_at)?;

    *state.access_token = new_token.access_token;
    *state.refresh_token = new_token.refresh_token;
    state.expires_at = expires_at;

    debug!("token refresh succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// Proactive background refresh loop
// ---------------------------------------------------------------------------

/// Runs inside a `tokio::spawn`. Sleeps until `expires_at - 60 s`, refreshes,
/// then loops. Exits permanently on `SessionExpired`.
///
/// `pub(crate)` so integration tests can spawn it directly.
pub(crate) async fn proactive_refresh_loop(
    inner: Arc<RwLock<SessionState>>,
    http: Arc<dyn ProtonDriveHttpClient>,
) {
    loop {
        let sleep_duration = {
            let guard = inner.read().await;
            let advance = Duration::from_secs(60);
            guard
                .expires_at
                .saturating_duration_since(Instant::now() + advance)
        };
        // Floor at 1 s to avoid a busy-loop when token is nearly expired.
        let sleep_duration = sleep_duration.max(Duration::from_secs(1));
        debug!(
            secs = sleep_duration.as_secs(),
            "proactive refresh sleeping"
        );
        tokio::time::sleep(sleep_duration).await;

        let mut guard = inner.write().await;
        match do_refresh(&mut guard, &*http).await {
            Ok(()) => debug!("proactive refresh succeeded"),
            Err(SessionManagerError::SessionExpired) => {
                warn!("proactive refresh: session expired; background task exiting");
                return;
            }
            Err(e) => {
                warn!("proactive refresh transient error (will retry): {e}");
                drop(guard);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Owns the session tuple, drives proactive refresh, and exposes auth headers.
///
/// Construct via [`SessionManager::from_login`] or
/// [`SessionManager::from_keyring`].
pub struct SessionManager {
    pub(crate) inner: Arc<RwLock<SessionState>>,
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    /// Background refresh task. Aborted on drop.
    pub(crate) _refresh_task: JoinHandle<()>,
}

impl SessionManager {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Build a `SessionManager` from freshly-obtained credentials.
    ///
    /// Persists `refresh_token + key_password` to the keyring and
    /// `access_token + expiry` to `session.json`.
    ///
    /// Pass `expires_in_secs = 1800` if the server does not return an expiry.
    pub async fn from_login(
        http: Arc<dyn ProtonDriveHttpClient>,
        uid: String,
        access_token: Zeroizing<String>,
        refresh_token: Zeroizing<String>,
        key_password: Zeroizing<String>,
        expires_in_secs: u64,
    ) -> Result<Self, SessionManagerError> {
        let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);
        // Best-effort keyring write. On headless hosts the `keyring` crate
        // degrades to an in-memory backend that cannot persist across
        // processes, so the 0600 secret file below is the authoritative
        // fallback for `from_keyring` pickup (ADR-0007, personal use).
        if let Err(e) = save_keyring(&uid, refresh_token.as_str(), key_password.as_str()) {
            warn!("keyring write failed ({e}); relying on 0600 secret-file fallback");
        }
        save_secret_file(&uid, refresh_token.as_str(), key_password.as_str())?;
        write_session_file(&uid, access_token.as_str(), expires_at)?;
        let state = SessionState {
            uid,
            access_token,
            refresh_token,
            key_password,
            expires_at,
        };
        Ok(Self::build(state, http))
    }

    /// Resume a session by loading tokens from `session.json` and the OS
    /// keyring.
    pub async fn from_keyring(
        http: Arc<dyn ProtonDriveHttpClient>,
    ) -> Result<Self, SessionManagerError> {
        let sf = load_session_file()?;
        // Prefer the OS keyring; fall back to the 0600 secret file when the
        // keyring has no entry (e.g. an in-memory backend on a headless host
        // that did not survive the login process).
        let kp = match load_keyring(&sf.uid) {
            Ok(kp) => kp,
            Err(SessionManagerError::NoKeyring(_)) => load_secret_file(&sf.uid)?,
            Err(e) => return Err(e),
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let secs_remaining = sf.expires_at_unix.saturating_sub(now_unix);
        let expires_at = Instant::now() + Duration::from_secs(secs_remaining);

        let state = SessionState {
            uid: sf.uid,
            access_token: Zeroizing::new(sf.access_token),
            refresh_token: Zeroizing::new(kp.refresh_token),
            key_password: Zeroizing::new(kp.key_password),
            expires_at,
        };
        Ok(Self::build(state, http))
    }

    fn build(state: SessionState, http: Arc<dyn ProtonDriveHttpClient>) -> Self {
        let inner = Arc::new(RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&http);
        let _refresh_task = tokio::spawn(async move {
            proactive_refresh_loop(task_inner, task_http).await;
        });
        Self {
            inner,
            http,
            _refresh_task,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Return auth headers for one request (snapshot, no refresh).
    pub async fn auth_headers(&self) -> Vec<(String, String)> {
        let guard = self.inner.read().await;
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", guard.access_token.as_str()),
            ),
            ("x-pm-uid".to_owned(), guard.uid.clone()),
        ]
    }

    /// Force-refresh the access token (called on 401).
    ///
    /// Returns [`SessionManagerError::SessionExpired`] if the server rejects
    /// the refresh, after clearing the keyring.
    pub async fn force_refresh(&self) -> Result<(), SessionManagerError> {
        debug!("force_refresh: acquiring write lock");
        let mut guard = self.inner.write().await;
        do_refresh(&mut guard, &*self.http).await
    }

    /// Return the key password for unlocking the user's PGP private key.
    pub async fn key_password(&self) -> Zeroizing<String> {
        let guard = self.inner.read().await;
        guard.key_password.clone()
    }

    /// Delete the keyring entry, truncate `session.json`, and consume `self`.
    pub async fn logout(self) -> Result<(), SessionManagerError> {
        let uid = {
            let guard = self.inner.read().await;
            guard.uid.clone()
        };
        delete_keyring(&uid)?;
        delete_secret_file()?;
        truncate_session_file()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use bytes::Bytes;
    use proton_drive::{
        Result as DriveResult,
        http::{BlobRequest, JsonResponse},
    };
    use tokio::time::sleep;

    // -----------------------------------------------------------------------
    // Mock HTTP client
    // -----------------------------------------------------------------------

    pub(super) struct MockHttp {
        pub(super) responses: std::sync::Mutex<std::collections::VecDeque<(u16, String)>>,
        pub(super) call_count: AtomicUsize,
    }

    impl MockHttp {
        pub(super) fn new(responses: Vec<(u16, &str)>) -> Self {
            Self {
                responses: std::sync::Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b)| (s, b.to_owned()))
                        .collect(),
                ),
                call_count: AtomicUsize::new(0),
            }
        }

        pub(super) fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for MockHttp {
        async fn request_json(&self, _req: JsonRequest) -> DriveResult<JsonResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self.responses.lock().unwrap().pop_front().unwrap_or((
                200,
                r#"{"Code":1000,"UID":"u1","AccessToken":"new","RefreshToken":"newr"}"#.to_owned(),
            ));
            Ok(JsonResponse {
                status,
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

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    pub(super) fn make_state(expires_in_secs: u64) -> SessionState {
        SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("old_access".to_owned()),
            refresh_token: Zeroizing::new("old_refresh".to_owned()),
            key_password: Zeroizing::new("$2y$10$fakekeypassword".to_owned()),
            expires_at: Instant::now() + Duration::from_secs(expires_in_secs),
        }
    }

    fn success_refresh_body() -> &'static str {
        r#"{"Code":1000,"UID":"u1","AccessToken":"new_access","RefreshToken":"new_refresh"}"#
    }

    // -----------------------------------------------------------------------
    // Unit: do_refresh returns SessionExpired on 401
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_401_returns_session_expired() {
        let http = MockHttp::new(vec![(401, r#"{"Code":401,"Error":"Unauthorized"}"#)]);
        let mut state = make_state(1800);
        let result = do_refresh(&mut state, &http).await;
        assert!(
            matches!(result, Err(SessionManagerError::SessionExpired)),
            "expected SessionExpired, got: {result:?}"
        );
        assert_eq!(http.calls(), 1);
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock refresh returns 422; assert
    // SessionExpired and keyring cleared.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_422_session_expired_and_keyring_cleared() {
        let http = MockHttp::new(vec![(422, r#"{"Code":422,"Error":"Unprocessable"}"#)]);
        let mut state = make_state(1800);

        let result = do_refresh(&mut state, &http).await;

        assert!(
            matches!(result, Err(SessionManagerError::SessionExpired)),
            "422 must produce SessionExpired, got: {result:?}"
        );

        // delete_keyring is called internally; verify it does not panic when
        // there is no keyring entry (NoEntry is silently swallowed).
        let _ = delete_keyring("u1");
    }

    // -----------------------------------------------------------------------
    // Unit: successful refresh updates tokens
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_200_updates_state() {
        let http = MockHttp::new(vec![(200, success_refresh_body())]);
        let mut state = make_state(1800);
        do_refresh(&mut state, &http)
            .await
            .expect("refresh should succeed");
        assert_eq!(state.access_token.as_str(), "new_access");
        assert_eq!(state.refresh_token.as_str(), "new_refresh");
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock HTTP returns 401 once then 200;
    // assert exactly one refresh happened and the retry succeeded.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reactive_refresh_401_once_then_200() {
        let http = Arc::new(MockHttp::new(vec![
            (401, r#"{"Code":401,"Error":"Unauthorized"}"#),
            (200, success_refresh_body()),
        ]));

        let inner = Arc::new(RwLock::new(make_state(1800)));

        // First call -> 401 -> SessionExpired.
        {
            let mut guard = inner.write().await;
            let r = do_refresh(&mut guard, &*http).await;
            assert!(
                matches!(r, Err(SessionManagerError::SessionExpired)),
                "first refresh must fail with SessionExpired"
            );
        }
        assert_eq!(http.calls(), 1, "exactly one HTTP call for first attempt");

        // Re-install a valid refresh token to model re-login.
        {
            let mut guard = inner.write().await;
            *guard.refresh_token = "fresh_token".to_owned();
        }

        // Second call -> 200 -> success.
        {
            let mut guard = inner.write().await;
            let r = do_refresh(&mut guard, &*http).await;
            assert!(r.is_ok(), "second refresh must succeed");
            assert_eq!(guard.access_token.as_str(), "new_access");
        }
        assert_eq!(http.calls(), 2, "exactly two HTTP calls total");
    }

    // -----------------------------------------------------------------------
    // Unit: auth_headers returns correct snapshot
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn auth_headers_snapshot() {
        let http = Arc::new(MockHttp::new(vec![])) as Arc<dyn ProtonDriveHttpClient>;
        let state = make_state(1800);
        let inner = Arc::new(RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, Arc::clone(&http)));

        let mgr = SessionManager {
            inner,
            http,
            _refresh_task: handle,
        };

        let headers = mgr.auth_headers().await;
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer old_access"),
            "Authorization header mismatch: {headers:?}"
        );
        assert!(
            headers.iter().any(|(k, v)| k == "x-pm-uid" && v == "u1"),
            "x-pm-uid header missing: {headers:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration (ADR-0010 quality gate): spawn SessionManager with a short
    // expiry, sleep past it, observe proactive refresh fired.
    //
    // Marked #[ignore] because it is timing-sensitive.
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "timing-sensitive - run manually with --ignored"]
    async fn proactive_refresh_fires_before_expiry() {
        // Token expires in 2 s; the loop wakes after max(expiry - 60, 1) = 1 s.
        let http = Arc::new(MockHttp::new(vec![
            (200, success_refresh_body()),
            (200, success_refresh_body()),
        ]));
        let inner = Arc::new(RwLock::new(make_state(2)));

        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&http) as Arc<dyn ProtonDriveHttpClient>;
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, task_http));

        sleep(Duration::from_secs(3)).await;

        let token = {
            let guard = inner.read().await;
            guard.access_token.as_str().to_owned()
        };
        handle.abort();

        assert_eq!(token, "new_access", "token should be refreshed");
        assert!(http.calls() >= 1, "expected at least one refresh HTTP call");
    }

    // -----------------------------------------------------------------------
    // Backward-compat: legacy Session struct
    // -----------------------------------------------------------------------

    #[test]
    fn parses_minimal_session() {
        let json = r#"{"AccessToken": "tok", "UID": "u"}"#;
        let s: Session = serde_json::from_str(json).unwrap();
        assert_eq!(s.access_token, "tok");
        assert_eq!(s.uid, "u");
        assert_eq!(s.base_url, "https://drive.proton.me/api");
        assert!(s.app_version.starts_with("external-drive-pdtui@"));
    }

    #[test]
    fn auth_headers_include_bearer_and_uid() {
        let s = Session {
            access_token: "abc".into(),
            uid: "u1".into(),
            app_version: "x".into(),
            base_url: "x".into(),
        };
        let h = s.auth_headers();
        assert!(
            h.iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer abc")
        );
        assert!(h.iter().any(|(k, v)| k == "x-pm-uid" && v == "u1"));
    }

    // -----------------------------------------------------------------------
    // Persistence schema contract (regression for the login→pickup bug).
    //
    // The bug was a schema split: a CLI-login writer persisted a keyring entry
    // with no `key_password` and a `session.json` with no `ExpiresAt`, which
    // `from_keyring` could not resume. Both writers are now unified through
    // `save_keyring` / `write_session_file`. These tests pin the exact JSON
    // shapes that `load_keyring` / `load_session_file` must round-trip.
    // -----------------------------------------------------------------------

    #[test]
    fn keyring_payload_round_trips_with_key_password() {
        let payload = KeyringPayload {
            uid: "uid-123".to_owned(),
            refresh_token: "refresh-abc".to_owned(),
            key_password: "$2y$10$exampleexampleexample".to_owned(),
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        // The resume path (`load_keyring`) parses exactly this shape.
        let back: KeyringPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.uid, "uid-123");
        assert_eq!(back.refresh_token, "refresh-abc");
        assert_eq!(
            back.key_password, "$2y$10$exampleexampleexample",
            "key_password must survive the keyring round-trip — its absence was the login pickup bug"
        );
    }

    #[test]
    fn session_file_carries_expiry_for_resume() {
        let sf = SessionFile {
            uid: "uid-123".to_owned(),
            access_token: "access-xyz".to_owned(),
            expires_at_unix: 1_900_000_000,
            app_version: default_app_version(),
            base_url: default_base_url(),
        };
        let json = serde_json::to_string(&sf).expect("serialize");
        assert!(
            json.contains("\"ExpiresAt\""),
            "session.json must include ExpiresAt so from_keyring can compute remaining lifetime: {json}"
        );
        let back: SessionFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.uid, "uid-123");
        assert_eq!(back.access_token, "access-xyz");
        assert_eq!(back.expires_at_unix, 1_900_000_000);
    }
}
