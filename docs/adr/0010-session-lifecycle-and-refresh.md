# ADR-0010: Session lifecycle and token refresh

**Status:** accepted, 2026-05-28.
**Context milestone:** MG.

## Decision

A `SessionManager` owns the (uid, access_token, refresh_token, key_password, expiry) tuple. It serialises access via a `tokio::sync::RwLock` so HTTP requests read a snapshot atomically. A background `tokio::task` refreshes proactively at `expiry - 60s`. HTTP 401 responses trigger a single forced refresh + retry. Persistence: refresh_token + key_password in the OS keyring (existing); access_token + expiry in `session.json` mode 0600. On logout the keyring entry is deleted and the file truncated.

## Why proactive + reactive

Proactive (background timer) avoids latency spikes mid-upload — a 4 MiB PUT that races a token refresh is the worst time to introduce a 200ms HTTPS round-trip into the critical path. Reactive (401 retry) handles the cases proactive misses: clock skew, revocation, sleep/resume.

## API shape

```rust
// apps/pdtui/src/session.rs (existing file, extended)
pub struct SessionManager {
    inner: Arc<RwLock<SessionState>>,
    http: Arc<dyn ProtonDriveHttpClient>,
    _refresh_task: JoinHandle<()>,
}

struct SessionState {
    uid: String,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    key_password: Zeroizing<String>,
    expires_at: Instant,
}

impl SessionManager {
    pub async fn from_login(http: Arc<dyn ProtonDriveHttpClient>, creds: Credentials)
        -> Result<Self, Error>;

    pub async fn from_keyring(http: Arc<dyn ProtonDriveHttpClient>) -> Result<Self, Error>;

    pub async fn auth_headers(&self) -> HeaderMap;  // reads snapshot, no refresh

    pub async fn force_refresh(&self) -> Result<(), Error>;  // call on 401

    pub async fn logout(self) -> Result<(), Error>;  // wipes keyring + file
}
```

The HTTP middleware (`apps/pdtui/src/http.rs`) gets a `Arc<SessionManager>` injected. On `401` response from any request it calls `force_refresh().await` then retries once. If the refresh itself returns 401 or 422, propagate `Error::SessionExpired` to the caller, which the TUI surfaces as "session expired, please log in again."

## Refresh endpoint

`POST /core/v4/auth/refresh` body `{ "ResponseType": "token", "GrantType": "refresh_token", "RefreshToken": "<token>", "RedirectURI": "https://protonmail.com" }`. Response: same shape as login `Auth` response (new access + refresh + expiry). On success, replace state atomically and persist.

## What is NOT done in this ADR

- Multiple parallel sessions (we have one user, one device)
- Session timeout / inactivity logout
- Forced re-auth after N hours regardless of refresh success
- Hardware-backed token storage beyond the OS keyring

## Quality gates

- **Unit test:** mock HTTP returns 401 once, then 200; assert one refresh call happened and the retry succeeded.
- **Unit test:** mock refresh endpoint returns 422; assert `Error::SessionExpired` and that the keyring entry was cleared.
- **Integration test (`#[ignore]`):** spawn a SessionManager, sleep past expiry, make a request, observe refresh fired.
- **Manual:** kill the network for 30s during an upload; reconnect; observe the upload resumes at the next block PUT after one refresh attempt.

## References

- JS reference: external Proton CLI handles this; not in `js/sdk/` proper.
- `tokio::sync::RwLock` over `Mutex` because reads (per-request header fetch) outnumber writes (per ~30min refresh) by 10⁴.
