//! `reqwest`-backed `ProtonDriveHttpClient` with retry/backoff middleware.
//!
//! Implements the operational requirements from `README.md`:
//! - `x-pm-appversion` injected on every request
//! - retry transient failures with exponential backoff + jitter
//! - surface 429 as `Error::RateLimited` honouring `Retry-After`
//! - never proxy endpoints (constructor pins the base URL)
//!
//! # Session-aware wrapper (ADR-0010)
//!
//! [`SessionAwareHttpClient`] wraps any [`ProtonDriveHttpClient`] and injects
//! auth headers (`Authorization` + `x-pm-uid`) from a [`SessionManager`] on
//! every request. On a `401` response it calls
//! [`SessionManager::force_refresh`] once and retries the original request
//! exactly once. If the refresh itself fails with
//! [`SessionManagerError::SessionExpired`] that error is converted to
//! `Error::Internal` so the TUI can surface a re-login prompt.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use proton_drive::{
    Error, ProtonDriveHttpClient, Result,
    http::{BlobRequest, HttpMethod, JsonRequest, JsonResponse},
};
use rand::Rng as _;
use reqwest::Client;
use tracing::{debug, warn};

use crate::session::{SessionManager, SessionManagerError};

// ---------------------------------------------------------------------------
// ReqwestHttpClient -- bare transport layer, no auth injection
// ---------------------------------------------------------------------------

pub struct ReqwestHttpClient {
    base_url: String,
    app_version: String,
    client: Client,
    max_attempts: u32,
}

impl ReqwestHttpClient {
    pub fn new(base_url: impl Into<String>, app_version: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .user_agent("pdtui/0.0.1")
            .build()
            .map_err(|e| Error::Internal(format!("reqwest builder: {e}")))?;
        Ok(Self {
            base_url: base_url.into(),
            app_version: app_version.into(),
            client,
            max_attempts: 5,
        })
    }

    fn method(m: HttpMethod) -> reqwest::Method {
        match m {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
        }
    }

    async fn send_with_retry(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<JsonResponse> {
        let mut delay_ms: u64 = 250;
        for attempt in 1..=self.max_attempts {
            let req = build()
                .header("x-pm-appversion", &self.app_version)
                .header("accept", "application/json");
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429 {
                        let retry_after = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(5);
                        return Err(Error::RateLimited {
                            retry_after_secs: retry_after,
                        });
                    }
                    let headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                        .collect();
                    let bytes = resp
                        .bytes()
                        .await
                        .map_err(|e| Error::Network(format!("body read: {e}")))?;
                    if status.is_server_error() && attempt < self.max_attempts {
                        warn!(attempt, %status, "server error; retrying");
                        Self::sleep_with_jitter(delay_ms).await;
                        delay_ms = (delay_ms * 2).min(8_000);
                        continue;
                    }
                    return Ok(JsonResponse {
                        status: status.as_u16(),
                        headers,
                        body: bytes,
                    });
                }
                Err(e) if e.is_timeout() || e.is_connect() => {
                    if attempt >= self.max_attempts {
                        return Err(Error::Network(format!(
                            "transport error after {attempt} attempts: {e}"
                        )));
                    }
                    debug!(attempt, error = %e, "transient transport error; retrying");
                    Self::sleep_with_jitter(delay_ms).await;
                    delay_ms = (delay_ms * 2).min(8_000);
                }
                Err(e) => return Err(Error::Network(e.to_string())),
            }
        }
        Err(Error::Network("max retries exhausted".into()))
    }

    async fn sleep_with_jitter(base_ms: u64) {
        let jitter: u64 = rand::thread_rng().gen_range(0..(base_ms / 2 + 1));
        tokio::time::sleep(Duration::from_millis(base_ms + jitter)).await;
    }
}

#[async_trait]
impl ProtonDriveHttpClient for ReqwestHttpClient {
    async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            req.path.trim_start_matches('/')
        );
        self.send_with_retry(|| {
            let mut rb = self.client.request(Self::method(req.method), &url);
            for (k, v) in &req.query {
                rb = rb.query(&[(k.as_str(), v.as_str())]);
            }
            for (k, v) in &req.headers {
                rb = rb.header(k, v);
            }
            if let Some(body) = &req.body {
                rb = rb
                    .header("content-type", "application/json")
                    .body(body.clone());
            }
            rb
        })
        .await
    }

    async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
        // Block tokens carry an absolute, server-issued BareURL
        // (e.g. https://upload.proton.me/block/...). These are opaque blobs;
        // never rewrite them or prepend the API base_url. Only relative paths
        // are joined against base_url.
        let url = if req.path.starts_with("http://") || req.path.starts_with("https://") {
            req.path.clone()
        } else {
            format!(
                "{}/{}",
                self.base_url.trim_end_matches('/'),
                req.path.trim_start_matches('/')
            )
        };
        let body: Bytes = req.body.clone();
        let headers = req.headers.clone();
        self.send_with_retry(|| {
            let mut rb = self.client.request(Self::method(req.method), &url);
            for (k, v) in &req.query {
                rb = rb.query(&[(k.as_str(), v.as_str())]);
            }
            for (k, v) in &headers {
                rb = rb.header(k, v);
            }
            rb.body(body.clone())
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// SessionAwareHttpClient -- auth injection + 401-retry (ADR-0010)
// ---------------------------------------------------------------------------

/// Wraps any [`ProtonDriveHttpClient`] with session-aware auth injection.
///
/// On a `401` response the client calls [`SessionManager::force_refresh`] once
/// and retries the original request. If the refresh itself fails with
/// [`SessionManagerError::SessionExpired`], the error is converted to
/// `Error::Internal("session expired -- please log in again")`.
pub struct SessionAwareHttpClient {
    inner: Arc<dyn ProtonDriveHttpClient>,
    session: Arc<SessionManager>,
}

impl SessionAwareHttpClient {
    /// Wrap a transport client with session-aware auth injection.
    pub fn new(inner: Arc<dyn ProtonDriveHttpClient>, session: Arc<SessionManager>) -> Self {
        Self { inner, session }
    }

    /// Prepend session auth headers to `req.headers`, preserving any
    /// caller-supplied overrides.
    async fn with_auth_headers(&self, mut req: JsonRequest) -> JsonRequest {
        let mut auth = self.session.auth_headers().await;
        // Caller headers appended last so they can override auth headers.
        auth.append(&mut req.headers);
        req.headers = auth;
        req
    }
}

#[async_trait]
impl ProtonDriveHttpClient for SessionAwareHttpClient {
    async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
        let authed = self.with_auth_headers(req.clone()).await;
        let resp = self.inner.request_json(authed).await?;

        if resp.status != 401 {
            return Ok(resp);
        }

        debug!("401 received; attempting token refresh");
        match self.session.force_refresh().await {
            Ok(()) => {
                debug!("refresh succeeded; retrying original request");
                let authed_retry = self.with_auth_headers(req).await;
                self.inner.request_json(authed_retry).await
            }
            Err(SessionManagerError::SessionExpired) => {
                warn!("refresh returned SessionExpired; propagating to caller");
                Err(Error::Internal(
                    "session expired -- please log in again".to_owned(),
                ))
            }
            Err(e) => Err(Error::Internal(format!("refresh failed: {e}"))),
        }
    }

    async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
        let auth_headers = self.session.auth_headers().await;
        let mut full_headers = auth_headers;
        full_headers.extend_from_slice(&req.headers);

        let authed_req = BlobRequest {
            method: req.method,
            path: req.path.clone(),
            query: req.query.clone(),
            headers: full_headers,
            body: req.body.clone(),
        };
        let resp = self.inner.request_blob(authed_req).await?;

        if resp.status != 401 {
            return Ok(resp);
        }

        debug!("401 on blob; attempting token refresh");
        match self.session.force_refresh().await {
            Ok(()) => {
                let auth_headers = self.session.auth_headers().await;
                let mut full_headers = auth_headers;
                full_headers.extend_from_slice(&req.headers);
                let retry_req = BlobRequest {
                    method: req.method,
                    path: req.path,
                    query: req.query,
                    headers: full_headers,
                    body: req.body,
                };
                self.inner.request_blob(retry_req).await
            }
            Err(SessionManagerError::SessionExpired) => Err(Error::Internal(
                "session expired -- please log in again".to_owned(),
            )),
            Err(e) => Err(Error::Internal(format!("refresh failed: {e}"))),
        }
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
    use std::time::Instant;

    use zeroize::Zeroizing;

    use crate::session::{SessionState, do_refresh, proactive_refresh_loop};

    // -----------------------------------------------------------------------
    // Minimal mock transport
    // -----------------------------------------------------------------------

    struct SequentialMock {
        responses: std::sync::Mutex<std::collections::VecDeque<(u16, &'static str)>>,
        calls: AtomicUsize,
    }

    impl SequentialMock {
        fn new(seq: Vec<(u16, &'static str)>) -> Self {
            Self {
                responses: std::sync::Mutex::new(seq.into()),
                calls: AtomicUsize::new(0),
            }
        }

        #[allow(dead_code)]
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for SequentialMock {
        async fn request_json(&self, _req: JsonRequest) -> Result<JsonResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, r#"{"ok":true}"#));
            Ok(JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> Result<JsonResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, ""));
            Ok(JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build a SessionManager backed by a SequentialMock without
    // touching the keyring or filesystem.
    // -----------------------------------------------------------------------

    fn make_manager(mock: Arc<SequentialMock>) -> SessionManager {
        let state = SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("old_access".to_owned()),
            refresh_token: Zeroizing::new("old_refresh".to_owned()),
            key_password: Zeroizing::new("$2y$10$fake".to_owned()),
            expires_at: Instant::now() + std::time::Duration::from_secs(1800),
        };
        let inner = Arc::new(tokio::sync::RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&mock) as Arc<dyn ProtonDriveHttpClient>;
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, task_http));
        SessionManager {
            inner,
            http: mock as Arc<dyn ProtonDriveHttpClient>,
            _refresh_task: handle,
        }
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock HTTP returns 401 once then 200;
    // assert exactly one refresh happened and the retry succeeded.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_aware_401_once_then_200() {
        // Transport returns: 401 (first request), 200 refresh, 200 retry.
        let transport = Arc::new(SequentialMock::new(vec![
            (401, r#"{"Code":401,"Error":"Unauthorized"}"#),
            (
                200,
                r#"{"Code":1000,"UID":"u1","AccessToken":"new_access","RefreshToken":"new_refresh"}"#,
            ),
            (200, r#"{"Code":1000,"ok":true}"#),
        ]));

        let manager = Arc::new(make_manager(Arc::clone(&transport)));
        let client = SessionAwareHttpClient::new(
            Arc::clone(&transport) as Arc<dyn ProtonDriveHttpClient>,
            Arc::clone(&manager),
        );

        let req = JsonRequest {
            method: HttpMethod::Get,
            path: "/test".to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        };
        // Call 1: 401 -> triggers refresh (call 2) -> retry (call 3) -> 200.
        let resp = client
            .request_json(req)
            .await
            .expect("request should succeed");
        assert_eq!(resp.status, 200, "retry after refresh should return 200");
        assert_eq!(
            transport.calls.load(Ordering::SeqCst),
            3,
            "expected 3 transport calls: original + refresh + retry"
        );
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock refresh returns 422 -> SessionExpired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_422_propagates_session_expired_error() {
        let http = Arc::new(SequentialMock::new(vec![(
            422,
            r#"{"Code":422,"Error":"Unprocessable"}"#,
        )]));

        let state = SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("tok".to_owned()),
            refresh_token: Zeroizing::new("ref".to_owned()),
            key_password: Zeroizing::new("kp".to_owned()),
            expires_at: Instant::now() + std::time::Duration::from_secs(10),
        };
        let inner = Arc::new(tokio::sync::RwLock::new(state));
        let mut guard = inner.write().await;
        let result = do_refresh(&mut guard, &*http).await;
        assert!(
            matches!(
                result,
                Err(crate::session::SessionManagerError::SessionExpired)
            ),
            "422 should produce SessionExpired, got: {result:?}"
        );
    }
}
