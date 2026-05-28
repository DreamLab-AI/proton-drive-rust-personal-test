//! `reqwest`-backed `ProtonDriveHttpClient` with retry/backoff middleware.
//!
//! Implements the operational requirements from `README.md`:
//! - `x-pm-appversion` injected on every request
//! - retry transient failures with exponential backoff + jitter
//! - surface 429 as `Error::RateLimited` honouring `Retry-After`
//! - never proxy endpoints (constructor pins the base URL)

#![allow(dead_code)] // wired into App in M3 once auth lands

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
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            req.path.trim_start_matches('/')
        );
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
