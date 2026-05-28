//! Live-API diagnostic probes. These call Proton endpoints that don't
//! require crypto, exercising M1 (DTOs) + M3 (HTTP middleware) end-to-end.
//!
//! Run via the `probe` subcommand (`pdtui probe`). Output is one JSON object
//! per probe with `name`, `ok`, and either `data` or `error`. Suitable for
//! piping to `jq` or storing as fixtures.

use std::sync::Arc;

use proton_drive::{
    ProtonDriveHttpClient,
    http::{HttpMethod, JsonRequest},
};
use serde::{Deserialize, Serialize};

use crate::session::Session;

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub name: &'static str,
    pub status: u16,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

const BODY_PREVIEW_BYTES: usize = 1024;

pub async fn run_all(http: Arc<dyn ProtonDriveHttpClient>, session: &Session) -> Vec<ProbeResult> {
    let mut results = Vec::with_capacity(3);

    results.push(run_one(http.clone(), session, "get_users", "core/v4/users").await);

    let shares = run_one(http.clone(), session, "list_shares", "drive/shares").await;
    let volume_id = shares
        .body_preview
        .as_deref()
        .and_then(extract_first_volume_id);
    results.push(shares);

    let event_path = match volume_id {
        Some(vid) => format!("drive/volumes/{vid}/events/latest"),
        None => "drive/volumes/UNKNOWN/events/latest".to_owned(),
    };
    results.push(run_one(http, session, "get_latest_event_id", &event_path).await);

    results
}

async fn run_one(
    http: Arc<dyn ProtonDriveHttpClient>,
    session: &Session,
    name: &'static str,
    path: &str,
) -> ProbeResult {
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: session.auth_headers(),
        body: None,
    };
    match http.request_json(req).await {
        Ok(resp) => {
            let preview =
                String::from_utf8_lossy(&resp.body[..resp.body.len().min(BODY_PREVIEW_BYTES)])
                    .into_owned();
            ProbeResult {
                name,
                status: resp.status,
                ok: (200..300).contains(&resp.status),
                body_preview: Some(preview),
                error: None,
            }
        }
        Err(e) => ProbeResult {
            name,
            status: 0,
            ok: false,
            body_preview: None,
            error: Some(e.to_string()),
        },
    }
}

/// Extract the first share's VolumeID from a `drive/shares` response body.
/// Tolerant of either `{"Shares":[...]}` or a bare `[...]` array. Returns
/// `None` if the body isn't valid JSON or has no shares.
fn extract_first_volume_id(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ShareLike {
        #[serde(rename = "VolumeID")]
        volume_id: Option<String>,
    }
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(rename = "Shares")]
        shares: Option<Vec<ShareLike>>,
    }

    if let Ok(env) = serde_json::from_str::<Envelope>(body)
        && let Some(shares) = env.shares
        && let Some(first) = shares.into_iter().next()
    {
        return first.volume_id;
    }
    if let Ok(arr) = serde_json::from_str::<Vec<ShareLike>>(body)
        && let Some(first) = arr.into_iter().next()
    {
        return first.volume_id;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_volume_id_from_envelope() {
        let body = r#"{"Code":1000,"Shares":[{"ShareID":"s1","VolumeID":"v1","LinkID":"l1"}]}"#;
        assert_eq!(extract_first_volume_id(body).as_deref(), Some("v1"));
    }

    #[test]
    fn extracts_volume_id_from_bare_array() {
        let body = r#"[{"ShareID":"s1","VolumeID":"v2"}]"#;
        assert_eq!(extract_first_volume_id(body).as_deref(), Some("v2"));
    }

    #[test]
    fn returns_none_on_garbage() {
        assert!(extract_first_volume_id("not json").is_none());
        assert!(extract_first_volume_id(r#"{"Shares":[]}"#).is_none());
    }
}
