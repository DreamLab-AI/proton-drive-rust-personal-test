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
use serde::Serialize;

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
    let probes: &[(&'static str, &'static str)] = &[
        ("get_users", "core/v4/users"),
        ("list_shares", "drive/shares"),
        ("get_latest_event_id", "drive/v2/events/latest"),
    ];

    let mut results = Vec::with_capacity(probes.len());
    for (name, path) in probes {
        results.push(run_one(http.clone(), session, name, path).await);
    }
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
