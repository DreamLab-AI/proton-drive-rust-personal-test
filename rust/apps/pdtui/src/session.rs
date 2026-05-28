//! Session config loaded from `$XDG_CONFIG_HOME/pdtui/session.json` (or
//! `~/.config/pdtui/session.json`).
//!
//! This sidesteps M3-auth/SRP entirely. The user pastes a session bearer
//! token from a live JS-SDK or web session into the file once; the TUI then
//! makes authenticated requests as that user.
//!
//! **Personal use only.** The file is gitignored and never logged.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no session file at {0}")]
    NotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

impl Session {
    pub fn config_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".config")
            });
        base.join("pdtui").join("session.json")
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
