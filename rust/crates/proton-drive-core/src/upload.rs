//! UploadJob aggregate. Mirrors `js/sdk/src/interface/upload.ts`.

use async_trait::async_trait;
use tokio::io::AsyncRead;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct UploadMetadata {
    pub media_type: String,
    /// Required — server uses it for integrity. Missing it is a programming error.
    pub expected_size: u64,
    /// Optional SHA1 of cleartext; SDK verifies after streaming.
    pub expected_sha1_hex: Option<String>,
    pub modification_time: Option<std::time::SystemTime>,
    pub additional_metadata_json: Option<String>,
    /// If true, override any existing draft owned by another client.
    pub override_existing_draft_by_other_client: bool,
}

/// Builder returned by `ProtonDriveClient::file_uploader`.
#[async_trait]
pub trait FileUploader: Send + Sync {
    /// Upload from a streaming source. Resolves to a controller with pause/resume.
    async fn upload_from_stream(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        progress: watch::Sender<u64>,
    ) -> Result<UploadController>;
}

/// Active upload handle.
pub struct UploadController {
    pub(crate) cancel: CancellationToken,
    pub(crate) progress: watch::Receiver<u64>,
}

impl UploadController {
    pub fn progress(&self) -> &watch::Receiver<u64> {
        &self.progress
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

impl UploadMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.expected_size == 0 {
            return Err(Error::Validation(
                "expected_size must be > 0 (server uses it for integrity)".into(),
            ));
        }
        if let Some(sha1) = &self.expected_sha1_hex
            && sha1.len() != 40
        {
            return Err(Error::Validation(
                "expected_sha1_hex must be 40 hex chars (SHA1)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(size: u64, sha1: Option<&str>) -> UploadMetadata {
        UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: size,
            expected_sha1_hex: sha1.map(str::to_owned),
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        }
    }

    #[test]
    fn rejects_zero_size() {
        let r = meta(0, None).validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn rejects_short_sha1() {
        let r = meta(10, Some("abc")).validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn accepts_valid_meta() {
        let r = meta(10, Some(&"a".repeat(40))).validate();
        assert!(r.is_ok());
    }

    #[test]
    fn accepts_no_sha1() {
        let r = meta(10, None).validate();
        assert!(r.is_ok());
    }
}
