//! DownloadJob aggregate. Mirrors `js/sdk/src/interface/download.ts`.

use async_trait::async_trait;
use tokio::io::AsyncWrite;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::error::Result;

#[async_trait]
pub trait FileDownloader: Send + Sync {
    /// Claimed cleartext size of the file. Encrypted server-side; treat as untrusted.
    fn claimed_size_bytes(&self) -> Option<u64>;

    /// Default path: download + decrypt + verify into the provided sink.
    async fn download_to_stream(
        &self,
        sink: Box<dyn AsyncWrite + Send + Unpin>,
        progress: watch::Sender<u64>,
    ) -> Result<DownloadController>;

    /// Skip integrity verification. Mirrors JS `unsafeDownloadToStream`.
    /// **Debug only** — real call sites must use `download_to_stream`.
    async fn unsafe_download_to_stream(
        &self,
        sink: Box<dyn AsyncWrite + Send + Unpin>,
        progress: watch::Sender<u64>,
    ) -> Result<DownloadController>;
}

pub struct DownloadController {
    pub(crate) cancel: CancellationToken,
    pub(crate) progress: watch::Receiver<u64>,
}

impl DownloadController {
    pub fn progress(&self) -> &watch::Receiver<u64> {
        &self.progress
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}
