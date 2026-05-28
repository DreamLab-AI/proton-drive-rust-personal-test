//! Root client. Mirrors `js/sdk/src/protonDriveClient.ts` shape.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, BoxStream};

use crate::account::ProtonDriveAccount;
use crate::config::ProtonDriveConfig;
use crate::download::FileDownloader;
use crate::error::{Error, Result};
use crate::events::{DriveListener, EventSubscription, LatestEventIdProvider};
use crate::http::ProtonDriveHttpClient;
use crate::nodes::{CachedCryptoMaterial, FolderChildrenFilter, MaybeNode, NodeUid};
use crate::upload::{FileUploader, UploadMetadata};
use proton_drive_cache::ProtonDriveCache;
use proton_drive_crypto::{OpenPgpCrypto, SrpModule};
use proton_drive_telemetry::Telemetry;

/// All host-supplied dependencies for the SDK.
/// Mirrors JS `ProtonDriveClientContructorParameters`.
pub struct ProtonDriveClientOptions {
    pub http_client: Arc<dyn ProtonDriveHttpClient>,
    pub entities_cache: Arc<dyn ProtonDriveCache<String>>,
    pub crypto_cache: Arc<dyn ProtonDriveCache<CachedCryptoMaterial>>,
    pub account: Arc<dyn ProtonDriveAccount>,
    pub openpgp: Arc<dyn OpenPgpCrypto>,
    pub srp: Arc<dyn SrpModule>,
    pub config: ProtonDriveConfig,
    pub telemetry: Option<Arc<dyn Telemetry>>,
    pub latest_event_id: Option<Arc<dyn LatestEventIdProvider>>,
}

/// Root entry point.
pub struct ProtonDriveClient {
    opts: ProtonDriveClientOptions,
}

impl ProtonDriveClient {
    pub fn new(opts: ProtonDriveClientOptions) -> Self {
        Self { opts }
    }

    pub fn config(&self) -> &ProtonDriveConfig {
        &self.opts.config
    }

    pub fn account(&self) -> &Arc<dyn ProtonDriveAccount> {
        &self.opts.account
    }

    // ----- Nodes ------------------------------------------------------------

    pub async fn my_files_root(&self) -> Result<MaybeNode> {
        Err(Error::NotImplemented("my_files_root — pending M3"))
    }

    pub async fn node(&self, _uid: &NodeUid) -> Result<MaybeNode> {
        Err(Error::NotImplemented("node — pending M3"))
    }

    pub fn iter_folder_children<'a>(
        &'a self,
        _parent: &NodeUid,
        _filter: FolderChildrenFilter,
    ) -> BoxStream<'a, Result<MaybeNode>> {
        Box::pin(stream::once(async {
            Err(Error::NotImplemented("iter_folder_children — pending M3"))
        }))
    }

    pub async fn available_name(&self, _parent: &NodeUid, name: &str) -> Result<String> {
        // Until M3 we just echo — call sites should not rely on conflict-safety.
        Ok(name.to_owned())
    }

    // ----- Transfer ---------------------------------------------------------

    pub async fn file_uploader(
        &self,
        _parent: &NodeUid,
        _name: &str,
        meta: UploadMetadata,
    ) -> Result<Box<dyn FileUploader>> {
        meta.validate()?;
        Err(Error::NotImplemented("file_uploader — pending M4"))
    }

    pub async fn file_downloader(&self, _uid: &NodeUid) -> Result<Box<dyn FileDownloader>> {
        Err(Error::NotImplemented("file_downloader — pending M5"))
    }

    // ----- Events -----------------------------------------------------------

    pub async fn subscribe_drive_events(
        &self,
        _listener: Box<dyn DriveListener>,
    ) -> Result<EventSubscription> {
        Err(Error::NotImplemented("subscribe_drive_events — pending M6"))
    }
}

// Re-export so callers don't have to chase the trait import.
pub use async_trait::async_trait as _async_trait;

#[async_trait]
trait _AssertSendSync: Send + Sync {}
impl _AssertSendSync for ProtonDriveClient {}
