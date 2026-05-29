//! # Proton Drive SDK (Rust)
//!
//! Re-export facade. Construct a client via [`ProtonDriveClient::new`] with a
//! [`ProtonDriveClientOptions`] populated by host-supplied trait objects.
//!
//! Domain model and bounded contexts: see `docs/domain-model.md`.
//! Architectural decisions: see `docs/adr/`.

#![forbid(unsafe_code)]

pub use proton_drive_cache::{MemoryCache, ProtonDriveCache};
pub use proton_drive_core::{
    Author, CachedCryptoMaterial, DriveEvent, DriveListener, Error, EventSubscription,
    FileDownloader, FileUploader, FolderChildrenFilter, MaybeNode, Node, NodeType, NodeUid,
    ProtonDriveAccount, ProtonDriveClient, ProtonDriveClientOptions, ProtonDriveConfig,
    ProtonDriveHttpClient, Result, Revision, UploadController, UploadMetadata, http, make_node_uid,
};
pub use proton_drive_crypto::{OpenPgpCrypto, RpgpCrypto, SessionKey, SrpModule};
pub use proton_drive_telemetry::{MetricEvent, NullTelemetry, Telemetry};

/// SDK semantic version. Used for `x-pm-appversion` headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
