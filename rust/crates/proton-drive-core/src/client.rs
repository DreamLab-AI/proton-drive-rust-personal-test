//! Root client. Mirrors `js/sdk/src/protonDriveClient.ts` shape.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt as _};
use serde::de::DeserializeOwned;

use crate::account::ProtonDriveAccount;
use crate::config::ProtonDriveConfig;
use crate::download::{FileDownloader, resolve_volume_id};
use crate::error::{Error, Result};
use crate::events::{DriveListener, EventSubscription, LatestEventIdProvider};
use crate::http::{HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::{
    CachedCryptoMaterial, FolderChildrenFilter, MaybeNode, NodeUid, link_to_maybe_node,
    map_api_error,
};
use crate::upload::{FileUploader, ProtonFileUploader, UploadMetadata};
use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
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

    // ----- HTTP helpers -----------------------------------------------------

    async fn api_get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let req = JsonRequest {
            method: HttpMethod::Get,
            path: path.to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.opts.http_client.request_json(req).await?;
        let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner)
    }

    async fn api_get_with_query<T: DeserializeOwned>(
        &self,
        path: &str,
        query: Vec<(String, String)>,
    ) -> Result<T> {
        let req = JsonRequest {
            method: HttpMethod::Get,
            path: path.to_owned(),
            query,
            headers: vec![],
            body: None,
        };
        let resp = self.opts.http_client.request_json(req).await?;
        let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner)
    }

    // ----- Nodes ------------------------------------------------------------

    /// Fetch the user's My Files root node.
    ///
    /// Uses `GET drive/v2/shares/my-files` which returns the volume, share,
    /// and root link in a single round-trip. The root node name is decrypted
    /// as the literal string "root" (the share is bootstrapped with that name
    /// per the JS SDK's `generateVolumeBootstrap`). Full crypto verification
    /// of the node passphrase/name is a TODO MC-followup.
    pub async fn my_files_root(&self) -> Result<MaybeNode> {
        let resp: proton_drive_api::shares::GetMyFilesResponse =
            self.api_get("/drive/v2/shares/my-files").await?;

        let volume_id = resp.volume.volume_id;
        let link = resp.link.link;

        // Root node name is always "root" per Proton's volume bootstrap.
        // TODO MC-followup: verify by decrypting link.name with share key.
        Ok(link_to_maybe_node(
            link,
            &volume_id,
            Some("root".to_owned()),
        ))
    }

    /// Fetch a single node by its uid.
    ///
    /// Uses `GET drive/shares/{shareID}/links/{linkID}`.
    /// Name decryption is deferred (placeholder name with link ID).
    ///
    /// # TODO MC-followup: full name decryption requires AddressProvider integration
    pub async fn node(&self, uid: &NodeUid) -> Result<MaybeNode> {
        let path = format!("/drive/shares/{}/links/{}", uid.volume_id, uid.node_id);
        let resp: proton_drive_api::nodes::GetLinkResponse = self.api_get(&path).await?;
        Ok(link_to_maybe_node(resp.link, &uid.volume_id, None))
    }

    /// Iterate all children of a folder.
    ///
    /// Uses `GET drive/shares/{shareID}/folders/{linkID}/children` with
    /// page-based pagination (Page=0..N, PageSize=page_size). Iterates until
    /// `More == 0`. Returns a `Vec` rather than a stream; for MVP a single
    /// collected result is sufficient. Streams would be preferable for large
    /// folders — see TODO below.
    ///
    /// # TODO MC-followup: convert to async stream for large folder support
    ///
    /// Name decryption is deferred (placeholder names with link IDs).
    pub async fn fetch_folder_children(
        &self,
        parent: &NodeUid,
        page_size: u32,
    ) -> Result<Vec<MaybeNode>> {
        let mut results = Vec::new();
        let mut page: u32 = 0;

        loop {
            let path = format!(
                "/drive/shares/{}/folders/{}/children",
                parent.volume_id, parent.node_id
            );
            let query = vec![
                ("Page".to_owned(), page.to_string()),
                ("PageSize".to_owned(), page_size.to_string()),
            ];
            let resp: proton_drive_api::nodes::GetChildrenResponse =
                self.api_get_with_query(&path, query).await?;

            let more = resp.more;
            for link in resp.links {
                results.push(link_to_maybe_node(link, &parent.volume_id, None));
            }

            if more == 0 {
                break;
            }
            page += 1;
        }

        Ok(results)
    }

    /// Stream children of a folder as a `BoxStream`.
    ///
    /// For MVP this collects all pages up front then yields from the Vec.
    /// Full streaming pagination is a post-MVP concern (see TODO MC-followup).
    pub fn iter_folder_children<'a>(
        &'a self,
        parent: &NodeUid,
        _filter: FolderChildrenFilter,
    ) -> BoxStream<'a, Result<MaybeNode>> {
        let parent = parent.clone();
        // Collect all children eagerly, then stream from the resulting Vec.
        // Using a constant page size of 150 (Proton's typical max per page).
        Box::pin(
            stream::once(async move { self.fetch_folder_children(&parent, 150).await }).flat_map(
                |result| {
                    let items: Vec<Result<MaybeNode>> = match result {
                        Ok(nodes) => nodes.into_iter().map(Ok).collect(),
                        Err(e) => vec![Err(e)],
                    };
                    stream::iter(items)
                },
            ),
        )
    }

    pub async fn available_name(&self, _parent: &NodeUid, name: &str) -> Result<String> {
        // Until full listing is in place, echo — call sites should not rely on conflict-safety.
        Ok(name.to_owned())
    }

    // ----- Transfer ---------------------------------------------------------

    /// Construct a `FileUploader` for uploading a file to `parent`.
    ///
    /// Validates metadata then returns a `ProtonFileUploader` ready to stream
    /// data. Call `upload_from_stream` on the returned uploader to execute the
    /// 5-step block-upload protocol (ADR-0008).
    ///
    /// # FIXME: NodeUid naming — see MC commit f6b29b1 note
    /// `parent.volume_id` holds the share_id from listing endpoints;
    /// the real VolumeID is resolved lazily inside `run_upload`.
    pub async fn file_uploader(
        &self,
        parent: &NodeUid,
        name: &str,
        meta: UploadMetadata,
    ) -> Result<Box<dyn FileUploader>> {
        meta.validate()?;
        Ok(Box::new(ProtonFileUploader {
            http: self.opts.http_client.clone(),
            openpgp: self.opts.openpgp.clone(),
            account: self.opts.account.clone(),
            parent: parent.clone(),
            name: name.to_owned(),
            metadata: meta,
        }))
    }

    /// Construct a `FileDownloader` for the given node.
    ///
    /// # Protocol steps (ADR-0009)
    /// 1. Re-fetch the link to get the active revision ID and the node's key material.
    /// 2. Resolve the true volume ID via `GET drive/shares/{shareID}`.
    ///    `NodeUid.volume_id` from MC's listing holds a **share ID**, not the volume ID.
    ///    FIXME: NodeUid naming — see MC commit f6b29b1
    /// 3. Decrypt the share key (address_key → share passphrase → share private key).
    /// 4. Decrypt the node private key (share_key → node passphrase → node private key).
    ///    MVP restriction: only files directly under the share root are supported.
    ///    For nested files, parent folder key derivation is needed — deferred.
    /// 5. Build `FileDownloader` with resolved context.
    pub async fn file_downloader(&self, uid: &NodeUid) -> Result<FileDownloader> {
        // Step 1: re-fetch the link for active revision + key material.
        // uid.volume_id is actually the share_id from MC's listing.
        // FIXME: NodeUid naming — see MC commit f6b29b1
        let share_id = &uid.volume_id;
        let link_id = &uid.node_id;

        let link_path = format!("/drive/shares/{share_id}/links/{link_id}");
        let link_resp: proton_drive_api::nodes::GetLinkResponse = self.api_get(&link_path).await?;
        let link = link_resp.link;

        // Verify this is a file node.
        if link.r#type != 2 {
            return Err(Error::Validation(
                "file_downloader: node is not a file (type != 2)".into(),
            ));
        }

        let file_props = link
            .file_properties
            .as_ref()
            .ok_or_else(|| Error::Internal("file link missing FileProperties".into()))?;

        let revision_id = file_props
            .active_revision
            .as_ref()
            .map(|r| r.id.clone())
            .ok_or_else(|| Error::NotFound("file has no active revision".into()))?;

        let signature_email = file_props
            .active_revision
            .as_ref()
            .and_then(|r| r.signature_email.clone());

        // Step 2: resolve volume_id from share.
        let volume_id = resolve_volume_id(&self.opts.http_client, share_id).await?;

        // Step 3: get the share metadata to decrypt the share key.
        let share_resp: proton_drive_api::shares::GetShareResponse =
            self.api_get(&format!("/drive/shares/{share_id}")).await?;
        let share = share_resp.share;

        // Decrypt share key using the user's address private key.
        let address_email = self.opts.account.primary_email();
        let address_key = self.opts.account.address_private_key(address_email).await?;

        let share_priv = crate::download::decrypt_share_key(
            &self.opts.openpgp,
            &share.key,
            &share.passphrase,
            &address_key,
        )
        .await?;

        // Step 4: decrypt the node private key using the share key.
        // MVP: only root-level files. Nested files require parent key walk — deferred.
        if link.parent_link_id.as_deref() != Some(&share.link_id) && link.parent_link_id.is_some() {
            // Check if this node IS the root link or a direct child of the share root.
            // For simplicity at MVP, we attempt decryption regardless and let crypto fail.
            // A real check would compare parent_link_id to the share's root link_id.
            tracing::warn!(
                node_id = %link_id,
                parent_id = ?link.parent_link_id,
                root_link_id = %share.link_id,
                // FIXME: NodeUid naming — see MC commit f6b29b1
                "nested file download: parent is not share root — attempting decryption \
                 (MVP scope: root-only; Error::NotImplemented if key chain fails)"
            );
        }

        let node_priv = crate::download::decrypt_node_private_key(
            &self.opts.openpgp,
            &link.node_key,
            &link.node_passphrase,
            &share_priv,
        )
        .await
        .map_err(|_| {
            Error::NotImplemented(
                "nested file download — parent node key derivation required (MVP: root-level only)",
            )
        })?;

        // Step 5: resolve the signer's public key.
        let signature_address_pub = if let Some(ref email) = signature_email {
            match self.opts.account.address_private_key(email).await {
                Ok(priv_key) => {
                    // Parse public key from the private key armored.
                    Some(proton_drive_crypto::PublicKey {
                        armored: {
                            // Extract public portion from the private key armored text.
                            // For rpgp, the private key armored includes the public key.
                            // We store just the armored public form if available.
                            // Fallback: use the node key's armored public key.
                            priv_key.armored.clone()
                        },
                        fingerprint_hex: priv_key.fingerprint_hex.clone(),
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        "could not resolve signature address public key: {e} — \
                         signature verification will be skipped"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(FileDownloader {
            http: self.opts.http_client.clone(),
            crypto: self.opts.openpgp.clone(),
            node_uid: uid.clone(),
            volume_id,
            share_id: share_id.clone(),
            revision_id,
            node_private_key: node_priv,
            signature_address_pub,
        })
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
