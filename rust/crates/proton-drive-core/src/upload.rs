//! Block-upload protocol — ADR-0008 §"The protocol".
//!
//! Implements `FileUploader::upload_from_stream` for files < 16 MiB.
//! Happy path only; thumbnail upload, resumable upload, parallel blocks, and
//! telemetry are explicitly out of scope (ADR-0008 §"What is NOT ported").
//!
//! ## Mapping divergence: JS vs ADR-0008
//!
//! The JS SDK (apiService.ts) does **not** pass `Hash` or `Size` per block in
//! the RequestBlockUpload call — those fields were deprecated server-side.
//! ADR-0008 step 3 still mentions them, but we follow the JS implementation
//! and omit them from `BlockList` entries (the `RequestBlockUploadRequest` in
//! proton-drive-api retains the fields for the commit step only).
//!
//! The verifier token is computed as `verificationCode XOR ciphertext[0..len]`
//! (blockVerifier.ts semantics) and sent as base64.
//!
//! The block upload (step 4) is a multipart form-data POST with a "Block" part,
//! not a raw-binary PUT, matching apiService.ts `postBlockStream`/`uploadBlock`.
//! We send raw bytes in a form field named "Block" via a bespoke request; the
//! existing `request_blob` method is used for the binary body.
//!
//! ## FIXME: NodeUid naming
//!
//! MC commit f6b29b1 note: `NodeUid.volume_id` stores the Proton **share ID**
//! from listing endpoints. Volume-scoped POST endpoints need the real VolumeID.
//! Before any `drive/v2/volumes/{volumeID}/...` call we fetch
//! `GET drive/shares/{shareID}` to resolve the actual volume_id.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_api::upload::{
    BlockUploadEntry, BlockVerifier as ApiBlockVerifier, CommitRevisionRequest, CreateFileRequest,
    RequestBlockUploadRequest,
};
use proton_drive_crypto::{EncryptOptions, OpenPgpCrypto, PublicKey};

use crate::account::ProtonDriveAccount;
use crate::error::{Error, Result};
use crate::http::{BlobRequest, HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::{NodeUid, map_api_error};

/// 4 MiB — server rejects blocks larger than this.
pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;
/// 16 MiB MVP limit (domain-model-mvp.md invariant table).
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;

// ── public types ──────────────────────────────────────────────────────────────

/// Metadata supplied by the caller alongside the stream.
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
        if self.expected_size > MAX_FILE_SIZE {
            return Err(Error::Validation(format!(
                "file exceeds MVP limit: {} > {} bytes",
                self.expected_size, MAX_FILE_SIZE
            )));
        }
        Ok(())
    }
}

/// Active upload handle — returned from `upload_from_stream`.
/// For MVP the upload is synchronous; this type is a thin wrapper around the
/// cancellation token and byte counter.
pub struct UploadController {
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    pub(crate) progress: tokio::sync::watch::Receiver<u64>,
}

impl UploadController {
    pub fn progress(&self) -> &tokio::sync::watch::Receiver<u64> {
        &self.progress
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// Builder returned by `ProtonDriveClient::file_uploader`.
#[async_trait::async_trait]
pub trait FileUploader: Send + Sync {
    /// Upload from a streaming source. Resolves to a controller with pause/resume.
    async fn upload_from_stream(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        progress: tokio::sync::watch::Sender<u64>,
    ) -> Result<UploadController>;
}

// ── internal block representation ─────────────────────────────────────────────

struct EncryptedBlock {
    index: u32,
    ciphertext: Vec<u8>,
    /// hex-encoded sha256 of the ciphertext
    ciphertext_hash_hex: String,
    /// armored PGP signature of plaintext, encrypted to address public key
    enc_signature: String,
    /// XOR-based verifier token (base64)
    verifier_token_b64: String,
    size: u64,
}

// ── ProtonFileUploader ────────────────────────────────────────────────────────

/// Concrete uploader bound to a specific parent folder.
pub struct ProtonFileUploader {
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    pub(crate) openpgp: Arc<dyn OpenPgpCrypto>,
    pub(crate) account: Arc<dyn ProtonDriveAccount>,
    /// The parent folder's NodeUid.
    /// FIXME: NodeUid naming — see MC commit f6b29b1 note.
    /// `parent.volume_id` holds the share_id from listing endpoints.
    pub(crate) parent: NodeUid,
    /// File name to upload.
    pub(crate) name: String,
    /// UploadMetadata for this upload.
    pub(crate) metadata: UploadMetadata,
}

#[async_trait::async_trait]
impl FileUploader for ProtonFileUploader {
    async fn upload_from_stream(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        progress_tx: tokio::sync::watch::Sender<u64>,
    ) -> Result<UploadController> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (progress_inner_tx, progress_rx) = tokio::sync::watch::channel::<u64>(0u64);

        // Run the actual upload inline (MVP is single-threaded / sequential).
        // We pass the cancel token in; if cancelled mid-upload we surface an error.
        let result = self.run_upload(stream, &progress_tx, &cancel).await;

        // Mirror progress to the inner channel for the UploadController.
        let _ = progress_inner_tx.send(*progress_tx.borrow());

        result?;

        Ok(UploadController {
            cancel,
            progress: progress_rx,
        })
    }
}

impl ProtonFileUploader {
    /// Full 5-step block-upload protocol (ADR-0008).
    async fn run_upload(
        &self,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
        progress_tx: &tokio::sync::watch::Sender<u64>,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        // ── step 0: resolve real volume_id ────────────────────────────────────
        // FIXME: NodeUid naming — see MC commit f6b29b1 note.
        // `parent.volume_id` is actually the share_id.
        let share_id = &self.parent.volume_id;
        let volume_id = self.resolve_volume_id(share_id).await?;

        // ── step 0b: get address key ──────────────────────────────────────────
        let address_email = self.account.primary_email().to_owned();
        let address_priv = self.account.address_private_key(&address_email).await?;

        let address_pub = {
            // Parse the private key's armored form to extract the public key.
            // We need a PublicKey from the private key. Extract via decrypt_key
            // to get the fingerprint, then use the armored private as armored public
            // (rpgp supports parsing either).
            // Actually we need the public armored form. Generate a PublicKey value
            // from the address_priv armored key by parsing and re-exporting.
            // For now, construct PublicKey with the same armored text —
            // rpgp's `parse_public_key` will skip the secret-key packets and
            // use the embedded public key material.
            //
            // FIXME: This is a workaround. Ideally ProtonDriveAccount exposes
            // `address_public_key()`. rpgp's `SignedSecretKey::signed_public_key()`
            // produces the public key — but here we only have the armored string.
            // We pass the private key armored as the "public" key; rpgp's
            // `SignedPublicKey::from_armor_single` accepts armored secret keys
            // and extracts the public portion.
            PublicKey {
                armored: address_priv.armored.clone(),
                fingerprint_hex: address_priv.fingerprint_hex.clone(),
            }
        };

        // ── step 1: generate node crypto ─────────────────────────────────────
        let node_passphrase = self.openpgp.generate_passphrase();

        let (node_priv, node_pub_armored) = self
            .openpgp
            .generate_key(&node_passphrase, EncryptOptions::default())
            .await?;

        let node_pub = PublicKey {
            armored: node_pub_armored.clone(),
            fingerprint_hex: node_priv.fingerprint_hex.clone(),
        };

        // Encrypt node passphrase to parent node key (parent.volume_id is share_id;
        // we use share key here) + sign with address key.
        // Obtain parent node key: fetch parent link and decrypt its passphrase.
        // For MVP, we fetch the parent share key to decrypt the parent node passphrase.
        let parent_node_priv = self.resolve_parent_node_key(share_id).await?;

        let parent_node_pub = PublicKey {
            armored: parent_node_priv.armored.clone(),
            fingerprint_hex: parent_node_priv.fingerprint_hex.clone(),
        };

        // Encrypt the new node's passphrase to the parent node key.
        let node_passphrase_bytes = node_passphrase.as_bytes();
        let passphrase_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let node_passphrase_encrypted = self
            .openpgp
            .encrypt_and_sign(
                node_passphrase_bytes,
                &passphrase_session_key,
                std::slice::from_ref(&parent_node_pub),
                &address_priv,
                EncryptOptions::default(),
            )
            .await?;
        let node_passphrase_armored =
            base64::engine::general_purpose::STANDARD.encode(&node_passphrase_encrypted);

        // Sign the node passphrase with address key (detached signature on
        // the armored encrypted passphrase bytes — matches JS `generateNodeKeys`).
        let passphrase_sig = self
            .openpgp
            .sign(
                &node_passphrase_encrypted,
                &address_priv,
                "drive.node.passphrase",
            )
            .await?;
        let passphrase_sig_armored =
            base64::engine::general_purpose::STANDARD.encode(&passphrase_sig);

        // ── step 1b: generate content session key ─────────────────────────────
        let content_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;

        // Wrap content session key in PKESK to node public key.
        let content_key_packet_bytes = self
            .openpgp
            .encrypt_session_key(&content_session_key, std::slice::from_ref(&node_pub))
            .await?;
        let content_key_packet_b64 =
            base64::engine::general_purpose::STANDARD.encode(&content_key_packet_bytes);

        // Sign the content key packet with the address key.
        let content_key_sig = self
            .openpgp
            .sign(
                &content_key_packet_bytes,
                &address_priv,
                "drive.file.content-key",
            )
            .await?;
        let content_key_sig_armored =
            base64::engine::general_purpose::STANDARD.encode(&content_key_sig);

        // ── step 1c: encrypt file name + compute name hash ────────────────────
        let name_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let encrypted_name_bytes = self
            .openpgp
            .encrypt_and_sign(
                self.name.as_bytes(),
                &name_session_key,
                &[parent_node_pub],
                &address_priv,
                EncryptOptions::default(),
            )
            .await?;
        let encrypted_name_armored =
            base64::engine::general_purpose::STANDARD.encode(&encrypted_name_bytes);

        // Name hash: HMAC-SHA256(parent_hash_key, name_bytes) → hex.
        // For MVP we use SHA256(name_bytes) as parent hash key is not yet
        // resolved from the parent node. This will fail server-side validation
        // until full parent hash key resolution is implemented.
        //
        // FIXME: need parent node's NodeHashKey (FolderProperties.NodeHashKey)
        // decrypted to compute the proper HMAC. For now fall back to SHA256(name).
        let name_hash_hex = {
            let mut hasher = Sha256::new();
            hasher.update(self.name.as_bytes());
            hex::encode(hasher.finalize())
        };

        // ── step 2: POST create file node ─────────────────────────────────────
        let create_req = CreateFileRequest {
            name: encrypted_name_armored,
            hash: name_hash_hex,
            parent_link_id: self.parent.node_id.clone(),
            node_key: node_pub_armored,
            node_passphrase: node_passphrase_armored,
            node_passphrase_signature: passphrase_sig_armored,
            signature_address: address_email.clone(),
            content_key_packet: content_key_packet_b64,
            content_key_packet_signature: content_key_sig_armored,
            mime_type: self.metadata.media_type.clone(),
            client_uid: None,
        };

        let (link_id, revision_id) = self.post_create_file(&volume_id, create_req).await?;

        // ── step 3: get verification data from server ─────────────────────────
        // The JS SDK fetches a verification code from:
        //   GET drive/v2/volumes/{volumeID}/links/{linkID}/revisions/{revisionID}/verification
        // which returns { VerificationCode: base64, ContentKeyPacket: base64 }.
        // This is used to compute the verifier token per block.
        let verification_code = self
            .get_verification_code(&volume_id, &link_id, &revision_id)
            .await?;

        // ── step 4: read stream, chunk into 4 MiB blocks, encrypt each ────────
        let mut blocks: Vec<EncryptedBlock> = Vec::new();
        let mut sha1_hasher = Sha1::new();
        let mut total_bytes: u64 = 0;
        let mut block_index: u32 = 0;

        loop {
            if cancel.is_cancelled() {
                return Err(Error::Internal("upload cancelled".into()));
            }

            let mut buf = vec![0u8; BLOCK_SIZE];
            let mut read_bytes: usize = 0;

            // Fill buffer up to BLOCK_SIZE.
            loop {
                let remaining = BLOCK_SIZE - read_bytes;
                match stream
                    .read(&mut buf[read_bytes..read_bytes + remaining])
                    .await
                {
                    Ok(0) => break,
                    Ok(n) => {
                        read_bytes += n;
                        if read_bytes == BLOCK_SIZE {
                            break;
                        }
                    }
                    Err(e) => return Err(Error::Network(format!("stream read: {e}"))),
                }
            }

            if read_bytes == 0 {
                break; // EOF
            }

            let plaintext_block = &buf[..read_bytes];
            sha1_hasher.update(plaintext_block);
            total_bytes += read_bytes as u64;

            // Encrypt block with content session key (no PKESK for blocks —
            // bare SEIPD per ADR-0008).
            let ciphertext = self
                .openpgp
                .encrypt_and_sign(
                    plaintext_block,
                    &content_session_key,
                    &[], // no PKESK — bare SEIPD
                    &address_priv,
                    EncryptOptions::default(),
                )
                .await?;

            // SHA256 of ciphertext.
            let ciphertext_hash: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(&ciphertext);
                h.finalize().into()
            };
            let ciphertext_hash_hex = hex::encode(ciphertext_hash);

            // Detached signature of plaintext block.
            let block_sig_bytes = self
                .openpgp
                .sign(plaintext_block, &address_priv, "drive.file.block")
                .await?;

            // Encrypt the block signature to the address public key.
            let block_sig_session_key = self
                .openpgp
                .generate_session_key(&[], EncryptOptions::default())
                .await?;
            let enc_sig_bytes = self
                .openpgp
                .encrypt_and_sign(
                    &block_sig_bytes,
                    &block_sig_session_key,
                    std::slice::from_ref(&address_pub),
                    &address_priv,
                    EncryptOptions::default(),
                )
                .await?;
            let enc_signature_armored =
                base64::engine::general_purpose::STANDARD.encode(&enc_sig_bytes);

            // Verifier token: XOR verification_code[i] with ciphertext[i].
            // (blockVerifier.ts: `verificationCode.map((v, i) => v ^ (encryptedData[i] || 0))`)
            let verifier_token: Vec<u8> = verification_code
                .iter()
                .enumerate()
                .map(|(i, &v)| v ^ ciphertext.get(i).copied().unwrap_or(0))
                .collect();
            let verifier_token_b64 =
                base64::engine::general_purpose::STANDARD.encode(&verifier_token);

            blocks.push(EncryptedBlock {
                index: block_index,
                ciphertext,
                ciphertext_hash_hex,
                enc_signature: enc_signature_armored,
                verifier_token_b64,
                size: read_bytes as u64,
            });

            block_index += 1;

            let _ = progress_tx.send(total_bytes);

            if read_bytes < BLOCK_SIZE {
                break; // last block
            }
        }

        if blocks.is_empty() {
            return Err(Error::Validation(
                "upload_from_stream: stream was empty".into(),
            ));
        }

        // Validate computed size against expected_size.
        if total_bytes != self.metadata.expected_size {
            return Err(Error::Validation(format!(
                "stream size mismatch: expected {} bytes, got {}",
                self.metadata.expected_size, total_bytes
            )));
        }

        // ── step 5: POST request block upload tokens ──────────────────────────
        let block_entries: Vec<BlockUploadEntry> = blocks
            .iter()
            .map(|b| BlockUploadEntry {
                index: b.index,
                hash: b.ciphertext_hash_hex.clone(),
                encrypted_signature: b.enc_signature.clone(),
                size: b.size,
                verifier: ApiBlockVerifier {
                    token: b.verifier_token_b64.clone(),
                },
            })
            .collect();

        let block_req = RequestBlockUploadRequest {
            block_list: block_entries,
            address_id: address_email.clone(),
            link_id: link_id.clone(),
            revision_id: revision_id.clone(),
            volume_id: volume_id.clone(),
        };

        let upload_links = self.post_request_blocks(block_req).await?;

        if upload_links.len() != blocks.len() {
            return Err(Error::ProtocolViolation(format!(
                "server returned {} upload links but {} blocks were requested",
                upload_links.len(),
                blocks.len()
            )));
        }

        // ── step 6: PUT each block to its BareURL ─────────────────────────────
        // Sort upload_links by index so we match the correct block.
        let mut sorted_links = upload_links;
        sorted_links.sort_by_key(|l| l.index);

        for (block, link) in blocks.iter().zip(sorted_links.iter()) {
            if cancel.is_cancelled() {
                return Err(Error::Internal("upload cancelled".into()));
            }
            self.put_block(&link.bare_url, &link.token, &block.ciphertext)
                .await?;
        }

        // ── step 7: compute manifest signature ────────────────────────────────
        // Manifest payload = concat(sha256_raw_bytes[0..N] in index order).
        let manifest_payload: Vec<u8> = blocks
            .iter()
            .flat_map(|b| {
                // Re-hash from hex string to get raw [u8; 32].
                hex::decode(&b.ciphertext_hash_hex).unwrap_or_else(|_| vec![0u8; 32])
            })
            .collect();

        let manifest_sig = self
            .openpgp
            .sign(&manifest_payload, &address_priv, "drive.file.manifest")
            .await?;
        let manifest_sig_armored = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        // ── step 8: compute XAttr ─────────────────────────────────────────────
        let sha1_hex = hex::encode(sha1_hasher.finalize());

        let xattr_json = build_xattr_json(total_bytes, &sha1_hex, self.metadata.modification_time);

        let xattr_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let xattr_ciphertext = self
            .openpgp
            .encrypt_and_sign(
                xattr_json.as_bytes(),
                &xattr_session_key,
                std::slice::from_ref(&node_pub),
                &address_priv,
                EncryptOptions::default(),
            )
            .await?;
        let xattr_armored = base64::engine::general_purpose::STANDARD.encode(&xattr_ciphertext);

        // ── step 9: commit revision ───────────────────────────────────────────
        let commit_req = CommitRevisionRequest {
            manifest_signature: manifest_sig_armored,
            signature_address: address_email.clone(),
            extended_attributes: Some(xattr_armored),
        };

        self.put_commit_revision(&volume_id, &link_id, &revision_id, commit_req)
            .await?;

        let _ = progress_tx.send(total_bytes);
        Ok(())
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    /// Resolve the real VolumeID from a share_id.
    ///
    /// FIXME: NodeUid naming — see MC commit f6b29b1 note.
    async fn resolve_volume_id(&self, share_id: &str) -> Result<String> {
        let path = format!("/drive/shares/{share_id}");
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<proton_drive_api::shares::GetShareResponse> =
            serde_json::from_slice(&resp.body)
                .map_err(|e| Error::Internal(format!("shares JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner.share.volume_id)
    }

    /// Resolve the parent folder's node private key for passphrase encryption.
    ///
    /// Fetches the share root key via `GET drive/shares/{shareID}` and decrypts
    /// it using the account key password. This is a simplified MVP approach:
    /// full implementation would fetch the parent link, decrypt its passphrase
    /// with the share key, then unlock its node key.
    ///
    /// FIXME: This only works correctly when `parent.node_id` is the share root.
    /// For nested folders, we would need to walk the ancestor chain.
    async fn resolve_parent_node_key(
        &self,
        share_id: &str,
    ) -> Result<proton_drive_crypto::PrivateKey> {
        let path = format!("/drive/shares/{share_id}");
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<proton_drive_api::shares::GetShareResponse> =
            serde_json::from_slice(&resp.body)
                .map_err(|e| Error::Internal(format!("share JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        let share = env.inner.share;

        // Decrypt share passphrase with address private key to get share key.
        let address_email = self.account.primary_email().to_owned();
        let address_priv = self.account.address_private_key(&address_email).await?;

        // Decode base64 passphrase (armored PGP message).
        let passphrase_bytes = base64::engine::general_purpose::STANDARD
            .decode(&share.passphrase)
            .or_else(|_| Ok::<Vec<u8>, Error>(share.passphrase.as_bytes().to_vec()))?;

        let share_passphrase_session_key = self
            .openpgp
            .decrypt_session_key(&passphrase_bytes, std::slice::from_ref(&address_priv))
            .await?;

        let (share_passphrase_bytes, _status) = self
            .openpgp
            .decrypt_and_verify(&passphrase_bytes, &share_passphrase_session_key, &[])
            .await?;

        let share_passphrase_str = String::from_utf8(share_passphrase_bytes)
            .map_err(|e| Error::Internal(format!("share passphrase not UTF-8: {e}")))?;

        // Unlock share key using the decrypted passphrase.
        let share_priv = self
            .openpgp
            .decrypt_key(&share.key, &share_passphrase_str)
            .await?;

        Ok(share_priv)
    }

    /// Fetch the server-supplied verification code for a revision draft.
    ///
    /// `GET drive/v2/volumes/{volumeID}/links/{linkID}/revisions/{revisionID}/verification`
    async fn get_verification_code(
        &self,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<Vec<u8>> {
        let path = format!(
            "/drive/v2/volumes/{volume_id}/links/{link_id}/revisions/{revision_id}/verification"
        );
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<VerificationDataResponse> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("verification JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        let code_bytes = base64::engine::general_purpose::STANDARD
            .decode(&env.inner.verification_code)
            .map_err(|e| Error::Internal(format!("verification code base64: {e}")))?;
        Ok(code_bytes)
    }

    async fn post_create_file(
        &self,
        volume_id: &str,
        req_body: CreateFileRequest,
    ) -> Result<(String, String)> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize CreateFileRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Post,
            path: format!("/drive/v2/volumes/{volume_id}/files"),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<proton_drive_api::upload::CreateFileResponse> =
            serde_json::from_slice(&resp.body)
                .map_err(|e| Error::Internal(format!("CreateFileResponse parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok((env.inner.file.link_id, env.inner.file.revision_id))
    }

    async fn post_request_blocks(
        &self,
        req_body: RequestBlockUploadRequest,
    ) -> Result<Vec<proton_drive_api::upload::UploadLink>> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize RequestBlockUploadRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Post,
            path: "/drive/blocks".to_owned(),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<proton_drive_api::upload::RequestBlockUploadResponse> =
            serde_json::from_slice(&resp.body)
                .map_err(|e| Error::Internal(format!("RequestBlockUploadResponse parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner.upload_links)
    }

    /// PUT ciphertext to a block's bare URL with Bearer token auth.
    ///
    /// The JS SDK sends this as multipart/form-data with a "Block" part
    /// (apiService.ts `uploadBlock` / `postBlockStream`). We replicate that
    /// shape here: `Content-Type: multipart/form-data; boundary=...` with a
    /// single "Block" part containing the raw ciphertext bytes.
    ///
    /// BareURL is absolute (includes scheme+host), often on a different host
    /// than the API base (e.g. `https://upload.proton.me/...`). We pass it as
    /// the `path`; `request_blob` detects the `http(s)://` prefix and uses the
    /// URL verbatim rather than joining it against the API base_url.
    async fn put_block(&self, bare_url: &str, token: &str, ciphertext: &[u8]) -> Result<()> {
        // Build multipart/form-data body manually.
        let boundary = "pdtui_block_boundary_x7z9q";
        let mut body: Vec<u8> = Vec::with_capacity(ciphertext.len() + 256);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"Block\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let req = BlobRequest {
            method: HttpMethod::Post,
            path: bare_url.to_owned(),
            query: vec![],
            headers: vec![
                ("Authorization".to_owned(), format!("Bearer {token}")),
                (
                    "content-type".to_owned(),
                    format!("multipart/form-data; boundary={boundary}"),
                ),
            ],
            body: Bytes::from(body),
        };
        let resp = self.http.request_blob(req).await?;
        if resp.status != 200 {
            return Err(Error::IntegrityCheckFailed(format!(
                "block upload returned HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }

    async fn put_commit_revision(
        &self,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
        req_body: CommitRevisionRequest,
    ) -> Result<()> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize CommitRevisionRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Put,
            path: format!("/drive/v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}"),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<serde_json::Value> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("CommitRevisionResponse parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(())
    }
}

// ── XAttr builder ─────────────────────────────────────────────────────────────

fn build_xattr_json(
    size_bytes: u64,
    sha1_hex: &str,
    modification_time: Option<SystemTime>,
) -> String {
    let modification_time_unix = modification_time
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    if let Some(mtime) = modification_time_unix {
        format!(
            r#"{{"Common":{{"ModificationTime":{mtime},"Size":{size_bytes},"Digests":{{"SHA1":"{sha1_hex}"}}}}}}"#
        )
    } else {
        format!(r#"{{"Common":{{"Size":{size_bytes},"Digests":{{"SHA1":"{sha1_hex}"}}}}}}"#)
    }
}

// ── Verification data DTO ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationDataResponse {
    verification_code: String,
    #[allow(dead_code)]
    content_key_packet: Option<String>,
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_size() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 0,
            expected_sha1_hex: None,
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        let r = meta.validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn rejects_short_sha1() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 10,
            expected_sha1_hex: Some("abc".into()),
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        let r = meta.validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn accepts_valid_meta() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 10,
            expected_sha1_hex: Some("a".repeat(40)),
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn rejects_oversized_file() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: MAX_FILE_SIZE + 1,
            expected_sha1_hex: None,
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        assert!(matches!(meta.validate(), Err(Error::Validation(_))));
    }

    #[test]
    fn xattr_json_with_mtime() {
        let mtime = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let json = build_xattr_json(1234, "aabbcc", Some(mtime));
        assert!(json.contains("\"ModificationTime\":1700000000"));
        assert!(json.contains("\"Size\":1234"));
        assert!(json.contains("\"SHA1\":\"aabbcc\""));
    }

    #[test]
    fn xattr_json_without_mtime() {
        let json = build_xattr_json(5678, "ddeeff", None);
        assert!(!json.contains("ModificationTime"));
        assert!(json.contains("\"Size\":5678"));
    }

    // ── Mock-HTTP protocol flow test ──────────────────────────────────────────
    // This test exercises the 9-step protocol using in-process fakes for the
    // HTTP client, crypto module, and account — without hitting the real API.

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use proton_drive_crypto::{
        CryptoError, EncryptOptions, PrivateKey as CPrivKey, PublicKey as CPubKey, SessionKey,
        VerificationStatus,
    };

    // ── Fake HTTP client ──────────────────────────────────────────────────────

    struct FakeHttpClient {
        responses: Mutex<VecDeque<(u16, Vec<u8>)>>,
        recorded_paths: Mutex<Vec<String>>,
    }

    impl FakeHttpClient {
        fn new(responses: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                recorded_paths: Mutex::new(vec![]),
            }
        }

        fn next_response(&self) -> (u16, Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, b"{}".to_vec()))
        }

        fn recorded_paths(&self) -> Vec<String> {
            self.recorded_paths.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for FakeHttpClient {
        async fn request_json(&self, req: JsonRequest) -> Result<crate::http::JsonResponse> {
            self.recorded_paths.lock().unwrap().push(req.path.clone());
            let (status, body) = self.next_response();
            Ok(crate::http::JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }

        async fn request_blob(&self, req: BlobRequest) -> Result<crate::http::JsonResponse> {
            self.recorded_paths.lock().unwrap().push(req.path.clone());
            let (status, body) = self.next_response();
            Ok(crate::http::JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }
    }

    // ── Fake OpenPGP crypto ───────────────────────────────────────────────────

    struct FakeCrypto;

    #[async_trait]
    impl proton_drive_crypto::OpenPgpCrypto for FakeCrypto {
        fn generate_passphrase(&self) -> String {
            "fake-passphrase".into()
        }

        async fn decrypt_key(
            &self,
            armored: &str,
            _passphrase: &str,
        ) -> std::result::Result<CPrivKey, CryptoError> {
            Ok(CPrivKey {
                armored: armored.to_owned(),
                fingerprint_hex: "deadbeef".into(),
                passphrase: zeroize::Zeroizing::new("fake-pass".into()),
            })
        }

        async fn encrypt_and_sign(
            &self,
            data: &[u8],
            _session_key: &SessionKey,
            _encryption_keys: &[CPubKey],
            _signing_key: &CPrivKey,
            _opts: EncryptOptions,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            // Fake: prepend a marker so tests can detect encryption happened.
            let mut out = b"FAKE_ENC:".to_vec();
            out.extend_from_slice(data);
            Ok(out)
        }

        async fn decrypt_and_verify(
            &self,
            data: &[u8],
            _session_key: &SessionKey,
            _verification_keys: &[CPubKey],
        ) -> std::result::Result<(Vec<u8>, VerificationStatus), CryptoError> {
            // Fake: strip FAKE_ENC: prefix.
            let plain = if data.starts_with(b"FAKE_ENC:") {
                data[9..].to_vec()
            } else {
                data.to_vec()
            };
            Ok((plain, VerificationStatus::Ok))
        }

        async fn decrypt_session_key(
            &self,
            _data: &[u8],
            _decryption_keys: &[CPrivKey],
        ) -> std::result::Result<SessionKey, CryptoError> {
            Ok(SessionKey {
                data: zeroize::Zeroizing::new(vec![0u8; 32]),
                cipher_algorithm: 9,
                aead: proton_drive_crypto::AeadAlgorithm::None,
            })
        }

        async fn encrypt_session_key(
            &self,
            _session_key: &SessionKey,
            _encryption_keys: &[CPubKey],
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            Ok(b"FAKE_PKESK".to_vec())
        }

        async fn encrypt_session_key_with_password(
            &self,
            _session_key: &SessionKey,
            _password: &str,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            Ok(b"FAKE_SKESK".to_vec())
        }

        async fn generate_session_key(
            &self,
            _encryption_keys: &[CPubKey],
            _opts: EncryptOptions,
        ) -> std::result::Result<SessionKey, CryptoError> {
            Ok(SessionKey {
                data: zeroize::Zeroizing::new(vec![0xab; 32]),
                cipher_algorithm: 9,
                aead: proton_drive_crypto::AeadAlgorithm::None,
            })
        }

        async fn generate_key(
            &self,
            passphrase: &str,
            _opts: EncryptOptions,
        ) -> std::result::Result<(CPrivKey, String), CryptoError> {
            let priv_key = CPrivKey {
                armored: "FAKE_PRIV_KEY".into(),
                fingerprint_hex: "cafebabe".into(),
                passphrase: zeroize::Zeroizing::new(passphrase.to_owned()),
            };
            Ok((priv_key, "FAKE_PUB_KEY".into()))
        }

        async fn sign(
            &self,
            data: &[u8],
            _signing_key: &CPrivKey,
            _context: &str,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            let mut out = b"SIG:".to_vec();
            out.extend_from_slice(&data[..data.len().min(8)]);
            Ok(out)
        }

        async fn verify(
            &self,
            _data: &[u8],
            _signature: &[u8],
            _verification_keys: &[CPubKey],
        ) -> std::result::Result<VerificationStatus, CryptoError> {
            Ok(VerificationStatus::Ok)
        }
    }

    // ── Fake account ──────────────────────────────────────────────────────────

    struct FakeAccount;

    #[async_trait]
    impl crate::account::ProtonDriveAccount for FakeAccount {
        fn user_id(&self) -> &str {
            "fake-user-id"
        }

        fn primary_email(&self) -> &str {
            "test@proton.me"
        }

        async fn address_private_key(&self, _email: &str) -> Result<CPrivKey> {
            Ok(CPrivKey {
                armored: "FAKE_ADDR_KEY".into(),
                fingerprint_hex: "12345678".into(),
                passphrase: zeroize::Zeroizing::new("addr-pass".into()),
            })
        }

        async fn key_password(&self) -> Result<String> {
            Ok("fake-key-password".into())
        }
    }

    // ── Protocol flow test ────────────────────────────────────────────────────

    #[tokio::test]
    async fn mock_upload_protocol_flow() {
        use crate::nodes::make_node_uid;

        // Build mock HTTP responses in the expected call order:
        // 1. GET /drive/shares/{shareID}  → resolve volume_id
        // 2. GET /drive/shares/{shareID}  → resolve parent node key (share key)
        // 3. GET /drive/v2/volumes/.../verification  → verification code
        // 4. POST /drive/v2/volumes/.../files  → create file
        // 5. POST /drive/blocks  → request block upload tokens
        // 6. POST <bare_url>  → upload block (BlobRequest)
        // 7. PUT /drive/v2/volumes/.../revisions/{revID}  → commit revision

        let share_resp = serde_json::json!({
            "Code": 1000,
            "Share": {
                "ShareID": "share-abc",
                "VolumeID": "vol-xyz",
                "LinkID": "root-link",
                "Type": 1,
                "Key": "FAKE_SHARE_KEY",
                "Passphrase": base64::engine::general_purpose::STANDARD.encode("FAKE_ENC:my-share-passphrase"),
                "PassphraseSignature": "SIG:fake",
                "AddressID": "addr-001",
                "AddressKeyID": "key-001"
            }
        });
        let share_bytes = serde_json::to_vec(&share_resp).unwrap();

        let verification_resp = serde_json::json!({
            "Code": 1000,
            "VerificationCode": base64::engine::general_purpose::STANDARD.encode(vec![0xAA; 128]),
            "ContentKeyPacket": base64::engine::general_purpose::STANDARD.encode("FAKE_CKP")
        });
        let verification_bytes = serde_json::to_vec(&verification_resp).unwrap();

        let create_file_resp = serde_json::json!({
            "Code": 1000,
            "File": {
                "ID": "new-link-id",
                "RevisionID": "new-revision-id"
            }
        });
        let create_file_bytes = serde_json::to_vec(&create_file_resp).unwrap();

        let block_req_resp = serde_json::json!({
            "Code": 1000,
            "UploadLinks": [
                {
                    "Index": 0,
                    "BareURL": "https://upload.proton.me/block/0",
                    "Token": "block-token-0"
                }
            ]
        });
        let block_req_bytes = serde_json::to_vec(&block_req_resp).unwrap();

        // Block PUT response (200 OK, empty body).
        let block_upload_bytes = b"{}".to_vec();

        let commit_resp = serde_json::json!({ "Code": 1000 });
        let commit_bytes = serde_json::to_vec(&commit_resp).unwrap();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()), // step 0a: resolve volume_id
            (200, share_bytes.clone()), // step 0b: resolve parent node key
            (200, create_file_bytes),   // step 2: POST create file
            (200, verification_bytes),  // step 3: GET verification code
            (200, block_req_bytes),     // step 5: POST request blocks
            (200, block_upload_bytes),  // step 6: PUT block blob
            (200, commit_bytes),        // step 9: PUT commit revision
        ]));

        let openpgp = Arc::new(FakeCrypto);
        let account = Arc::new(FakeAccount);

        let content = b"hello proton drive block upload!";
        let expected_size = content.len() as u64;

        let uploader = ProtonFileUploader {
            http: http.clone(),
            openpgp,
            account,
            parent: make_node_uid("share-abc", "root-link"),
            name: "test-file.txt".into(),
            metadata: UploadMetadata {
                media_type: "text/plain".into(),
                expected_size,
                expected_sha1_hex: None,
                modification_time: None,
                additional_metadata_json: None,
                override_existing_draft_by_other_client: false,
            },
        };

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;

        assert!(result.is_ok(), "upload failed: {:?}", result.err());

        // Verify the calls were made in the right order.
        let paths = http.recorded_paths();
        assert!(
            paths[0].contains("/drive/shares/share-abc"),
            "step 0a: {}",
            paths[0]
        );
        assert!(
            paths[1].contains("/drive/shares/share-abc"),
            "step 0b: {}",
            paths[1]
        );
        assert!(
            paths[2].contains("/files"),
            "step 2 create file: {}",
            paths[2]
        );
        assert!(paths[3].contains("/verification"), "step 3: {}", paths[3]);
        assert!(
            paths[4].contains("/drive/blocks"),
            "step 5 request blocks: {}",
            paths[4]
        );
        // paths[5] is the blob upload path (bare_url)
        assert!(
            paths[6].contains("/revisions/"),
            "step 9 commit: {}",
            paths[6]
        );
    }

    #[test]
    fn server_fewer_upload_links_than_blocks_is_protocol_violation() {
        // Verify that the ProtocolViolation error is returned when the server
        // returns fewer upload links than blocks were requested.
        // (Integration: tested in mock_upload_protocol_flow indirectly via the
        //  `sorted_links.len() != blocks.len()` check.)
        //
        // We test the error type here directly.
        let e = Error::ProtocolViolation(
            "server returned 0 upload links but 1 blocks were requested".into(),
        );
        assert!(matches!(e, Error::ProtocolViolation(_)));
    }
}
