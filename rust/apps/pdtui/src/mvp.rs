//! Headless MVP acceptance test (`pdtui mvp`).
//!
//! Resumes the persisted session, then drives the full crypto-backed transfer
//! path against the live API: my-files root → list children → upload a small
//! file → re-list to locate it → download → assert byte-identical. This is the
//! end-to-end validation for the upload wire-format work (HMAC name hash,
//! parent node key, XAttr, armored decode) that unit tests can only cover
//! offline.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt as _;
use proton_drive::{
    FolderChildrenFilter, MaybeNode, NodeType, ProtonDriveClient, ProtonDriveClientOptions,
    ProtonDriveConfig, ProtonDriveHttpClient, RpgpCrypto, UploadMetadata,
};
use proton_drive_cache::MemoryCache;
use tokio::sync::watch;

use crate::account::PdtuiAccount;
use crate::http::SessionAwareHttpClient;
use crate::session::SessionManager;

const BASE_URL: &str = "https://drive.proton.me/api";

pub async fn run() -> Result<(), String> {
    let client = build_client().await?;

    // ── step 1: my-files root ────────────────────────────────────────────────
    let root_uid = match client
        .my_files_root()
        .await
        .map_err(|e| format!("my_files_root: {e}"))?
    {
        MaybeNode::Node(n) => n.uid.clone(),
        other => return Err(format!("root is not a live node: {other:?}")),
    };
    println!("root: {}/{}", root_uid.volume_id, root_uid.node_id);

    // ── step 2: list root children (exercises decrypt path) ──────────────────
    println!("listing root:");
    let mut count = 0usize;
    let mut stream = client.iter_folder_children(&root_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        match item.map_err(|e| format!("list: {e}"))? {
            MaybeNode::Node(n) if !n.trashed => {
                let kind = match n.node_type {
                    NodeType::Folder | NodeType::Album => 'd',
                    NodeType::File => '-',
                };
                let size = n
                    .size_bytes
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into());
                println!("  {kind} {size:>10}  {}", n.name);
                count += 1;
            }
            MaybeNode::Degraded { uid, reason } => {
                println!("  ! <degraded {}: {reason}>", uid.node_id);
            }
            _ => {}
        }
    }
    drop(stream);
    println!("  ({count} entries)");

    // ── step 3: upload a small file ──────────────────────────────────────────
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!("pdtui-mvp-{ts}.txt");
    let content =
        format!("pdtui MVP round-trip {ts}\nThe quick brown fox jumps over the lazy dog.\n")
            .into_bytes();
    println!("uploading {name} ({} bytes)…", content.len());

    let meta = UploadMetadata {
        media_type: "text/plain".into(),
        expected_size: content.len() as u64,
        expected_sha1_hex: None,
        modification_time: Some(SystemTime::now()),
        additional_metadata_json: None,
        override_existing_draft_by_other_client: false,
    };
    let uploader = client
        .file_uploader(&root_uid, &name, meta)
        .await
        .map_err(|e| format!("file_uploader: {e}"))?;

    let (progress_tx, _progress_rx) = watch::channel::<u64>(0);
    let source: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(content.clone()));
    uploader
        .upload_from_stream(source, progress_tx)
        .await
        .map_err(|e| format!("upload_from_stream: {e}"))?;
    println!("✓ upload complete");

    // ── step 4: re-list to locate the uploaded node ──────────────────────────
    let mut uploaded_uid = None;
    let mut stream = client.iter_folder_children(&root_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        if let MaybeNode::Node(n) = item.map_err(|e| format!("re-list: {e}"))?
            && !n.trashed
            && n.name == name
        {
            uploaded_uid = Some(n.uid.clone());
            break;
        }
    }
    drop(stream);
    let uploaded_uid =
        uploaded_uid.ok_or_else(|| format!("uploaded file {name} not found in re-list"))?;
    println!(
        "✓ located uploaded node: {}/{}",
        uploaded_uid.volume_id, uploaded_uid.node_id
    );

    // ── step 5: download + byte-compare ──────────────────────────────────────
    let dest = std::env::temp_dir().join(&name);
    let file = tokio::fs::File::create(&dest)
        .await
        .map_err(|e| format!("create {}: {e}", dest.display()))?;
    let downloader = client
        .file_downloader(&uploaded_uid)
        .await
        .map_err(|e| format!("file_downloader: {e}"))?;
    let stats = downloader
        .download_to_writer(file)
        .await
        .map_err(|e| format!("download_to_writer: {e}"))?;

    let roundtrip = tokio::fs::read(&dest)
        .await
        .map_err(|e| format!("read back {}: {e}", dest.display()))?;
    println!("✓ downloaded {} bytes to {}", stats.bytes, dest.display());

    if roundtrip == content {
        println!("✓ PASS — {} bytes byte-identical round-trip", content.len());
        Ok(())
    } else {
        Err(format!(
            "BYTE MISMATCH: uploaded {} bytes, downloaded {} bytes",
            content.len(),
            roundtrip.len()
        ))
    }
}

/// Resume the persisted session and assemble a live `ProtonDriveClient`.
/// Mirrors the TUI's keyring-resume path without any terminal state.
async fn build_client() -> Result<Arc<ProtonDriveClient>, String> {
    let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
    let transport: Arc<dyn ProtonDriveHttpClient> = Arc::new(
        crate::http::ReqwestHttpClient::new(BASE_URL, &app_version)
            .map_err(|e| format!("http client: {e}"))?,
    );

    let session = SessionManager::from_keyring(Arc::clone(&transport))
        .await
        .map_err(|e| format!("session resume (run `pdtui login` first): {e}"))?;
    let key_password = session.key_password().await;
    let session = Arc::new(session);

    let http: Arc<dyn ProtonDriveHttpClient> =
        Arc::new(SessionAwareHttpClient::new(transport, Arc::clone(&session)));
    let crypto = Arc::new(RpgpCrypto::new());

    let account = PdtuiAccount::bootstrap(
        Arc::clone(&http),
        Arc::clone(&crypto) as Arc<dyn proton_drive::OpenPgpCrypto>,
        String::new(),
        key_password,
    )
    .await
    .map_err(|e| format!("account bootstrap: {e}"))?;

    let opts = ProtonDriveClientOptions {
        http_client: http,
        entities_cache: Arc::new(MemoryCache::<String>::new()),
        crypto_cache: Arc::new(MemoryCache::<proton_drive::CachedCryptoMaterial>::new()),
        account: Arc::new(account),
        openpgp: Arc::clone(&crypto) as Arc<dyn proton_drive::OpenPgpCrypto>,
        srp: crypto as Arc<dyn proton_drive::SrpModule>,
        config: ProtonDriveConfig::default(),
        telemetry: None,
        latest_event_id: None,
    };
    Ok(Arc::new(ProtonDriveClient::new(opts)))
}
