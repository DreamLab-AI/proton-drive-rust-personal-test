//! Real [`ProtonDriveAccount`] implementation backed by the live Proton
//! Account API.
//!
//! # Key-unlock chain
//!
//! Login (`auth.rs`) yields a bcrypt-derived mailbox password (`$2y$10…`).
//! Resolving private keys uses a cascading unlock:
//!
//! 1. Try every user key and address key directly with the mailbox password.
//! 2. For any key that has a `Token` (armored PGP message) but didn't unlock
//!    directly, decrypt the Token with an already-unlocked key — the plaintext
//!    is the per-key passphrase.
//! 3. Repeat step 2 until no new keys unlock (fixpoint).
//!
//! On **legacy** accounts the user key unlocks directly (step 1). On **modern**
//! (post-migration) accounts the address key unlocks directly and the user key
//! has a Token that requires the address key (step 2).
//!
//! Token signature verification against the SignedKeyList is **deferred** for
//! MVP — we decrypt only.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use proton_drive::{
    Error, ProtonDriveAccount, ProtonDriveHttpClient, Result,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    addresses::{Address, GetAddressesResponse},
    common::{self, ResponseEnvelope},
    user::{GetUserResponse, User},
};
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey};
use serde::de::DeserializeOwned;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A live account context. Unlocked address keys are resolved once at
/// [`PdtuiAccount::bootstrap`] and cached by lowercased email.
pub struct PdtuiAccount {
    user_id: String,
    key_password: Zeroizing<String>,
    /// Address with the lowest `Order` (the primary).
    primary_email: String,
    /// Unlocked address private keys, keyed by lowercased email.
    address_keys: HashMap<String, PrivateKey>,
}

impl PdtuiAccount {
    /// Fetch the user + addresses and unlock every address key.
    ///
    /// `http` must already inject auth headers (use `SessionAwareHttpClient`).
    pub async fn bootstrap(
        http: Arc<dyn ProtonDriveHttpClient>,
        crypto: Arc<dyn OpenPgpCrypto>,
        user_id: String,
        key_password: Zeroizing<String>,
    ) -> Result<Self> {
        let user_resp: GetUserResponse = api_get(&*http, "/core/v4/users").await?;
        let user = user_resp.user;
        debug!(user_id = %user.id, key_count = user.keys.len(), "fetched user keys");

        let addr_resp: GetAddressesResponse = api_get(&*http, "/core/v4/addresses").await?;
        debug!(count = addr_resp.addresses.len(), "fetched addresses");

        // Cascading key unlock: try direct, then token-based, until fixpoint.
        let (user_keys, address_keys) = cascade_unlock(
            &*crypto,
            &user,
            &addr_resp.addresses,
            &key_password,
        )
        .await?;

        debug!(
            user_keys = user_keys.len(),
            address_keys = address_keys.len(),
            "cascade unlock complete"
        );

        if address_keys.is_empty() {
            return Err(Error::Decryption(
                "no address key could be unlocked".to_owned(),
            ));
        }

        // primary_email = address with the lowest Order (fall back to first).
        let primary_email = addr_resp
            .addresses
            .iter()
            .filter(|a| address_keys.contains_key(&a.email.to_ascii_lowercase()))
            .min_by_key(|a| a.order)
            .map(|a| a.email.clone())
            .or_else(|| addr_resp.addresses.first().map(|a| a.email.clone()))
            .ok_or_else(|| Error::Internal("no addresses returned for user".to_owned()))?;

        debug!(%primary_email, unlocked = address_keys.len(), "account bootstrap complete");

        Ok(Self {
            user_id,
            key_password,
            primary_email,
            address_keys,
        })
    }
}

#[async_trait]
impl ProtonDriveAccount for PdtuiAccount {
    fn user_id(&self) -> &str {
        &self.user_id
    }

    fn primary_email(&self) -> &str {
        &self.primary_email
    }

    async fn address_private_key(&self, email: &str) -> Result<PrivateKey> {
        self.address_keys
            .get(&email.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| Error::Internal(format!("no unlocked address private key for {email}")))
    }

    async fn key_password(&self) -> Result<String> {
        Ok(self.key_password.as_str().to_owned())
    }
}

// ---------------------------------------------------------------------------
// Cascading key unlock
// ---------------------------------------------------------------------------

/// Unlock all user and address keys via a cascading strategy:
///
/// 1. Try every key directly with key_password.
/// 2. For Token-bearing keys that didn't unlock, decrypt the Token with any
///    already-unlocked key to recover the per-key passphrase.
/// 3. Repeat until no new keys unlock.
///
/// Returns `(user_keys, address_keys_by_email)`.
async fn cascade_unlock(
    crypto: &dyn OpenPgpCrypto,
    user: &User,
    addresses: &[Address],
    key_password: &str,
) -> Result<(Vec<PrivateKey>, HashMap<String, PrivateKey>)> {
    // Pool of all unlocked keys (used to decrypt Tokens in subsequent rounds).
    let mut pool: Vec<PrivateKey> = Vec::new();

    let mut unlocked_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    struct Pending {
        id: String,
        armored: String,
        token: Option<String>,
    }

    let mut pending: Vec<Pending> = Vec::new();
    for uk in &user.keys {
        pending.push(Pending {
            id: uk.id.clone(),
            armored: uk.private_key.clone(),
            token: uk.token.clone(),
        });
    }
    for addr in addresses {
        let ak = addr
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| addr.keys.first());
        if let Some(ak) = ak {
            pending.push(Pending {
                id: ak.id.clone(),
                armored: ak.private_key.clone(),
                token: ak.token.clone(),
            });
        }
    }

    // Round 1: try direct unlock with key_password.
    let mut still_pending = Vec::new();
    for p in pending {
        match crypto.decrypt_key(&p.armored, key_password).await {
            Ok(key) => {
                debug!(key_id = %p.id, "direct unlock ok");
                unlocked_ids.insert(p.id.clone());
                pool.push(key);
            }
            Err(_) => still_pending.push(p),
        }
    }
    pending = still_pending;

    // Rounds 2+: token-based unlock using the pool.
    loop {
        if pending.is_empty() || pool.is_empty() {
            break;
        }
        let mut progress = false;
        let mut next_pending = Vec::new();

        for p in pending {
            if unlocked_ids.contains(&p.id) {
                continue;
            }
            let Some(ref token_armored) = p.token else {
                debug!(key_id = %p.id, "no token, cannot unlock via cascade");
                next_pending.push(p);
                continue;
            };
            match decrypt_token_and_unlock(crypto, token_armored, &p.armored, &pool).await {
                Ok(key) => {
                    debug!(key_id = %p.id, "token-based unlock ok");
                    unlocked_ids.insert(p.id.clone());
                    pool.push(key);
                    progress = true;
                }
                Err(e) => {
                    debug!(key_id = %p.id, "token unlock failed: {e}");
                    next_pending.push(p);
                }
            }
        }

        pending = next_pending;
        if !progress {
            break;
        }
    }

    for p in &pending {
        warn!(key_id = %p.id, "could not unlock key");
    }

    // Partition unlocked keys into user keys and address keys.
    // Re-derive from pool using the pending metadata we kept track of.
    let mut user_keys = Vec::new();
    let mut address_keys: HashMap<String, PrivateKey> = HashMap::new();

    // We need to know which pool entry corresponds to which dest. Since pool
    // was built in order, reconstruct by re-trying each original key.
    for uk in &user.keys {
        if unlocked_ids.contains(&uk.id) {
            if let Ok(key) = try_unlock(crypto, &uk.private_key, uk.token.as_deref(), key_password, &pool).await {
                user_keys.push(key);
            }
        }
    }
    for addr in addresses {
        let ak = addr
            .keys
            .iter()
            .find(|k| k.primary == 1)
            .or_else(|| addr.keys.first());
        if let Some(ak) = ak {
            if unlocked_ids.contains(&ak.id) {
                if let Ok(key) = try_unlock(crypto, &ak.private_key, ak.token.as_deref(), key_password, &pool).await {
                    address_keys.insert(addr.email.to_ascii_lowercase(), key);
                }
            }
        }
    }

    if user_keys.is_empty() && address_keys.is_empty() {
        return Err(Error::Decryption(
            "no keys could be unlocked (tried direct + token-based cascade)".to_owned(),
        ));
    }

    Ok((user_keys, address_keys))
}

/// Try to unlock a key: first direct with key_password, then via token.
async fn try_unlock(
    crypto: &dyn OpenPgpCrypto,
    armored: &str,
    token: Option<&str>,
    key_password: &str,
    pool: &[PrivateKey],
) -> Result<PrivateKey> {
    if let Ok(key) = crypto.decrypt_key(armored, key_password).await {
        return Ok(key);
    }
    if let Some(tok) = token {
        return decrypt_token_and_unlock(crypto, tok, armored, pool).await;
    }
    Err(Error::Decryption("key could not be unlocked".into()))
}

/// Decrypt a Token with any key in `pool`, yielding the per-key passphrase,
/// then unlock the target key.
async fn decrypt_token_and_unlock(
    crypto: &dyn OpenPgpCrypto,
    token_armored: &str,
    key_armored: &str,
    pool: &[PrivateKey],
) -> Result<PrivateKey> {
    let token_bytes = dearmor_pgp(token_armored)?;

    let session_key = crypto
        .decrypt_session_key(&token_bytes, pool)
        .await
        .map_err(|e| Error::Decryption(format!("token session key: {e}")))?;
    let (passphrase_bytes, _) = crypto
        .decrypt_and_verify(&token_bytes, &session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("token plaintext: {e}")))?;

    let passphrase = std::str::from_utf8(&passphrase_bytes)
        .map_err(|e| Error::Internal(format!("token passphrase not utf-8: {e}")))?;

    crypto
        .decrypt_key(key_armored, passphrase)
        .await
        .map_err(|e| Error::Decryption(format!("unlock key: {e}")))
}

// ---------------------------------------------------------------------------
// Armor handling
// ---------------------------------------------------------------------------

/// De-armor an ASCII-armored PGP message into its binary packet stream.
///
/// `OpenPgpCrypto::decrypt_session_key` parses raw binary packets and does not
/// de-armor, so armored Tokens must be converted first. We strip the
/// `-----BEGIN/END-----` lines, the blank header-separator, optional armor
/// headers (`Key: value`), and the trailing `=CRC` checksum, then base64-decode
/// the remaining body.
fn dearmor_pgp(armored: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    let trimmed = armored.trim();
    if !trimmed.contains("-----BEGIN PGP") {
        // Not armored — assume it is already binary/base64 of binary.
        return base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| Error::Internal(format!("token base64: {e}")));
    }

    let mut body = String::new();
    let mut in_body = false;
    let mut seen_blank = false;
    for line in trimmed.lines() {
        let line = line.trim_end();
        if line.starts_with("-----BEGIN PGP") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END PGP") {
            break;
        }
        if !in_body {
            continue;
        }
        // Armor headers precede a blank line; skip until the blank separator.
        if !seen_blank {
            if line.is_empty() {
                seen_blank = true;
            }
            continue;
        }
        // The CRC-24 checksum line begins with '='.
        if line.starts_with('=') {
            continue;
        }
        if !line.is_empty() {
            body.push_str(line);
        }
    }

    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| Error::Internal(format!("token armor base64: {e}")))
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async fn api_get<T: DeserializeOwned>(http: &dyn ProtonDriveHttpClient, path: &str) -> Result<T> {
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Internal(format!("JSON parse {path}: {e}")))?;
    if env.code != common::CODE_OK {
        return Err(Error::Internal(format!(
            "API error {} on {path}: {}",
            env.code,
            env.error.unwrap_or_default()
        )));
    }
    Ok(env.inner)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use bytes::Bytes;
    use proton_drive::{
        Result as DriveResult, RpgpCrypto,
        http::{BlobRequest, JsonResponse},
    };
    use proton_drive_crypto::{EncryptOptions, PublicKey, SessionKey};

    // ── Mock HTTP that replays a fixed response per path -----------------------

    struct PathMock {
        responses: Mutex<VecDeque<(String, String)>>,
    }

    impl PathMock {
        fn new(responses: Vec<(&str, String)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(p, b)| (p.to_owned(), b))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for PathMock {
        async fn request_json(&self, req: JsonRequest) -> DriveResult<JsonResponse> {
            let body = {
                let mut q = self.responses.lock().unwrap();
                // Find a queued response whose path matches; else pop front.
                let idx = q.iter().position(|(p, _)| req.path.contains(p.as_str()));
                match idx {
                    Some(i) => q.remove(i).map(|(_, b)| b).unwrap_or_default(),
                    None => q.pop_front().map(|(_, b)| b).unwrap_or_default(),
                }
            };
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from(body.into_bytes()),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> DriveResult<JsonResponse> {
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::new(),
            })
        }
    }

    /// RFC 4880 ASCII-armor a binary PGP message (PKESK + SEIPD) the way Proton
    /// serves address-key Tokens. Includes the CRC-24 checksum trailer.
    fn armor_message(data: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let mut out = String::from("-----BEGIN PGP MESSAGE-----\n\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        let crc = crc24(data);
        let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
        out.push('=');
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(crc_bytes));
        out.push('\n');
        out.push_str("-----END PGP MESSAGE-----\n");
        out
    }

    /// CRC-24 over `data` (RFC 4880 §6.1).
    fn crc24(data: &[u8]) -> u32 {
        let mut crc: u32 = 0x00B7_04CE;
        for &byte in data {
            crc ^= (byte as u32) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x0100_0000 != 0 {
                    crc ^= 0x0186_4CFB;
                }
            }
        }
        crc & 0x00FF_FFFF
    }

    /// Build a PGP message wrapping `plaintext`, encrypted to `recipient_pub`.
    /// Used to fabricate a realistic address-key Token.
    async fn make_token(
        crypto: &RpgpCrypto,
        recipient_pub: &PublicKey,
        signing_key: &PrivateKey,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let session_key: SessionKey = crypto
            .generate_session_key(
                std::slice::from_ref(recipient_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(recipient_pub),
                signing_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap()
    }

    /// Full key-unlock orchestration using the real RpgpCrypto: generate a user
    /// key, an address key locked with a random passphrase, and a Token that
    /// wraps that passphrase encrypted to the user key. Bootstrap must resolve
    /// the address private key.
    #[tokio::test]
    async fn bootstrap_unlocks_address_key_via_token() {
        let crypto = RpgpCrypto::new();
        let mailbox_pw = "$2y$10$mailboxpasswordforuserkey";

        // 1. User key, locked with the mailbox password.
        let (user_priv, user_pub_armored) = crypto
            .generate_key(mailbox_pw, EncryptOptions::default())
            .await
            .unwrap();
        let user_pub = PublicKey {
            armored: user_pub_armored,
            fingerprint_hex: user_priv.fingerprint_hex.clone(),
        };

        // 2. Address key, locked with a random passphrase.
        let addr_passphrase = "address-key-passphrase-xyz";
        let (addr_priv, _addr_pub) = crypto
            .generate_key(addr_passphrase, EncryptOptions::default())
            .await
            .unwrap();

        // 3. Token = addr_passphrase encrypted to the user key, ASCII-armored
        // the way Proton serves it.
        let token_bytes =
            make_token(&crypto, &user_pub, &user_priv, addr_passphrase.as_bytes()).await;
        let token_armored = armor_message(&token_bytes);

        // Sanity: dearmor + crypto round-trip recovers the passphrase.
        let unlocked_user = crypto
            .decrypt_key(&user_priv.armored, mailbox_pw)
            .await
            .unwrap();
        let dearmored = dearmor_pgp(&token_armored).expect("dearmor token");
        assert_eq!(dearmored, token_bytes, "dearmor must match original binary");
        let sk = crypto
            .decrypt_session_key(&dearmored, std::slice::from_ref(&unlocked_user))
            .await
            .expect("token session key");
        let (pt, _) = crypto
            .decrypt_and_verify(&dearmored, &sk, &[])
            .await
            .expect("token plaintext");
        assert_eq!(pt, addr_passphrase.as_bytes());

        let users_body = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "user-123",
                "Name": "tester",
                "Email": "tester@proton.me",
                "Keys": [{ "ID": "uk1", "Primary": 1, "PrivateKey": user_priv.armored }]
            }
        })
        .to_string();

        let addresses_body = serde_json::json!({
            "Code": 1000,
            "Addresses": [{
                "ID": "addr-1",
                "Email": "tester@proton.me",
                "Order": 1,
                "Keys": [{
                    "ID": "ak1",
                    "Primary": 1,
                    "PrivateKey": addr_priv.armored,
                    "Token": token_armored
                }]
            }]
        })
        .to_string();

        let http = Arc::new(PathMock::new(vec![
            ("/core/v4/users", users_body),
            ("/core/v4/addresses", addresses_body),
        ])) as Arc<dyn ProtonDriveHttpClient>;
        let crypto_arc = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let account = PdtuiAccount::bootstrap(
            http,
            crypto_arc,
            "user-123".to_owned(),
            Zeroizing::new(mailbox_pw.to_owned()),
        )
        .await
        .expect("bootstrap should succeed");

        assert_eq!(account.user_id(), "user-123");
        assert_eq!(account.primary_email(), "tester@proton.me");

        let resolved = account
            .address_private_key("tester@proton.me")
            .await
            .expect("primary address key resolves");
        assert_eq!(resolved.fingerprint_hex, addr_priv.fingerprint_hex);
        // Case-insensitive lookup.
        assert!(
            account
                .address_private_key("TESTER@PROTON.ME")
                .await
                .is_ok()
        );
        // Unknown email is an error.
        assert!(
            account
                .address_private_key("nobody@proton.me")
                .await
                .is_err()
        );
        assert_eq!(account.key_password().await.unwrap(), mailbox_pw);
    }

    #[tokio::test]
    async fn bootstrap_fails_when_no_key_unlocks() {
        let crypto = RpgpCrypto::new();
        let (user_priv, _) = crypto
            .generate_key("correct-password", EncryptOptions::default())
            .await
            .unwrap();

        let users_body = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "u",
                "Name": "n",
                "Email": "e@proton.me",
                "Keys": [{ "ID": "uk1", "Primary": 1, "PrivateKey": user_priv.armored }]
            }
        })
        .to_string();

        let addresses_body = serde_json::json!({
            "Code": 1000,
            "Addresses": []
        })
        .to_string();

        let http = Arc::new(PathMock::new(vec![
            ("/core/v4/users", users_body),
            ("/core/v4/addresses", addresses_body),
        ])) as Arc<dyn ProtonDriveHttpClient>;
        let crypto_arc = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let result = PdtuiAccount::bootstrap(
            http,
            crypto_arc,
            "u".to_owned(),
            Zeroizing::new("wrong-password".to_owned()),
        )
        .await;
        assert!(
            result.is_err(),
            "wrong mailbox password must fail bootstrap"
        );
    }

    /// Modern account layout: user key has a Token, address key unlocks
    /// directly with key_password. Bootstrap cascades: address key first,
    /// then user key via Token.
    #[tokio::test]
    async fn bootstrap_cascades_address_to_user_key() {
        let crypto = RpgpCrypto::new();
        let mailbox_pw = "$2y$10$cascadetest";

        // Address key — unlocks directly with mailbox password.
        let (addr_priv, addr_pub_armored) = crypto
            .generate_key(mailbox_pw, EncryptOptions::default())
            .await
            .unwrap();
        let addr_pub = PublicKey {
            armored: addr_pub_armored,
            fingerprint_hex: addr_priv.fingerprint_hex.clone(),
        };

        // User key — locked with a DIFFERENT passphrase.
        let user_passphrase = "user-key-internal-passphrase";
        let (user_priv, _) = crypto
            .generate_key(user_passphrase, EncryptOptions::default())
            .await
            .unwrap();

        // User key Token = user_passphrase encrypted to the address key.
        let user_token_bytes =
            make_token(&crypto, &addr_pub, &addr_priv, user_passphrase.as_bytes()).await;
        let user_token_armored = armor_message(&user_token_bytes);

        let users_body = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "user-456",
                "Name": "modern",
                "Email": "modern@proton.me",
                "Keys": [{
                    "ID": "uk1",
                    "Primary": 1,
                    "PrivateKey": user_priv.armored,
                    "Token": user_token_armored
                }]
            }
        })
        .to_string();

        let addresses_body = serde_json::json!({
            "Code": 1000,
            "Addresses": [{
                "ID": "addr-1",
                "Email": "modern@proton.me",
                "Order": 1,
                "Keys": [{
                    "ID": "ak1",
                    "Primary": 1,
                    "PrivateKey": addr_priv.armored
                }]
            }]
        })
        .to_string();

        let http = Arc::new(PathMock::new(vec![
            ("/core/v4/users", users_body),
            ("/core/v4/addresses", addresses_body),
        ])) as Arc<dyn ProtonDriveHttpClient>;
        let crypto_arc = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let account = PdtuiAccount::bootstrap(
            http,
            crypto_arc,
            "user-456".to_owned(),
            Zeroizing::new(mailbox_pw.to_owned()),
        )
        .await
        .expect("cascade bootstrap should succeed");

        assert_eq!(account.primary_email(), "modern@proton.me");
        account
            .address_private_key("modern@proton.me")
            .await
            .expect("address key resolves");
    }

    // -----------------------------------------------------------------------
    // Live end-to-end (ignored). Requires a persisted session + keyring entry
    // produced by `pdtui login`. Run manually:
    //   cargo test -p pdtui --bin pdtui account::tests::live_bootstrap -- --ignored
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "hits the live Proton API; requires a logged-in session"]
    async fn live_bootstrap_resolves_primary_address_key() {
        use crate::http::{ReqwestHttpClient, SessionAwareHttpClient};
        use crate::session::SessionManager;

        let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
        let transport: Arc<dyn ProtonDriveHttpClient> =
            Arc::new(ReqwestHttpClient::new("https://drive.proton.me/api", &app_version).unwrap());
        let session = Arc::new(
            SessionManager::from_keyring(Arc::clone(&transport))
                .await
                .expect("a persisted session is required (run `pdtui login` first)"),
        );
        let key_password = session.key_password().await;
        let http: Arc<dyn ProtonDriveHttpClient> =
            Arc::new(SessionAwareHttpClient::new(transport, Arc::clone(&session)));
        let crypto = Arc::new(RpgpCrypto::new()) as Arc<dyn OpenPgpCrypto>;

        let account = PdtuiAccount::bootstrap(http, crypto, String::new(), key_password)
            .await
            .expect("live bootstrap should succeed");

        let email = account.primary_email().to_owned();
        assert!(!email.is_empty(), "primary email must be populated");
        account
            .address_private_key(&email)
            .await
            .expect("primary address key must resolve");
    }
}
