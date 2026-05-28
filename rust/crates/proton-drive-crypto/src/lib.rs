//! OpenPGP crypto (ADR-0002) — rpgp v0.16 implementation.
//!
//! Mirrors `js/sdk/src/crypto/interface.ts`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

use pgp::{
    composed::{
        Deserializable,
        KeyType,
        MessageBuilder,
        PlainSessionKey,
        // Key builder types are re-exported from pgp::composed via key::*
        SecretKeyParamsBuilder,
        SignedPublicKey,
        SignedSecretKey,
        StandaloneSignature,
        SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{
        Notation, PacketParser, PacketTrait, PublicKeyEncryptedSessionKey, SignatureConfig,
        SignatureType, Subpacket, SubpacketData, SymEncryptedProtectedData,
    },
    ser::Serialize,
    types::{EskType, KeyDetails, Password, PkeskVersion, PublicKeyTrait},
};

/// Proton binds a signature to a purpose ("signature context") via a critical
/// notation with this name. Matches gopenpgp / OpenPGP.js; a verifier that
/// requires a different context value rejects the signature.
const PROTON_SIGNATURE_CONTEXT_NOTATION: &[u8] = b"context@proton.ch";

// ── error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("SRP: {0}")]
    Srp(String),
    #[error("AEAD/SEIPDv2 not supported in v1 (see ADR-0006)")]
    AeadNotSupported,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl From<proton_srp::SRPError> for CryptoError {
    fn from(e: proton_srp::SRPError) -> Self {
        CryptoError::Srp(e.to_string())
    }
}

impl From<proton_srp::MailboxHashError> for CryptoError {
    fn from(e: proton_srp::MailboxHashError) -> Self {
        CryptoError::Srp(e.to_string())
    }
}

// ── key types ─────────────────────────────────────────────────────────────────

/// An unlocked PGP private key. `passphrase` is preserved so rpgp can re-derive
/// the key material on every crypto operation (rpgp does not cache unlocked state).
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub armored: String,
    pub fingerprint_hex: String,
    /// Passphrase used to lock/unlock this key. Empty for unencrypted keys.
    /// Wrapped in `Zeroizing` so the secret is wiped on drop (ADR-0011).
    pub passphrase: Zeroizing<String>,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub armored: String,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// SEIPDv1 — default in v1 (ADR-0006).
    None,
    /// AEAD-GCM, gated by per-key feature flag. v1 rejects when set.
    Gcm,
}

/// Symmetric session key. `cipher_algorithm` is the OpenPGP numeric ID
/// (9 = AES-256, 7 = AES-128).
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// Raw key bytes. Wrapped in `Zeroizing` so the secret is wiped on drop (ADR-0011).
    pub data: Zeroizing<Vec<u8>>,
    pub cipher_algorithm: u8,
    pub aead: AeadAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    Ok,
    NoSignature,
    SignatureInvalid,
    SignatureWrongSigner,
}

#[derive(Debug, Clone, Default)]
pub struct EncryptOptions {
    /// Mirrors JS `enableAeadWithEncryptionKeys`. Must be false in v1.
    pub enable_aead_with_encryption_keys: bool,
    pub compress: bool,
}

// ── SRP types + trait ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrpVerifier {
    pub modulus_id: String,
    pub version: u32,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Clone)]
pub struct SrpExchange {
    pub expected_server_proof: String,
    pub client_proof: String,
    pub client_ephemeral: String,
}

#[async_trait]
pub trait SrpModule: Send + Sync {
    async fn get_srp(
        &self,
        version: u32,
        modulus: &str,
        server_ephemeral: &str,
        salt: &str,
        password: &str,
    ) -> Result<SrpExchange, CryptoError>;

    async fn get_srp_verifier(&self, password: &str) -> Result<SrpVerifier, CryptoError>;

    async fn compute_key_password(&self, password: &str, salt: &str)
    -> Result<String, CryptoError>;

    fn generate_key_salt(&self) -> String;
}

// ── OpenPGP trait ─────────────────────────────────────────────────────────────

#[async_trait]
pub trait OpenPgpCrypto: Send + Sync {
    fn generate_passphrase(&self) -> String;

    /// Parse `armored` as a PGP private key and verify `passphrase` unlocks it.
    async fn decrypt_key(&self, armored: &str, passphrase: &str)
    -> Result<PrivateKey, CryptoError>;

    /// Encrypt `data` with `session_key` (SEIPDv1) and sign with `signing_key`.
    /// Prepends PKESK packets when `encryption_keys` is non-empty (node names /
    /// passphrases). Empty `encryption_keys` → bare SEIPD (block content).
    async fn encrypt_and_sign(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt `data` (SEIPD, possibly with leading PKESK) using `session_key`.
    async fn decrypt_and_verify(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError>;

    /// Extract the session key from PKESK packet(s) in `data`.
    async fn decrypt_session_key(
        &self,
        data: &[u8],
        decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError>;

    /// Wrap `session_key` in PKESK packets for each of `encryption_keys`.
    async fn encrypt_session_key(
        &self,
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
    ) -> Result<Vec<u8>, CryptoError>;

    async fn encrypt_session_key_with_password(
        &self,
        session_key: &SessionKey,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Generate a random AES-256 session key.
    async fn generate_session_key(
        &self,
        encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError>;

    /// Generate an Ed25519Legacy+X25519 keypair locked with `passphrase`.
    /// Returns `(PrivateKey, armored_public_key)`.
    async fn generate_key(
        &self,
        passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError>;

    /// Detached binary signature over `data`.
    async fn sign(
        &self,
        data: &[u8],
        signing_key: &PrivateKey,
        signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Verify a detached signature produced by `sign`.
    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError>;
}

// ── RpgpCrypto ───────────────────────────────────────────────────────────────

pub struct RpgpCrypto;

impl Default for RpgpCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl RpgpCrypto {
    pub fn new() -> Self {
        Self
    }

    #[inline]
    fn reject_aead(opts: &EncryptOptions) -> Result<(), CryptoError> {
        if opts.enable_aead_with_encryption_keys {
            return Err(CryptoError::AeadNotSupported);
        }
        Ok(())
    }

    fn random_passphrase() -> String {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(buf)
    }

    fn parse_sym_alg(id: u8) -> SymmetricKeyAlgorithm {
        SymmetricKeyAlgorithm::from(id)
    }

    /// Map a `SymmetricKeyAlgorithm` back to its OpenPGP numeric id.
    fn sym_alg_id(alg: SymmetricKeyAlgorithm) -> u8 {
        match alg {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 1,
            SymmetricKeyAlgorithm::TripleDES => 2,
            SymmetricKeyAlgorithm::CAST5 => 3,
            SymmetricKeyAlgorithm::Blowfish => 4,
            SymmetricKeyAlgorithm::AES128 => 7,
            SymmetricKeyAlgorithm::AES192 => 8,
            SymmetricKeyAlgorithm::AES256 => 9,
            SymmetricKeyAlgorithm::Twofish => 10,
            SymmetricKeyAlgorithm::Camellia128 => 11,
            SymmetricKeyAlgorithm::Camellia192 => 12,
            SymmetricKeyAlgorithm::Camellia256 => 13,
            _ => 9,
        }
    }

    fn plain_to_session_key(sk: PlainSessionKey) -> Result<SessionKey, CryptoError> {
        // PlainSessionKey implements Drop (zeroize), so match by ref + clone.
        let (raw_data, cipher_algorithm) = match &sk {
            PlainSessionKey::V3_4 { key, sym_alg } => (key.clone(), Self::sym_alg_id(*sym_alg)),
            PlainSessionKey::V6 { key } => (key.clone(), 9u8),
            PlainSessionKey::Unknown { key, sym_alg } => (key.clone(), Self::sym_alg_id(*sym_alg)),
            PlainSessionKey::V5 { key } => (key.clone(), 9u8),
        };
        Ok(SessionKey {
            data: Zeroizing::new(raw_data),
            cipher_algorithm,
            aead: AeadAlgorithm::None,
        })
    }

    fn parse_secret_key(priv_key: &PrivateKey) -> Result<SignedSecretKey, CryptoError> {
        let (key, _) =
            SignedSecretKey::from_armor_single(std::io::Cursor::new(priv_key.armored.as_bytes()))
                .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(key)
    }

    fn parse_public_key(pub_key: &PublicKey) -> Result<SignedPublicKey, CryptoError> {
        let (key, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(pub_key.armored.as_bytes()))
                .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(key)
    }

    /// Write a PKESK packet that wraps `session_key` for `pub_key`'s
    /// first encryption subkey (or primary key if no subkeys exist).
    fn write_pkesk(
        session_key: &SessionKey,
        sym_alg: SymmetricKeyAlgorithm,
        pub_key: &SignedPublicKey,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        // Prefer the first encryption subkey; fall back to primary.
        let pkesk = if let Some(subkey) = pub_key.public_subkeys.first() {
            PublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key.data,
                sym_alg,
                &subkey.key,
            )
        } else {
            PublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key.data,
                sym_alg,
                &pub_key.primary_key,
            )
        }
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        pkesk
            .to_writer_with_header(out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))
    }
}

// ── SrpModule impl ────────────────────────────────────────────────────────────

#[async_trait]
impl SrpModule for RpgpCrypto {
    async fn get_srp(
        &self,
        version: u32,
        modulus: &str,
        server_ephemeral: &str,
        salt: &str,
        password: &str,
    ) -> Result<SrpExchange, CryptoError> {
        let hash_version = proton_srp::SrpHashVersion::try_from(version as u8)?;
        let auth = proton_srp::SRPAuth::with_pgp(
            None,
            password,
            hash_version,
            salt,
            modulus,
            server_ephemeral,
        )?;
        let proof = auth.generate_proofs()?;
        let b64 = proton_srp::SRPProofB64::from(proof);
        Ok(SrpExchange {
            client_ephemeral: b64.client_ephemeral,
            client_proof: b64.client_proof,
            expected_server_proof: b64.expected_server_proof,
        })
    }

    async fn get_srp_verifier(&self, _password: &str) -> Result<SrpVerifier, CryptoError> {
        Err(CryptoError::NotImplemented(
            "get_srp_verifier — needs server modulus, out of scope for login",
        ))
    }

    async fn compute_key_password(
        &self,
        password: &str,
        salt: &str,
    ) -> Result<String, CryptoError> {
        use base64::Engine as _;
        let salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(salt)
            .map_err(|e| CryptoError::Key(format!("key-salt base64: {e}")))?;
        let hashed = proton_srp::mailbox_password_hash(password, &salt_bytes)?;
        std::str::from_utf8(hashed.as_bytes())
            .map(str::to_owned)
            .map_err(|e| CryptoError::Key(format!("bcrypt output not utf-8: {e}")))
    }

    fn generate_key_salt(&self) -> String {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut buf = [0u8; proton_srp::SALT_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(buf)
    }
}

// ── OpenPgpCrypto impl ────────────────────────────────────────────────────────

#[async_trait]
impl OpenPgpCrypto for RpgpCrypto {
    fn generate_passphrase(&self) -> String {
        Self::random_passphrase()
    }

    async fn decrypt_key(
        &self,
        armored: &str,
        passphrase: &str,
    ) -> Result<PrivateKey, CryptoError> {
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored.as_bytes()))
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        // Verify passphrase by attempting to unlock the key.
        let pw = Password::from(passphrase);
        key.unlock(&pw, |_, _| Ok(()))
            .map_err(|e| CryptoError::Key(format!("unlock: {e}")))?
            .map_err(|e| CryptoError::Key(format!("unlock inner: {e}")))?;

        let fingerprint_hex = hex::encode(key.primary_key.fingerprint().as_bytes());
        Ok(PrivateKey {
            armored: armored.to_owned(),
            fingerprint_hex,
            passphrase: Zeroizing::new(passphrase.to_owned()),
        })
    }

    async fn decrypt_session_key(
        &self,
        data: &[u8],
        decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError> {
        let parser = PacketParser::new(std::io::BufReader::new(data));
        for packet_result in parser {
            let packet = packet_result.map_err(|e| CryptoError::Decrypt(e.to_string()))?;

            let pgp::packet::Packet::PublicKeyEncryptedSessionKey(pkesk) = packet else {
                continue;
            };

            let values = pkesk
                .values()
                .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            // ESK type must match the PKESK packet version, not a hardcoded
            // guess — a V6 PKESK decrypted as V3_4 (or vice-versa) fails.
            let typ = match pkesk.version() {
                PkeskVersion::V3 => EskType::V3_4,
                PkeskVersion::V6 => EskType::V6,
                PkeskVersion::Other(_) => continue,
            };

            for priv_key in decryption_keys {
                let key = Self::parse_secret_key(priv_key)?;
                let pw = Password::from(priv_key.passphrase.as_str());

                if let Ok(Ok(sk)) = key.decrypt_session_key(&pw, values, typ) {
                    return Self::plain_to_session_key(sk);
                }
                for subkey in &key.secret_subkeys {
                    if let Ok(Ok(sk)) = subkey.decrypt_session_key(&pw, values, typ) {
                        return Self::plain_to_session_key(sk);
                    }
                }
            }
        }
        Err(CryptoError::Decrypt(
            "no key could decrypt the session key".into(),
        ))
    }

    async fn decrypt_and_verify(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError> {
        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let plain_sk = PlainSessionKey::V3_4 {
            sym_alg,
            key: (*session_key.data).clone(),
        };

        let msg = pgp::composed::Message::from_bytes(std::io::BufReader::new(data))
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        let mut decrypted = msg
            .decrypt_with_session_key(plain_sk)
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        // Determine whether the message actually carries a signature before
        // draining it into plaintext. A bare SEIPD payload (no signature) must
        // map to NoSignature, not to a spurious verification verdict.
        let has_signature = matches!(
            decrypted,
            pgp::composed::Message::Signed { .. } | pgp::composed::Message::SignedOnePass { .. }
        );

        let plaintext = decrypted
            .as_data_vec()
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        if verification_keys.is_empty() {
            return Ok((plaintext, VerificationStatus::NoSignature));
        }

        let pub_keys: Vec<SignedPublicKey> = verification_keys
            .iter()
            .filter_map(|k| Self::parse_public_key(k).ok())
            .collect();

        // Pass primary keys as PublicKeyTrait references.
        let key_refs: Vec<&dyn PublicKeyTrait> = pub_keys
            .iter()
            .map(|k| &k.primary_key as &dyn PublicKeyTrait)
            .collect();

        let status = match decrypted.verify_nested(&key_refs) {
            Ok(results)
                if results
                    .iter()
                    .any(|r| matches!(r, pgp::composed::VerificationResult::Valid(_))) =>
            {
                VerificationStatus::Ok
            }
            // A signature is present but none of the supplied keys validated it.
            Ok(_) if has_signature => VerificationStatus::SignatureWrongSigner,
            // No signature packet at all (bare SEIPD payload).
            Ok(_) => VerificationStatus::NoSignature,
            Err(_) => VerificationStatus::SignatureInvalid,
        };

        Ok((plaintext, status))
    }

    async fn encrypt_and_sign(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::reject_aead(&opts)?;

        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let sec_key = Self::parse_secret_key(signing_key)?;
        let pw = Password::from(signing_key.passphrase.as_str());

        // Build a signed-but-unencrypted literal message as the SEIPD plaintext.
        let inner_bytes = {
            let mut builder = MessageBuilder::from_bytes("", data.to_vec());
            builder.sign_binary();
            // primary_key implements SecretKeyTrait via the packet layer.
            builder.sign(&sec_key.primary_key, pw, HashAlgorithm::Sha256);
            builder
                .to_vec(rand::thread_rng())
                .map_err(|e| CryptoError::Encrypt(e.to_string()))?
        };

        // Encrypt the inner bytes with the provided session key.
        let seipd = SymEncryptedProtectedData::encrypt_seipdv1(
            rand::thread_rng(),
            sym_alg,
            &session_key.data,
            &inner_bytes,
        )
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        let mut out = Vec::new();
        for pub_key in encryption_keys {
            let key = Self::parse_public_key(pub_key)?;
            Self::write_pkesk(session_key, sym_alg, &key, &mut out)?;
        }
        seipd
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        Ok(out)
    }

    async fn encrypt_session_key(
        &self,
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
    ) -> Result<Vec<u8>, CryptoError> {
        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let mut out = Vec::new();
        for pub_key in encryption_keys {
            let key = Self::parse_public_key(pub_key)?;
            Self::write_pkesk(session_key, sym_alg, &key, &mut out)?;
        }
        Ok(out)
    }

    async fn encrypt_session_key_with_password(
        &self,
        _session_key: &SessionKey,
        _password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotImplemented(
            "encrypt_session_key_with_password — Proton Drive uses PKESK, not SKESK",
        ))
    }

    async fn generate_session_key(
        &self,
        _encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError> {
        Self::reject_aead(&opts)?;
        use rand::RngCore as _;
        let mut data = Zeroizing::new(vec![0u8; 32]);
        rand::thread_rng().fill_bytes(&mut data);
        Ok(SessionKey {
            data,
            cipher_algorithm: 9, // AES-256
            aead: AeadAlgorithm::None,
        })
    }

    async fn generate_key(
        &self,
        passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError> {
        Self::reject_aead(&opts)?;
        let mut rng = rand::thread_rng();
        let pass_opt = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase.to_owned())
        };

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Drive Key".into())
            .passphrase(pass_opt.clone())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::X25519)
                    .can_encrypt(true)
                    .passphrase(pass_opt)
                    .build()
                    .map_err(|e| CryptoError::Key(format!("subkey builder: {e}")))?,
            )
            .build()
            .map_err(|e| CryptoError::Key(format!("key builder: {e}")))?;

        let sec_key = key_params
            .generate(&mut rng)
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let signed = sec_key
            .sign(&mut rng, &passphrase.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let armored_private = signed
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let armored_public = signed
            .signed_public_key()
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let fingerprint_hex = hex::encode(signed.primary_key.fingerprint().as_bytes());

        Ok((
            PrivateKey {
                armored: armored_private,
                fingerprint_hex,
                passphrase: Zeroizing::new(passphrase.to_owned()),
            },
            armored_public,
        ))
    }

    async fn sign(
        &self,
        data: &[u8],
        signing_key: &PrivateKey,
        signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Self::parse_secret_key(signing_key)?;
        let pw = Password::from(signing_key.passphrase.as_str());

        let mut rng = rand::thread_rng();
        let mut sig_config =
            SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::Binary)
                .map_err(|e| CryptoError::Key(e.to_string()))?;

        // `from_key` leaves the subpacket sets empty; a v4 detached signature is
        // only RFC-valid (and verifiable by OpenPGP.js / Proton) with a
        // creation-time and an issuer subpacket.
        let now = chrono::Utc::now();
        let mut hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(now))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                key.primary_key.fingerprint(),
            ))
            .map_err(|e| CryptoError::Key(e.to_string()))?,
        ];

        // A non-empty context is bound into the signature as a critical notation
        // (mirrors openPGPCrypto.ts `sign`). Empty context = no binding, matching
        // `signArmored` / the detached block & manifest signatures.
        if !signature_context.is_empty() {
            hashed.push(
                Subpacket::critical(SubpacketData::Notation(Notation {
                    readable: true,
                    name: PROTON_SIGNATURE_CONTEXT_NOTATION.to_vec().into(),
                    value: signature_context.as_bytes().to_vec().into(),
                }))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
            );
        }

        sig_config.hashed_subpackets = hashed;
        sig_config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(key.primary_key.key_id()))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
        ];

        let sig = sig_config
            .sign(&key.primary_key, &pw, std::io::Cursor::new(data))
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let standalone = StandaloneSignature::new(sig);
        let mut out = Vec::new();
        standalone
            .to_writer(&mut out)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(out)
    }

    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError> {
        if verification_keys.is_empty() {
            return Ok(VerificationStatus::NoSignature);
        }

        let standalone = StandaloneSignature::from_bytes(std::io::BufReader::new(signature))
            .map_err(|e| CryptoError::Verify(e.to_string()))?;

        for pub_key in verification_keys {
            let key = Self::parse_public_key(pub_key)?;
            if standalone.verify(&key.primary_key, data).is_ok() {
                return Ok(VerificationStatus::Ok);
            }
            for subkey in &key.public_subkeys {
                if standalone.verify(&subkey.key, data).is_ok() {
                    return Ok(VerificationStatus::Ok);
                }
            }
        }
        Ok(VerificationStatus::SignatureWrongSigner)
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::cloned_ref_to_slice_refs,
    clippy::unnecessary_fallible_conversions
)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_is_44_char_base64() {
        let crypto = RpgpCrypto::new();
        let p = crypto.generate_passphrase();
        assert_eq!(p.len(), 44, "passphrase: {p:?}");
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "non-base64: {p:?}"
        );
    }

    #[test]
    fn passphrases_are_unique() {
        let crypto = RpgpCrypto::new();
        assert_ne!(crypto.generate_passphrase(), crypto.generate_passphrase());
    }

    #[test]
    fn aead_option_is_rejected() {
        let opts = EncryptOptions {
            enable_aead_with_encryption_keys: true,
            ..Default::default()
        };
        assert!(matches!(
            RpgpCrypto::reject_aead(&opts),
            Err(CryptoError::AeadNotSupported)
        ));
    }

    #[tokio::test]
    async fn generate_key_roundtrip() {
        let crypto = RpgpCrypto::new();
        let (priv_key, pub_armored) = crypto
            .generate_key("test-pass", EncryptOptions::default())
            .await
            .unwrap();
        assert!(!priv_key.armored.is_empty());
        assert!(!priv_key.fingerprint_hex.is_empty());
        assert!(!pub_armored.is_empty());

        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "test-pass")
            .await
            .unwrap();
        assert_eq!(unlocked.fingerprint_hex, priv_key.fingerprint_hex);
    }

    #[tokio::test]
    async fn session_key_encrypt_decrypt_roundtrip() {
        let crypto = RpgpCrypto::new();
        let (priv_key, pub_armored) = crypto
            .generate_key("key-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[pub_key.clone()], EncryptOptions::default())
            .await
            .unwrap();
        assert_eq!(session_key.data.len(), 32);

        let pkesk_bytes = crypto
            .encrypt_session_key(&session_key, &[pub_key])
            .await
            .unwrap();
        assert!(!pkesk_bytes.is_empty());

        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "key-pass")
            .await
            .unwrap();
        let recovered = crypto
            .decrypt_session_key(&pkesk_bytes, &[unlocked])
            .await
            .unwrap();
        assert_eq!(recovered.data, session_key.data);
    }

    #[tokio::test]
    async fn encrypt_sign_decrypt_roundtrip() {
        let crypto = RpgpCrypto::new();
        let plaintext = b"hello proton drive";
        let (signing_key, pub_armored) = crypto
            .generate_key("sign-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: signing_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let encrypted = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                &[pub_key.clone()],
                &signing_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        let unlocked = crypto
            .decrypt_key(&signing_key.armored, "sign-pass")
            .await
            .unwrap();
        let recovered_sk = crypto
            .decrypt_session_key(&encrypted, &[unlocked])
            .await
            .unwrap();
        let (decrypted, status) = crypto
            .decrypt_and_verify(&encrypted, &recovered_sk, &[pub_key])
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(
            status,
            VerificationStatus::Ok,
            "embedded signature must verify (no double-wrap / lost signature)"
        );
    }

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let crypto = RpgpCrypto::new();
        let data = b"manifest data";
        let (priv_key, pub_armored) = crypto
            .generate_key("sig-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "sig-pass")
            .await
            .unwrap();
        let sig = crypto.sign(data, &unlocked, "").await.unwrap();
        let status = crypto.verify(data, &sig, &[pub_key]).await.unwrap();
        assert_eq!(status, VerificationStatus::Ok);

        // An empty context must NOT add a notation (matches signArmored).
        let parsed = StandaloneSignature::from_bytes(std::io::Cursor::new(&sig)).unwrap();
        assert!(
            parsed.signature.notations().is_empty(),
            "empty context must not embed a notation"
        );
    }

    #[tokio::test]
    async fn sign_embeds_critical_context_notation() {
        let crypto = RpgpCrypto::new();
        let data = b"key packet bytes";
        let (priv_key, pub_armored) = crypto
            .generate_key("ctx-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "ctx-pass")
            .await
            .unwrap();

        let sig = crypto
            .sign(data, &unlocked, "drive.sharing.member")
            .await
            .unwrap();

        // Cryptographically valid even with the extra hashed subpackets.
        let status = crypto.verify(data, &sig, &[pub_key]).await.unwrap();
        assert_eq!(status, VerificationStatus::Ok);

        // The context is bound as a critical `context@proton.ch` notation.
        let parsed = StandaloneSignature::from_bytes(std::io::Cursor::new(&sig)).unwrap();
        let notations = parsed.signature.notations();
        let ctx = notations
            .iter()
            .find(|n| n.name.as_ref() == PROTON_SIGNATURE_CONTEXT_NOTATION)
            .unwrap();
        assert_eq!(ctx.value.as_ref(), b"drive.sharing.member");
    }
}
