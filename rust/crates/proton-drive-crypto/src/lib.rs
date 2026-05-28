//! OpenPGP crypto contract (ADR-0002). v1 `rpgp` impl lands in M2.
//!
//! Mirrors `js/sdk/src/crypto/interface.ts`. Today the trait shapes are
//! defined; `RpgpCrypto` is a stub returning `NotImplemented`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use thiserror::Error;

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
    #[error("AEAD/SEIPDv2 not supported in v1 (see ADR-0006)")]
    AeadNotSupported,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub armored: String,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub armored: String,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// SEIPDv1 — default path in v1 (ADR-0006).
    None,
    /// AEAD-GCM, gated by Proton's per-key feature flag. v1 returns
    /// `CryptoError::AeadNotSupported` when set.
    Gcm,
}

#[derive(Debug, Clone)]
pub struct SessionKey {
    pub data: Vec<u8>,
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
    /// Mirrors JS `enableAeadWithEncryptionKeys`. v1 must be `false`.
    pub enable_aead_with_encryption_keys: bool,
    pub compress: bool,
}

#[derive(Debug, Clone)]
pub struct SrpVerifier {
    pub modulus_id: String,
    pub version: u32,
    pub salt: String,
    pub verifier: String,
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

#[derive(Debug, Clone)]
pub struct SrpExchange {
    pub expected_server_proof: String,
    pub client_proof: String,
    pub client_ephemeral: String,
}

/// Full OpenPGP operations surface. Subset is exercised by the SDK; the full
/// shape mirrors JS `OpenPGPCrypto` so the porting reviewer can map 1:1.
#[async_trait]
pub trait OpenPgpCrypto: Send + Sync {
    fn generate_passphrase(&self) -> String;

    async fn generate_session_key(
        &self,
        encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError>;

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

    async fn generate_key(
        &self,
        passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError>;

    async fn decrypt_key(&self, armored: &str, passphrase: &str)
    -> Result<PrivateKey, CryptoError>;

    async fn encrypt_and_sign(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError>;

    async fn decrypt_and_verify(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError>;

    async fn sign(
        &self,
        data: &[u8],
        signing_key: &PrivateKey,
        signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError>;

    async fn decrypt_session_key(
        &self,
        data: &[u8],
        decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError>;
}

/// `rpgp`-backed impl. Trait shape lands in M0; bodies in M2 (ADR-0002).
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

    /// 32 random bytes, base64-encoded — matches the JS contract.
    fn random_passphrase() -> String {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(buf)
    }
}

#[async_trait]
impl OpenPgpCrypto for RpgpCrypto {
    fn generate_passphrase(&self) -> String {
        Self::random_passphrase()
    }

    async fn generate_session_key(
        &self,
        _enc: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError> {
        Self::reject_aead(&opts)?;
        Err(CryptoError::NotImplemented("generate_session_key — M2"))
    }

    async fn encrypt_session_key(
        &self,
        _sk: &SessionKey,
        _enc: &[PublicKey],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotImplemented("encrypt_session_key — M2"))
    }

    async fn encrypt_session_key_with_password(
        &self,
        _sk: &SessionKey,
        _password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotImplemented(
            "encrypt_session_key_with_password — M2",
        ))
    }

    async fn generate_key(
        &self,
        _passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError> {
        Self::reject_aead(&opts)?;
        Err(CryptoError::NotImplemented("generate_key — M2"))
    }

    async fn decrypt_key(
        &self,
        _armored: &str,
        _passphrase: &str,
    ) -> Result<PrivateKey, CryptoError> {
        Err(CryptoError::NotImplemented("decrypt_key — M2"))
    }

    async fn encrypt_and_sign(
        &self,
        _data: &[u8],
        _session_key: &SessionKey,
        _enc: &[PublicKey],
        _signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::reject_aead(&opts)?;
        Err(CryptoError::NotImplemented("encrypt_and_sign — M2"))
    }

    async fn decrypt_and_verify(
        &self,
        _data: &[u8],
        _session_key: &SessionKey,
        _verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError> {
        Err(CryptoError::NotImplemented("decrypt_and_verify — M2"))
    }

    async fn sign(
        &self,
        _data: &[u8],
        _signing_key: &PrivateKey,
        _signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotImplemented("sign — M2"))
    }

    async fn verify(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError> {
        Err(CryptoError::NotImplemented("verify — M2"))
    }

    async fn decrypt_session_key(
        &self,
        _data: &[u8],
        _decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError> {
        Err(CryptoError::NotImplemented("decrypt_session_key — M2"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_is_44_char_base64_of_32_bytes() {
        let crypto = RpgpCrypto::new();
        let p = crypto.generate_passphrase();
        // 32 bytes base64 (no padding-trim) = 44 chars including '=' padding
        assert_eq!(p.len(), 44, "passphrase: {p:?}");
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "non-base64 chars: {p:?}"
        );
    }

    #[test]
    fn passphrases_are_unique() {
        let crypto = RpgpCrypto::new();
        let a = crypto.generate_passphrase();
        let b = crypto.generate_passphrase();
        assert_ne!(a, b);
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

    #[test]
    fn aead_disabled_passes() {
        let opts = EncryptOptions::default();
        assert!(RpgpCrypto::reject_aead(&opts).is_ok());
    }
}
