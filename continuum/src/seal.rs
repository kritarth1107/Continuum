use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ContinuumError, Kernel, Result};

/// Ed25519 key pair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from secret key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the secret key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Continuity seal: cryptographic binding of kernel state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuitySeal {
    /// SHA-256 hash of canonical kernel JSON (hex encoded)
    pub kernel_hash: String,

    /// Ed25519 signature of the hash (hex encoded)
    pub signature: String,

    /// Public key that created this seal (hex encoded)
    pub public_key: String,
}

impl ContinuitySeal {
    /// Create a new seal for a kernel
    pub fn create(kernel: &Kernel, keypair: &KeyPair) -> Result<Self> {
        let canonical = kernel.to_canonical_json()?;
        let hash = compute_sha256(canonical.as_bytes());
        let signature = keypair.sign(&hash);

        Ok(Self {
            kernel_hash: hex::encode(hash),
            signature: hex::encode(signature.to_bytes()),
            public_key: keypair.public_key_hex(),
        })
    }

    /// Verify the seal against a kernel
    pub fn verify(&self, kernel: &Kernel) -> Result<bool> {
        let canonical = kernel.to_canonical_json()?;
        let computed_hash = compute_sha256(canonical.as_bytes());
        let computed_hash_hex = hex::encode(computed_hash);

        if computed_hash_hex != self.kernel_hash {
            return Err(ContinuumError::HashMismatch {
                expected: self.kernel_hash.clone(),
                actual: computed_hash_hex,
            });
        }

        self.verify_signature()
    }

    /// Verify just the signature (assumes hash already checked)
    pub fn verify_signature(&self) -> Result<bool> {
        let public_key_bytes: [u8; 32] = hex::decode(&self.public_key)?
            .try_into()
            .map_err(|_| ContinuumError::Crypto("invalid public key length".to_string()))?;

        let signature_bytes: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| ContinuumError::Crypto("invalid signature length".to_string()))?;

        let hash_bytes = self.hash_bytes()?;

        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| ContinuumError::Crypto(e.to_string()))?;

        let signature = Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify(&hash_bytes, &signature)
            .map_err(|_| ContinuumError::VerificationFailed)?;

        Ok(true)
    }

    /// Get the kernel hash bytes
    pub fn hash_bytes(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.kernel_hash)?)
    }
}

/// Compute SHA-256 hash of data
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify a public key hex string and signature against a message
pub fn verify_detached(message: &[u8], signature_hex: &str, public_key_hex: &str) -> Result<bool> {
    let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)?
        .try_into()
        .map_err(|_| ContinuumError::Crypto("invalid public key length".to_string()))?;

    let signature_bytes: [u8; 64] = hex::decode(signature_hex)?
        .try_into()
        .map_err(|_| ContinuumError::Crypto("invalid signature length".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|e| ContinuumError::Crypto(e.to_string()))?;

    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| ContinuumError::VerificationFailed)?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let kp = KeyPair::generate();
        let bytes = kp.to_bytes();
        let kp2 = KeyPair::from_bytes(&bytes);
        assert_eq!(kp.public_key_hex(), kp2.public_key_hex());
    }

    #[test]
    fn test_seal_create_verify() {
        let kernel = Kernel::new("test");
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();

        assert!(seal.verify(&kernel).unwrap());
    }

    #[test]
    fn test_seal_detects_tampering() {
        let kernel = Kernel::new("test");
        let keypair = KeyPair::generate();
        let seal = ContinuitySeal::create(&kernel, &keypair).unwrap();

        let mut tampered = kernel.clone();
        tampered.spend_ceiling_usd = 999999.0;

        assert!(seal.verify(&tampered).is_err());
    }

    #[test]
    fn test_seal_detects_wrong_key() {
        let kernel = Kernel::new("test");
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let seal = ContinuitySeal::create(&kernel, &keypair1).unwrap();
        let mut bad_seal = seal.clone();
        bad_seal.public_key = keypair2.public_key_hex();

        assert!(bad_seal.verify(&kernel).is_err());
    }

    #[test]
    fn test_sha256() {
        let hash = compute_sha256(b"hello world");
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
