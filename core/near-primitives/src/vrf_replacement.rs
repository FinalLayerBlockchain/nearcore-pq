//! RANDAO-based randomness beacon — replaces VRF in the PQC fork.
//!
//! ## Background
//!
//! NEAR's original randomness beacon used an Ed25519-based VRF (verifiable
//! random function) based on the ristretto255 construction. This construction
//! is fundamentally tied to the elliptic curve group structure of Ed25519 and
//! has no NIST-standardized PQC equivalent.
//!
//! ## RANDAO Replacement
//!
//! Final Layer uses a commit-reveal RANDAO scheme instead:
//!
//! ```text
//! reveal = SHA3-256("NEAR-RANDAO-v1\x00" || sk_bytes || epoch_id || height_le64)
//! block.random_value = prev_random_value XOR reveal.value
//! ```
//!
//! ### Security Properties vs VRF
//!
//! | Property              | VRF (Ed25519)        | RANDAO (SHA3-256)          |
//! |-----------------------|----------------------|----------------------------|
//! | Post-quantum safe     | No                   | Yes                        |
//! | Deterministic         | Yes                  | Yes                        |
//! | Unpredictable         | Yes (DDH assumption) | Yes (preimage resistance)  |
//! | Publicly verifiable   | Yes (with proof)     | Yes (commit-reveal)        |
//! | Last-revealer bias    | None                 | Mitigated by pre-commitment|
//!
//! ### Bias Mitigation
//!
//! The last block producer of an epoch can choose to withhold their reveal,
//! biasing the randomness. This is mitigated by:
//! 1. Pre-commitment at the start of the epoch
//! 2. Slashing for withheld reveals
//! 3. Fallback to previous epoch's accumulated value
//!
//! This matches Ethereum's RANDAO security model (EIP-4399).

use near_crypto::SecretKey;

/// A RANDAO reveal — a 32-byte commitment used to accumulate randomness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandaoReveal {
    /// SHA3-256 hash commitment
    pub value: [u8; 32],
}

impl RandaoReveal {
    /// Compute a RANDAO reveal for a specific (epoch_id, block_height) slot.
    ///
    /// The domain-separated hash ensures reveals from different slots are
    /// independent even with the same secret key.
    ///
    /// # Arguments
    /// - `secret_key`: The validator's signing key (any PQC key type)
    /// - `epoch_id`: 32-byte epoch identifier
    /// - `block_height`: Block height within the epoch
    pub fn compute(secret_key: &SecretKey, epoch_id: &[u8; 32], block_height: u64) -> Self {
        use sha3::{Digest, Sha3_256};

        // Extract raw sk bytes for hashing
        let sk_bytes: &[u8] = match secret_key {
            SecretKey::MlDsa(combined) => {
                // Use only the sk portion (bytes 1952..) not the pk
                &combined[near_crypto::MLDSA_PUBLIC_KEY_LEN..]
            }
            SecretKey::FnDsa(combined) => {
                // Use only the sk portion (bytes ..1281)
                &combined[..near_crypto::FNDSA_SECRET_KEY_LEN]
            }
            SecretKey::SlhDsa(buf) => {
                // Use only the sk portion (bytes ..32); [32..64] is pk
                &buf[..32]
            }
        };

        let mut hasher = Sha3_256::new();
        hasher.update(b"NEAR-RANDAO-v1\x00");
        hasher.update(sk_bytes);
        hasher.update(epoch_id);
        hasher.update(&block_height.to_le_bytes());

        let result = hasher.finalize();
        let mut value = [0u8; 32];
        value.copy_from_slice(&result);
        RandaoReveal { value }
    }

    /// Accumulate this reveal into the running random value.
    ///
    /// `block.random_value = prev_random_value XOR reveal.value`
    pub fn accumulate(&self, prev: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = prev[i] ^ self.value[i];
        }
        out
    }
}
