/// PQC-NEAR: core/crypto/src/signer.rs  (v2 — post-review fixes)
///
/// ═══════════════════════════════════════════════════════════════════
/// FIXES IN v2:
///
/// BUG FIX 1 — from_random() was calling dilithium3::keypair() twice:
///   v1 had a complex branching path inside InMemorySigner::from_random()
///   that re-generated a keypair just to get the pk, resulting in a sk/pk
///   mismatch for MlDsa. Now that SecretKey stores pk‖sk combined, from_random()
///   is a single-line call: SecretKey::from_random(kt).
///
/// BUG FIX 2 — from_random() return type inconsistency:
///   v1 returned Signer (the enum) sometimes and panicked other times.
///   Now InMemorySigner::from_random() returns Self consistently.
///
/// ADDITION — from_seed_drbg() constructor:
///   Wraps SecretKey::from_seed_drbg() for deterministic key derivation
///   from BIP-39 mnemonics. Essential for wallet compatibility.
///
/// VRF: replaced by compute_randao_reveal(). compute_vrf_with_proof() returns
///   an explicit Err — callers must migrate to the RANDAO API.
/// ═══════════════════════════════════════════════════════════════════

use crate::key_file::KeyFile;

/// Returned by the deprecated compute_vrf_with_proof() to force migration
/// to compute_randao_reveal() at every call site.
#[derive(Debug)]
pub struct VrfRemovedError;

impl std::fmt::Display for VrfRemovedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VRF removed in PQC fork — use Signer::compute_randao_reveal(epoch_id, height)")
    }
}
impl std::error::Error for VrfRemovedError {}

/// Returned when compute_randao_reveal() is called on an EmptySigner.
#[derive(Debug)]
pub enum RandaoRevealError {
    /// EmptySigner has no key material — use InMemorySigner.
    EmptySigner,
}

impl std::fmt::Display for RandaoRevealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RandaoRevealError::EmptySigner =>
                write!(f, "EmptySigner cannot produce RANDAO reveals; use InMemorySigner::from_random()"),
        }
    }
}
impl std::error::Error for RandaoRevealError {}


use crate::{KeyType, PublicKey, SecretKey, Signature};
use near_account_id::AccountId;
use std::fmt::{self, Debug};
use std::io;
use std::path::Path;

/// Unified signer enum — wraps EmptySigner or InMemorySigner.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Signer {
    Empty(EmptySigner),
    InMemory(InMemorySigner),
}

impl Signer {
    pub fn public_key(&self) -> PublicKey {
        match self {
            Signer::Empty(s)    => s.public_key(),
            Signer::InMemory(s) => s.public_key(),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Signer::Empty(s)    => s.sign(data),
            Signer::InMemory(s) => s.sign(data),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        signature.verify(data, &self.public_key())
    }

    /// Compute a RANDAO reveal for the given (epoch_id, block_height).
    ///
    /// This REPLACES the classical compute_vrf_with_proof() which used the
    /// Ed25519 ristretto255 VRF construction. That construction is
    /// fundamentally Ed25519-specific and has no PQC equivalent in any
    /// current NIST standard.
    ///
    /// The RANDAO scheme (see core/primitives/src/vrf_replacement.rs):
    ///   reveal = SHA3-256("NEAR-RANDAO-v1\x00" ‖ sk_bytes ‖ epoch_id ‖ height)
    ///   accumulate: block.random_value = prev_random_value XOR reveal.value
    ///
    /// Properties vs VRF:
    ///   ✅ Post-quantum safe (SHA3-256 only)
    ///   ✅ Deterministic per (sk, epoch, slot) — verifiable without interaction
    ///   ✅ Unpredictable — requires knowing all future reveals to bias
    ///   ⚠️  Last-revealer bias (mitigated by pre-commitment + slashing)
    ///
    /// In block_producer.rs, replace:
    ///   signer.compute_vrf_with_proof(prev_random.as_ref())
    /// With:
    ///   signer.compute_randao_reveal(epoch_id.as_ref(), block_height)
    /// Compute a RANDAO reveal for the given (epoch_id, block_height).
    ///
    /// Returns Err if called on an EmptySigner (which has no key material).
    pub fn compute_randao_reveal(
        &self,
        epoch_id: &[u8; 32],
        block_height: u64,
    ) -> Result<near_primitives::vrf_replacement::RandaoReveal, RandaoRevealError> {
        match self {
            Signer::InMemory(s) => {
                Ok(near_primitives::vrf_replacement::RandaoReveal::compute(
                    &s.secret_key,
                    epoch_id,
                    block_height,
                ))
            }
            Signer::Empty(_) => Err(RandaoRevealError::EmptySigner),
        }
    }

    /// VRF entry point — REMOVED in PQC fork.
    ///
    /// Returns Err(VrfRemovedError) immediately. Do not use.
    /// Every call site must migrate to compute_randao_reveal(epoch_id, block_height).
    ///
    /// Returning fake proof bytes would be dangerous: callers may treat them as
    /// valid proofs and use them in consensus-critical paths. This method makes
    /// migration failures loud rather than silently wrong.
    #[deprecated(
        since = "pqc-nearcore-0.1.0",
        note = "VRF removed. Migrate call sites to Signer::compute_randao_reveal()."
    )]
    pub fn compute_vrf_with_proof(&self, _data: &[u8]) -> Result<!, VrfRemovedError> {
        Err(VrfRemovedError)
    }

    pub fn write_to_file(&self, path: &Path) -> io::Result<()> {
        match self {
            Signer::Empty(_)    => Err(io::Error::new(io::ErrorKind::Unsupported, "EmptySigner cannot be written to file")),
            Signer::InMemory(s) => s.write_to_file(path),
        }
    }

    pub fn get_account_id(&self) -> Option<&AccountId> {
        match self {
            Signer::Empty(_)    => None,
            Signer::InMemory(s) => Some(&s.account_id),
        }
    }
}

impl From<EmptySigner> for Signer {
    fn from(s: EmptySigner) -> Self { Signer::Empty(s) }
}

impl From<InMemorySigner> for Signer {
    fn from(s: InMemorySigner) -> Self { Signer::InMemory(s) }
}

impl TryFrom<Signer> for KeyFile {
    type Error = &'static str;
    fn try_from(signer: Signer) -> Result<KeyFile, Self::Error> {
        match signer {
            Signer::Empty(_) => Err("EmptySigner has no associated KeyFile"),
            Signer::InMemory(s) => Ok(KeyFile {
                account_id: s.account_id,
                public_key: s.public_key,
                secret_key: s.secret_key,
            }),
        }
    }
}

// ── EmptySigner ───────────────────────────────────────────────────────────────

/// Dummy signer for test contexts that do not exercise actual signing.
/// Uses MlDsa (validator key type) as the default, returning all-zero outputs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct EmptySigner;

impl EmptySigner {
    pub fn new() -> Self { Self }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::empty(KeyType::MlDsa)
    }

    pub fn sign(&self, _data: &[u8]) -> Signature {
        Signature::empty(KeyType::MlDsa)
    }
}

impl Default for EmptySigner {
    fn default() -> Self { Self }
}

// ── InMemorySigner ────────────────────────────────────────────────────────────

/// An in-memory signer backed by a PQC secret key.
///
/// The `public_key` field is always stored explicitly alongside `secret_key`.
/// For MlDsa keys, the public key CANNOT be re-derived from the secret key
/// after generation — this struct correctly handles that by always persisting
/// both. See `SecretKey` documentation for the combined storage layout.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InMemorySigner {
    pub account_id: AccountId,
    /// Always stored explicitly — critical for MlDsa where pk ≠ f(sk).
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl InMemorySigner {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Generate a fresh PQC keypair using OS randomness.
    ///
    /// This is the preferred constructor. Use this for new accounts and
    /// validators. For deterministic derivation from a mnemonic, use
    /// `from_seed_drbg()` instead.
    ///
    /// FIX v2: No longer calls keypair() twice. SecretKey::from_random()
    /// now stores pk‖sk combined, so public_key() is a simple slice read.
    #[cfg(feature = "rand")]
    pub fn from_random(account_id: AccountId, key_type: KeyType) -> Self {
        let secret_key = SecretKey::from_random(key_type);
        // public_key() is now O(copy) and never panics — pk is in the combined buffer
        let public_key = secret_key.public_key();
        Self { account_id, public_key, secret_key }
    }

    /// Derive a deterministic keypair from a 32-byte seed via SHAKE256-DRBG.
    ///
    /// Use this for wallet key derivation from BIP-39 mnemonics:
    ///   1. Generate mnemonic → 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512)
    ///   2. Derive purpose key: HMAC-SHA256(seed, "NEAR-purpose-{index}")
    ///   3. Truncate to 32 bytes, pass as `seed` here
    ///
    /// The SHAKE256 expansion inside ensures the PQC algorithm gets the
    /// correct-length seed even though input is always 32 bytes.
    ///
    /// SECURITY: Keys are as strong as the input entropy. A 24-word BIP-39
    /// mnemonic provides 256 bits of entropy — sufficient for all three schemes.
    pub fn from_seed_drbg(account_id: AccountId, key_type: KeyType, seed: &[u8; 32]) -> Self {
        let secret_key = SecretKey::from_seed_drbg(key_type, seed);
        let public_key = secret_key.public_key();
        Self { account_id, public_key, secret_key }
    }

    /// Construct from an explicitly provided keypair.
    ///
    /// The caller is responsible for ensuring `public_key` matches `secret_key`.
    /// Prefer `from_random()` or `from_seed_drbg()` which guarantee consistency.
    pub fn from_keypair(account_id: AccountId, public_key: PublicKey, secret_key: SecretKey) -> Self {
        // Sanity-check key type consistency
        debug_assert_eq!(
            public_key.key_type(), secret_key.key_type(),
            "PublicKey and SecretKey key types must match"
        );
        Self { account_id, public_key, secret_key }
    }

    /// Construct from a secret key, deriving the public key automatically.
    /// Valid for FnDsa and SlhDsa. For MlDsa, use `from_keypair()` or
    /// `from_random()` — calling this on an MlDsa key loaded from a bare
    /// string (with zeroed pk slot) will produce a broken signer.
    pub fn from_secret_key(account_id: AccountId, secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self { account_id, public_key, secret_key }
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        KeyFile::from_file(path).map(Self::from)
    }

    // ── Signer operations ─────────────────────────────────────────────────────

    pub fn public_key(&self) -> PublicKey { self.public_key.clone() }

    pub fn sign(&self, data: &[u8]) -> Signature { self.secret_key.sign(data) }

    pub fn write_to_file(&self, path: &Path) -> io::Result<()> {
        KeyFile::from(self).write_to_file(path)
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Create a test signer with an FnDsa key (user account key type).
    ///
    /// For deterministic test signers (reproducible across runs), use:
    ///   `InMemorySigner::from_seed_drbg(account, KeyType::FnDsa, &[test_index as u8; 32])`
    #[cfg(feature = "rand")]
    pub fn test_signer(account_id: &AccountId) -> Self {
        Self::from_random(account_id.clone(), KeyType::FnDsa)
    }

    /// Create a deterministic test signer from a u64 test index.
    /// Reproducible across all runs — use in unit tests and golden tests.
    pub fn test_signer_deterministic(account_id: &AccountId, index: u64) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        Self::from_seed_drbg(account_id.clone(), KeyType::FnDsa, &seed)
    }

    /// Create a deterministic validator signer (MlDsa) for test use.
    pub fn test_validator_signer_deterministic(account_id: &AccountId, index: u64) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        Self::from_seed_drbg(account_id.clone(), KeyType::MlDsa, &seed)
    }
}

impl fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InMemorySigner {{ account_id: {}, public_key: {} }}", self.account_id, self.public_key)
    }
}

impl From<KeyFile> for InMemorySigner {
    fn from(key_file: KeyFile) -> Self {
        Self {
            account_id: key_file.account_id,
            public_key: key_file.public_key,
            secret_key: key_file.secret_key,
        }
    }
}

impl From<&InMemorySigner> for KeyFile {
    fn from(signer: &InMemorySigner) -> KeyFile {
        KeyFile {
            account_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            secret_key: signer.secret_key.clone(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_random_sign_verify() {
        let account: AccountId = "alice.near".parse().unwrap();
        for kt in [KeyType::MlDsa, KeyType::FnDsa] {
            let signer = InMemorySigner::from_random(account.clone(), kt);
            let msg = b"signer test message";
            let sig = signer.sign(msg);
            assert!(sig.verify(msg, &signer.public_key()), "from_random sign/verify failed for {:?}", kt);
        }
    }

    #[test]
    fn test_from_seed_drbg_deterministic() {
        let account: AccountId = "bob.near".parse().unwrap();
        let seed = [99u8; 32];
        let s1 = InMemorySigner::from_seed_drbg(account.clone(), KeyType::FnDsa, &seed);
        let s2 = InMemorySigner::from_seed_drbg(account.clone(), KeyType::FnDsa, &seed);
        assert_eq!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn test_test_signer_deterministic() {
        let account: AccountId = "test.near".parse().unwrap();
        let s0 = InMemorySigner::test_signer_deterministic(&account, 0);
        let s1 = InMemorySigner::test_signer_deterministic(&account, 1);
        assert_ne!(s0.public_key(), s1.public_key(), "Different indices must produce different keys");
        // Same index → same key
        let s0b = InMemorySigner::test_signer_deterministic(&account, 0);
        assert_eq!(s0.public_key(), s0b.public_key(), "Same index must produce same key");
    }

    #[test]
    fn test_key_type_consistency() {
        let account: AccountId = "validator.near".parse().unwrap();
        let validator_signer = InMemorySigner::from_random(account.clone(), KeyType::MlDsa);
        assert_eq!(validator_signer.public_key().key_type(), KeyType::MlDsa);
        assert_eq!(validator_signer.secret_key.key_type(), KeyType::MlDsa);

        let user_signer = InMemorySigner::from_random(account.clone(), KeyType::FnDsa);
        assert_eq!(user_signer.public_key().key_type(), KeyType::FnDsa);
        assert_eq!(user_signer.secret_key.key_type(), KeyType::FnDsa);
    }
}
