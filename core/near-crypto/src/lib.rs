//! # near-crypto — Post-Quantum Cryptography for Final Layer
//!
//! This crate replaces the classical Ed25519/secp256k1 signing in nearcore
//! with NIST-standardized post-quantum algorithms.
//!
//! ## Key Types
//!
//! | Variant       | Algorithm              | Standard   | Use Case          | Sig Size |
//! |---------------|------------------------|------------|-------------------|----------|
//! | `MlDsa`  (0)  | ML-DSA / Dilithium3    | FIPS 204   | Validators        | 3293 B   |
//! | `FnDsa`  (1)  | FN-DSA / Falcon-512    | FIPS 206   | User wallets      | ≤752 B   |
//! | `SlhDsa` (2)  | SLH-DSA / SPHINCS+     | FIPS 205   | Governance        | 7856 B   |
//!
//! ## Key String Format
//!
//! ```text
//! <keytype>:<bs58-encoded-key-bytes>
//! ```
//!
//! Examples:
//! - `mldsa:2LtqmD...`   (ML-DSA Dilithium3 validator key)
//! - `fndsa:34emUD...`   (FN-DSA Falcon-512 user wallet key)
//! - `slhdsa:4Xyz...`    (SLH-DSA SPHINCS+ governance key)
//!
//! ## P2P Encryption (ML-KEM)
//!
//! The P2P networking layer uses ML-KEM-768 (FIPS 203) for key encapsulation
//! followed by AES-256-GCM for session message encryption. This is handled
//! at the network layer and is not exposed through this crate's public API.

pub mod errors;
pub mod key_file;
pub mod signature;
pub mod signer;

// Re-export the most commonly used types at the crate root
pub use signature::{
    // Key types
    KeyType,
    // Public key types
    PublicKey,
    MlDsaPublicKey,
    FnDsaPublicKey,
    SlhDsaPublicKey,
    // Secret key
    SecretKey,
    // Signature
    Signature,
    // Size constants
    MLDSA_PUBLIC_KEY_LEN,
    MLDSA_SECRET_KEY_LEN,
    MLDSA_COMBINED_KEY_LEN,
    MLDSA_SIGNATURE_LEN,
    FNDSA_PUBLIC_KEY_LEN,
    FNDSA_SECRET_KEY_LEN,
    FNDSA_COMBINED_KEY_LEN,
    FNDSA_SIGNATURE_MAX_LEN,
    SLHDSA_PUBLIC_KEY_LEN,
    SLHDSA_SECRET_KEY_LEN,
    SLHDSA_SIGNATURE_LEN,
};

pub use signer::{EmptySigner, InMemorySigner, Signer};
pub use key_file::KeyFile;
