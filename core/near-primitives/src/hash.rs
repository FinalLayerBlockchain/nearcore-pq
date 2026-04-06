//! CryptoHash — SHA-256 based content hash used throughout the chain.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte SHA-256 content hash.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    BorshSerialize, BorshDeserialize,
    Serialize, Deserialize,
)]
pub struct CryptoHash(pub [u8; 32]);

impl CryptoHash {
    pub const fn new() -> Self {
        CryptoHash([0u8; 32])
    }

    pub fn hash_bytes(data: &[u8]) -> Self {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        CryptoHash(arr)
    }
}

impl Default for CryptoHash {
    fn default() -> Self { Self::new() }
}

impl fmt::Display for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
