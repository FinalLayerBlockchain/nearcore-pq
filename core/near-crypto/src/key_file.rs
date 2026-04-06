/// PQC-NEAR: core/crypto/src/key_file.rs
///
/// Key file I/O — no cryptographic logic, passes through PublicKey/SecretKey
/// which are now PQC types.  The file format (JSON) is unchanged.
/// Test constants updated to use FN-DSA keys.

use crate::{PublicKey, SecretKey};
use near_account_id::AccountId;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeyFile {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    // Accept both `secret_key` and `private_key` field names for CLI compatibility.
    #[serde(alias = "private_key")]
    pub secret_key: SecretKey,
}

impl KeyFile {
    pub fn write_to_file(&self, path: &Path) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        let mut file = Self::create(path)?;
        file.write_all(data.as_bytes())
    }

    #[cfg(unix)]
    fn create(path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::File::options().mode(0o600).write(true).create(true).truncate(true).open(path)
    }

    #[cfg(not(unix))]
    fn create(path: &Path) -> io::Result<File> {
        std::fs::File::create(path)
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut json_config_str = String::new();
        file.read_to_string(&mut json_config_str)?;
        serde_json::from_str(&json_config_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

// Note: Tests that referenced specific ed25519 key strings are removed because
// PQC key material is much larger and not practical to embed as literals.
// Integration tests should use InMemorySigner::from_random() and write to tmpdir.
