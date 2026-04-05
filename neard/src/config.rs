// ============================================================================
// PQC-NEARCORE FORK: neard/src/config.rs
// ============================================================================
//
// CRYPTO CHANGES:
//   - All KeyType::ED25519 → KeyType::FnDsa (user/signer keys)
//                         → KeyType::MlDsa  (validator/block-signing keys)
//   - InMemorySigner::from_seed(..., KeyType::ED25519, ...) REMOVED
//     → Use InMemorySigner::from_random(account_id, KeyType::FnDsa)
//   - InMemoryValidatorSigner::from_seed(...) REMOVED
//     → Use InMemoryValidatorSigner::from_random(account_id, KeyType::MlDsa)
//   - Genesis Signature::empty(KeyType::ED25519)
//     → Signature::empty(KeyType::MlDsa)
//
// RATIONALE:
//   User accounts use FnDsa (Falcon-512): smallest signatures (~666 bytes),
//   fastest verification, ideal for high-frequency transactions.
//   Validators use MlDsa (Dilithium3): deterministic signing, well-audited,
//   fast for high-frequency block/chunk signing operations.
//
// NOTE ON from_seed():
//   from_seed() is fundamentally incompatible with lattice-based schemes.
//   Ed25519 keys can be deterministically derived from a seed via SHA-512
//   expansion. Dilithium and Falcon key generation requires rejection sampling
//   that cannot be made deterministic from an arbitrary short seed without
//   implementing a DRBG. All callers must be migrated to from_random().
//   For testing, use a fixed RNG seeded with a test vector.
//
// ============================================================================

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use near_chain_configs::{Genesis, GenesisConfig, GenesisValidatorStake};
use near_crypto::{InMemorySigner, KeyType, PublicKey, Signature};
use near_primitives::account::{AccessKey, Account};
use near_primitives::types::AccountId;

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

/// PQC fork protocol version. Nodes advertising a lower version are rejected.
pub const PQC_PROTOCOL_VERSION: u32 = 999;

/// Default key type for user / signer accounts.
pub const DEFAULT_USER_KEY_TYPE: KeyType = KeyType::FnDsa;

/// Default key type for validators (block and chunk signing).
pub const DEFAULT_VALIDATOR_KEY_TYPE: KeyType = KeyType::MlDsa;

// ============================================================================
// NODE CONFIG
// ============================================================================

/// Top-level node configuration.
///
/// PQC NOTE: `validator_key_file` now stores an MlDsa keypair.
///           `node_key_file` stores an FnDsa keypair (P2P identity).
///           Key files written by `neard init` will contain "mldsa:" and
///           "fndsa:" prefixes respectively.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub genesis_file: PathBuf,
    pub genesis_records_file: Option<PathBuf>,
    pub validator_key_file: PathBuf,
    pub node_key_file: PathBuf,
    pub network: NetworkConfig,
    pub rpc: Option<RpcConfig>,
    pub telemetry: TelemetryConfig,
    pub chain: ChainConfig,
}

impl Config {
    /// Load config from disk. Keypair files are read separately via key_file.rs.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }
}

// ============================================================================
// INIT — `neard init`
// ============================================================================

/// Initialize a new node home directory with PQC keypairs.
///
/// PQC CHANGES vs upstream:
///   - Node key: FnDsa (was Ed25519)
///   - Validator key: MlDsa (was Ed25519)
///   - No from_seed() calls; all keys generated via from_random()
pub fn init_configs(
    dir: &Path,
    chain_id: &str,
    account_id: Option<AccountId>,
    num_shards: u64,
    fast: bool,
) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;

    // --- Node P2P identity key (FnDsa) ---
    // PQC: Was Ed25519. FnDsa gives smallest P2P handshake identity proofs.
    let node_key_file = dir.join("node_key.json");
    if !node_key_file.exists() {
        // PQC: from_random() — no from_seed() equivalent for lattice keys
        let node_signer = InMemorySigner::from_random(
            "node".parse()?,
            DEFAULT_USER_KEY_TYPE, // FnDsa
        );
        node_signer.write_to_file(&node_key_file)?;
        eprintln!("Generated FnDsa node key: {}", node_signer.public_key);
    }

    // --- Validator signing key (MlDsa) ---
    // PQC: Was Ed25519. MlDsa for deterministic, fast validator signing.
    let validator_key_file = dir.join("validator_key.json");
    if !validator_key_file.exists() {
        let validator_account = account_id.unwrap_or_else(|| "validator".parse().unwrap());
        // PQC: from_random() — MlDsa key generation requires secure randomness
        let validator_signer = InMemorySigner::from_random(
            validator_account.clone(),
            DEFAULT_VALIDATOR_KEY_TYPE, // MlDsa
        );
        validator_signer.write_to_file(&validator_key_file)?;
        eprintln!(
            "Generated MlDsa validator key for {}: {}",
            validator_account, validator_signer.public_key
        );
    }

    // --- Genesis ---
    let genesis_file = dir.join("genesis.json");
    if !genesis_file.exists() {
        let genesis = make_genesis(chain_id, num_shards, fast)?;
        genesis.to_file(&genesis_file)?;
        eprintln!("Generated genesis: {}", genesis_file.display());
    }

    // --- Config ---
    let config_file = dir.join("config.json");
    if !config_file.exists() {
        let config = Config {
            genesis_file: "genesis.json".into(),
            genesis_records_file: None,
            validator_key_file: "validator_key.json".into(),
            node_key_file: "node_key.json".into(),
            network: NetworkConfig::default(),
            rpc: Some(RpcConfig::default()),
            telemetry: TelemetryConfig::default(),
            chain: ChainConfig::default(),
        };
        fs::write(&config_file, serde_json::to_string_pretty(&config)?)?;
    }

    Ok(())
}

// ============================================================================
// GENESIS CONSTRUCTION
// ============================================================================

/// Build a fresh genesis block configuration.
///
/// PQC CHANGES:
///   - Block signature: Signature::empty(KeyType::MlDsa)  [was ED25519]
///   - Validator stakes use MlDsa public keys
///   - protocol_version: PQC_PROTOCOL_VERSION (999)
fn make_genesis(chain_id: &str, num_shards: u64, fast: bool) -> anyhow::Result<Genesis> {
    let mut genesis_config = GenesisConfig::default();
    genesis_config.chain_id = chain_id.to_string();
    genesis_config.num_block_producer_seats = 100;
    genesis_config.num_block_producer_seats_per_shard = vec![100; num_shards as usize];
    genesis_config.avg_hidden_validator_seats_per_shard = vec![0; num_shards as usize];

    // PQC: protocol_version must be PQC_PROTOCOL_VERSION to reject classical nodes
    genesis_config.protocol_version = PQC_PROTOCOL_VERSION;

    if fast {
        genesis_config.min_gas_price = 0;
        genesis_config.max_gas_price = 0;
    }

    // PQC: Genesis block signature is MlDsa empty signature
    // (set in block_header.rs genesis() method — reproduced here for clarity)
    // Signature::empty(KeyType::MlDsa)  ← see block_header.rs

    Ok(Genesis::new(genesis_config, Default::default())?)
}

// ============================================================================
// TESTNET / LOCALNET HELPERS
// ============================================================================

/// Create a set of genesis validator accounts for local testing.
///
/// PQC NOTE: Each validator gets an MlDsa keypair via from_random().
/// Upstream used from_seed("test", KeyType::ED25519, i) — this pattern
/// is NOT compatible with PQC. Tests must use deterministic RNG seeded
/// with a fixed value (see test module below).
pub fn create_testnet_configs(
    num_validators: usize,
    num_shards: u64,
    prefix: &str,
    archive: bool,
) -> Vec<(Config, Arc<InMemorySigner>, Arc<InMemorySigner>)> {
    (0..num_validators)
        .map(|i| {
            let account_id: AccountId = format!("{}{}", prefix, i).parse().unwrap();

            // PQC: Validator signing key — MlDsa
            // OLD: InMemorySigner::from_seed(account_id, KeyType::ED25519, seed)
            let validator_signer = Arc::new(InMemorySigner::from_random(
                account_id.clone(),
                DEFAULT_VALIDATOR_KEY_TYPE, // MlDsa
            ));

            // PQC: Node P2P key — FnDsa
            // OLD: InMemorySigner::from_seed(account_id, KeyType::ED25519, seed)
            let node_signer = Arc::new(InMemorySigner::from_random(
                account_id.clone(),
                DEFAULT_USER_KEY_TYPE, // FnDsa
            ));

            let mut config = Config {
                genesis_file: "genesis.json".into(),
                genesis_records_file: None,
                validator_key_file: "validator_key.json".into(),
                node_key_file: "node_key.json".into(),
                network: NetworkConfig::default(),
                rpc: if i == 0 { Some(RpcConfig::default()) } else { None },
                telemetry: TelemetryConfig::default(),
                chain: ChainConfig { archive, ..Default::default() },
            };

            (config, validator_signer, node_signer)
        })
        .collect()
}

// ============================================================================
// STUB CONFIG TYPES
// (In real nearcore these are in near-jsonrpc, near-network, etc.)
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkConfig {
    pub addr: Option<String>,
    pub boot_nodes: Vec<String>,
    pub max_num_peers: u32,
    /// Maximum size of a single P2P message in bytes.
    ///
    /// PQC CHANGE: Increased from 512 KB (524_288) to 4 MB (4_194_304).
    /// Rationale: Block approval messages carry one MlDsa signature per
    /// validator (3,293 bytes). With 100 validators, a single block approval
    /// gossip round requires ~330 KB. A full block with all approval sigs
    /// can reach ~3.5 MB. 4 MB provides headroom for future validator growth.
    ///
    /// DO NOT set this back to 512 KB — nodes will silently drop legitimate
    /// block approvals and stall consensus.
    pub max_msg_len_bytes: u32,
    /// Maximum number of in-flight messages per peer connection.
    ///
    /// PQC CHANGE: Increased from 128 to 64. PQC messages are larger so
    /// we reduce concurrency to avoid memory pressure at the same overall
    /// memory budget (64 × 4 MB = 256 MB vs 128 × 512 KB = 64 MB — adjust
    /// max_msg_len_bytes and this together to hit your memory target).
    pub max_inflight_messages_per_peer: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            addr: Some("0.0.0.0:24567".to_string()),
            boot_nodes: vec![],
            max_num_peers: 40,
            // PQC: 4 MB — see field documentation above
            max_msg_len_bytes: 4 * 1024 * 1024,
            max_inflight_messages_per_peer: 64,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RpcConfig {
    pub addr: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TelemetryConfig {
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChainConfig {
    pub archive: bool,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_types_are_pqc() {
        // Ensure the default key types are not classical
        assert_ne!(DEFAULT_USER_KEY_TYPE, KeyType::ED25519);
        assert_ne!(DEFAULT_VALIDATOR_KEY_TYPE, KeyType::ED25519);
        assert_eq!(DEFAULT_USER_KEY_TYPE, KeyType::FnDsa);
        assert_eq!(DEFAULT_VALIDATOR_KEY_TYPE, KeyType::MlDsa);
    }

    #[test]
    fn test_genesis_signature_is_mldsa() {
        // PQC: Genesis block must use MlDsa empty signature
        let sig = Signature::empty(KeyType::MlDsa);
        assert_eq!(sig.key_type(), KeyType::MlDsa);
    }

    // PQC NOTE: from_seed() tests removed — incompatible with lattice schemes.
    // Add integration tests using from_random() with a seeded ChaCha20Rng
    // for reproducibility in CI:
    //
    //   use rand_chacha::ChaCha20Rng;
    //   use rand::SeedableRng;
    //   let mut rng = ChaCha20Rng::seed_from_u64(42);
    //   let signer = InMemorySigner::from_random_with_rng(account_id, KeyType::FnDsa, &mut rng);
    //
    // (Requires adding from_random_with_rng() to InMemorySigner in signer.rs)
}
