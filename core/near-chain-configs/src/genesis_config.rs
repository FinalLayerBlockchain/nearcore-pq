//! Genesis configuration for Final Layer blockchain.
//!
//! Final Layer is a quantum-resistant fork of NEAR Protocol with the following
//! key parameters:
//!
//! - Chain ID:              final-layer-mainnet
//! - Protocol version:      999 (PQC-enabled)
//! - Block time:            ~1.5 seconds
//! - Epoch length:          43200 blocks (~12 hours at 1.5s/block)
//! - Active shards:         4 (shard0..shard3)
//! - Block producers:       100 seats
//! - Chunk producers:       300 seats
//! - Initial APY:           ~10%
//! - Halving:               Every 4 years (every 4 * num_blocks_per_year blocks)
//! - Protocol treasury:     10% of inflation to treasury.fl
//! - Total supply at genesis: 10 billion NEAR (10^34 yoctoNEAR)

use near_primitives_core::{
    AccountId, Balance, BlockHeightDelta, Gas, NumBlocks, NumSeats, ProtocolVersion,
};
use near_primitives::types::AccountInfo;
use num_rational::Rational32;
use serde::{Deserialize, Serialize};

// ── Chain constants ───────────────────────────────────────────────────────────

/// Chain identifier for Final Layer mainnet.
pub const CHAIN_ID: &str = "final-layer-mainnet";

/// Protocol version. 999 signals PQC-enabled fork.
pub const PROTOCOL_VERSION: ProtocolVersion = 999;

/// Average block time in seconds.
pub const BLOCK_TIME_SECS: f64 = 1.5;

/// Number of blocks per epoch (~12 hours at 1.5s per block).
pub const EPOCH_LENGTH: BlockHeightDelta = 43200;

/// Number of block producer seats.
pub const NUM_BLOCK_PRODUCER_SEATS: NumSeats = 100;

/// Number of chunk producer seats.
pub const NUM_CHUNK_PRODUCER_SEATS: NumSeats = 300;

/// Number of chunk validator seats.
pub const NUM_CHUNK_VALIDATOR_SEATS: NumSeats = 300;

/// Gas limit per block (1 PetaGas = 10^15 gas units).
pub const GAS_LIMIT: Gas = 1_000_000_000_000_000;

/// Minimum gas price (in yoctoNEAR per gas unit).
pub const MIN_GAS_PRICE: Balance = 100_000_000;

/// Maximum gas price (in yoctoNEAR per gas unit).
pub const MAX_GAS_PRICE: Balance = 10_000_000_000_000_000_000;

/// Number of blocks per year (~1 block per 1.5 seconds, 365 days).
/// 365 * 24 * 60 * 60 / 1.5 = 21_024_000
pub const NUM_BLOCKS_PER_YEAR: NumBlocks = 21_024_000;

/// Transaction validity period in blocks (~1 day at 1.5s/block).
pub const TRANSACTION_VALIDITY_PERIOD: NumBlocks = 86400;

/// Protocol treasury account — receives protocol_reward_rate of inflation.
pub const PROTOCOL_TREASURY_ACCOUNT: &str = "treasury.fl";

/// Total token supply at genesis: 10 billion NEAR in yoctoNEAR (10^34).
/// 10,000,000,000 NEAR × 10^24 yoctoNEAR/NEAR = 10^34
pub const TOTAL_SUPPLY: &str = "10000000000000000000000000000000000";

/// Halving interval: every 4 years in blocks.
pub const HALVING_INTERVAL_BLOCKS: NumBlocks = 4 * NUM_BLOCKS_PER_YEAR;

/// Kickout threshold for block producers (80%).
pub const BLOCK_PRODUCER_KICKOUT_THRESHOLD: u8 = 80;

/// Kickout threshold for chunk producers (80%).
pub const CHUNK_PRODUCER_KICKOUT_THRESHOLD: u8 = 80;

/// Kickout threshold for chunk-only validators (80%).
pub const CHUNK_VALIDATOR_ONLY_KICKOUT_THRESHOLD: u8 = 80;

/// Fishermen stake threshold (minimum stake to be a fisherman, in yoctoNEAR).
/// 10 NEAR
pub const FISHERMEN_THRESHOLD: Balance = 10_000_000_000_000_000_000_000_000;

// ── Shard layout ──────────────────────────────────────────────────────────────

/// Final Layer uses 4 shards at genesis.
pub const NUM_SHARDS: u64 = 4;

/// Shard identifiers.
pub const SHARD_NAMES: [&str; 4] = ["shard0", "shard1", "shard2", "shard3"];

/// Simple 4-shard layout for Final Layer genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLayout {
    /// Number of shards.
    pub num_shards: u64,
    /// Human-readable names for each shard.
    pub shard_names: Vec<String>,
    /// Account prefix boundaries between shards.
    /// Accounts are assigned to shards by prefix hash mod num_shards.
    pub boundary_accounts: Vec<String>,
}

impl ShardLayout {
    /// Create the Final Layer 4-shard layout.
    pub fn final_layer_4_shards() -> Self {
        ShardLayout {
            num_shards: NUM_SHARDS,
            shard_names: SHARD_NAMES.iter().map(|s| s.to_string()).collect(),
            // 3 boundary accounts split address space into 4 ranges:
            //   [start, "p")       → shard0
            //   ["p",   "t")       → shard1
            //   ["t",   "z")       → shard2
            //   ["z",   end]       → shard3
            boundary_accounts: vec![
                "p".to_string(),
                "t".to_string(),
                "z".to_string(),
            ],
        }
    }
}

// ── GenesisConfig ─────────────────────────────────────────────────────────────

/// Full genesis configuration for a Final Layer chain instance.
///
/// This struct drives chain initialization. The `default()` implementation
/// returns the mainnet configuration. Modify fields for testnet/devnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    // ── Identity ──────────────────────────────────────────────────────────────

    /// Chain identifier. Must be unique for each deployment.
    pub chain_id: String,

    /// Protocol version this genesis activates.
    pub protocol_version: ProtocolVersion,

    // ── Epoch parameters ──────────────────────────────────────────────────────

    /// Epoch length in blocks.
    pub epoch_length: BlockHeightDelta,

    /// Number of block producer seats.
    pub num_block_producer_seats: NumSeats,

    /// Number of chunk producer seats.
    pub num_chunk_producer_seats: NumSeats,

    /// Number of chunk validator seats.
    pub num_chunk_validator_seats: NumSeats,

    // ── Economic parameters ───────────────────────────────────────────────────

    /// Maximum inflation per epoch as a fraction of total supply.
    /// Rational32::new(1, 10) = 10% APY.
    pub max_inflation_rate: Rational32,

    /// Fraction of block reward sent to protocol treasury.
    /// Rational32::new(1, 10) = 10%.
    pub protocol_reward_rate: Rational32,

    /// Minimum online threshold for validator rewards (fraction of blocks online).
    pub online_min_threshold: Rational32,

    /// Maximum online threshold above which validator gets full reward.
    pub online_max_threshold: Rational32,

    /// Gas price adjustment rate per block.
    pub gas_price_adjustment_rate: Rational32,

    /// Protocol upgrade stake threshold (fraction of stake needed to upgrade).
    pub protocol_upgrade_stake_threshold: Rational32,

    // ── Gas parameters ────────────────────────────────────────────────────────

    /// Initial (and minimum) gas limit per block.
    pub gas_limit: Gas,

    /// Minimum gas price in yoctoNEAR per gas unit.
    pub min_gas_price: Balance,

    /// Maximum gas price in yoctoNEAR per gas unit.
    pub max_gas_price: Balance,

    // ── Supply ────────────────────────────────────────────────────────────────

    /// Total supply at genesis in yoctoNEAR (as a decimal string).
    pub total_supply: String,

    /// Expected number of blocks per year (used for inflation calculation).
    pub num_blocks_per_year: NumBlocks,

    // ── Timing ────────────────────────────────────────────────────────────────

    /// Number of blocks a transaction remains valid after submission.
    pub transaction_validity_period: NumBlocks,

    // ── Governance ────────────────────────────────────────────────────────────

    /// Account ID receiving protocol treasury payments.
    pub protocol_treasury_account: String,

    // ── Validators ────────────────────────────────────────────────────────────

    /// Initial validator set. Populated from genesis.json.
    pub validators: Vec<AccountInfo>,

    // ── Sharding ─────────────────────────────────────────────────────────────

    /// Shard layout at genesis.
    pub shard_layout: ShardLayout,

    // ── Kickout thresholds ────────────────────────────────────────────────────

    /// Minimum online % before a block producer is kicked out.
    pub block_producer_kickout_threshold: u8,

    /// Minimum online % before a chunk producer is kicked out.
    pub chunk_producer_kickout_threshold: u8,

    /// Minimum online % before a chunk-only validator is kicked out.
    pub chunk_validator_only_kickout_threshold: u8,

    /// Fishermen stake threshold in yoctoNEAR.
    pub fishermen_threshold: Balance,

    // ── Halving ───────────────────────────────────────────────────────────────

    /// Block height interval between halvings.
    /// Every `halving_interval_blocks` blocks, the max inflation rate halves.
    pub halving_interval_blocks: NumBlocks,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        GenesisConfig {
            // Identity
            chain_id:         CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION,

            // Epoch
            epoch_length:                    EPOCH_LENGTH,
            num_block_producer_seats:        NUM_BLOCK_PRODUCER_SEATS,
            num_chunk_producer_seats:        NUM_CHUNK_PRODUCER_SEATS,
            num_chunk_validator_seats:       NUM_CHUNK_VALIDATOR_SEATS,

            // Economics
            max_inflation_rate:                  Rational32::new(1, 10),  // 10% APY
            protocol_reward_rate:                Rational32::new(1, 10),  // 10% to treasury
            online_min_threshold:                Rational32::new(9, 10),  // 90%
            online_max_threshold:                Rational32::new(99, 100),// 99%
            gas_price_adjustment_rate:           Rational32::new(1, 100), // 1%
            protocol_upgrade_stake_threshold:    Rational32::new(8, 10),  // 80%

            // Gas
            gas_limit:     GAS_LIMIT,
            min_gas_price: MIN_GAS_PRICE,
            max_gas_price: MAX_GAS_PRICE,

            // Supply
            total_supply:      TOTAL_SUPPLY.to_string(),
            num_blocks_per_year: NUM_BLOCKS_PER_YEAR,

            // Timing
            transaction_validity_period: TRANSACTION_VALIDITY_PERIOD,

            // Governance
            protocol_treasury_account: PROTOCOL_TREASURY_ACCOUNT.to_string(),

            // Validators — populated from genesis.json at node init
            validators: Vec::new(),

            // Sharding
            shard_layout: ShardLayout::final_layer_4_shards(),

            // Kickout thresholds
            block_producer_kickout_threshold:        BLOCK_PRODUCER_KICKOUT_THRESHOLD,
            chunk_producer_kickout_threshold:        CHUNK_PRODUCER_KICKOUT_THRESHOLD,
            chunk_validator_only_kickout_threshold:  CHUNK_VALIDATOR_ONLY_KICKOUT_THRESHOLD,

            // Fishermen
            fishermen_threshold: FISHERMEN_THRESHOLD,

            // Halving: every 4 years
            halving_interval_blocks: HALVING_INTERVAL_BLOCKS,
        }
    }
}

// ── FinalLayerGenesisConfig ───────────────────────────────────────────────────

/// Final Layer genesis configuration builder.
///
/// Provides a typed builder with Final Layer mainnet defaults.
/// Use `.build()` to get the final `GenesisConfig`.
///
/// # Example
///
/// ```rust
/// use near_chain_configs::FinalLayerGenesisConfig;
///
/// // Get mainnet defaults
/// let config = FinalLayerGenesisConfig::default().build();
/// assert_eq!(config.chain_id, "final-layer-mainnet");
/// assert_eq!(config.protocol_version, 999);
///
/// // Customize for testnet
/// let testnet = FinalLayerGenesisConfig::default()
///     .chain_id("final-layer-testnet")
///     .epoch_length(1000)  // shorter epochs for testing
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct FinalLayerGenesisConfig {
    inner: GenesisConfig,
}

impl Default for FinalLayerGenesisConfig {
    fn default() -> Self {
        FinalLayerGenesisConfig {
            inner: GenesisConfig::default(),
        }
    }
}

impl FinalLayerGenesisConfig {
    pub fn new() -> Self { Self::default() }

    /// Override the chain ID (e.g., for testnet).
    pub fn chain_id(mut self, chain_id: &str) -> Self {
        self.inner.chain_id = chain_id.to_string();
        self
    }

    /// Override the epoch length in blocks.
    pub fn epoch_length(mut self, epoch_length: BlockHeightDelta) -> Self {
        self.inner.epoch_length = epoch_length;
        self
    }

    /// Set the initial validators.
    pub fn validators(mut self, validators: Vec<AccountInfo>) -> Self {
        self.inner.validators = validators;
        self
    }

    /// Set a custom shard layout.
    pub fn shard_layout(mut self, shard_layout: ShardLayout) -> Self {
        self.inner.shard_layout = shard_layout;
        self
    }

    /// Override the protocol treasury account.
    pub fn protocol_treasury_account(mut self, account: &str) -> Self {
        self.inner.protocol_treasury_account = account.to_string();
        self
    }

    /// Override total supply (as yoctoNEAR decimal string).
    pub fn total_supply(mut self, total_supply: &str) -> Self {
        self.inner.total_supply = total_supply.to_string();
        self
    }

    /// Consume the builder and return the final `GenesisConfig`.
    pub fn build(self) -> GenesisConfig {
        self.inner
    }
}

// ── Halving schedule ──────────────────────────────────────────────────────────

/// Calculate the current inflation multiplier based on block height.
///
/// Every `halving_interval_blocks`, the `max_inflation_rate` halves.
/// This mirrors Bitcoin's halving schedule.
///
/// # Arguments
/// - `block_height`:           Current block height
/// - `halving_interval_blocks`: Blocks between halvings
/// - `base_inflation_rate`:    Initial max inflation rate
///
/// # Returns
/// The adjusted inflation rate for the given block height.
pub fn inflation_rate_at_height(
    block_height: u64,
    halving_interval_blocks: NumBlocks,
    base_inflation_rate: Rational32,
) -> Rational32 {
    let halvings = block_height / halving_interval_blocks;
    if halvings >= 64 {
        // After 64 halvings (~256 years), inflation is effectively zero
        return Rational32::new(0, 1);
    }
    // Each halving divides by 2: rate / 2^halvings
    let divisor = 1i32.checked_shl(halvings as u32).unwrap_or(i32::MAX);
    Rational32::new(*base_inflation_rate.numer(), base_inflation_rate.denom() * divisor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_chain_id() {
        let config = GenesisConfig::default();
        assert_eq!(config.chain_id, "final-layer-mainnet");
    }

    #[test]
    fn test_default_protocol_version() {
        let config = GenesisConfig::default();
        assert_eq!(config.protocol_version, 999);
    }

    #[test]
    fn test_default_epoch_length() {
        let config = GenesisConfig::default();
        assert_eq!(config.epoch_length, 43200);
    }

    #[test]
    fn test_default_seats() {
        let config = GenesisConfig::default();
        assert_eq!(config.num_block_producer_seats, 100);
        assert_eq!(config.num_chunk_producer_seats, 300);
        assert_eq!(config.num_chunk_validator_seats, 300);
    }

    #[test]
    fn test_default_inflation() {
        let config = GenesisConfig::default();
        assert_eq!(config.max_inflation_rate, Rational32::new(1, 10));
        assert_eq!(config.protocol_reward_rate, Rational32::new(1, 10));
    }

    #[test]
    fn test_default_shard_count() {
        let config = GenesisConfig::default();
        assert_eq!(config.shard_layout.num_shards, 4);
        assert_eq!(config.shard_layout.shard_names.len(), 4);
    }

    #[test]
    fn test_default_treasury() {
        let config = GenesisConfig::default();
        assert_eq!(config.protocol_treasury_account, "treasury.fl");
    }

    #[test]
    fn test_halving_at_genesis() {
        let rate = inflation_rate_at_height(0, HALVING_INTERVAL_BLOCKS, Rational32::new(1, 10));
        assert_eq!(rate, Rational32::new(1, 10));
    }

    #[test]
    fn test_halving_after_one_period() {
        let rate = inflation_rate_at_height(
            HALVING_INTERVAL_BLOCKS,
            HALVING_INTERVAL_BLOCKS,
            Rational32::new(1, 10),
        );
        assert_eq!(rate, Rational32::new(1, 20)); // half of 10% = 5%
    }

    #[test]
    fn test_builder_chain_id_override() {
        let config = FinalLayerGenesisConfig::default()
            .chain_id("final-layer-testnet")
            .build();
        assert_eq!(config.chain_id, "final-layer-testnet");
        // Other values should still be defaults
        assert_eq!(config.protocol_version, 999);
    }

    #[test]
    fn test_gas_limit() {
        let config = GenesisConfig::default();
        assert_eq!(config.gas_limit, 1_000_000_000_000_000);
    }

    #[test]
    fn test_transaction_validity_period() {
        let config = GenesisConfig::default();
        assert_eq!(config.transaction_validity_period, 86400);
    }
}
