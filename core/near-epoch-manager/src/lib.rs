//! Epoch management for Final Layer blockchain.
//!
//! An epoch is a fixed-length period (43200 blocks = ~12 hours) during which
//! the validator set remains constant. At the end of each epoch:
//! 1. Validator performance is assessed
//! 2. Slashing is applied to misbehaving validators
//! 3. The new validator set is elected based on stake
//! 4. RANDAO randomness for the new epoch is finalized
//!
//! ## Epoch Parameters (Final Layer mainnet)
//!
//! | Parameter                   | Value                      |
//! |-----------------------------|----------------------------|
//! | Epoch length                | 43200 blocks (~12 hours)   |
//! | Block producer seats        | 100                        |
//! | Chunk producer seats        | 300                        |
//! | Chunk validator seats       | 300                        |
//! | Block producer kickout      | 80% online threshold       |
//! | Chunk producer kickout      | 80% online threshold       |

use near_chain_configs::GenesisConfig;
use near_primitives_core::{BlockHeight, BlockHeightDelta, NumSeats};

/// Epoch identifier — a 32-byte hash derived from the epoch's random value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EpochId(pub [u8; 32]);

impl EpochId {
    pub fn genesis() -> Self {
        EpochId([0u8; 32])
    }
}

/// Information about a specific epoch.
#[derive(Debug, Clone)]
pub struct EpochInfo {
    /// Sequential epoch number (0 = genesis epoch).
    pub epoch_height: u64,
    /// First block height of this epoch.
    pub first_block: BlockHeight,
    /// Last block height of this epoch.
    pub last_block: BlockHeight,
    /// Number of active block producers this epoch.
    pub num_block_producers: NumSeats,
}

/// Epoch manager — tracks the current epoch and transitions.
pub struct EpochManager {
    config: GenesisConfig,
}

impl EpochManager {
    pub fn new(config: GenesisConfig) -> Self {
        EpochManager { config }
    }

    /// Determine which epoch a block height belongs to.
    pub fn epoch_of_height(&self, block_height: BlockHeight) -> u64 {
        block_height / self.config.epoch_length
    }

    /// Get the first block height of the epoch containing `block_height`.
    pub fn epoch_start(&self, block_height: BlockHeight) -> BlockHeight {
        self.epoch_of_height(block_height) * self.config.epoch_length
    }

    /// Get the last block height of the epoch containing `block_height`.
    pub fn epoch_end(&self, block_height: BlockHeight) -> BlockHeight {
        self.epoch_start(block_height) + self.config.epoch_length - 1
    }

    /// Returns true if `block_height` is the last block of its epoch.
    pub fn is_last_block_in_epoch(&self, block_height: BlockHeight) -> bool {
        (block_height + 1) % self.config.epoch_length == 0
    }

    /// Returns true if `block_height` is the first block of its epoch.
    pub fn is_first_block_in_epoch(&self, block_height: BlockHeight) -> bool {
        block_height % self.config.epoch_length == 0
    }

    /// Return the epoch length from config.
    pub fn epoch_length(&self) -> BlockHeightDelta {
        self.config.epoch_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_chain_configs::FinalLayerGenesisConfig;

    fn test_epoch_manager() -> EpochManager {
        let config = FinalLayerGenesisConfig::default()
            .epoch_length(100)
            .build();
        EpochManager::new(config)
    }

    #[test]
    fn test_epoch_of_height() {
        let em = test_epoch_manager();
        assert_eq!(em.epoch_of_height(0),   0);
        assert_eq!(em.epoch_of_height(99),  0);
        assert_eq!(em.epoch_of_height(100), 1);
        assert_eq!(em.epoch_of_height(199), 1);
        assert_eq!(em.epoch_of_height(200), 2);
    }

    #[test]
    fn test_epoch_start() {
        let em = test_epoch_manager();
        assert_eq!(em.epoch_start(0),   0);
        assert_eq!(em.epoch_start(50),  0);
        assert_eq!(em.epoch_start(100), 100);
        assert_eq!(em.epoch_start(150), 100);
    }

    #[test]
    fn test_epoch_end() {
        let em = test_epoch_manager();
        assert_eq!(em.epoch_end(0),  99);
        assert_eq!(em.epoch_end(50), 99);
        assert_eq!(em.epoch_end(100), 199);
    }

    #[test]
    fn test_is_last_block_in_epoch() {
        let em = test_epoch_manager();
        assert!( em.is_last_block_in_epoch(99));
        assert!(!em.is_last_block_in_epoch(98));
        assert!( em.is_last_block_in_epoch(199));
    }

    #[test]
    fn test_is_first_block_in_epoch() {
        let em = test_epoch_manager();
        assert!( em.is_first_block_in_epoch(0));
        assert!(!em.is_first_block_in_epoch(1));
        assert!( em.is_first_block_in_epoch(100));
    }
}
