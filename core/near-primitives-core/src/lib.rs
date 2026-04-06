//! Core primitive types for Final Layer blockchain.
//!
//! This crate contains the smallest set of types that everything else depends on.

pub use near_account_id::AccountId;

/// Protocol version type. Final Layer uses protocol version 999.
pub type ProtocolVersion = u32;

/// Balance in yoctoNEAR (10^-24 NEAR).
pub type Balance = u128;

/// Block height.
pub type BlockHeight = u64;

/// Block height delta (difference between block heights).
pub type BlockHeightDelta = u64;

/// Gas amount.
pub type Gas = u64;

/// Number of blocks.
pub type NumBlocks = u64;

/// Number of seats (for validators etc).
pub type NumSeats = u64;

/// Current Final Layer protocol version.
pub const PROTOCOL_VERSION: ProtocolVersion = 999;

/// Chain identifier for Final Layer mainnet.
pub const FINAL_LAYER_MAINNET: &str = "final-layer-mainnet";

/// Chain identifier for Final Layer testnet.
pub const FINAL_LAYER_TESTNET: &str = "final-layer-testnet";
