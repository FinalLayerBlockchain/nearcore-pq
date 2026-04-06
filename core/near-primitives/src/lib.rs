//! Primitive types for Final Layer blockchain.

pub mod hash;
pub mod types;
pub mod vrf_replacement;

pub use near_primitives_core::{
    AccountId, Balance, BlockHeight, BlockHeightDelta, Gas, NumBlocks, NumSeats, ProtocolVersion,
};
