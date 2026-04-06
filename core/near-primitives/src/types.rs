//! Common type aliases and structs used across the chain.

pub use near_primitives_core::{
    AccountId, Balance, BlockHeight, BlockHeightDelta, Gas, NumBlocks, NumSeats,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Account information as stored in genesis.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountInfo {
    pub account_id: AccountId,
    pub public_key: near_crypto::PublicKey,
    pub amount: Balance,
}
