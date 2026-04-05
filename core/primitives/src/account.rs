/// PQC-NEAR: core/primitives/src/account.rs
///
/// The pasted upstream version used the old proto-based Account (near_protos::access_key).
/// This is the current Borsh-based Account with PQC notes:
///
///   • `is_valid_staking_key()` — removes the Ed25519 ristretto curve check.
///     ML-DSA and FN-DSA keys are both valid staking keys.
///     SLH-DSA is rejected for staking (7856-byte signatures are too large for
///     chunk header inclusion at scale).
///
/// No structural changes to the Account or AccessKey types are needed for PQC —
/// the key material is stored as opaque `PublicKey` which is now a PQC type.

use borsh::{BorshDeserialize, BorshSerialize};
use near_crypto::{KeyType, PublicKey};
use near_primitives_core::types::{Balance, Nonce, StorageUsage};
use near_schema_checker_lib::ProtocolSchema;
use std::fmt;

/// Account data stored in the state trie.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, ProtocolSchema)]
pub struct Account {
    /// Non-staked balance.
    pub amount: Balance,
    /// Staked balance (locked).
    pub locked: Balance,
    /// Hash of the deployed contract code, or CryptoHash::default() if none.
    pub code_hash: near_primitives_core::hash::CryptoHash,
    /// Storage usage in bytes.
    pub storage_usage: StorageUsage,
}

impl Account {
    pub fn new(amount: Balance, locked: Balance, code_hash: near_primitives_core::hash::CryptoHash, storage_usage: StorageUsage) -> Self {
        Account { amount, locked, code_hash, storage_usage }
    }
}

/// Access key permission level.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, ProtocolSchema)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum AccessKeyPermission {
    FunctionCall(FunctionCallPermission),
    FullAccess,
}

/// Restricts access to specific method names on a specific receiver.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, ProtocolSchema)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct FunctionCallPermission {
    /// Optional allowance in yoctoNEAR (None = unlimited).
    pub allowance: Option<Balance>,
    pub receiver_id: near_account_id::AccountId,
    pub method_names: Vec<String>,
}

/// Per-key nonce and permission stored under `account_id:public_key`.
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug, Clone, ProtocolSchema)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct AccessKey {
    pub nonce: Nonce,
    pub permission: AccessKeyPermission,
}

impl AccessKey {
    pub fn full_access() -> Self {
        AccessKey { nonce: 0, permission: AccessKeyPermission::FullAccess }
    }
}

/// Returns true if the given public key is acceptable as a staking key.
///
/// PQC-NEAR change: replaces the Ed25519 ristretto curve check with a PQC
/// algorithm type check.
///
///   • ML-DSA → accepted (validator default key type)
///   • FN-DSA → accepted (also suitable for staking)
///   • SLH-DSA → REJECTED (7856-byte signatures are too large for chunk header
///     inclusion across all shards at scale; use ML-DSA for validators)
pub fn is_valid_staking_key(public_key: &PublicKey) -> bool {
    match public_key.key_type() {
        KeyType::MlDsa  => true,
        KeyType::FnDsa  => true,
        KeyType::SlhDsa => false, // signatures too large for validator/chunk headers
    }
}

impl fmt::Display for AccessKeyPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessKeyPermission::FunctionCall(fp) => write!(f, "FunctionCall({})", fp.receiver_id),
            AccessKeyPermission::FullAccess       => write!(f, "FullAccess"),
        }
    }
}
