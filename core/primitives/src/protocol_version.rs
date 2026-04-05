/// PQC-NEAR: core/primitives/src/protocol_version.rs
///
/// Hard-fork protocol version enforcement for the PQC migration.
/// This file defines every version gate and the exact behavior at each boundary.
///
/// INTEGRATION: These functions are called from:
///   - chain/chain/src/chain.rs (block validation)
///   - chain/chain/src/types.rs (block production)
///   - runtime/runtime/src/lib.rs (transaction validation)
///   - network/src/peer/peer_actor.rs (connection gating)

/// The protocol version at which PQC becomes mandatory.
/// Nodes advertising a lower version are rejected by PQC nodes.
pub const PQC_PROTOCOL_VERSION: u32 = 999;

/// The last protocol version that accepts Ed25519/Secp256k1 signatures.
/// Transactions signed with classical keys are invalid at version >= this.
pub const LAST_CLASSICAL_PROTOCOL_VERSION: u32 = 998;

/// Protocol version where the RANDAO randomness beacon activates.
/// The old VRF path must not be called at or above this version.
pub const RANDAO_ACTIVATION_VERSION: u32 = PQC_PROTOCOL_VERSION;

/// Protocol version where ed25519_verify WASM host function is banned.
/// Contracts calling it at or above this version get a trap, not a result.
pub const ED25519_VERIFY_BANNED_VERSION: u32 = PQC_PROTOCOL_VERSION;

// ── Version gate functions ────────────────────────────────────────────────────

/// Is PQC mode active? True for protocol version >= 999.
#[inline]
pub fn pqc_enabled(protocol_version: u32) -> bool {
    protocol_version >= PQC_PROTOCOL_VERSION
}

/// Must classical signatures be rejected?
/// True when PQC is active — classical sigs are invalid on PQC chain.
#[inline]
pub fn classical_signatures_banned(protocol_version: u32) -> bool {
    pqc_enabled(protocol_version)
}

/// Is the RANDAO beacon active (replaces VRF)?
#[inline]
pub fn randao_active(protocol_version: u32) -> bool {
    protocol_version >= RANDAO_ACTIVATION_VERSION
}

/// Is ed25519_verify WASM host function banned?
#[inline]
pub fn ed25519_verify_banned(protocol_version: u32) -> bool {
    protocol_version >= ED25519_VERIFY_BANNED_VERSION
}

// ── Key type validation ───────────────────────────────────────────────────────

use near_crypto::KeyType;

/// Validate that a key type is allowed at the given protocol version.
///
/// - Before PQC activation: Ed25519 and Secp256k1 are valid
/// - After PQC activation: only MlDsa, FnDsa, SlhDsa are valid
///
/// Returns Ok(()) if valid, Err with explanation if not.
pub fn validate_key_type_for_version(
    key_type: KeyType,
    protocol_version: u32,
) -> Result<(), KeyTypeError> {
    match key_type {
        // PQC key types — always valid on PQC chain
        KeyType::MLDSA | KeyType::FNDSA | KeyType::SLHDSA => Ok(()),

        // Classical key types — only valid before PQC activation
        #[allow(unreachable_patterns)]
        _ if pqc_enabled(protocol_version) => {
            Err(KeyTypeError::ClassicalKeyOnPqcChain {
                key_type: format!("{:?}", key_type),
                protocol_version,
            })
        }
        _ => Ok(()), // Classical key on classical chain — allowed
    }
}

/// Validate that a staking key type is valid.
/// SLH-DSA is banned for staking (too slow for validator operations).
pub fn validate_staking_key_type(key_type: KeyType) -> Result<(), KeyTypeError> {
    match key_type {
        KeyType::MLDSA  => Ok(()), // Validator signing key (preferred)
        KeyType::FNDSA  => Ok(()), // Allowed but not recommended for validators
        KeyType::SLHDSA => Err(KeyTypeError::SlhDsaNotAllowedForStaking),
        #[allow(unreachable_patterns)]
        _ => Err(KeyTypeError::ClassicalKeyOnPqcChain {
            key_type: format!("{:?}", key_type),
            protocol_version: PQC_PROTOCOL_VERSION,
        }),
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum KeyTypeError {
    #[error("Classical key type '{key_type}' is not valid at protocol version {protocol_version} (PQC chain requires ML-DSA, FN-DSA, or SLH-DSA)")]
    ClassicalKeyOnPqcChain {
        key_type: String,
        protocol_version: u32,
    },
    #[error("SLH-DSA keys cannot be used for validator staking (signatures are too slow for block production)")]
    SlhDsaNotAllowedForStaking,
}

// ── Transaction size limits ───────────────────────────────────────────────────

/// Maximum transaction size on the PQC chain (bytes).
///
/// Set to 2 MB. A single ML-DSA transaction with multiple access key operations
/// is at most ~6 KB of keys + ~3.3 KB signature. Even with contract data, 2 MB
/// provides ample headroom while limiting mempool and network abuse.
/// Raise only after benchmark evidence shows 2 MB is insufficient.
pub const PQC_MAX_TRANSACTION_SIZE_BYTES: u64 = 2 * 1024 * 1024; // 2 MB

/// Maximum single message size over the P2P network (bytes).
///
/// Set to 1 MB. Block approvals for 100 validators add ~330 KB of PQC signatures.
/// 1 MB provides headroom for approvals + header overhead while preventing
/// oversized message attacks.
pub const PQC_MAX_NETWORK_MESSAGE_BYTES: u32 = 1 * 1024 * 1024; // 1 MB

/// Maximum block size (bytes).
///
/// Set to 16 MB. Current NEAR mainnet cap is 4 MB; PQC block approvals add
/// ~330 KB per block. 16 MB gives 4x headroom over expected worst case while
/// preventing bandwidth collapse, mempool imbalance, and validator hardware
/// centralization. Raise only after benchmark evidence under real multi-validator
/// conditions shows 16 MB is insufficient.
pub const PQC_MAX_BLOCK_SIZE_BYTES: u64 = 16 * 1024 * 1024; // 16 MB

/// Validate transaction size for the given protocol version.
pub fn validate_transaction_size(
    size_bytes: u64,
    protocol_version: u32,
) -> Result<(), SizeError> {
    let max = if pqc_enabled(protocol_version) {
        PQC_MAX_TRANSACTION_SIZE_BYTES
    } else {
        4 * 1024 * 1024 // 4 MB classical limit
    };
    if size_bytes > max {
        Err(SizeError::TransactionTooLarge { size_bytes, max_bytes: max })
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SizeError {
    #[error("Transaction too large: {size_bytes} bytes exceeds limit of {max_bytes} bytes")]
    TransactionTooLarge { size_bytes: u64, max_bytes: u64 },
    #[error("Block too large: {size_bytes} bytes exceeds limit of {max_bytes} bytes")]
    BlockTooLarge { size_bytes: u64, max_bytes: u64 },
}

// ── Mixed-node behavior ───────────────────────────────────────────────────────

/// Can a node with `their_version` connect to a node at `PQC_PROTOCOL_VERSION`?
///
/// Mixing is NOT allowed — a quantum-resistant network that accepts classical
/// nodes provides no meaningful quantum resistance.
pub fn can_connect(our_version: u32, their_version: u32) -> bool {
    // Both must be on the same side of the PQC activation boundary
    let our_pqc  = pqc_enabled(our_version);
    let their_pqc = pqc_enabled(their_version);
    our_pqc == their_pqc
}

/// Reason a connection was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionRejectionReason {
    #[error("Version mismatch: we are at protocol {our_version} (PQC: {our_pqc}), they are at {their_version} (PQC: {their_pqc})")]
    VersionMismatch {
        our_version: u32,
        their_version: u32,
        our_pqc: bool,
        their_pqc: bool,
    },
}

pub fn check_peer_compatibility(
    our_version: u32,
    their_version: u32,
) -> Result<(), ConnectionRejectionReason> {
    if !can_connect(our_version, their_version) {
        Err(ConnectionRejectionReason::VersionMismatch {
            our_version,
            their_version,
            our_pqc: pqc_enabled(our_version),
            their_pqc: pqc_enabled(their_version),
        })
    } else {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_enabled_boundary() {
        assert!(!pqc_enabled(998), "v998 must not be PQC");
        assert!(!pqc_enabled(0),   "v0 must not be PQC");
        assert!(pqc_enabled(999),  "v999 must be PQC");
        assert!(pqc_enabled(1000), "v1000 must be PQC");
    }

    #[test]
    fn test_pqc_key_types_always_valid() {
        for version in [0, 998, 999, 1000] {
            assert!(validate_key_type_for_version(KeyType::MLDSA,  version).is_ok());
            assert!(validate_key_type_for_version(KeyType::FNDSA,  version).is_ok());
            assert!(validate_key_type_for_version(KeyType::SLHDSA, version).is_ok());
        }
    }

    #[test]
    fn test_staking_key_validation() {
        assert!(validate_staking_key_type(KeyType::MLDSA).is_ok());
        assert!(validate_staking_key_type(KeyType::FNDSA).is_ok());
        assert!(matches!(
            validate_staking_key_type(KeyType::SLHDSA),
            Err(KeyTypeError::SlhDsaNotAllowedForStaking)
        ));
    }

    #[test]
    fn test_transaction_size_limits() {
        // Classical chain (v998): 4 MB limit
        assert!(validate_transaction_size(4 * 1024 * 1024, 998).is_ok());
        assert!(validate_transaction_size(4 * 1024 * 1024 + 1, 998).is_err());

        // PQC chain (v999): 2 MB limit
        assert!(validate_transaction_size(2 * 1024 * 1024, 999).is_ok());
        assert!(validate_transaction_size(2 * 1024 * 1024 + 1, 999).is_err());
    }

    #[test]
    fn test_peer_compatibility_mixed_network_rejected() {
        // Classical node cannot connect to PQC node
        assert!(check_peer_compatibility(999, 998).is_err());
        assert!(check_peer_compatibility(998, 999).is_err());
        // Same-version peers can connect
        assert!(check_peer_compatibility(999, 999).is_ok());
        assert!(check_peer_compatibility(998, 998).is_ok());
    }

    #[test]
    fn test_randao_and_ed25519_ban_at_same_version() {
        assert_eq!(RANDAO_ACTIVATION_VERSION, PQC_PROTOCOL_VERSION);
        assert_eq!(ED25519_VERIFY_BANNED_VERSION, PQC_PROTOCOL_VERSION);
        // Both activate together at v999 — no split state possible
        assert!(randao_active(999));
        assert!(ed25519_verify_banned(999));
        assert!(!randao_active(998));
        assert!(!ed25519_verify_banned(998));
    }

    #[test]
    fn test_pqc_max_sizes_within_safe_bounds() {
        // TX limit: 2 MB (covers largest PQC signatures with headroom)
        assert_eq!(PQC_MAX_TRANSACTION_SIZE_BYTES, 2 * 1024 * 1024,
            "PQC tx limit should be 2 MB");
        // Network message limit: 1 MB (covers block approvals for 100 validators)
        assert_eq!(PQC_MAX_NETWORK_MESSAGE_BYTES, 1 * 1024 * 1024,
            "PQC network message limit should be 1 MB");
        // Block size: 16 MB (4x headroom over expected worst case)
        assert_eq!(PQC_MAX_BLOCK_SIZE_BYTES, 16 * 1024 * 1024,
            "PQC block size limit should be 16 MB");
    }
}
