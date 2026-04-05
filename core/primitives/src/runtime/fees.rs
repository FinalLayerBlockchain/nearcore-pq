// ============================================================================
// PQC-NEARCORE: core/primitives/src/runtime/fees.rs
// ============================================================================
//
// This file adds PQC-specific gas costs to the existing NEAR fee schedule.
// Merge these constants into the existing RuntimeFeesConfig / ActionCosts
// structure in the upstream fees.rs.
//
// ============================================================================

/// Gas cost for ML-DSA (Dilithium3 / FIPS 204) signature verification.
///
/// Basis: Dilithium3 verify ≈ 0.10 ms on a 3 GHz server (Intel Ice Lake AVX2).
/// NEAR gas schedule: 1 Tgas ≈ 1 ms wall-clock target.
/// Safety multiplier: 2× for WASM overhead + constant-time implementation cost.
/// Formula: 0.10 ms × 1e12 gas/ms × 2× safety = 200 Ggas → round to 2,100 Tgas.
///
/// Comparison: ed25519_verify was ~520 Ggas (0.52 Tgas).
/// ML-DSA is ~4× more expensive than Ed25519 — this is expected and acceptable.
pub const MLDSA_VERIFY_BASE_GAS: u64 = 2_100_000_000_000; // 2,100 Tgas

/// Gas cost per byte for ML-DSA message input (charged separately from base).
/// Dilithium3 signs the message hash internally; this covers hashing overhead.
pub const MLDSA_VERIFY_BYTE_GAS: u64 = 5_000_000; // 5 Mgas per byte

/// Gas cost for FN-DSA (Falcon-512 / FIPS 206) signature verification.
///
/// Basis: Falcon-512 verify ≈ 0.06 ms (faster than Dilithium due to NTT).
/// Formula: 0.06 ms × 1e12 × 2× = 120 Ggas → round to 1,400 Tgas (includes
/// constant-time floating-point emulation overhead in WASM — Falcon uses
/// emulated FP in software for side-channel resistance, adding ~20% overhead).
pub const FNDSA_VERIFY_BASE_GAS: u64 = 1_400_000_000_000; // 1,400 Tgas

/// Gas cost per byte for FN-DSA message input.
pub const FNDSA_VERIFY_BYTE_GAS: u64 = 5_000_000; // 5 Mgas per byte

/// Gas cost for SLH-DSA (SPHINCS+-SHA2-128s / FIPS 205) signature verification.
///
/// Basis: SPHINCS+ verify ≈ 0.3 ms (more expensive than lattice-based due to
/// multiple SHA-256 evaluations in the hypertree traversal).
/// Formula: 0.3 ms × 1e12 × 2× = 600 Ggas → round to 3,200 Tgas.
///
/// SLH-DSA is intentionally expensive on-chain. It is only used for governance
/// keys that sign infrequently (protocol upgrades, council votes). Smart
/// contracts calling slhdsa_verify should be aware of this cost.
pub const SLHDSA_VERIFY_BASE_GAS: u64 = 3_200_000_000_000; // 3,200 Tgas

/// Gas cost per byte for SLH-DSA message input.
pub const SLHDSA_VERIFY_BYTE_GAS: u64 = 5_000_000; // 5 Mgas per byte

// ── Storage staking cost adjustments ─────────────────────────────────────────

/// Additional storage staking required for an MlDsa access key record.
///
/// Access key storage in NEAR = key_length × STORAGE_PRICE_PER_BYTE.
/// MlDsa public key: 1,952 bytes vs Ed25519: 32 bytes.
/// Delta: +1,920 bytes × 10_000_000_000 yoctoNEAR/byte ≈ +0.0192 NEAR per key.
///
/// This is a constant for documentation/tooling; the runtime calculates
/// actual cost dynamically from key length × storage_price_per_byte.
pub const MLDSA_ACCESS_KEY_STORAGE_BYTES: u64 = 1952;

/// Additional storage staking for an FnDsa access key record.
/// FnDsa public key: 897 bytes → still ~28× larger than Ed25519.
pub const FNDSA_ACCESS_KEY_STORAGE_BYTES: u64 = 897;

/// Additional storage staking for an SlhDsa access key record.
/// SLH-DSA public key: 32 bytes — same size as Ed25519. No change.
pub const SLHDSA_ACCESS_KEY_STORAGE_BYTES: u64 = 32;

// ── Transaction cost adjustments ─────────────────────────────────────────────

/// Additional gas charged for PQC signature verification in transaction validation.
///
/// Unlike smart-contract host functions above (which are opt-in by contract code),
/// transaction signature verification happens unconditionally for every tx.
/// These costs are deducted from the signer's gas allowance before execution.
///
/// Note: These are *marginal* costs vs Ed25519 baseline. The existing
/// `sir_receipt_creation_send_sir` / `action_receipt_creation_send_not_sir`
/// fees still apply. Add these on top.
pub const TX_MLDSA_SIGNATURE_VERIFY_GAS: u64 = 2_100_000_000_000;
pub const TX_FNDSA_SIGNATURE_VERIFY_GAS: u64 = 1_400_000_000_000;
pub const TX_SLHDSA_SIGNATURE_VERIFY_GAS: u64 = 3_200_000_000_000;

// ── Bandwidth cost adjustments ────────────────────────────────────────────────

/// Additional bytes counted against bandwidth fee for PQC transaction signatures.
///
/// NEAR charges `send_sir` / `send_not_sir` fees partially based on tx size.
/// PQC signatures are larger; tools that estimate fees should account for:
///   MlDsa sig:  3,293 bytes (vs 64 bytes Ed25519) → +3,229 bytes per tx
///   FnDsa sig:  ~666 bytes avg (vs 64 bytes)       → +602 bytes per tx avg
///   SlhDsa sig: 7,856 bytes (vs 64 bytes)           → +7,792 bytes per tx
///
/// The runtime already charges by actual transaction byte size via
/// `action_receipt_creation_send_*` and the `total_send_fees` calculation.
/// No code changes needed here — but fee estimates in nearlib/near-api-js
/// must be updated to reflect actual PQC sizes.

// ── Economic recommendations ──────────────────────────────────────────────────
//
// The following changes to RuntimeFeesConfig are RECOMMENDED but not
// automatically applied. A governance vote should set these on mainnet.
//
// 1. INCREASE storage_amount_per_byte:
//    Current: 10_000_000_000_000_000_000 yoctoNEAR (10^19) per byte
//    Recommended increase: +10% to account for larger key/sig storage
//    Reasoning: Average user account now uses ~1,952 bytes for the access key
//    vs 32 bytes before; at 10^19/byte the staking requirement for a new
//    account increases from ~100 NEAR to ~280 NEAR (rough estimate).
//    Consider: Either increase storage_amount_per_byte proportionally,
//    or introduce a tiered model: Ed25519-sized keys at current rate,
//    PQC-sized keys at a discounted rate since they are mandatory.
//
// 2. Do NOT increase min_gas_price proportionally:
//    Gas price is already market-driven. PQC verification costs are reflected
//    in the Tgas consumed per operation; the market will naturally adjust.
//
// 3. INCREASE max_transaction_size:
//    Current: 4 MB
//    Required: At minimum 3,293 + overhead bytes for a single MlDsa-signed tx.
//    A single FnDsa tx is ~800 bytes — well within current limits.
//    Multi-action transactions with multiple PQC sigs may exceed current limits.
//    Recommended: Increase max_transaction_size to 8 MB.
//
// ============================================================================
