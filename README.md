# Final Layer — Quantum-Resistant Node (nearcore-pq)

**Final Layer** is a production-ready blockchain node forked from [NEAR Protocol](https://near.org), with all elliptic curve cryptography replaced by NIST-standardized post-quantum signature schemes.

> This repository contains the full node source. For contracts, documentation, and benchmarks see [final-layer](https://github.com/FinalLayerBlockchain/final-layer).

---

## What is Final Layer?

Final Layer extends NEAR Protocol's sharded proof-of-stake architecture with quantum-resistant cryptography. Ed25519 and secp256k1 — both vulnerable to Shor's algorithm on a sufficiently powerful quantum computer — are removed entirely and replaced with three NIST-standardized schemes:

| Algorithm | Standard | Family | Public Key | Signature | Gas (v1003) |
|---|---|---|---|---|---|
| **FN-DSA** (Falcon-512) | FIPS 206 | Lattice (NTRU) | 897 bytes | 666 bytes | 1.4 TGas |
| **ML-DSA** (Dilithium3) | FIPS 204 | Lattice (Module-LWE) | 1952 bytes | 3309 bytes | 3.0 TGas |
| **SLH-DSA** (SPHINCS+-128) | FIPS 205 | Hash-based | 32 bytes | ~8000 bytes | 8.0 TGas |

---

## Key Changes from NEAR Protocol

### Cryptographic Layer
- New key types: `MLDSA`, `FNDSA`, `SLHDSA` replacing Ed25519 and secp256k1
- Borsh serialization uses 4-byte LE u32 length prefix for variable-length PQC keys
- Key format: `algo:base58(bytes)` — e.g. `fndsa:34emUD6...`

### VM Host Functions
Three new host functions exposed to WASM smart contracts in `runtime/near-vm-runner/src/logic/pqc_host_fns.rs`:

```
pqc_verify_fndsa  (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
pqc_verify_mldsa  (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
pqc_verify_slhdsa (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
```

Gas constants calibrated from 1000-iteration benchmarks on min-spec validator hardware (2-core, 4GB) at p99:

```rust
const FNDSA_VERIFY_BASE_GAS:  u64 = 1_400_000_000_000; // p99 = 0.24ms
const MLDSA_VERIFY_BASE_GAS:  u64 = 3_000_000_000_000; // p99 = 1.70ms  (v1003: raised from 2.1T)
const SLHDSA_VERIFY_BASE_GAS: u64 = 8_000_000_000_000; // p99 = 5.10ms  (v1003: raised from 3.2T)
```

### Protocol Versions

| Version | Change |
|---|---|
| v1001 | Genesis — PQC cryptography introduced, 9-shard config |
| v1002 | Multi-shard epoch config |
| v1003 | Gas rebalance hard fork (current) |

---

## Network

| Property | Value |
|---|---|
| Chain ID | `final-layer-mainnet` |
| Protocol version | 1003 |
| Shards | 9 |
| Block time | ~1 second |
| Native token | FLC |
| Consensus | Doomslug (inherited from NEAR Protocol) |

---

## Building

```bash
# Prerequisites: Rust toolchain, cmake, clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the node binary
cargo build --release -p neard
```

Minimum hardware: 4 vCPU, 8GB RAM, 200GB SSD.

---

## Running a Validator

```bash
# Initialize node
neard --home ~/.fl-node init --chain-id final-layer-mainnet --account-id <your-validator.fl>

# Start
neard --home ~/.fl-node run
```

See [`scripts/deploy-validator.sh`](scripts/deploy-validator.sh) and the [docs](https://github.com/FinalLayerBlockchain/final-layer/tree/main/docs) for the full setup guide.

---

## Final Layer-Specific Files

```
runtime/near-vm-runner/src/logic/pqc_host_fns.rs   # PQC host functions + gas constants
core/crypto/                                         # PQC key types
core/primitives-core/src/version.rs                  # Protocol version (1003)
contracts/staking-pool/                              # PQC-aware staking pool v5
```

---

## Related Repositories

| Repo | Description |
|---|---|
| [final-layer](https://github.com/FinalLayerBlockchain/final-layer) | Staking contract, docs, benchmarks, upgrade guides |
| [nearcore](https://github.com/FinalLayerBlockchain/nearcore) | Unmodified NEAR Protocol reference fork |

---

*Final Layer is built on [NEAR Protocol](https://github.com/near/nearcore) — a sharded, proof-of-stake Layer 1 blockchain. Final Layer modifications copyright 2026 Final Layer Blockchain. Licensed under Apache 2.0.*
