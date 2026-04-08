# Final Layer: Quantum-Resistant Blockchain

Final Layer is a blockchain forked from [NEAR Protocol](https://near.org) with all elliptic curve cryptography replaced by NIST post-quantum standards. Ed25519 and secp256k1 are gone entirely, no fallback.

For the staking contract, docs, and benchmarks check out [final-layer-staking](https://github.com/FinalLayerBlockchain/final-layer-staking).

## What changed from NEAR Protocol

**Cryptographic layer.** Three new key types replace the old ones: `FNDSA` (Falcon-512, FIPS 206), `MLDSA` (Dilithium3, FIPS 204), and `SLHDSA` (SPHINCS+-128, FIPS 205). Keys are encoded as `algo:base58(bytes)` and stored with a Borsh 4-byte length prefix for correct WASM VM deserialization.

**VM host functions.** Three new functions are exposed to WASM contracts for on-chain signature verification:

```
pqc_verify_fndsa  (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
pqc_verify_mldsa  (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
pqc_verify_slhdsa (pk, pk_len, sig, sig_len, msg, msg_len) -> u64
```

**Gas constants** are set from 1000-iteration benchmarks on a 2-core/4GB validator at p99. The gas constants were finalized in protocol v1003 (ML-DSA raised from 2.1→3.0 TGas, SLH-DSA raised from 3.2→8.0 TGas after production benchmarks) and carry forward unchanged into v1004 and v1005.

```rust
const FNDSA_VERIFY_BASE_GAS:  u64 = 1_400_000_000_000;
const MLDSA_VERIFY_BASE_GAS:  u64 = 3_000_000_000_000;
const SLHDSA_VERIFY_BASE_GAS: u64 = 8_000_000_000_000;
```

## Algorithm overview

| Algorithm | Standard | Key size | Sig size | Gas |
|---|---|---|---|---|
| FN-DSA (Falcon-512) | FIPS 206 | 897 bytes | 666 bytes | 1.4 TGas |
| ML-DSA (Dilithium3) | FIPS 204 | 1952 bytes | 3309 bytes | 3.0 TGas |
| SLH-DSA (SPHINCS+-128) | FIPS 205 | 32 bytes | ~8000 bytes | 8.0 TGas |

## Network

Chain ID `final-layer-mainnet`, protocol version 1005, 9 shards, ~1 second blocks, native token FLC.

Protocol history: v1001 introduced PQC at genesis, v1002 deployed the 9-shard config, v1003 was the gas rebalance hard fork, v1004 added ShardLayoutV2 (DynamicResharding), GlobalContracts, and mandatory FN-DSA signing. v1005 deployed the staking pool smart contract (v10) with proportional reward attribution and added the browser-based FLC wallet UI.

## Building

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build --release -p neard
```

Minimum specs: 4 vCPU, 8GB RAM, 200GB SSD.

## Running a validator

```bash
neard --home ~/.fl-node init --chain-id final-layer-mainnet --account-id <your-validator.fl>
neard --home ~/.fl-node run
```

See [scripts/deploy-validator.sh](scripts/deploy-validator.sh) and the [docs](https://github.com/FinalLayerBlockchain/final-layer-staking/tree/main/docs) for the full setup.

## Where the changes live

```
runtime/near-vm-runner/src/logic/pqc_host_fns.rs   PQC host functions and gas constants
core/crypto/                                         PQC key types
core/primitives-core/src/version.rs                  Protocol version
```

Built on [NEAR Protocol](https://github.com/near/nearcore). Licensed Apache 2.0.
