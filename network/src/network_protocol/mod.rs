// ============================================================================
// PQC-NEARCORE FORK: network/src/network_protocol/mod.rs
// ============================================================================
//
// CRYPTO CHANGES: NONE (structural)
//
// All network message types that carry near_crypto::Signature are already
// updated transitively — they hold the enum variants from signature.rs which
// now encode MlDsa/FnDsa/SlhDsa instead of Ed25519/Secp256k1.
//
// BORSH SERIALIZATION SIZE CHANGES:
//   The following message types carry validator signatures and will be larger:
//
//   | Message Type              | Old sig size | New sig size | Delta    |
//   |---------------------------|-------------|-------------|----------|
//   | BlockApproval             | 64 bytes    | 3,293 bytes | +3,229 B |
//   | ChunkEndorsement          | 64 bytes    | 3,293 bytes | +3,229 B |
//   | PartialEncodedChunk       | 64 bytes    | 3,293 bytes | +3,229 B |
//   | SignedTransaction (gossip)| 64 bytes    | ~666 bytes  | +602 B   |
//
//   Max network message size (PeerMessage::max_size()) should be updated
//   from 512 MB to account for blocks with 100+ validator signatures.
//
// RECEIPT ATTESTATION MESSAGE (NEW):
//
//   ```rust
//   #[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
//   pub struct ReceiptAttestation {
//       /// Hash of the transaction being attested.
//       pub tx_hash: CryptoHash,
//       /// Nanosecond timestamp at which THIS validator first received the tx.
//       pub signature: near_crypto::Signature,
//       /// The attesting validator's account ID (for slashing lookup).
//       pub validator_id: AccountId,
//   }
//   ```
//
//   Add `PeerMessage::ReceiptAttestation(ReceiptAttestation)` to the
//   PeerMessage enum and handle it in peer_actor.rs:
//     - Verify MlDsa signature
//     - Store in a local attestation table (tx_hash → Vec<ReceiptAttestation>)
//     - Gossip to other validators
//
// HANDSHAKE PROTOCOL VERSION:
//   Bump PROTOCOL_VERSION in Handshake to a PQC-specific value (e.g., 200)
//   so that pre-fork nodes are immediately rejected. PQC nodes should refuse
//   connections from nodes advertising protocol_version < 200.
//
// ============================================================================

// No source code changes in this file beyond what's inherited from signature.rs.
// See annotations above for new message types and size limit updates.
