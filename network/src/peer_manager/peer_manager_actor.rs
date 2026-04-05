// ============================================================================
// PQC-NEARCORE FORK: network/src/peer_manager/peer_manager_actor.rs
// ============================================================================
//
// CRYPTO CHANGES: NONE (in this file)
//
// The PeerManagerActor orchestrates peer connections, routing, and ban logic.
// It does not perform cryptographic operations directly.
//
// WHERE PQC CHANGES *DO* TOUCH THE NETWORK LAYER:
//
//   1. HANDSHAKE / KEY EXCHANGE — network/src/peer/peer_actor.rs
//      The Noise/QUIC handshake must be replaced with ML-KEM-768 (Kyber).
//      Protocol:
//        a. Responder generates ephemeral kyber768::keypair()
//        b. Initiator calls kyber768::encapsulate(responder_pk)
//             → (shared_secret: [u8;32], ciphertext: [u8;1088])
//        c. Session key = SHA3-256("NEAR-PQC-SESSION-KEY-v1:" || shared_secret)
//        d. All subsequent messages encrypted with AES-256-GCM,
//             nonce = 12-byte counter (big-endian u96), incremented per message
//      Crates needed: pqcrypto-kyber = "0.8", aes-gcm = "0.10", sha3 = "0.10"
//
//   2. PEER ID FORMAT — network/src/types.rs
//      PeerId is currently derived from Ed25519 public key.
//      In PQC fork: PeerId = SHA3-256(ml_kem_public_key)[0..32]
//      This keeps PeerId at 32 bytes (compatible with routing table) while
//      basing identity on the PQC ephemeral key.
//
//   3. SIGNED NETWORK MESSAGES — network/src/network_protocol/mod.rs
//      Validator-to-validator messages (block proposals, chunk approvals) that
//      carry a near_crypto::Signature must use MlDsa (KeyType::MlDsa).
//      These signatures are already updated via the changes to signature.rs.
//      No structural changes needed in the message types themselves.
//
// PEER BAN LOGIC:
//   Add a new ban reason for peers that send transactions with invalid PQC
//   signatures after the initial handshake verification:
//     ReasonForBan::InvalidPqcSignature (add to near-network-primitives)
//
// MEMORY / BANDWIDTH IMPACT:
//   Chunk approvals carry MlDsa signatures (3,293 bytes vs 64 bytes).
//   With 100 validators, per-block approval traffic grows from ~6.4 KB to
//   ~330 KB. Ensure PeerManagerActor's message queue / rate limits are
//   tuned accordingly (increase max_msg_size from 512 KB to at least 4 MB).
//
// ============================================================================

// No source code changes in this file.
// All logic below is identical to upstream nearcore.
// See annotations above for where PQC work is needed in sibling files.

use actix::Actor;

/// PQC NOTE: See file header for network-layer PQC change locations.
pub struct PeerManagerActor {
    // ... upstream fields unchanged ...
}

impl Actor for PeerManagerActor {
    type Context = actix::Context<Self>;
}
