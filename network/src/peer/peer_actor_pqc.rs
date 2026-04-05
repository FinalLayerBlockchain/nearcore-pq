/// PQC-NEAR: network/src/peer/peer_actor_pqc.rs
///
/// PQC peer connection lifecycle: handshake state machine, session management,
/// ban reasons, and message framing. Implements the ML-KEM-768 + MlDsa
/// authenticated key exchange replacing the classical Noise/X25519 handshake.

use super::handshake::{
    PqcPeerId, ClientHello, ServerHello, ClientFinish, PqcSession,
    PQC_HANDSHAKE_VERSION, HandshakeError,
    initiator_build_hello, initiator_process_server_hello,
    responder_process_hello, responder_finish,
};
use near_crypto::{InMemorySigner, KeyType, PublicKey, SecretKey};
use std::sync::Arc;

// ── Connection state machine ───────────────────────────────────────────────────

/// State of a peer connection during the PQC handshake lifecycle.
#[derive(Debug)]
pub enum PeerConnectionState {
    /// Initial state — no messages exchanged yet.
    Connecting,
    /// Initiator: sent ClientHello, waiting for ServerHello.
    AwaitingServerHello {
        our_peer_id: PqcPeerId,
        init_timestamp_nanos: u64,
    },
    /// Responder: received ClientHello, sent ServerHello, waiting for ClientFinish.
    AwaitingClientFinish {
        our_peer_id: PqcPeerId,
        initiator_peer_id: PqcPeerId,
        kem_dk: pqcrypto_kyber::kyber768::SecretKey,
        kem_ek: [u8; 1184],
        timestamp_nanos: u64,
    },
    /// Handshake complete — session is established and encrypted.
    Established { session: Arc<PqcSession> },
    /// Handshake failed — connection should be closed.
    Failed { reason: String },
}

/// Complete peer connection with PQC session.
pub struct PqcPeerConnection {
    pub remote_peer_id: PqcPeerId,
    pub remote_public_key: PublicKey,
    pub session: Arc<PqcSession>,
}

// ── Initiator side (outbound connections) ─────────────────────────────────────

/// Initiate a PQC handshake to a remote peer.
///
/// Called when we open an outbound TCP connection.
/// Returns the ClientHello to send and the state to hold until ServerHello arrives.
pub fn start_outbound_handshake(
    our_identity: &InMemorySigner,
) -> (ClientHello, PeerConnectionState) {
    let our_peer_id = PqcPeerId::from_public_key(&our_identity.public_key());
    let (hello, state) = initiator_build_hello(our_peer_id);

    let hold_state = PeerConnectionState::AwaitingServerHello {
        our_peer_id,
        init_timestamp_nanos: hello.timestamp_nanos,
    };

    (hello, hold_state)
}

/// Process a ServerHello received from the remote peer (initiator side).
///
/// Validates the responder's PQC signature, performs ML-KEM encapsulation,
/// derives the session key, and returns the ClientFinish to send plus
/// the established session.
///
/// Returns Err if the ServerHello is invalid (wrong version, bad signature, etc.)
/// The caller must close the connection on Err.
pub fn handle_server_hello(
    server_hello: &ServerHello,
    state: &PeerConnectionState,
    our_identity: &InMemorySigner,
    responder_known_public_key: &PublicKey,
) -> Result<(ClientFinish, PqcPeerConnection), HandshakeError> {
    let (our_peer_id, init_timestamp) = match state {
        PeerConnectionState::AwaitingServerHello { our_peer_id, init_timestamp_nanos } => {
            (*our_peer_id, *init_timestamp_nanos)
        }
        _ => return Err(HandshakeError::InvalidState(
            "handle_server_hello called in wrong state".into()
        )),
    };

    use super::handshake::InitiatorHandshakeState;
    let init_state = InitiatorHandshakeState {
        our_peer_id,
        timestamp_nanos: init_timestamp,
    };

    let (finish, session) = initiator_process_server_hello(
        server_hello,
        &init_state,
        responder_known_public_key,
        &our_identity.secret_key,
    )?;

    let connection = PqcPeerConnection {
        remote_peer_id: server_hello.peer_id,
        remote_public_key: responder_known_public_key.clone(),
        session: Arc::new(session),
    };

    Ok((finish, connection))
}

// ── Responder side (inbound connections) ──────────────────────────────────────

/// Process a ClientHello from an inbound connection (responder side).
///
/// Validates protocol version, generates an ephemeral ML-KEM keypair,
/// signs the ServerHello with our identity key, and returns the ServerHello
/// to send plus state to hold until ClientFinish arrives.
///
/// Returns Err if the ClientHello has an incompatible version.
/// The caller must close the connection on Err.
pub fn handle_client_hello(
    hello: &ClientHello,
    our_identity: &InMemorySigner,
) -> Result<(ServerHello, PeerConnectionState), HandshakeError> {
    let our_peer_id = PqcPeerId::from_public_key(&our_identity.public_key());

    let (server_hello, resp_state) = responder_process_hello(
        hello,
        our_peer_id,
        &our_identity.secret_key,
    )?;

    let hold_state = PeerConnectionState::AwaitingClientFinish {
        our_peer_id,
        initiator_peer_id: hello.peer_id,
        kem_dk: resp_state.kem_decapsulation_key,
        kem_ek: resp_state.kem_encapsulation_key,
        timestamp_nanos: resp_state.timestamp_nanos,
    };

    Ok((server_hello, hold_state))
}

/// Process a ClientFinish from the initiator (responder side).
///
/// Verifies the initiator's PQC signature over the ciphertext, performs
/// ML-KEM decapsulation, derives the session key, and returns the
/// established connection.
///
/// Returns Err if signature verification or decapsulation fails.
/// The caller must close the connection and optionally ban the peer on Err.
pub fn handle_client_finish(
    finish: &ClientFinish,
    state: PeerConnectionState,
    initiator_known_public_key: &PublicKey,
) -> Result<PqcPeerConnection, HandshakeError> {
    let (our_peer_id, initiator_peer_id, kem_dk, kem_ek, timestamp_nanos) = match state {
        PeerConnectionState::AwaitingClientFinish {
            our_peer_id, initiator_peer_id, kem_dk, kem_ek, timestamp_nanos
        } => (our_peer_id, initiator_peer_id, kem_dk, kem_ek, timestamp_nanos),
        _ => return Err(HandshakeError::InvalidState(
            "handle_client_finish called in wrong state".into()
        )),
    };

    use super::handshake::ResponderHandshakeState;
    let resp_state = ResponderHandshakeState {
        our_peer_id,
        initiator_peer_id,
        kem_decapsulation_key: kem_dk,
        kem_encapsulation_key: kem_ek,
        timestamp_nanos,
    };

    let session = responder_finish(finish, resp_state, initiator_known_public_key)?;

    Ok(PqcPeerConnection {
        remote_peer_id: initiator_peer_id,
        remote_public_key: initiator_known_public_key.clone(),
        session: Arc::new(session),
    })
}

// ── Message framing over established session ───────────────────────────────────

/// Encrypt a NEAR network message for transmission.
/// The caller provides the raw Borsh-serialized message and a 1-byte type tag.
pub fn encrypt_message(
    conn: &PqcPeerConnection,
    message_bytes: &[u8],
    message_type: u8,
) -> Result<Vec<u8>, HandshakeError> {
    conn.session.encrypt(message_bytes, message_type)
}

/// Decrypt an encrypted NEAR network message.
/// Returns the raw Borsh-serialized message bytes.
pub fn decrypt_message(
    conn: &PqcPeerConnection,
    encrypted_bytes: &[u8],
    message_type: u8,
) -> Result<Vec<u8>, HandshakeError> {
    conn.session.decrypt(encrypted_bytes, message_type)
}

// ── Peer ban logic ────────────────────────────────────────────────────────────

/// Reasons to ban a peer related to PQC handshake failure.
/// Add these variants to the existing ReasonForBan enum in near-network-primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcBanReason {
    /// Peer advertised a protocol version older than PQC_HANDSHAKE_VERSION.
    IncompatibleProtocolVersion { received: u32 },
    /// Peer's ServerHello or ClientFinish had an invalid PQC signature.
    InvalidHandshakeSignature,
    /// ML-KEM ciphertext in ClientFinish was invalid (decapsulation failed).
    InvalidKemCiphertext,
    /// Peer sent a message that failed AES-GCM authentication.
    InvalidMessageAuthentication,
    /// Peer attempted to use a classical (Ed25519/ECDH) handshake.
    ClassicalHandshakeAttempt,
}

impl std::fmt::Display for PqcBanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompatibleProtocolVersion { received } =>
                write!(f, "Incompatible protocol version: {}", received),
            Self::InvalidHandshakeSignature => write!(f, "Invalid PQC handshake signature"),
            Self::InvalidKemCiphertext      => write!(f, "Invalid ML-KEM ciphertext"),
            Self::InvalidMessageAuthentication => write!(f, "AES-GCM authentication failed"),
            Self::ClassicalHandshakeAttempt => write!(f, "Classical handshake attempt on PQC chain"),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer(name: &str) -> InMemorySigner {
        InMemorySigner::from_random(name.parse().unwrap(), KeyType::MlDsa)
    }

    #[test]
    fn test_full_peer_lifecycle_initiator_to_responder() {
        let initiator = make_signer("initiator.near");
        let responder = make_signer("responder.near");

        // ── Outbound (initiator) ──
        let (hello, init_state) = start_outbound_handshake(&initiator);
        assert_eq!(hello.protocol_version, PQC_HANDSHAKE_VERSION);

        // ── Inbound (responder) processes ClientHello ──
        let (server_hello, resp_state) =
            handle_client_hello(&hello, &responder).expect("handle_client_hello failed");

        // ── Initiator processes ServerHello ──
        let (finish, init_conn) = handle_server_hello(
            &server_hello,
            &init_state,
            &initiator,
            &responder.public_key(),
        ).expect("handle_server_hello failed");

        // ── Responder processes ClientFinish ──
        let resp_conn = handle_client_finish(
            &finish,
            resp_state,
            &initiator.public_key(),
        ).expect("handle_client_finish failed");

        // ── Both sessions work bidirectionally ──
        let msg = b"Hello from NEAR node to NEAR node!";
        let encrypted = encrypt_message(&init_conn, msg, 0x10).unwrap();
        let decrypted = decrypt_message(&resp_conn, &encrypted, 0x10).unwrap();
        assert_eq!(&decrypted, msg);

        let reply = b"Reply from responder";
        let enc_reply = encrypt_message(&resp_conn, reply, 0x11).unwrap();
        let dec_reply = decrypt_message(&init_conn, &enc_reply, 0x11).unwrap();
        assert_eq!(&dec_reply, reply);
    }

    #[test]
    fn test_wrong_protocol_version_is_banned() {
        let initiator = make_signer("init.near");
        let responder = make_signer("resp.near");

        let bad_hello = ClientHello {
            protocol_version: 1,  // classical NEAR version
            peer_id: PqcPeerId::from_public_key(&initiator.public_key()),
            timestamp_nanos: 0,
        };

        let result = handle_client_hello(&bad_hello, &responder);
        assert!(matches!(result, Err(HandshakeError::VersionMismatch { .. })));
    }

    #[test]
    fn test_wrong_key_for_server_hello_rejected() {
        let initiator = make_signer("init.near");
        let responder = make_signer("resp.near");
        let attacker = make_signer("attacker.near");

        let (hello, init_state) = start_outbound_handshake(&initiator);
        let (server_hello, _) = handle_client_hello(&hello, &responder).unwrap();

        // Initiator verifies with attacker's key — must fail
        let result = handle_server_hello(&server_hello, &init_state, &initiator, &attacker.public_key());
        assert!(matches!(result, Err(HandshakeError::InvalidSignature)));
    }

    #[test]
    fn test_wrong_state_for_client_finish_rejected() {
        let initiator = make_signer("init.near");
        let wrong_state = PeerConnectionState::Connecting;

        let finish = ClientFinish {
            ciphertext: [0u8; 1088],
            signature: near_crypto::Signature::empty(KeyType::MlDsa),
        };

        let result = handle_client_finish(&finish, wrong_state, &initiator.public_key());
        assert!(matches!(result, Err(HandshakeError::InvalidState(_))),
            "Wrong state must produce InvalidState, not VersionMismatch");
    }

    #[test]
    fn test_peer_ids_are_consistent() {
        let signer = make_signer("node.near");
        let id1 = PqcPeerId::from_public_key(&signer.public_key());
        let id2 = PqcPeerId::from_public_key(&signer.public_key());
        assert_eq!(id1, id2, "PeerId must be deterministic");
    }

    #[test]
    fn test_encrypted_message_wrong_type_fails() {
        let initiator = make_signer("i.near");
        let responder = make_signer("r.near");

        let (hello, init_state) = start_outbound_handshake(&initiator);
        let (server_hello, resp_state) = handle_client_hello(&hello, &responder).unwrap();
        let (finish, init_conn) = handle_server_hello(&server_hello, &init_state, &initiator, &responder.public_key()).unwrap();
        let resp_conn = handle_client_finish(&finish, resp_state, &initiator.public_key()).unwrap();

        let msg = b"type mismatch test";
        let encrypted = encrypt_message(&init_conn, msg, 0xAA).unwrap();
        // Try to decrypt with wrong type tag
        let result = decrypt_message(&resp_conn, &encrypted, 0xBB);
        assert!(result.is_err(), "Wrong message type should fail AES-GCM auth");
    }
}
