/// PQC-NEAR: network/src/peer/handshake.rs
///
/// Replaces the classical Noise/X25519 ECDH handshake with a
/// post-quantum ML-KEM-768 (Kyber, FIPS 203) key encapsulation handshake,
/// followed by AES-256-GCM session encryption.
///
/// ════════════════════════════════════════════════════════════════════
/// PROTOCOL: PQC-NEAR Handshake v1
/// ════════════════════════════════════════════════════════════════════
///
/// 1. INITIATOR → RESPONDER: ClientHello
///    { protocol_version: u32, peer_id: PqcPeerId, timestamp_nanos: u64 }
///
/// 2. RESPONDER generates ephemeral ML-KEM-768 keypair (ek, dk).
///    Sends ServerHello:
///    { protocol_version: u32, peer_id: PqcPeerId,
///      kem_encapsulation_key: [u8; 1184], timestamp_nanos: u64,
///      signature: MlDsaSignature }   ← signs (peer_id ‖ ek ‖ timestamp)
///
/// 3. INITIATOR calls ML-KEM-768 encapsulate(ek):
///      → shared_secret: [u8; 32],  ciphertext: [u8; 1088]
///    Derives session key:
///      session_key = SHAKE256("NEAR-PQC-SESSION-v1\x00" ‖ shared_secret ‖
///                              initiator_peer_id ‖ responder_peer_id)[..32]
///    Sends ClientFinish:
///    { ciphertext: [u8; 1088], signature: MlDsaSignature }
///      ← signs (responder_peer_id ‖ ciphertext ‖ timestamp)
///
/// 4. RESPONDER calls ML-KEM-768 decapsulate(dk, ciphertext):
///      → shared_secret: [u8; 32]
///    Derives same session_key using same KDF.
///
/// 5. Both sides now share session_key.
///    All subsequent messages encrypted with AES-256-GCM:
///      nonce = 12-byte big-endian message counter (u96)
///      aad   = message_type_byte
///
/// PEER IDENTITY:
///   PqcPeerId = SHA3-256(ml_dsa_public_key)[0..32]
///   This keeps PeerId at 32 bytes (compatible with routing table) while
///   basing identity on the validator's MlDsa public key.
///
/// FORWARD SECRECY:
///   The ML-KEM keypair is generated fresh per connection (ephemeral).
///   Compromise of the long-term MlDsa identity key does not expose
///   past session traffic.
///
/// AUTHENTICATION:
///   Both parties sign their contributions with their long-term MlDsa
///   identity keys (stored in node_key.json as FnDsa or MlDsa).
///   A MITM attacker cannot forge either signature.
/// ════════════════════════════════════════════════════════════════════

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use borsh::{BorshDeserialize, BorshSerialize};
use near_crypto::{PublicKey, Signature};
use pqcrypto_kyber::kyber768::{
    self, Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as KemPk, SecretKey as KemSk, SharedSecret};
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};
use std::sync::atomic::{AtomicU64, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Protocol version for the PQC handshake. Nodes advertising lower versions
/// are immediately rejected — no fallback to classical is permitted.
pub const PQC_HANDSHAKE_VERSION: u32 = 1000;

/// ML-KEM-768 encapsulation key size (bytes).
pub const KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size (bytes).
pub const KEM_CT_LEN: usize = 1088;
/// ML-KEM-768 shared secret size (bytes).
pub const KEM_SS_LEN: usize = 32;
/// AES-256-GCM key size (bytes).
pub const SESSION_KEY_LEN: usize = 32;
/// AES-256-GCM nonce size (bytes).
pub const GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag size (bytes).
pub const GCM_TAG_LEN: usize = 16;

/// Domain separator for session key derivation.
const SESSION_KDF_DOMAIN: &[u8] = b"NEAR-PQC-SESSION-v1\x00";

// ── PeerId (PQC) ──────────────────────────────────────────────────────────────

/// Post-quantum peer identity: SHA3-256 of the node's MlDsa public key.
/// 32 bytes — compatible with NEAR's existing routing table and peer store.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub struct PqcPeerId(pub [u8; 32]);

impl PqcPeerId {
    /// Derive a PeerId from a public key.
    ///
    /// Includes a domain separator and key-type tag to prevent collisions
    /// between different algorithms that might share raw byte prefixes.
    ///
    /// PeerId = SHA3-256("NEAR-PQC-PEERID-v1\0" || key_type_byte || key_bytes)
    pub fn from_public_key(pk: &PublicKey) -> Self {
        use sha3::{Digest, Sha3_256};
        let key_type_byte = match pk.key_type() {
            near_crypto::KeyType::MlDsa  => 0u8,
            near_crypto::KeyType::FnDsa  => 1u8,
            near_crypto::KeyType::SlhDsa => 2u8,
        };
        let mut hasher = Sha3_256::new();
        hasher.update(b"NEAR-PQC-PEERID-v1\0"); // domain separator
        hasher.update(&[key_type_byte]);           // key type tag
        hasher.update(pk.key_data());              // raw key bytes
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        PqcPeerId(id)
    }
}

impl std::fmt::Display for PqcPeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

// ── Handshake messages ────────────────────────────────────────────────────────

/// Step 1: Initiator → Responder
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ClientHello {
    pub protocol_version: u32,
    pub peer_id: PqcPeerId,
    /// Nanoseconds since Unix epoch — used for replay protection.
    pub timestamp_nanos: u64,
}

/// Step 2: Responder → Initiator
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ServerHello {
    pub protocol_version: u32,
    pub peer_id: PqcPeerId,
    /// Ephemeral ML-KEM-768 encapsulation key.
    pub kem_encapsulation_key: [u8; KEM_EK_LEN],
    pub timestamp_nanos: u64,
    /// MlDsa signature over:
    ///   borsh(peer_id) ‖ kem_encapsulation_key ‖ timestamp_nanos.to_le_bytes()
    pub signature: Signature,
}

/// Step 3: Initiator → Responder
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ClientFinish {
    /// ML-KEM-768 ciphertext (encapsulated shared secret).
    pub ciphertext: [u8; KEM_CT_LEN],
    /// MlDsa signature over:
    ///   borsh(responder_peer_id) ‖ ciphertext ‖ timestamp_nanos.to_le_bytes()
    pub signature: Signature,
}

// ── Session cipher ────────────────────────────────────────────────────────────

/// An established encrypted session over a TCP connection.
///
/// Thread-safety: `send_counter` and `recv_counter` use atomic u64.
/// The cipher itself (`Aes256Gcm`) is `!Sync` so wrap in a Mutex at the
/// actor level before sharing across threads.
pub struct PqcSession {
    cipher: Aes256Gcm,
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
}

impl PqcSession {
    fn new(session_key: &[u8; SESSION_KEY_LEN]) -> Self {
        let cipher = Aes256Gcm::new(session_key.into());
        Self {
            cipher,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
        }
    }

    /// Encrypt `plaintext` with the next send nonce.
    /// Returns: nonce(12) ‖ ciphertext+tag
    ///
    /// Returns Err(NonceExhausted) if the session has reached MAX_MESSAGES_PER_SESSION.
    /// Callers must terminate the connection on NonceExhausted.
    pub fn encrypt(&self, plaintext: &[u8], msg_type: u8) -> Result<Vec<u8>, HandshakeError> {
        let counter = self.send_counter.fetch_add(1, Ordering::SeqCst);
        if counter >= MAX_MESSAGES_PER_SESSION {
            return Err(HandshakeError::NonceExhausted);
        }
        let nonce = Self::make_nonce(counter);
        let payload = Payload { msg: plaintext, aad: &[msg_type] };
        let ciphertext = self.cipher
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| HandshakeError::EncryptionFailed)?;
        let mut out = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a message produced by `encrypt()`.
    /// Input must be: nonce(12) ‖ ciphertext+tag
    pub fn decrypt(&self, data: &[u8], msg_type: u8) -> Result<Vec<u8>, HandshakeError> {
        if data.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
            return Err(HandshakeError::TruncatedMessage);
        }
        let counter = self.recv_counter.fetch_add(1, Ordering::SeqCst);
        let expected_nonce = Self::make_nonce(counter);
        let nonce = &data[..GCM_NONCE_LEN];
        // Verify nonce matches expected counter (prevents replay)
        if nonce != expected_nonce {
            return Err(HandshakeError::NonceMismatch { expected: counter });
        }
        let payload = Payload { msg: &data[GCM_NONCE_LEN..], aad: &[msg_type] };
        self.cipher
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| HandshakeError::DecryptionFailed)
    }

    fn make_nonce(counter: u64) -> [u8; GCM_NONCE_LEN] {
        // 4 zero bytes ‖ 8-byte big-endian counter = 12-byte nonce
        let mut nonce = [0u8; GCM_NONCE_LEN];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }
}

// ── Handshake errors ──────────────────────────────────────────────────────────

/// Maximum AES-GCM messages before mandatory session termination.
/// At 2^64 - 1 the nonce counter wraps; terminate before that.
/// Set conservatively at 2^48 (~281 trillion messages — ~3.5 years at 2.5M msg/sec).
pub const MAX_MESSAGES_PER_SESSION: u64 = (1u64 << 48) - 1;

/// Maximum clock skew for handshake timestamp freshness (nanoseconds).
pub const MAX_HANDSHAKE_TIMESTAMP_SKEW_NS: u64 = 30_000_000_000; // 30 seconds

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Protocol version mismatch: expected {expected}, got {received}")]
    VersionMismatch { expected: u32, received: u32 },
    #[error("Invalid internal state: {0}")]
    InvalidState(String),
    #[error("Handshake timestamp is stale (skew exceeds {MAX_HANDSHAKE_TIMESTAMP_SKEW_NS}ns)")]
    StaleTimestamp,
    #[error("Session nonce counter exhausted — connection must be terminated")]
    NonceExhausted,
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("ML-KEM encapsulation/decapsulation failed")]
    KemError,
    #[error("AES-256-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-256-GCM decryption failed (authentication tag mismatch)")]
    DecryptionFailed,
    #[error("Message counter mismatch: expected {expected}")]
    NonceMismatch { expected: u64 },
    #[error("Message too short to contain nonce+tag")]
    TruncatedMessage,
    #[error("Handshake timestamp too old (replay protection)")]
    TimestampExpired,
    #[error("Borsh serialization error: {0}")]
    SerializationError(String),
}

// ── KDF ───────────────────────────────────────────────────────────────────────

/// Derive the 32-byte AES-256-GCM session key from the ML-KEM shared secret
/// and both peers' identities (prevents cross-connection key reuse).
///
/// session_key = SHAKE256(
///     "NEAR-PQC-SESSION-v1\x00" ‖
///     shared_secret(32) ‖
///     initiator_peer_id(32) ‖
///     responder_peer_id(32)
/// )[0..32]
fn derive_session_key(
    shared_secret: &[u8; KEM_SS_LEN],
    initiator: &PqcPeerId,
    responder: &PqcPeerId,
) -> [u8; SESSION_KEY_LEN] {
    let mut xof = Shake256::default();
    xof.update(SESSION_KDF_DOMAIN);
    xof.update(shared_secret.as_ref());
    xof.update(&initiator.0);
    xof.update(&responder.0);
    let mut key = [0u8; SESSION_KEY_LEN];
    xof.finalize_xof().read(&mut key);
    key
}

// ── ServerHello signing data ──────────────────────────────────────────────────

fn server_hello_signing_data(
    peer_id: &PqcPeerId,
    kem_ek: &[u8; KEM_EK_LEN],
    timestamp_nanos: u64,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + KEM_EK_LEN + 8);
    data.extend_from_slice(&peer_id.0);
    data.extend_from_slice(kem_ek);
    data.extend_from_slice(&timestamp_nanos.to_le_bytes());
    data
}

fn client_finish_signing_data(
    responder_peer_id: &PqcPeerId,
    ciphertext: &[u8; KEM_CT_LEN],
    timestamp_nanos: u64,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + KEM_CT_LEN + 8);
    data.extend_from_slice(&responder_peer_id.0);
    data.extend_from_slice(ciphertext);
    data.extend_from_slice(&timestamp_nanos.to_le_bytes());
    data
}

// ── Responder handshake ───────────────────────────────────────────────────────

/// State held by the responder between receiving ClientHello and ClientFinish.
pub struct ResponderHandshakeState {
    pub our_peer_id: PqcPeerId,
    pub initiator_peer_id: PqcPeerId,
    pub kem_decapsulation_key: KemSecretKey,
    pub kem_encapsulation_key: [u8; KEM_EK_LEN],
    pub timestamp_nanos: u64,
}

/// Responder: process ClientHello and produce ServerHello.
pub fn responder_process_hello(
    hello: &ClientHello,
    our_peer_id: PqcPeerId,
    our_identity_key: &near_crypto::SecretKey,
) -> Result<(ServerHello, ResponderHandshakeState), HandshakeError> {
    if hello.protocol_version < PQC_HANDSHAKE_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PQC_HANDSHAKE_VERSION,
            received: hello.protocol_version,
        });
    }

    // Generate ephemeral ML-KEM-768 keypair
    let (kem_pk, kem_sk) = kyber768::keypair();
    let mut kem_ek_bytes = [0u8; KEM_EK_LEN];
    kem_ek_bytes.copy_from_slice(kem_pk.as_bytes());

    let timestamp_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let signing_data = server_hello_signing_data(&our_peer_id, &kem_ek_bytes, timestamp_nanos);
    let signature = our_identity_key.sign(&signing_data);

    let server_hello = ServerHello {
        protocol_version: PQC_HANDSHAKE_VERSION,
        peer_id: our_peer_id,
        kem_encapsulation_key: kem_ek_bytes,
        timestamp_nanos,
        signature,
    };

    // Validate hello timestamp freshness (replay protection)
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let skew = now_ns.max(hello.timestamp_nanos) - now_ns.min(hello.timestamp_nanos);
    if skew > MAX_HANDSHAKE_TIMESTAMP_SKEW_NS {
        return Err(HandshakeError::StaleTimestamp);
    }

    let state = ResponderHandshakeState {
        our_peer_id,
        initiator_peer_id: hello.peer_id,
        kem_decapsulation_key: kem_sk,
        kem_encapsulation_key: kem_ek_bytes,
        timestamp_nanos,
    };

    Ok((server_hello, state))
}

/// Responder: process ClientFinish and produce the established session.
pub fn responder_finish(
    finish: &ClientFinish,
    state: ResponderHandshakeState,
    initiator_public_key: &PublicKey,
) -> Result<PqcSession, HandshakeError> {
    // Verify initiator's signature over (our_peer_id ‖ ciphertext ‖ timestamp)
    let signing_data = client_finish_signing_data(
        &state.our_peer_id,
        &finish.ciphertext,
        state.timestamp_nanos,
    );
    if !finish.signature.verify(&signing_data, initiator_public_key) {
        return Err(HandshakeError::InvalidSignature);
    }

    // ML-KEM-768 decapsulate
    let ct = KemCiphertext::from_bytes(&finish.ciphertext)
        .map_err(|_| HandshakeError::KemError)?;
    let ss = kyber768::decapsulate(&ct, &state.kem_decapsulation_key);
    let mut shared_secret = [0u8; KEM_SS_LEN];
    shared_secret.copy_from_slice(ss.as_bytes());

    let session_key = derive_session_key(
        &shared_secret,
        &state.initiator_peer_id,
        &state.our_peer_id,
    );

    // Zero the shared secret from stack memory
    shared_secret.iter_mut().for_each(|b| *b = 0);

    Ok(PqcSession::new(&session_key))
}

// ── Initiator handshake ───────────────────────────────────────────────────────

/// State held by the initiator between sending ClientHello and receiving ServerHello.
pub struct InitiatorHandshakeState {
    pub our_peer_id: PqcPeerId,
    pub timestamp_nanos: u64,
}

/// Initiator: build ClientHello.
pub fn initiator_build_hello(our_peer_id: PqcPeerId) -> (ClientHello, InitiatorHandshakeState) {
    let timestamp_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let hello = ClientHello {
        protocol_version: PQC_HANDSHAKE_VERSION,
        peer_id: our_peer_id,
        timestamp_nanos,
    };

    let state = InitiatorHandshakeState { our_peer_id, timestamp_nanos };
    (hello, state)
}

/// Initiator: process ServerHello, produce ClientFinish and the established session.
pub fn initiator_process_server_hello(
    server_hello: &ServerHello,
    state: &InitiatorHandshakeState,
    responder_public_key: &PublicKey,
    our_identity_key: &near_crypto::SecretKey,
) -> Result<(ClientFinish, PqcSession), HandshakeError> {
    if server_hello.protocol_version < PQC_HANDSHAKE_VERSION {
        return Err(HandshakeError::VersionMismatch {
            expected: PQC_HANDSHAKE_VERSION,
            received: server_hello.protocol_version,
        });
    }

    // Verify responder's signature over (their_peer_id ‖ kem_ek ‖ timestamp)
    let signing_data = server_hello_signing_data(
        &server_hello.peer_id,
        &server_hello.kem_encapsulation_key,
        server_hello.timestamp_nanos,
    );
    if !server_hello.signature.verify(&signing_data, responder_public_key) {
        return Err(HandshakeError::InvalidSignature);
    }

    // ML-KEM-768 encapsulate against responder's ephemeral key
    let kem_pk = KemPublicKey::from_bytes(&server_hello.kem_encapsulation_key)
        .map_err(|_| HandshakeError::KemError)?;
    let (ss, ct) = kyber768::encapsulate(&kem_pk);

    let mut shared_secret = [0u8; KEM_SS_LEN];
    shared_secret.copy_from_slice(ss.as_bytes());
    let mut ciphertext = [0u8; KEM_CT_LEN];
    ciphertext.copy_from_slice(ct.as_bytes());

    // Sign (responder_peer_id ‖ ciphertext ‖ server_timestamp)
    let signing_data =
        client_finish_signing_data(&server_hello.peer_id, &ciphertext, server_hello.timestamp_nanos);
    let signature = our_identity_key.sign(&signing_data);

    let client_finish = ClientFinish { ciphertext, signature };

    let session_key = derive_session_key(
        &shared_secret,
        &state.our_peer_id,
        &server_hello.peer_id,
    );

    // Zero shared secret
    shared_secret.iter_mut().for_each(|b| *b = 0);

    Ok((client_finish, PqcSession::new(&session_key)))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::{InMemorySigner, KeyType};

    fn make_node(name: &str) -> (InMemorySigner, PqcPeerId) {
        let account: near_account_id::AccountId = name.parse().unwrap();
        let signer = InMemorySigner::from_random(account, KeyType::MlDsa);
        let peer_id = PqcPeerId::from_public_key(&signer.public_key());
        (signer, peer_id)
    }

    /// Full handshake: both sides establish the same session key and can
    /// encrypt/decrypt messages to each other.
    #[test]
    fn test_full_handshake_establishes_shared_session() {
        let (initiator_signer, initiator_id) = make_node("initiator.near");
        let (responder_signer, responder_id) = make_node("responder.near");

        // Step 1: Initiator builds ClientHello
        let (hello, init_state) = initiator_build_hello(initiator_id);
        assert_eq!(hello.protocol_version, PQC_HANDSHAKE_VERSION);

        // Step 2: Responder processes hello, produces ServerHello
        let (server_hello, resp_state) = responder_process_hello(
            &hello,
            responder_id,
            &responder_signer.secret_key,
        ).expect("responder_process_hello failed");

        // Step 3: Initiator processes ServerHello, produces ClientFinish + session
        let (finish, init_session) = initiator_process_server_hello(
            &server_hello,
            &init_state,
            &responder_signer.public_key(),
            &initiator_signer.secret_key,
        ).expect("initiator_process_server_hello failed");

        // Step 4: Responder processes ClientFinish, gets session
        let resp_session = responder_finish(
            &finish,
            resp_state,
            &initiator_signer.public_key(),
        ).expect("responder_finish failed");

        // Both sessions must be able to communicate
        let plaintext = b"Hello from initiator to responder!";
        let encrypted = init_session.encrypt(plaintext, 0x01).expect("encrypt failed");
        let decrypted = resp_session.decrypt(&encrypted, 0x01).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);

        // Reverse direction
        let plaintext2 = b"Hello from responder to initiator!";
        let encrypted2 = resp_session.encrypt(plaintext2, 0x02).expect("encrypt failed");
        let decrypted2 = init_session.decrypt(&encrypted2, 0x02).expect("decrypt failed");
        assert_eq!(decrypted2, plaintext2);
    }

    /// Wrong version in ClientHello must be rejected.
    #[test]
    fn test_old_protocol_version_rejected() {
        let (responder_signer, responder_id) = make_node("responder.near");
        let (_, initiator_id) = make_node("initiator.near");

        let hello = ClientHello {
            protocol_version: 999, // too old
            peer_id: initiator_id,
            timestamp_nanos: 0,
        };

        let result = responder_process_hello(&hello, responder_id, &responder_signer.secret_key);
        assert!(matches!(result, Err(HandshakeError::VersionMismatch { .. })));
    }

    /// Tampered KEM ciphertext must fail authentication.
    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let (initiator_signer, initiator_id) = make_node("init.near");
        let (responder_signer, responder_id) = make_node("resp.near");

        let (hello, init_state) = initiator_build_hello(initiator_id);
        let (server_hello, resp_state) =
            responder_process_hello(&hello, responder_id, &responder_signer.secret_key).unwrap();
        let (mut finish, _) = initiator_process_server_hello(
            &server_hello, &init_state,
            &responder_signer.public_key(),
            &initiator_signer.secret_key,
        ).unwrap();

        // Tamper with ciphertext
        finish.ciphertext[0] ^= 0xFF;

        let result = responder_finish(&finish, resp_state, &initiator_signer.public_key());
        // Either KEM decap fails or signature check fails (ciphertext changed but sig covers it)
        assert!(result.is_err(), "Tampered ciphertext should be rejected");
    }

    /// Wrong signature (different key) must be rejected at ServerHello verification.
    #[test]
    fn test_wrong_responder_signature_rejected() {
        let (initiator_signer, initiator_id) = make_node("init.near");
        let (responder_signer, responder_id) = make_node("resp.near");
        let (attacker_signer, _) = make_node("attacker.near");

        let (hello, init_state) = initiator_build_hello(initiator_id);
        let (server_hello, _) =
            responder_process_hello(&hello, responder_id, &responder_signer.secret_key).unwrap();

        // Initiator verifies with attacker's public key instead of responder's
        let result = initiator_process_server_hello(
            &server_hello,
            &init_state,
            &attacker_signer.public_key(), // wrong key
            &initiator_signer.secret_key,
        );
        assert!(matches!(result, Err(HandshakeError::InvalidSignature)));
    }

    /// PqcPeerId derivation is deterministic.
    #[test]
    fn test_peer_id_deterministic() {
        let (signer, _) = make_node("alice.near");
        let pk = signer.public_key();
        let id1 = PqcPeerId::from_public_key(&pk);
        let id2 = PqcPeerId::from_public_key(&pk);
        assert_eq!(id1, id2);
    }

    /// Session counter prevents replay: same ciphertext fails on second decrypt.
    #[test]
    fn test_replay_attack_rejected() {
        let (initiator_signer, initiator_id) = make_node("init.near");
        let (responder_signer, responder_id) = make_node("resp.near");

        let (hello, init_state) = initiator_build_hello(initiator_id);
        let (server_hello, resp_state) =
            responder_process_hello(&hello, responder_id, &responder_signer.secret_key).unwrap();
        let (finish, init_session) = initiator_process_server_hello(
            &server_hello, &init_state,
            &responder_signer.public_key(),
            &initiator_signer.secret_key,
        ).unwrap();
        let resp_session =
            responder_finish(&finish, resp_state, &initiator_signer.public_key()).unwrap();

        let plaintext = b"replay me";
        let encrypted = init_session.encrypt(plaintext, 0x01).unwrap();

        // First decrypt succeeds
        resp_session.decrypt(&encrypted, 0x01).expect("first decrypt should succeed");

        // Replaying same ciphertext fails (counter mismatch)
        let replay_result = resp_session.decrypt(&encrypted, 0x01);
        assert!(replay_result.is_err(), "Replay attack should be rejected");
    }

    /// Borsh round-trip for all handshake messages.
    #[test]
    fn test_handshake_messages_borsh_roundtrip() {
        let peer_id = PqcPeerId([42u8; 32]);
        let hello = ClientHello {
            protocol_version: PQC_HANDSHAKE_VERSION,
            peer_id,
            timestamp_nanos: 1_000_000_000,
        };
        let encoded = borsh::to_vec(&hello).unwrap();
        let decoded: ClientHello = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, hello.protocol_version);
        assert_eq!(decoded.peer_id, hello.peer_id);
    }
}
