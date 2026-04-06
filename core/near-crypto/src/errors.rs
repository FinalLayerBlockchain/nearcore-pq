//! Error types for PQC key parsing and signature validation.

use std::fmt;

// ── Key type parsing ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseKeyTypeError {
    #[error("Unknown key type: {unknown_key_type}")]
    UnknownKeyType { unknown_key_type: String },
}

// ── Public key parsing ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseKeyError {
    #[error("Invalid key data: {error_message}")]
    InvalidData { error_message: String },

    #[error("Invalid key length: expected {expected_length} bytes, got {received_length}")]
    InvalidLength {
        expected_length: usize,
        received_length: usize,
    },
}

// ── Signature parsing ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseSignatureError {
    #[error("Invalid signature data: {error_message}")]
    InvalidData { error_message: String },

    #[error("Invalid signature length: expected {expected_length} bytes, got {received_length}")]
    InvalidLength {
        expected_length: usize,
        received_length: usize,
    },
}
