#![cfg_attr(enable_const_type_id, feature(const_type_id))]
#![deny(clippy::arithmetic_side_effects)]

pub use errors::{ParseKeyError, ParseKeyTypeError, ParseSignatureError};
pub use key_file::KeyFile;
pub use signature::{
    ED25519PublicKey, ED25519SecretKey, FnDsaPublicKey, FnDsaSecretKey, KeyType, MlDsaPublicKey,
    MlDsaSecretKey, PublicKey, Secp256K1PublicKey, Secp256K1Signature, SecretKey, Signature,
    SlhDsaPublicKey, SlhDsaSecretKey,
    FNDSA_PUBLIC_KEY_LEN, FNDSA_SECRET_KEY_LEN, FNDSA_SIGNATURE_MAX_LEN,
    MLDSA_PUBLIC_KEY_LEN, MLDSA_SECRET_KEY_LEN, MLDSA_SIGNATURE_LEN,
    SLHDSA_PUBLIC_KEY_LEN, SLHDSA_SECRET_KEY_LEN, SLHDSA_SIGNATURE_LEN,
};
pub use signer::{EmptySigner, InMemorySigner, Signer};

#[macro_use]
mod hash;
#[macro_use]
mod traits;
#[macro_use]
mod util;

mod errors;
pub mod key_conversion;
mod key_file;
mod signature;
mod signer;
mod test_utils;
pub mod vrf;
