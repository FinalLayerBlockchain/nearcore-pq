use crate::signature::{KeyType, PublicKey, SecretKey};
use crate::{InMemorySigner, Signature};
use pqcrypto_traits::sign::{PublicKey as PqcPkTrait, SecretKey as PqcSkTrait};

#[cfg(feature = "rand")]
fn ed25519_key_pair_from_seed(seed: &str) -> ed25519_dalek::SigningKey {
    let seed_bytes = seed.as_bytes();
    let len = std::cmp::min(ed25519_dalek::SECRET_KEY_LENGTH, seed_bytes.len());
    let mut seed: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = [b' '; ed25519_dalek::SECRET_KEY_LENGTH];
    seed[..len].copy_from_slice(&seed_bytes[..len]);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

#[cfg(feature = "rand")]
fn secp256k1_secret_key_from_seed(seed: &str) -> secp256k1::SecretKey {
    use secp256k1::rand::SeedableRng;

    let seed_bytes = seed.as_bytes();
    let len = std::cmp::min(32, seed_bytes.len());
    let mut seed: [u8; 32] = [b' '; 32];
    seed[..len].copy_from_slice(&seed_bytes[..len]);
    let mut rng = secp256k1::rand::rngs::StdRng::from_seed(seed);
    secp256k1::SecretKey::new(&mut rng)
}

impl PublicKey {
    #[cfg(feature = "rand")]
    pub fn from_seed(key_type: KeyType, seed: &str) -> Self {
        match key_type {
            KeyType::ED25519 => {
                let keypair = ed25519_key_pair_from_seed(seed);
                PublicKey::ED25519(crate::signature::ED25519PublicKey(
                    keypair.verifying_key().to_bytes(),
                ))
            }
            KeyType::SECP256K1 => {
                let secret_key = SecretKey::SECP256K1(secp256k1_secret_key_from_seed(seed));
                PublicKey::SECP256K1(secret_key.public_key().unwrap_as_secp256k1().clone())
            }
            // PQC key types: generate from random (seeded generation not supported in pqcrypto)
            KeyType::MLDSA => {
                let (pk, _) = pqcrypto_dilithium::dilithium3::keypair();
                crate::signature::MlDsaPublicKey(pk.as_bytes().to_vec()).into()
            }
            KeyType::FNDSA => {
                let (pk, _) = pqcrypto_falcon::falcon512::keypair();
                crate::signature::FnDsaPublicKey(pk.as_bytes().to_vec()).into()
            }
            KeyType::SLHDSA => {
                let (pk, _) = pqcrypto_sphincsplus::sphincssha2128ssimple::keypair();
                crate::signature::SlhDsaPublicKey(pk.as_bytes().to_vec()).into()
            }
        }
    }
}

impl SecretKey {
    #[cfg(feature = "rand")]
    pub fn from_seed(key_type: KeyType, seed: &str) -> Self {
        match key_type {
            KeyType::ED25519 => {
                let keypair = ed25519_key_pair_from_seed(seed);
                SecretKey::ED25519(crate::signature::ED25519SecretKey(keypair.to_keypair_bytes()))
            }
            KeyType::SECP256K1 => SecretKey::SECP256K1(secp256k1_secret_key_from_seed(seed)),
            // PQC key types: generate randomly (pqcrypto has no seeded keypair API)
            KeyType::MLDSA => {
                let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
                // Store pk||sk together so public_key() can extract pk without re-computing
                let mut combined = Vec::with_capacity(
                    crate::signature::MLDSA_PUBLIC_KEY_LEN
                        + crate::signature::MLDSA_SECRET_KEY_LEN,
                );
                combined.extend_from_slice(pk.as_bytes());
                combined.extend_from_slice(sk.as_bytes());
                SecretKey::MlDsa(crate::signature::MlDsaSecretKey(combined))
            }
            KeyType::FNDSA => {
                let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
                // pk is stored first so public_key() can extract it
                let mut combined = Vec::with_capacity(
                    crate::signature::FNDSA_PUBLIC_KEY_LEN
                        + crate::signature::FNDSA_SECRET_KEY_LEN,
                );
                combined.extend_from_slice(pk.as_bytes());
                combined.extend_from_slice(sk.as_bytes());
                SecretKey::FnDsa(crate::signature::FnDsaSecretKey(combined))
            }
            KeyType::SLHDSA => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2128ssimple::keypair();
                // sk contains pk in its last bytes per SPHINCS+ spec
                let _ = pk;
                SecretKey::SlhDsa(crate::signature::SlhDsaSecretKey(sk.as_bytes().to_vec()))
            }
        }
    }
}

const SIG: [u8; ed25519_dalek::SIGNATURE_LENGTH] = [0u8; ed25519_dalek::SIGNATURE_LENGTH];

impl Signature {
    /// Empty signature that doesn't correspond to anything.
    pub fn empty(key_type: KeyType) -> Self {
        match key_type {
            KeyType::ED25519 => Signature::ED25519(ed25519_dalek::Signature::from_bytes(&SIG)),
            _ => unimplemented!(),
        }
    }
}

impl InMemorySigner {
    #[cfg(feature = "rand")]
    pub fn from_random(account_id: near_account_id::AccountId, key_type: KeyType) -> Self {
        let secret_key = SecretKey::from_random(key_type);
        Self { account_id, public_key: secret_key.public_key(), secret_key }
    }
}
