use crate::{PublicKey, signature, vrf};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::mem::transmute;

pub fn is_valid_staking_key(public_key: &PublicKey) -> bool {
    match public_key {
        PublicKey::ED25519(key) => convert_public_key(key).is_some(),
        PublicKey::SECP256K1(_) => false,
        // All three NIST PQC algorithms are valid staking key types for Final Layer.
        PublicKey::MlDsa(_) | PublicKey::FnDsa(_) | PublicKey::SlhDsa(_) => true,
    }
}

pub fn convert_public_key(key: &signature::ED25519PublicKey) -> Option<vrf::PublicKey> {
    let ep: EdwardsPoint = CompressedEdwardsY::from_slice(&key.0).ok()?.decompress()?;
    // All properly generated public keys are torsion-free. RistrettoPoint type can handle some values that are not torsion-free, but not all.
    if !ep.is_torsion_free() {
        return None;
    }
    // Unfortunately, dalek library doesn't provide a better way to do this.
    let rp: RistrettoPoint = unsafe { transmute(ep) };
    Some(vrf::PublicKey(rp.compress().to_bytes(), rp))
}

pub fn convert_secret_key(key: &signature::ED25519SecretKey) -> vrf::SecretKey {
    let b = <&[u8; 32]>::try_from(&key.0[..32]).unwrap();
    let s = ed25519_dalek::hazmat::ExpandedSecretKey::from(b).scalar;
    vrf::SecretKey::from_scalar(s)
}

/// Derive a deterministic VRF secret key from a PQC public key's bytes.
/// Uses SHA-256(domain || pk_bytes) → 32-byte scalar.
/// This enables PQC staking keys to participate in VRF-based block production.
/// The derived key is deterministic (same PQC key → same VRF key) and one-way.
fn pqc_vrf_scalar(pk_bytes: &[u8]) -> Scalar {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(b"FL-VRF-V1\x00")
        .chain_update(pk_bytes)
        .finalize()
        .into();
    Scalar::from_bytes_mod_order(hash)
}

/// Derive a VRF secret key from any PQC public key for block production signing.
pub fn pqc_derive_vrf_secret(pk_bytes: &[u8]) -> vrf::SecretKey {
    vrf::SecretKey::from_scalar(pqc_vrf_scalar(pk_bytes))
}

/// Derive a VRF public key from any PublicKey type.
/// For ED25519 keys, uses the standard Edwards-to-Ristretto conversion.
/// For PQC keys, derives a deterministic Ristretto VRF key from the public key bytes.
pub fn any_key_to_vrf_public(public_key: &PublicKey) -> Option<vrf::PublicKey> {
    match public_key {
        PublicKey::ED25519(key) => convert_public_key(key),
        PublicKey::MlDsa(k) => Some(vrf::SecretKey::from_scalar(pqc_vrf_scalar(&k.0)).public_key().clone()),
        PublicKey::FnDsa(k) => Some(vrf::SecretKey::from_scalar(pqc_vrf_scalar(&k.0)).public_key().clone()),
        PublicKey::SlhDsa(k) => Some(vrf::SecretKey::from_scalar(pqc_vrf_scalar(&k.0)).public_key().clone()),
        PublicKey::SECP256K1(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "rand")]
    #[test]
    fn test_conversion() {
        use super::*;

        for _ in 0..10 {
            let kk = signature::SecretKey::from_random(signature::KeyType::ED25519);
            let pk = match kk.public_key() {
                signature::PublicKey::ED25519(k) => k,
                _ => unreachable!(),
            };
            let sk = match kk {
                signature::SecretKey::ED25519(k) => k,
                _ => unreachable!(),
            };
            assert_eq!(
                convert_secret_key(&sk).public_key().clone(),
                convert_public_key(&pk).unwrap()
            );
        }
    }
}
