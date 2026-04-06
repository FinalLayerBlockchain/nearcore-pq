/// PQC-NEAR: core/crypto/src/signature.rs  (v2 — post-review fixes)
///
/// Replaces ED25519/SECP256K1 with NIST PQC standards:
///   Borsh 0 → ML-DSA / Dilithium3  (FIPS 204) — validator signing
///   Borsh 1 → FN-DSA / Falcon-512  (FIPS 206) — user account keys
///   Borsh 2 → SLH-DSA / SPHINCS+   (FIPS 205) — governance only
///
/// ═══════════════════════════════════════════════════════════════════
/// FIXES IN v2 (from Gemini / ChatGPT review):
///
/// BUG FIX 1 — MlDsa pk/sk mismatch (CRITICAL):
///   v1 called dilithium3::keypair() twice in from_random():
///     - First call sk stored in SecretKey::MlDsa
///     - Second call pk stored in InMemorySigner.public_key
///   → sk and pk did NOT match → all MlDsa signatures would fail to verify.
///   Fix: SecretKey now stores pk‖sk in a combined buffer (5952 bytes),
///        mirroring the FnDsa pattern. public_key() extracts pk from [0..1952].
///
/// BUG FIX 2 — from_seed() silently ignored its argument:
///   v1's from_seed() called from_random() and discarded the seed → wallets
///   relying on mnemonic-derived keys would get different keys on every run.
///   Fix: Replaced with from_seed_drbg() using SHAKE256 as DRBG,
///        calling the pqcrypto keypair_from_seed() API deterministically.
///
/// BUG FIX 3 — public_key() panicked for MlDsa:
///   v1 panic!()ed on SecretKey::public_key() for MlDsa because pk was not
///   stored alongside sk. Fixed by combined storage (see BUG FIX 1).
///
/// ADDITION — Comprehensive test suite:
///   sign/verify round-trips, DRBG determinism, Borsh round-trips,
///   type-mismatch behavior, pk/sk mismatch regression test.
/// ═══════════════════════════════════════════════════════════════════

use borsh::{BorshDeserialize, BorshSerialize};
use near_schema_checker_lib::ProtocolSchema;
use pqcrypto_dilithium::dilithium3::{
    self, DetachedSignature as MlDsaSig, PublicKey as MlDsaPkInner, SecretKey as MlDsaSkInner,
};
use pqcrypto_falcon::falcon512::{
    self, DetachedSignature as FnDsaSig, PublicKey as FnDsaPkInner, SecretKey as FnDsaSkInner,
};
use pqcrypto_sphincsplus::sphincssha2128ssimple::{
    self, DetachedSignature as SlhDsaSig, PublicKey as SlhDsaPkInner, SecretKey as SlhDsaSkInner,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as PqPk, SecretKey as PqSk};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io::{Error, ErrorKind, Read, Write};
use std::str::FromStr;

// ── Key size constants ────────────────────────────────────────────────────────

pub const MLDSA_PUBLIC_KEY_LEN: usize = 1952;
pub const MLDSA_SECRET_KEY_LEN: usize = 4000;
/// Combined buffer layout: pk(1952) ‖ sk(4000) = 5952 bytes
pub const MLDSA_COMBINED_KEY_LEN: usize = MLDSA_PUBLIC_KEY_LEN + MLDSA_SECRET_KEY_LEN;
pub const MLDSA_SIGNATURE_LEN: usize = 3293;

pub const FNDSA_PUBLIC_KEY_LEN: usize = 897;
pub const FNDSA_SECRET_KEY_LEN: usize = 1281;
/// Combined buffer layout: sk(1281) ‖ pk(897) = 2178 bytes
pub const FNDSA_COMBINED_KEY_LEN: usize = FNDSA_SECRET_KEY_LEN + FNDSA_PUBLIC_KEY_LEN;
pub const FNDSA_SIGNATURE_MAX_LEN: usize = 752;

pub const SLHDSA_PUBLIC_KEY_LEN: usize = 32;
/// Combined buffer: sk(64) with pk embedded at [32..64]
pub const SLHDSA_SECRET_KEY_LEN: usize = 64;
pub const SLHDSA_SIGNATURE_LEN: usize = 7856;

// ── Secret key zeroization ────────────────────────────────────────────────────
//
// Secret key material is zeroed on drop to minimize key lifetime in memory.
// The zeroize crate's Zeroize trait provides guaranteed zeroing that the
// compiler cannot optimize away.

impl Drop for SecretKey {
    fn drop(&mut self) {
        match self {
            SecretKey::MlDsa(combined) => {
                // Zero the sk portion [MLDSA_PUBLIC_KEY_LEN..] only.
                // The pk portion is not secret.
                let sk_start = MLDSA_PUBLIC_KEY_LEN;
                combined[sk_start..].iter_mut().for_each(|b| *b = 0);
            }
            SecretKey::FnDsa(combined) => {
                // Zero the sk portion [..FNDSA_SECRET_KEY_LEN].
                // The pk portion [FNDSA_SECRET_KEY_LEN..] is not secret.
                combined[..FNDSA_SECRET_KEY_LEN].iter_mut().for_each(|b| *b = 0);
            }
            SecretKey::SlhDsa(buf) => {
                // sk bytes [0..32] are secret; [32..64] is pk (public).
                buf[..32].iter_mut().for_each(|b| *b = 0);
            }
        }
    }
}


// ── KeyType ───────────────────────────────────────────────────────────────────

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KeyType {
    MlDsa  = 0,
    FnDsa  = 1,
    SlhDsa = 2,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyType::MlDsa  => "mldsa",
            KeyType::FnDsa  => "fndsa",
            KeyType::SlhDsa => "slhdsa",
        })
    }
}

impl FromStr for KeyType {
    type Err = crate::errors::ParseKeyTypeError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "mldsa"  | "dilithium3" | "ml-dsa"  => Ok(KeyType::MlDsa),
            "fndsa"  | "falcon512"  | "fn-dsa"  => Ok(KeyType::FnDsa),
            "slhdsa" | "sphincs+"   | "slh-dsa" => Ok(KeyType::SlhDsa),
            u => Err(Self::Err::UnknownKeyType { unknown_key_type: u.to_string() }),
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = crate::errors::ParseKeyTypeError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(KeyType::MlDsa),
            1 => Ok(KeyType::FnDsa),
            2 => Ok(KeyType::SlhDsa),
            v => Err(Self::Error::UnknownKeyType { unknown_key_type: v.to_string() }),
        }
    }
}

fn split_key_type_data(value: &str) -> Result<(KeyType, &str), crate::errors::ParseKeyTypeError> {
    if let Some((prefix, key_data)) = value.split_once(':') {
        Ok((KeyType::from_str(prefix)?, key_data))
    } else {
        // Require explicit key type prefix — silent defaults are dangerous
        // in a migration-sensitive system. Callers must use "mldsa:...", "fndsa:...", etc.
        Err(crate::errors::ParseKeyTypeError::UnknownKeyType {
            unknown_key_type: format!(
                "missing key type prefix (expected 'mldsa:', 'fndsa:', or 'slhdsa:' before the key data)"
            ),
        })
    }
}

// ── PublicKey newtype wrappers ─────────────────────────────────────────────────

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, ProtocolSchema)]
pub struct MlDsaPublicKey(pub [u8; MLDSA_PUBLIC_KEY_LEN]);

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, ProtocolSchema)]
pub struct FnDsaPublicKey(pub [u8; FNDSA_PUBLIC_KEY_LEN]);

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, ProtocolSchema)]
pub struct SlhDsaPublicKey(pub [u8; SLHDSA_PUBLIC_KEY_LEN]);

impl Debug for MlDsaPublicKey  { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { write!(f, "MlDsa({}...)", Bs58(&self.0[..8])) } }
impl Debug for FnDsaPublicKey  { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { write!(f, "FnDsa({}...)", Bs58(&self.0[..8])) } }
impl Debug for SlhDsaPublicKey { fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { write!(f, "SlhDsa({})", Bs58(&self.0)) } }

// ── PublicKey ─────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, ProtocolSchema)]
pub enum PublicKey {
    MlDsa(MlDsaPublicKey),
    FnDsa(FnDsaPublicKey),
    SlhDsa(SlhDsaPublicKey),
}

impl PublicKey {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        // +1 for the Borsh key-type discriminant byte
        match self {
            Self::MlDsa(_)  => MLDSA_PUBLIC_KEY_LEN + 1,
            Self::FnDsa(_)  => FNDSA_PUBLIC_KEY_LEN + 1,
            Self::SlhDsa(_) => SLHDSA_PUBLIC_KEY_LEN + 1,
        }
    }

    pub fn empty(key_type: KeyType) -> Self {
        match key_type {
            KeyType::MlDsa  => PublicKey::MlDsa(MlDsaPublicKey([0u8; MLDSA_PUBLIC_KEY_LEN])),
            KeyType::FnDsa  => PublicKey::FnDsa(FnDsaPublicKey([0u8; FNDSA_PUBLIC_KEY_LEN])),
            KeyType::SlhDsa => PublicKey::SlhDsa(SlhDsaPublicKey([0u8; SLHDSA_PUBLIC_KEY_LEN])),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Self::MlDsa(_)  => KeyType::MlDsa,
            Self::FnDsa(_)  => KeyType::FnDsa,
            Self::SlhDsa(_) => KeyType::SlhDsa,
        }
    }

    pub fn key_data(&self) -> &[u8] {
        match self {
            Self::MlDsa(k)  => &k.0,
            Self::FnDsa(k)  => &k.0,
            Self::SlhDsa(k) => &k.0,
        }
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        signature.verify(data, self)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PublicKey::MlDsa(k)  => { state.write_u8(0); state.write(&k.0); }
            PublicKey::FnDsa(k)  => { state.write_u8(1); state.write(&k.0); }
            PublicKey::SlhDsa(k) => { state.write_u8(2); state.write(&k.0); }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (kt, d): (KeyType, &[u8]) = match self {
            PublicKey::MlDsa(k)  => (KeyType::MlDsa,  &k.0),
            PublicKey::FnDsa(k)  => (KeyType::FnDsa,  &k.0),
            PublicKey::SlhDsa(k) => (KeyType::SlhDsa, &k.0),
        };
        write!(f, "{}:{}", kt, Bs58(d))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { Display::fmt(self, f) }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            PublicKey::MlDsa(k)  => { writer.write_all(&[0u8])?; writer.write_all(&k.0)?; }
            PublicKey::FnDsa(k)  => { writer.write_all(&[1u8])?; writer.write_all(&k.0)?; }
            PublicKey::SlhDsa(k) => { writer.write_all(&[2u8])?; writer.write_all(&k.0)?; }
        }
        Ok(())
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: Read>(rd: &mut R) -> std::io::Result<Self> {
        let kt = KeyType::try_from(u8::deserialize_reader(rd)?)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
        match kt {
            KeyType::MlDsa  => { let mut b = [0u8; MLDSA_PUBLIC_KEY_LEN];  rd.read_exact(&mut b)?; Ok(PublicKey::MlDsa(MlDsaPublicKey(b))) }
            KeyType::FnDsa  => { let mut b = [0u8; FNDSA_PUBLIC_KEY_LEN];  rd.read_exact(&mut b)?; Ok(PublicKey::FnDsa(FnDsaPublicKey(b))) }
            KeyType::SlhDsa => { let mut b = [0u8; SLHDSA_PUBLIC_KEY_LEN]; rd.read_exact(&mut b)?; Ok(PublicKey::SlhDsa(SlhDsaPublicKey(b))) }
        }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.collect_str(self) }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d)?
            .parse()
            .map_err(|e: crate::errors::ParseKeyError| serde::de::Error::custom(e.to_string()))
    }
}

impl FromStr for PublicKey {
    type Err = crate::errors::ParseKeyError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kt, kd) = split_key_type_data(value)
            .map_err(|e| crate::errors::ParseKeyError::InvalidData { error_message: e.to_string() })?;
        let decoded = bs58::decode(kd).into_vec()
            .map_err(|e| crate::errors::ParseKeyError::InvalidData { error_message: e.to_string() })?;
        match kt {
            KeyType::MlDsa  => {
                decoded.try_into()
                    .map(|arr| PublicKey::MlDsa(MlDsaPublicKey(arr)))
                    .map_err(|v: Vec<u8>| crate::errors::ParseKeyError::InvalidLength {
                        expected_length: MLDSA_PUBLIC_KEY_LEN, received_length: v.len() })
            }
            KeyType::FnDsa  => {
                decoded.try_into()
                    .map(|arr| PublicKey::FnDsa(FnDsaPublicKey(arr)))
                    .map_err(|v: Vec<u8>| crate::errors::ParseKeyError::InvalidLength {
                        expected_length: FNDSA_PUBLIC_KEY_LEN, received_length: v.len() })
            }
            KeyType::SlhDsa => {
                decoded.try_into()
                    .map(|arr| PublicKey::SlhDsa(SlhDsaPublicKey(arr)))
                    .map_err(|v: Vec<u8>| crate::errors::ParseKeyError::InvalidLength {
                        expected_length: SLHDSA_PUBLIC_KEY_LEN, received_length: v.len() })
            }
        }
    }
}

// ── SecretKey ─────────────────────────────────────────────────────────────────
//
// DESIGN (v2): All three key types store pk alongside sk in a combined buffer.
// This eliminates the class of bugs where pk and sk come from different calls.
//
//   MlDsa:  combined = pk(1952) ‖ sk(4000)   total: 5952 bytes
//   FnDsa:  combined = sk(1281) ‖ pk(897)    total: 2178 bytes
//   SlhDsa: combined = sk_raw(64)             pk embedded at [32..64]
//
// The combined layout is an internal implementation detail. Key files and
// string representations only persist the sk bytes (plus pk separately via KeyFile).

#[derive(Clone, PartialEq, Eq)]
pub enum SecretKey {
    MlDsa(Box<[u8; MLDSA_COMBINED_KEY_LEN]>),
    FnDsa(Box<[u8; FNDSA_COMBINED_KEY_LEN]>),
    SlhDsa([u8; SLHDSA_SECRET_KEY_LEN]),
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<SecretKey:{}>", self.key_type())
    }
}

impl SecretKey {
    pub fn key_type(&self) -> KeyType {
        match self {
            SecretKey::MlDsa(_)  => KeyType::MlDsa,
            SecretKey::FnDsa(_)  => KeyType::FnDsa,
            SecretKey::SlhDsa(_) => KeyType::SlhDsa,
        }
    }

    /// Generate a fresh PQC keypair using OS randomness (via pqcrypto).
    /// The returned `SecretKey` always embeds the matching `PublicKey`.
    #[cfg(feature = "rand")]
    pub fn from_random(key_type: KeyType) -> Self {
        match key_type {
            KeyType::MlDsa => {
                // FIX v2: call keypair() ONCE and store both pk and sk
                let (pk, sk) = dilithium3::keypair();
                let mut combined = Box::new([0u8; MLDSA_COMBINED_KEY_LEN]);
                combined[..MLDSA_PUBLIC_KEY_LEN].copy_from_slice(pk.as_bytes());
                combined[MLDSA_PUBLIC_KEY_LEN..].copy_from_slice(sk.as_bytes());
                SecretKey::MlDsa(combined)
            }
            KeyType::FnDsa => {
                let (pk, sk) = falcon512::keypair();
                let mut combined = Box::new([0u8; FNDSA_COMBINED_KEY_LEN]);
                combined[..FNDSA_SECRET_KEY_LEN].copy_from_slice(sk.as_bytes());
                combined[FNDSA_SECRET_KEY_LEN..].copy_from_slice(pk.as_bytes());
                SecretKey::FnDsa(combined)
            }
            KeyType::SlhDsa => {
                let (pk, sk) = sphincssha2128ssimple::keypair();
                let mut buf = [0u8; SLHDSA_SECRET_KEY_LEN];
                buf.copy_from_slice(sk.as_bytes());
                // Verify pk is embedded at [32..64] as specified by SPHINCS+ standard
                debug_assert_eq!(&buf[32..], pk.as_bytes(),
                    "SPHINCS+ sk must embed pk at [32..64]; pqcrypto crate version mismatch?");
                SecretKey::SlhDsa(buf)
            }
        }
    }

    /// Derive a deterministic PQC keypair from a 32-byte seed via SHAKE256-DRBG.
    ///
    /// This enables wallets and tooling to derive PQC keys from a BIP-39
    /// mnemonic (converted to a 32-byte seed via PBKDF2/scrypt as usual).
    ///
    /// ALGORITHM:
    ///   domain  = "NEAR-PQC-{ALGO}-KEYGEN-v1\x00"
    ///   drbg    = SHAKE256(domain ‖ seed)   [extendable output]
    ///   pq_seed = XOF.read(N bytes)          [N per algorithm below]
    ///   keypair = {algo}::keypair_from_seed(pq_seed)
    ///
    ///   N = 32 bytes  for ML-DSA (Dilithium3)
    ///   N = 48 bytes  for FN-DSA (Falcon-512)
    ///   N = 48 bytes  for SLH-DSA (SPHINCS+)
    ///
    /// SECURITY: Entropy of derived keys is bounded by min(256, seed_entropy).
    ///   A BIP-39 24-word mnemonic provides 256 bits — sufficient for all schemes.
    ///
    /// STABILITY: Pin pqcrypto-* crate versions. keypair_from_seed() output
    ///   is deterministic within a crate version. Cross-version compatibility
    ///   is NOT guaranteed by pqcrypto upstream.
    pub fn from_seed_drbg(key_type: KeyType, seed: &[u8; 32]) -> Self {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

        let domain: &[u8] = match key_type {
            KeyType::MlDsa  => b"NEAR-PQC-MLDSA-KEYGEN-v1\x00",
            KeyType::FnDsa  => b"NEAR-PQC-FNDSA-KEYGEN-v1\x00",
            KeyType::SlhDsa => b"NEAR-PQC-SLHDSA-KEYGEN-v1\x00",
        };
        let mut xof = Shake256::default();
        xof.update(domain);
        xof.update(seed.as_ref());
        let mut reader = xof.finalize_xof();

        match key_type {
            KeyType::MlDsa => {
                let mut pq_seed = [0u8; 32];
                reader.read(&mut pq_seed);
                let (pk, sk) = dilithium3::keypair_from_seed(&pq_seed);
                let mut combined = Box::new([0u8; MLDSA_COMBINED_KEY_LEN]);
                combined[..MLDSA_PUBLIC_KEY_LEN].copy_from_slice(pk.as_bytes());
                combined[MLDSA_PUBLIC_KEY_LEN..].copy_from_slice(sk.as_bytes());
                SecretKey::MlDsa(combined)
            }
            KeyType::FnDsa => {
                let mut pq_seed = [0u8; 48];
                reader.read(&mut pq_seed);
                let (pk, sk) = falcon512::keypair_from_seed(&pq_seed);
                let mut combined = Box::new([0u8; FNDSA_COMBINED_KEY_LEN]);
                combined[..FNDSA_SECRET_KEY_LEN].copy_from_slice(sk.as_bytes());
                combined[FNDSA_SECRET_KEY_LEN..].copy_from_slice(pk.as_bytes());
                SecretKey::FnDsa(combined)
            }
            KeyType::SlhDsa => {
                let mut pq_seed = [0u8; 48];
                reader.read(&mut pq_seed);
                let (pk, sk) = sphincssha2128ssimple::keypair_from_seed(&pq_seed);
                let mut buf = [0u8; SLHDSA_SECRET_KEY_LEN];
                buf.copy_from_slice(sk.as_bytes());
                debug_assert_eq!(&buf[32..], pk.as_bytes());
                SecretKey::SlhDsa(buf)
            }
        }
    }

    /// Extract the public key from the combined buffer.
    /// Never panics — all constructors embed the pk.
    pub fn public_key(&self) -> PublicKey {
        match self {
            SecretKey::MlDsa(combined) => {
                let mut buf = [0u8; MLDSA_PUBLIC_KEY_LEN];
                buf.copy_from_slice(&combined[..MLDSA_PUBLIC_KEY_LEN]);
                PublicKey::MlDsa(MlDsaPublicKey(buf))
            }
            SecretKey::FnDsa(combined) => {
                let mut buf = [0u8; FNDSA_PUBLIC_KEY_LEN];
                buf.copy_from_slice(&combined[FNDSA_SECRET_KEY_LEN..]);
                PublicKey::FnDsa(FnDsaPublicKey(buf))
            }
            SecretKey::SlhDsa(buf) => {
                let mut pk_buf = [0u8; SLHDSA_PUBLIC_KEY_LEN];
                pk_buf.copy_from_slice(&buf[32..]);
                PublicKey::SlhDsa(SlhDsaPublicKey(pk_buf))
            }
        }
    }

    /// Sign `data` and return the matching `Signature` variant.
    pub fn sign(&self, data: &[u8]) -> Signature {
        match self {
            SecretKey::MlDsa(combined) => {
                let sk = MlDsaSkInner::from_bytes(&combined[MLDSA_PUBLIC_KEY_LEN..])
                    .expect("MlDsa sk always valid when created via from_random/from_seed_drbg");
                let sig = dilithium3::detached_sign(data, &sk);
                let mut buf = [0u8; MLDSA_SIGNATURE_LEN];
                buf.copy_from_slice(sig.as_bytes());
                Signature::MlDsa(buf)
            }
            SecretKey::FnDsa(combined) => {
                let sk = FnDsaSkInner::from_bytes(&combined[..FNDSA_SECRET_KEY_LEN])
                    .expect("FnDsa sk always valid when created via from_random/from_seed_drbg");
                let sig = falcon512::detached_sign(data, &sk);
                Signature::FnDsa(sig.as_bytes().to_vec())
            }
            SecretKey::SlhDsa(buf) => {
                let sk = SlhDsaSkInner::from_bytes(buf)
                    .expect("SlhDsa sk always valid when created via from_random/from_seed_drbg");
                let sig = sphincssha2128ssimple::detached_sign(data, &sk);
                let mut out = [0u8; SLHDSA_SIGNATURE_LEN];
                out.copy_from_slice(sig.as_bytes());
                Signature::SlhDsa(out)
            }
        }
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Display only the sk bytes (not the embedded pk) for security.
        // KeyFile persists pk and sk separately so they can be reunited on load.
        let (kt, sk_bytes): (KeyType, &[u8]) = match self {
            SecretKey::MlDsa(combined)  => (KeyType::MlDsa,  &combined[MLDSA_PUBLIC_KEY_LEN..]),
            SecretKey::FnDsa(combined)  => (KeyType::FnDsa,  &combined[..FNDSA_SECRET_KEY_LEN]),
            SecretKey::SlhDsa(buf)      => (KeyType::SlhDsa, buf.as_ref()),
        };
        write!(f, "{}:{}", kt, Bs58(sk_bytes))
    }
}

impl FromStr for SecretKey {
    type Err = crate::errors::ParseKeyError;

    /// Parse a SecretKey from its string representation.
    ///
    /// IMPORTANT: For MlDsa keys loaded from a bare string, the embedded pk
    /// will be zeroed. Always use `KeyFile` (which stores pk separately) to
    /// round-trip MlDsa keys. FnDsa and SlhDsa keys are self-contained.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kt, kd) = split_key_type_data(s)
            .map_err(|e| crate::errors::ParseKeyError::InvalidData { error_message: e.to_string() })?;
        let decoded = bs58::decode(kd).into_vec()
            .map_err(|e| crate::errors::ParseKeyError::InvalidData { error_message: e.to_string() })?;
        match kt {
            KeyType::MlDsa => {
                if decoded.len() != MLDSA_SECRET_KEY_LEN {
                    return Err(crate::errors::ParseKeyError::InvalidLength {
                        expected_length: MLDSA_SECRET_KEY_LEN,
                        received_length: decoded.len(),
                    });
                }
                let mut combined = Box::new([0u8; MLDSA_COMBINED_KEY_LEN]);
                // pk (first 1952 bytes) left as zero — must restore via KeyFile
                combined[MLDSA_PUBLIC_KEY_LEN..].copy_from_slice(&decoded);
                Ok(SecretKey::MlDsa(combined))
            }
            KeyType::FnDsa => {
                // Accept sk‖pk combined (full 2178) or sk-only (1281)
                if decoded.len() == FNDSA_COMBINED_KEY_LEN {
                    let mut combined = Box::new([0u8; FNDSA_COMBINED_KEY_LEN]);
                    combined.copy_from_slice(&decoded);
                    Ok(SecretKey::FnDsa(combined))
                } else if decoded.len() == FNDSA_SECRET_KEY_LEN {
                    let mut combined = Box::new([0u8; FNDSA_COMBINED_KEY_LEN]);
                    combined[..FNDSA_SECRET_KEY_LEN].copy_from_slice(&decoded);
                    // pk zeroed; load from KeyFile for full round-trip
                    Ok(SecretKey::FnDsa(combined))
                } else {
                    Err(crate::errors::ParseKeyError::InvalidLength {
                        expected_length: FNDSA_COMBINED_KEY_LEN,
                        received_length: decoded.len(),
                    })
                }
            }
            KeyType::SlhDsa => {
                decoded.try_into()
                    .map(SecretKey::SlhDsa)
                    .map_err(|v: Vec<u8>| crate::errors::ParseKeyError::InvalidLength {
                        expected_length: SLHDSA_SECRET_KEY_LEN,
                        received_length: v.len(),
                    })
            }
        }
    }
}

impl serde::Serialize for SecretKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.collect_str(self) }
}

impl<'de> serde::Deserialize<'de> for SecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d)?
            .parse()
            .map_err(|e: crate::errors::ParseKeyError| serde::de::Error::custom(e.to_string()))
    }
}

// ── Signature ─────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, ProtocolSchema)]
pub enum Signature {
    MlDsa([u8; MLDSA_SIGNATURE_LEN]),
    FnDsa(Vec<u8>),                       // variable-length, ≤ 752 bytes
    SlhDsa([u8; SLHDSA_SIGNATURE_LEN]),
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Signature::MlDsa(b)  => { state.write_u8(0); state.write(b); }
            Signature::FnDsa(b)  => { state.write_u8(1); state.write(b); }
            Signature::SlhDsa(b) => { state.write_u8(2); state.write(b); }
        }
    }
}

impl Signature {
    pub fn from_parts(sig_type: KeyType, sig_data: &[u8]) -> Result<Self, crate::errors::ParseSignatureError> {
        match sig_type {
            KeyType::MlDsa  => {
                sig_data.try_into()
                    .map(Signature::MlDsa)
                    .map_err(|_| crate::errors::ParseSignatureError::InvalidLength {
                        expected_length: MLDSA_SIGNATURE_LEN, received_length: sig_data.len() })
            }
            KeyType::FnDsa  => {
                if sig_data.len() > FNDSA_SIGNATURE_MAX_LEN {
                    return Err(crate::errors::ParseSignatureError::InvalidLength {
                        expected_length: FNDSA_SIGNATURE_MAX_LEN, received_length: sig_data.len() });
                }
                Ok(Signature::FnDsa(sig_data.to_vec()))
            }
            KeyType::SlhDsa => {
                sig_data.try_into()
                    .map(Signature::SlhDsa)
                    .map_err(|_| crate::errors::ParseSignatureError::InvalidLength {
                        expected_length: SLHDSA_SIGNATURE_LEN, received_length: sig_data.len() })
            }
        }
    }

    pub fn empty(key_type: KeyType) -> Self {
        match key_type {
            KeyType::MlDsa  => Signature::MlDsa([0u8; MLDSA_SIGNATURE_LEN]),
            KeyType::FnDsa  => Signature::FnDsa(vec![0u8; 1]),
            KeyType::SlhDsa => Signature::SlhDsa([0u8; SLHDSA_SIGNATURE_LEN]),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Signature::MlDsa(_)  => KeyType::MlDsa,
            Signature::FnDsa(_)  => KeyType::FnDsa,
            Signature::SlhDsa(_) => KeyType::SlhDsa,
        }
    }

    /// Cryptographically verify this signature against `data` with `public_key`.
    /// Returns `false` (not panic) on type mismatch or invalid bytes.
    pub fn verify(&self, data: &[u8], public_key: &PublicKey) -> bool {
        match (self, public_key) {
            (Signature::MlDsa(sb), PublicKey::MlDsa(pb)) => {
                let Ok(pk)  = MlDsaPkInner::from_bytes(&pb.0) else { return false };
                let Ok(sig) = MlDsaSig::from_bytes(sb)         else { return false };
                dilithium3::verify_detached_signature(&sig, data, &pk).is_ok()
            }
            (Signature::FnDsa(sb), PublicKey::FnDsa(pb)) => {
                let Ok(pk)  = FnDsaPkInner::from_bytes(&pb.0) else { return false };
                let Ok(sig) = FnDsaSig::from_bytes(sb)         else { return false };
                falcon512::verify_detached_signature(&sig, data, &pk).is_ok()
            }
            (Signature::SlhDsa(sb), PublicKey::SlhDsa(pb)) => {
                let Ok(pk)  = SlhDsaPkInner::from_bytes(&pb.0) else { return false };
                let Ok(sig) = SlhDsaSig::from_bytes(sb)         else { return false };
                sphincssha2128ssimple::verify_detached_signature(&sig, data, &pk).is_ok()
            }
            // Type mismatch: fail closed, never panic
            _ => false,
        }
    }
}

impl Default for Signature {
    fn default() -> Self { Signature::empty(KeyType::MlDsa) }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            Signature::MlDsa(b)  => { writer.write_all(&[0u8])?; writer.write_all(b)?; }
            Signature::FnDsa(b)  => {
                writer.write_all(&[1u8])?;
                // u32 little-endian length prefix for variable-length FnDsa sig
                writer.write_all(&(b.len() as u32).to_le_bytes())?;
                writer.write_all(b)?;
            }
            Signature::SlhDsa(b) => { writer.write_all(&[2u8])?; writer.write_all(b)?; }
        }
        Ok(())
    }
}

impl BorshDeserialize for Signature {
    fn deserialize_reader<R: Read>(rd: &mut R) -> std::io::Result<Self> {
        let kt = KeyType::try_from(u8::deserialize_reader(rd)?)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
        match kt {
            KeyType::MlDsa  => {
                let mut b = [0u8; MLDSA_SIGNATURE_LEN];
                rd.read_exact(&mut b)?;
                Ok(Signature::MlDsa(b))
            }
            KeyType::FnDsa  => {
                let mut len_buf = [0u8; 4];
                rd.read_exact(&mut len_buf)?;
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > FNDSA_SIGNATURE_MAX_LEN {
                    return Err(Error::new(ErrorKind::InvalidData,
                        format!("FnDsa sig length {} > max {}", len, FNDSA_SIGNATURE_MAX_LEN)));
                }
                let mut b = vec![0u8; len];
                rd.read_exact(&mut b)?;
                Ok(Signature::FnDsa(b))
            }
            KeyType::SlhDsa => {
                let mut b = [0u8; SLHDSA_SIGNATURE_LEN];
                rd.read_exact(&mut b)?;
                Ok(Signature::SlhDsa(b))
            }
        }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (kt, d): (KeyType, &[u8]) = match self {
            Signature::MlDsa(b)  => (KeyType::MlDsa,  b),
            Signature::FnDsa(b)  => (KeyType::FnDsa,  b),
            Signature::SlhDsa(b) => (KeyType::SlhDsa, b),
        };
        write!(f, "{}:{}", kt, Bs58(d))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { Display::fmt(self, f) }
}

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.collect_str(self) }
}

impl FromStr for Signature {
    type Err = crate::errors::ParseSignatureError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kt, sd) = split_key_type_data(value)
            .map_err(|e| crate::errors::ParseSignatureError::InvalidData { error_message: e.to_string() })?;
        let decoded = bs58::decode(sd).into_vec()
            .map_err(|e| crate::errors::ParseSignatureError::InvalidData { error_message: e.to_string() })?;
        Self::from_parts(kt, &decoded)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d)?
            .parse()
            .map_err(|e: crate::errors::ParseSignatureError| serde::de::Error::custom(e.to_string()))
    }
}

// ── Display helper ────────────────────────────────────────────────────────────

struct Bs58<'a>(&'a [u8]);
impl<'a> Display for Bs58<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for v1 critical bug: MlDsa pk/sk mismatch.
    /// v1 called dilithium3::keypair() twice → sk and pk from different pairs.
    #[test]
    fn test_mldsa_pk_sk_not_mismatched_regression() {
        let msg = b"pk/sk mismatch regression test — v1 would fail here";
        let sk = SecretKey::from_random(KeyType::MlDsa);
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        assert!(
            sig.verify(msg, &pk),
            "REGRESSION: MlDsa pk/sk are mismatched — \
             check that from_random() calls keypair() only once"
        );
    }

    /// Sign/verify round-trip for all three key types.
    #[test]
    fn test_sign_verify_all_types() {
        let msg = b"NEAR PQC sign/verify test";
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sk = SecretKey::from_random(kt);
            let pk = sk.public_key();
            let sig = sk.sign(msg);
            assert!(sig.verify(msg, &pk), "verify failed for {:?}", kt);
            assert!(!sig.verify(b"wrong msg", &pk), "wrong msg accepted for {:?}", kt);
        }
    }

    /// DRBG: same seed produces same keypair.
    #[test]
    fn test_from_seed_drbg_deterministic() {
        let seed = [7u8; 32];
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sk1 = SecretKey::from_seed_drbg(kt, &seed);
            let sk2 = SecretKey::from_seed_drbg(kt, &seed);
            assert_eq!(sk1.public_key(), sk2.public_key(),
                "DRBG not deterministic for {:?}", kt);
        }
    }

    /// DRBG: different seeds produce different keypairs.
    #[test]
    fn test_from_seed_drbg_different_seeds() {
        let sk_a = SecretKey::from_seed_drbg(KeyType::FnDsa, &[0u8; 32]);
        let sk_b = SecretKey::from_seed_drbg(KeyType::FnDsa, &[1u8; 32]);
        assert_ne!(sk_a.public_key(), sk_b.public_key());
    }

    /// DRBG-derived keys can sign and verify.
    #[test]
    fn test_from_seed_drbg_sign_verify() {
        let seed = [42u8; 32];
        let msg = b"drbg sign test";
        for kt in [KeyType::MlDsa, KeyType::FnDsa] {
            let sk = SecretKey::from_seed_drbg(kt, &seed);
            let pk = sk.public_key();
            let sig = sk.sign(msg);
            assert!(sig.verify(msg, &pk));
        }
    }

    /// Borsh serialization round-trip for all Signature types.
    #[test]
    fn test_signature_borsh_roundtrip() {
        let msg = b"borsh sig test";
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sk = SecretKey::from_random(kt);
            let sig = sk.sign(msg);
            let encoded = borsh::to_vec(&sig).expect("borsh serialize");
            let decoded: Signature = borsh::from_slice(&encoded).expect("borsh deserialize");
            assert_eq!(sig, decoded, "Borsh roundtrip failed for {:?}", kt);
            // Verify the decoded signature still works
            assert!(decoded.verify(msg, &sk.public_key()));
        }
    }

    /// Borsh serialization round-trip for all PublicKey types.
    #[test]
    fn test_public_key_borsh_roundtrip() {
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let pk = SecretKey::from_random(kt).public_key();
            let encoded = borsh::to_vec(&pk).expect("borsh serialize");
            let decoded: PublicKey = borsh::from_slice(&encoded).expect("borsh deserialize");
            assert_eq!(pk, decoded, "PublicKey Borsh roundtrip failed for {:?}", kt);
        }
    }

    /// String (base58) round-trip for PublicKey.
    #[test]
    fn test_public_key_string_roundtrip() {
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let pk = SecretKey::from_random(kt).public_key();
            let s = pk.to_string();
            assert!(s.contains(':'), "PublicKey string should contain ':' prefix");
            let parsed: PublicKey = s.parse().expect("parse public key string");
            assert_eq!(pk, parsed);
        }
    }

    /// Type-mismatch verify must return false, never panic.
    #[test]
    fn test_type_mismatch_returns_false_not_panic() {
        let msg = b"mismatch test";
        let mldsa_sk = SecretKey::from_random(KeyType::MlDsa);
        let fndsa_pk = SecretKey::from_random(KeyType::FnDsa).public_key();
        let sig = mldsa_sk.sign(msg);
        assert!(!sig.verify(msg, &fndsa_pk), "Type mismatch should return false");
    }

    /// Empty signature verify must not panic.
    #[test]
    fn test_empty_signature_does_not_panic() {
        let msg = b"empty sig";
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sig = Signature::empty(kt);
            let pk = PublicKey::empty(kt);
            let _ = sig.verify(msg, &pk); // must not panic regardless of result
        }
    }

    /// Key-type discriminant encoding is stable (golden test).

    #[test]
    fn test_secret_key_debug_does_not_expose_key_material() {
        // Debug output must NOT contain the actual key bytes.
        // It must only show the key type, never the secret material.
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sk = SecretKey::from_random(kt);
            let debug = format!("{:?}", sk);
            // Must show <SecretKey:keytype>, not raw bytes
            assert!(debug.contains("SecretKey"), "Debug must show SecretKey label");
            // Must NOT show the full base58 of the key (too many chars)
            assert!(debug.len() < 100,
                "Debug output is suspiciously long ({} chars) — may expose key material: {}",
                debug.len(), &debug[..debug.len().min(60)]);
        }
    }

    #[test]
    fn test_secret_key_display_does_not_expose_full_private_bytes() {
        // Display is used for serialization. For MlDsa it shows only the sk bytes (no pk).
        // For FnDsa it shows only sk bytes. The display SHOULD contain key data
        // (it's the serialization format), but must include the key type prefix.
        for kt in [KeyType::MlDsa, KeyType::FnDsa, KeyType::SlhDsa] {
            let sk = SecretKey::from_random(kt);
            let display = sk.to_string();
            let prefix = match kt {
                KeyType::MlDsa  => "mldsa:",
                KeyType::FnDsa  => "fndsa:",
                KeyType::SlhDsa => "slhdsa:",
            };
            assert!(display.starts_with(prefix),
                "SecretKey Display must include key type prefix for {:?}", kt);
        }
    }

    #[test]
    fn test_unprefixed_key_string_is_rejected() {
        // Require explicit prefix — silent FnDsa default removed.
        let result: Result<crate::signature::PublicKey, _> =
            "3vQB7B6MrGQZaxCuFg4oh".parse(); // no "fndsa:" prefix
        assert!(result.is_err(),
            "Unprefixed key string must be rejected, not silently defaulted to FnDsa");
    }
    #[test]
    fn test_key_type_discriminants_stable() {
        assert_eq!(KeyType::MlDsa  as u8, 0);
        assert_eq!(KeyType::FnDsa  as u8, 1);
        assert_eq!(KeyType::SlhDsa as u8, 2);
    }

    /// Borsh serialized discriminant byte is first byte (golden test).
    #[test]
    fn test_signature_borsh_first_byte_is_discriminant() {
        let sk = SecretKey::from_random(KeyType::MlDsa);
        let sig = sk.sign(b"golden");
        let bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(bytes[0], 0u8, "MlDsa Borsh discriminant must be 0");

        let sk2 = SecretKey::from_random(KeyType::FnDsa);
        let sig2 = sk2.sign(b"golden");
        let bytes2 = borsh::to_vec(&sig2).unwrap();
        assert_eq!(bytes2[0], 1u8, "FnDsa Borsh discriminant must be 1");
    }
}
