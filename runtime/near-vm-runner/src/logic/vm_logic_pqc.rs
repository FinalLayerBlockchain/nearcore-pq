/// PQC-NEAR: runtime/near-vm-runner/src/logic/vm_logic_pqc.rs
///
/// VMLogic adapter and host-function shims for PQC signature verification.
/// Implements PqcHostContext for VmLogicPqcAdapter so pqc_host_fns
/// can be called from the Wasmer/Wasmtime import tables.

use crate::logic::pqc_host_fns::{self, HostError, PqcHostContext};
use near_crypto::signature::{
    MLDSA_PUBLIC_KEY_LEN, MLDSA_SIGNATURE_LEN,
    FNDSA_PUBLIC_KEY_LEN, FNDSA_SIGNATURE_MAX_LEN,
    SLHDSA_PUBLIC_KEY_LEN, SLHDSA_SIGNATURE_LEN,
};

// ── Error mapping ─────────────────────────────────────────────────────────────

/// Errors returned by PQC host functions — maps into the WASM runtime trap system.
#[derive(Debug, thiserror::Error)]
pub enum VmPqcError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Memory access violation: ptr={ptr} len={len}")]
    MemoryAccessViolation { ptr: u64, len: u64 },
    #[error("Invalid host function argument: {0}")]
    InvalidArgument(String),
    #[error("Host function deprecated at this protocol version")]
    Deprecated,
}

impl From<HostError> for VmPqcError {
    fn from(e: HostError) -> Self {
        match e {
            HostError::OutOfGas => VmPqcError::OutOfGas,
            HostError::MemoryOutOfBounds { ptr, len } =>
                VmPqcError::MemoryAccessViolation { ptr, len },
            HostError::InvalidParameter(msg) => VmPqcError::InvalidArgument(msg),
            HostError::Deprecated { .. } => VmPqcError::Deprecated,
            _ => VmPqcError::InvalidArgument(e.to_string()),
        }
    }
}

// ── VmLogicPqcAdapter ─────────────────────────────────────────────────────────
//
// Wraps the VMLogic memory slice and gas counter into the PqcHostContext trait.
// In the real nearcore VMLogic, this adapter is replaced by a direct blanket
// impl on the VMLogic struct using its existing memory/gas infrastructure.

pub struct VmLogicPqcAdapter<'a> {
    memory: &'a [u8],
    gas_remaining: &'a mut u64,
    protocol_version: u32,
}

impl<'a> VmLogicPqcAdapter<'a> {
    pub fn new(memory: &'a [u8], gas: &'a mut u64, protocol_version: u32) -> Self {
        Self { memory, gas_remaining: gas, protocol_version }
    }
}

impl<'a> PqcHostContext for VmLogicPqcAdapter<'a> {
    fn prepay_gas(&mut self, gas: u64) -> Result<(), HostError> {
        *self.gas_remaining = self.gas_remaining
            .checked_sub(gas)
            .ok_or(HostError::OutOfGas)?;
        Ok(())
    }

    fn read_memory(&self, ptr: u64, len: u64) -> Result<Vec<u8>, HostError> {
        let start = ptr as usize;
        let end = start.checked_add(len as usize)
            .filter(|&e| e <= self.memory.len())
            .ok_or(HostError::MemoryOutOfBounds { ptr, len })?;
        Ok(self.memory[start..end].to_vec())
    }

    fn protocol_version(&self) -> u32 { self.protocol_version }
}

// ── Input validation ──────────────────────────────────────────────────────────
//
// All host function args arrive as i64 from WASM (WASM has no unsigned types).
// We reject negative values explicitly before any cast to u64, preventing
// sign-extension from producing absurdly large pointer values.

fn validate_wasm_u64(v: i64, name: &str) -> Result<u64, VmPqcError> {
    if v < 0 {
        return Err(VmPqcError::InvalidArgument(
            format!("{} must be non-negative, got {}", name, v)
        ));
    }
    Ok(v as u64)
}

// ── Host function shims ───────────────────────────────────────────────────────
//
// These three functions are registered with the Wasmer/Wasmtime import table
// in the runtime's import registry (imports.rs). The signature matches the
// WASM ABI: all arguments are i64, return is i64.
//
// Return values:
//   1i64  — signature is valid
//   0i64  — signature is invalid (wrong key, wrong message, bad bytes)
//   Err   — VM trap (out of gas, OOB memory, invalid argument)
//
// Callers should treat Err as a WASM trap, not a soft error.

/// mldsa_verify — ML-DSA (Dilithium3 / FIPS 204) signature verification.
///
/// sig_len must equal MLDSA_SIGNATURE_LEN (3293). Other lengths are trapped.
/// Gas charged upfront: MLDSA_VERIFY_BASE_GAS + msg_len * MLDSA_VERIFY_BYTE_GAS
pub fn mldsa_verify(
    memory: &[u8],
    gas: &mut u64,
    protocol_version: u32,
    sig_len: i64, sig_ptr: i64,
    msg_len: i64, msg_ptr: i64,
    pk_ptr:  i64,
) -> Result<i64, VmPqcError> {
    // Reject negative args before any u64 cast
    let sig_len = validate_wasm_u64(sig_len, "sig_len")?;
    let sig_ptr = validate_wasm_u64(sig_ptr, "sig_ptr")?;
    let msg_len = validate_wasm_u64(msg_len, "msg_len")?;
    let msg_ptr = validate_wasm_u64(msg_ptr, "msg_ptr")?;
    let pk_ptr  = validate_wasm_u64(pk_ptr,  "pk_ptr")?;

    let mut adapter = VmLogicPqcAdapter::new(memory, gas, protocol_version);
    pqc_host_fns::mldsa_verify(&mut adapter, sig_len, sig_ptr, msg_len, msg_ptr, pk_ptr)
        .map(|v| v as i64)
        .map_err(VmPqcError::from)
}

/// fndsa_verify — FN-DSA (Falcon-512 / FIPS 206) signature verification.
///
/// sig_len must be 1..=FNDSA_SIGNATURE_MAX_LEN (752). Other lengths are trapped.
/// Gas charged upfront: FNDSA_VERIFY_BASE_GAS + msg_len * FNDSA_VERIFY_BYTE_GAS
pub fn fndsa_verify(
    memory: &[u8],
    gas: &mut u64,
    protocol_version: u32,
    sig_len: i64, sig_ptr: i64,
    msg_len: i64, msg_ptr: i64,
    pk_ptr:  i64,
) -> Result<i64, VmPqcError> {
    let sig_len = validate_wasm_u64(sig_len, "sig_len")?;
    let sig_ptr = validate_wasm_u64(sig_ptr, "sig_ptr")?;
    let msg_len = validate_wasm_u64(msg_len, "msg_len")?;
    let msg_ptr = validate_wasm_u64(msg_ptr, "msg_ptr")?;
    let pk_ptr  = validate_wasm_u64(pk_ptr,  "pk_ptr")?;

    let mut adapter = VmLogicPqcAdapter::new(memory, gas, protocol_version);
    pqc_host_fns::fndsa_verify(&mut adapter, sig_len, sig_ptr, msg_len, msg_ptr, pk_ptr)
        .map(|v| v as i64)
        .map_err(VmPqcError::from)
}

/// slhdsa_verify — SLH-DSA (SPHINCS+-SHA2-128s / FIPS 205) signature verification.
///
/// sig_len must equal SLHDSA_SIGNATURE_LEN (7856). Other lengths are trapped.
/// Gas charged upfront: SLHDSA_VERIFY_BASE_GAS + msg_len * SLHDSA_VERIFY_BYTE_GAS
pub fn slhdsa_verify(
    memory: &[u8],
    gas: &mut u64,
    protocol_version: u32,
    sig_len: i64, sig_ptr: i64,
    msg_len: i64, msg_ptr: i64,
    pk_ptr:  i64,
) -> Result<i64, VmPqcError> {
    let sig_len = validate_wasm_u64(sig_len, "sig_len")?;
    let sig_ptr = validate_wasm_u64(sig_ptr, "sig_ptr")?;
    let msg_len = validate_wasm_u64(msg_len, "msg_len")?;
    let msg_ptr = validate_wasm_u64(msg_ptr, "msg_ptr")?;
    let pk_ptr  = validate_wasm_u64(pk_ptr,  "pk_ptr")?;

    let mut adapter = VmLogicPqcAdapter::new(memory, gas, protocol_version);
    pqc_host_fns::slhdsa_verify(&mut adapter, sig_len, sig_ptr, msg_len, msg_ptr, pk_ptr)
        .map(|v| v as i64)
        .map_err(VmPqcError::from)
}

// ── Wasmer registration ───────────────────────────────────────────────────────
//
// In the nearcore Wasmer runner (wasmer_runner.rs), add the following to the
// import object builder, replacing ed25519_verify at protocol version >= 999.
// Each host function propagates VmPqcError through the runtime's trap path.
//
// Example (expand into the real import builder):
//
//   register_host_fn!(store, env, "mldsa_verify",
//       |ctx, sig_len: i64, sig_ptr: i64, msg_len: i64, msg_ptr: i64, pk_ptr: i64| -> i64 {
//           let data = ctx.data_mut();
//           match mldsa_verify(&data.memory, &mut data.gas, data.protocol_version,
//                              sig_len, sig_ptr, msg_len, msg_ptr, pk_ptr) {
//               Ok(result) => result,
//               Err(VmPqcError::OutOfGas) => return runtime_trap!(GasExceeded),
//               Err(VmPqcError::MemoryAccessViolation{..}) => return runtime_trap!(MemoryAccessViolation),
//               Err(e) => return runtime_trap!(GuestPanic { msg: e.to_string() }),
//           }
//       }
//   );

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::{KeyType, SecretKey};

    fn sign_and_layout(kt: KeyType, msg: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let sk = SecretKey::from_random(kt);
        let pk = sk.public_key();
        let sig = sk.sign(msg);
        let sig_bytes = match &sig {
            near_crypto::Signature::MlDsa(b) => b.to_vec(),
            near_crypto::Signature::FnDsa(b) => b.clone(),
            near_crypto::Signature::SlhDsa(b) => b.to_vec(),
        };
        (sig_bytes, msg.to_vec(), pk.key_data().to_vec())
    }

    fn make_memory(parts: &[&[u8]]) -> (Vec<u8>, Vec<usize>) {
        let mut mem = Vec::new();
        let mut offsets = Vec::new();
        for part in parts {
            offsets.push(mem.len());
            mem.extend_from_slice(part);
        }
        mem.resize(mem.len() + 64, 0); // guard bytes
        (mem, offsets)
    }

    #[test]
    fn test_mldsa_valid_signature() {
        let msg = b"vm_logic_pqc mldsa test";
        let (sig_b, msg_b, pk_b) = sign_and_layout(KeyType::MlDsa, msg);
        let (mem, off) = make_memory(&[&sig_b, &msg_b, &pk_b]);
        let mut gas = u64::MAX;
        let result = mldsa_verify(&mem, &mut gas, 999,
            MLDSA_SIGNATURE_LEN as i64, off[0] as i64,
            msg_b.len() as i64, off[1] as i64,
            off[2] as i64).unwrap();
        assert_eq!(result, 1i64);
        assert!(gas < u64::MAX, "gas must be deducted");
    }

    #[test]
    fn test_fndsa_valid_signature() {
        let msg = b"vm_logic_pqc fndsa test";
        let (sig_b, msg_b, pk_b) = sign_and_layout(KeyType::FnDsa, msg);
        let (mem, off) = make_memory(&[&sig_b, &msg_b, &pk_b]);
        let mut gas = u64::MAX;
        let result = fndsa_verify(&mem, &mut gas, 999,
            sig_b.len() as i64, off[0] as i64,
            msg_b.len() as i64, off[1] as i64,
            off[2] as i64).unwrap();
        assert_eq!(result, 1i64);
    }

    #[test]
    fn test_negative_sig_len_is_trapped() {
        let mem = vec![0u8; 4096];
        let mut gas = u64::MAX;
        let result = mldsa_verify(&mem, &mut gas, 999, -1, 0, 4, 0, 100);
        assert!(matches!(result, Err(VmPqcError::InvalidArgument(_))),
            "Negative sig_len must trap, not silently cast");
    }

    #[test]
    fn test_negative_ptr_is_trapped() {
        let mem = vec![0u8; 4096];
        let mut gas = u64::MAX;
        let result = mldsa_verify(&mem, &mut gas, 999,
            MLDSA_SIGNATURE_LEN as i64, -100, 4, 0, 0);
        assert!(matches!(result, Err(VmPqcError::InvalidArgument(_))),
            "Negative ptr must trap before memory access");
    }

    #[test]
    fn test_out_of_gas_maps_to_typed_error() {
        let mem = vec![0u8; 4096];
        let mut gas = 0u64;
        let result = mldsa_verify(&mem, &mut gas, 999,
            MLDSA_SIGNATURE_LEN as i64, 0, 4, 0, 100);
        assert!(matches!(result, Err(VmPqcError::OutOfGas)));
    }

    #[test]
    fn test_memory_oob_maps_to_typed_error() {
        let mem = vec![0u8; 64];
        let mut gas = u64::MAX;
        let result = mldsa_verify(&mem, &mut gas, 999,
            MLDSA_SIGNATURE_LEN as i64, 50000, 4, 0, 0);
        assert!(matches!(result, Err(VmPqcError::MemoryAccessViolation { .. })));
    }

    #[test]
    fn test_gas_deducted_correctly() {
        let msg = b"gas test";
        let (sig_b, msg_b, pk_b) = sign_and_layout(KeyType::MlDsa, msg);
        let (mem, off) = make_memory(&[&sig_b, &msg_b, &pk_b]);
        let initial = 100_000_000_000_000u64;
        let mut gas = initial;
        mldsa_verify(&mem, &mut gas, 999,
            MLDSA_SIGNATURE_LEN as i64, off[0] as i64,
            msg_b.len() as i64, off[1] as i64,
            off[2] as i64).unwrap();
        let expected = 2_100_000_000_000u64 + msg_b.len() as u64 * 5_000_000;
        assert_eq!(initial - gas, expected);
    }

    #[test]
    fn test_wrong_message_returns_zero_not_error() {
        let (sig_b, _, pk_b) = sign_and_layout(KeyType::FnDsa, b"correct");
        let wrong_msg = b"wrong message here";
        let (mem, off) = make_memory(&[&sig_b, wrong_msg, &pk_b]);
        let mut gas = u64::MAX;
        let result = fndsa_verify(&mem, &mut gas, 999,
            sig_b.len() as i64, off[0] as i64,
            wrong_msg.len() as i64, off[1] as i64,
            off[2] as i64).unwrap();
        assert_eq!(result, 0i64, "Wrong message must return 0, not trap");
    }
}
