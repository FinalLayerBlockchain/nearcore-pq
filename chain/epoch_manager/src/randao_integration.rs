/// PQC-NEAR: chain/epoch_manager/src/randao_integration.rs
///
/// Integrates the RANDAO commit-reveal scheme into NEAR's EpochManager.
///
/// v3 (hardened): Uses real hash commitments (not reveal values).
///   - commitments store RandaoCommit, not RandaoValue
///   - Missing pre-commit is REJECTED (Err), not accepted-and-flagged
///   - Duplicate reveal for the same slot is REJECTED
///   - XORs the randao_output_hash into the accumulator (not the nonce)

use near_primitives::vrf_replacement::{
    RandaoReveal, RandaoCommit, RandaoValue, RandaoNonce,
    EpochRandaoCommitments, ValidatorCommitment, RandaoError,
    make_randao_commitment, make_randao_reveal, verify_randao_reveal,
    randao_output_hash,
};
use near_crypto::{PublicKey, SecretKey};
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::HashMap;

// ── RANDAO state per epoch ─────────────────────────────────────────────────────

/// Accumulated RANDAO state for a running epoch.
/// Stored in EpochManager alongside other epoch data.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct EpochRandaoState {
    pub epoch_id: [u8; 32],
    /// The running XOR accumulator — starts at 0, updated each block.
    pub accumulated: RandaoValue,
    /// Hash commitments from validators at epoch start.
    ///
    /// Map: validator_account_id → (block_height → RandaoCommit)
    ///
    /// The stored value is the COMMIT (hash of pk+epoch+height+nonce),
    /// NOT the future reveal value. The nonce is kept secret by the validator.
    pub commitments: HashMap<String, HashMap<u64, RandaoCommit>>,
    /// Revealed slots — used to detect non-revealers (slash candidates)
    /// and to reject duplicate reveals.
    pub revealed_slots: HashMap<u64, String>, // slot → validator_account_id
}

impl EpochRandaoState {
    pub fn new(epoch_id: [u8; 32]) -> Self {
        Self {
            epoch_id,
            accumulated: RandaoValue::default(),
            commitments: HashMap::new(),
            revealed_slots: HashMap::new(),
        }
    }

    /// Register a validator's pre-commitments at epoch start.
    ///
    /// `slot_commits` is Vec<(block_height, RandaoCommit)> where each commit
    /// = H("FL-RANDAO-COMMIT-v3" ‖ pk ‖ epoch ‖ height ‖ nonce).
    /// The nonce stays secret with the validator until reveal time.
    pub fn register_commitments(
        &mut self,
        validator_id: String,
        slot_commits: Vec<(u64, RandaoCommit)>,
    ) {
        let map: HashMap<u64, RandaoCommit> = slot_commits.into_iter().collect();
        self.commitments.insert(validator_id, map);
    }

    /// Process a block's RANDAO reveal.
    ///
    /// Hardened rules:
    ///   1. Reject duplicate reveal for the same slot.
    ///   2. Require a registered pre-commitment — missing commit = Err.
    ///   3. Verify the reveal signature.
    ///   4. Verify the nonce matches the stored commitment hash.
    ///   5. XOR the output (derived from nonce, different domain from commit)
    ///      into the accumulator.
    ///
    /// Returns the new accumulated random_value (goes into the block header).
    pub fn process_reveal(
        &mut self,
        block_height: u64,
        reveal: &RandaoReveal,
        validator_id: &str,
        validator_public_key: &PublicKey,
    ) -> Result<RandaoValue, RandaoError> {
        // Rule 1: reject duplicate reveals
        if self.revealed_slots.contains_key(&block_height) {
            return Err(RandaoError::DuplicateReveal { block_height });
        }

        // Rule 2: require a registered pre-commitment — no fallback
        let expected_commit: RandaoCommit = self.commitments
            .get(validator_id)
            .and_then(|slots| slots.get(&block_height))
            .copied()
            .ok_or(RandaoError::MissingPreCommitment)?;

        // Rules 3 + 4: verify sig and nonce-to-commit match; derive output
        let output = verify_randao_reveal(
            reveal,
            validator_public_key,
            &self.epoch_id,
            block_height,
            &expected_commit,
        )?;

        // Accumulate the output (not the nonce) into the running random value
        self.accumulated = self.accumulated.xor(&output);
        self.revealed_slots.insert(block_height, validator_id.to_string());

        Ok(self.accumulated)
    }

    /// Returns the list of expected-but-missing reveals (slash candidates).
    /// Called at epoch end.
    pub fn non_revealers(&self, expected_slots: &[(u64, String)]) -> Vec<(u64, String)> {
        expected_slots.iter()
            .filter(|(slot, validator)| {
                !self.revealed_slots.contains_key(slot)
                    || self.revealed_slots.get(slot) != Some(validator)
            })
            .cloned()
            .collect()
    }
}

// ── VRF call site replacement ─────────────────────────────────────────────────
//
// NEAR's block producer previously called:
//   let (vrf_value, vrf_proof) = signer.compute_vrf_with_proof(prev_random_value.as_ref());
//   header.random_value = CryptoHash::hash_bytes(vrf_value.0.as_ref());
//
// Replace with (at epoch start, per assigned slot):
//   let (slot, commit, _nonce) = make_randao_commitment(
//       &signer.secret_key, &signer.public_key(), &epoch_id_bytes, slot);
//   epoch_randao_state.register_commitments(validator_id, vec![(slot, commit)]);
//
// And at block production time:
//   let reveal = make_randao_reveal(&signer.secret_key, &epoch_id_bytes, block_height);
//   let new_random = epoch_randao_state.process_reveal(
//       block_height, &reveal, &validator_id, &signer.public_key()
//   )?;
//   header.random_value = CryptoHash::from(new_random.0);
//   header.randao_reveal = Some(reveal);

/// Compute the new block random_value given the previous value and a new reveal.
/// Pure function — no EpochRandaoState mutation — for use in stateless block validation.
///
/// `expected_commit` must be retrieved from the epoch manager's stored commitments
/// for this (validator, block_height) pair. Returns an error if commit mismatch.
pub fn compute_block_random_value(
    prev_random_value: &RandaoValue,
    reveal: &RandaoReveal,
    validator_public_key: &PublicKey,
    epoch_id: &[u8; 32],
    block_height: u64,
    expected_commit: &RandaoCommit,
) -> Result<RandaoValue, RandaoError> {
    let output = verify_randao_reveal(reveal, validator_public_key, epoch_id, block_height, expected_commit)?;
    Ok(prev_random_value.xor(&output))
}

// ── Slashing integration ──────────────────────────────────────────────────────

/// A slash evidence record for a validator who failed to reveal or revealed incorrectly.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RandaoSlashEvidence {
    pub epoch_id: [u8; 32],
    pub block_height: u64,
    pub validator_account_id: String,
    pub stored_commit: RandaoCommit,
    pub slash_reason: RandaoSlashReason,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum RandaoSlashReason {
    /// Validator did not produce their assigned block and thus did not reveal.
    FailedToReveal,
    /// Validator's revealed nonce did not match their pre-commitment.
    InvalidReveal { received_nonce: RandaoNonce },
    /// Validator skipped the pre-commitment phase entirely.
    MissingPreCommitment,
    /// Validator attempted to reveal the same slot twice.
    DuplicateReveal,
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::{InMemorySigner, KeyType};

    fn make_validator(name: &str) -> InMemorySigner {
        InMemorySigner::from_random(name.parse().unwrap(), KeyType::FNDSA)
    }

    #[test]
    fn test_epoch_randao_accumulates_correctly() {
        let epoch_id = [1u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v1 = make_validator("v1.near");
        let v2 = make_validator("v2.near");

        // Register hash commitments at epoch start
        let (_, c1, _) = make_randao_commitment(&v1.secret_key, &v1.public_key(), &epoch_id, 100);
        let (_, c2, _) = make_randao_commitment(&v2.secret_key, &v2.public_key(), &epoch_id, 101);
        state.register_commitments("v1.near".to_string(), vec![(100, c1)]);
        state.register_commitments("v2.near".to_string(), vec![(101, c2)]);

        // Reveals at block time
        let reveal1 = make_randao_reveal(&v1.secret_key, &epoch_id, 100);
        let reveal2 = make_randao_reveal(&v2.secret_key, &epoch_id, 101);

        let out1 = verify_randao_reveal(&reveal1, &v1.public_key(), &epoch_id, 100, &c1).unwrap();
        let out2 = verify_randao_reveal(&reveal2, &v2.public_key(), &epoch_id, 101, &c2).unwrap();

        let new_random1 = state.process_reveal(100, &reveal1, "v1.near", &v1.public_key()).unwrap();
        let new_random2 = state.process_reveal(101, &reveal2, "v2.near", &v2.public_key()).unwrap();

        let expected1 = RandaoValue::default().xor(&out1);
        let expected2 = expected1.xor(&out2);

        assert_eq!(new_random1, expected1);
        assert_eq!(new_random2, expected2);
        assert_eq!(state.accumulated, expected2);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let epoch_id = [2u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v1 = make_validator("v1.near");
        let v2 = make_validator("v2.near");

        let (_, c1, _) = make_randao_commitment(&v1.secret_key, &v1.public_key(), &epoch_id, 100);
        state.register_commitments("v1.near".to_string(), vec![(100, c1)]);

        let reveal = make_randao_reveal(&v1.secret_key, &epoch_id, 100);
        // Verify with v2's public key — must fail
        let result = state.process_reveal(100, &reveal, "v1.near", &v2.public_key());
        assert!(matches!(result, Err(RandaoError::InvalidSignature)));
    }

    /// Missing pre-commitment must be REJECTED, not accepted.
    #[test]
    fn test_reveal_without_precommit_rejected() {
        let epoch_id = [4u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v = make_validator("v.near");
        // No pre-commitment registered for this validator/slot
        let reveal = make_randao_reveal(&v.secret_key, &epoch_id, 200);

        let result = state.process_reveal(200, &reveal, "v.near", &v.public_key());
        assert!(
            matches!(result, Err(RandaoError::MissingPreCommitment)),
            "reveal without pre-commitment must be rejected with MissingPreCommitment"
        );
    }

    /// Duplicate reveal for the same slot must be REJECTED.
    #[test]
    fn test_duplicate_reveal_rejected() {
        let epoch_id = [6u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v = make_validator("v.near");
        let (_, commit, _) = make_randao_commitment(&v.secret_key, &v.public_key(), &epoch_id, 100);
        state.register_commitments("v.near".to_string(), vec![(100, commit)]);

        let reveal = make_randao_reveal(&v.secret_key, &epoch_id, 100);
        // First reveal succeeds
        assert!(state.process_reveal(100, &reveal, "v.near", &v.public_key()).is_ok());
        // Second reveal for same slot must fail
        let result = state.process_reveal(100, &reveal, "v.near", &v.public_key());
        assert!(
            matches!(result, Err(RandaoError::DuplicateReveal { block_height: 100 })),
            "duplicate reveal for the same slot must be rejected"
        );
    }

    /// Wrong reveal nonce must fail commitment check.
    #[test]
    fn test_wrong_reveal_value_rejected() {
        let epoch_id = [3u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v = make_validator("v.near");
        let (_, commit, _) = make_randao_commitment(&v.secret_key, &v.public_key(), &epoch_id, 100);
        state.register_commitments("v.near".to_string(), vec![(100, commit)]);

        // Attacker uses their own sk to make a reveal for slot 100
        // (they sign correctly with their own key, but nonce mismatch is secondary;
        //  the primary failure is InvalidSignature since it's the wrong signer)
        let attacker = make_validator("attacker.near");
        let bad_reveal = make_randao_reveal(&attacker.secret_key, &epoch_id, 100);
        let result = state.process_reveal(100, &bad_reveal, "v.near", &attacker.public_key());
        // Fails: commit was computed with v's public key, verification uses attacker's pk
        assert!(result.is_err());
    }

    #[test]
    fn test_non_revealers_detected() {
        let epoch_id = [5u8; 32];
        let mut state = EpochRandaoState::new(epoch_id);

        let v1 = make_validator("v1.near");
        let (_, c1, _) = make_randao_commitment(&v1.secret_key, &v1.public_key(), &epoch_id, 100);
        state.register_commitments("v1.near".to_string(), vec![(100, c1)]);

        let reveal = make_randao_reveal(&v1.secret_key, &epoch_id, 100);
        state.process_reveal(100, &reveal, "v1.near", &v1.public_key()).unwrap();
        // slot 101 never revealed

        let expected_slots = vec![
            (100, "v1.near".to_string()),
            (101, "v2.near".to_string()),
        ];
        let missing = state.non_revealers(&expected_slots);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, 101);
        assert_eq!(missing[0].1, "v2.near");
    }

    #[test]
    fn test_compute_block_random_value() {
        let epoch_id = [6u8; 32];
        let v = make_validator("v.near");
        let prev = RandaoValue([42u8; 32]);

        let (_, commit, _) = make_randao_commitment(&v.secret_key, &v.public_key(), &epoch_id, 200);
        let reveal = make_randao_reveal(&v.secret_key, &epoch_id, 200);
        let output = verify_randao_reveal(&reveal, &v.public_key(), &epoch_id, 200, &commit).unwrap();

        let new_random = compute_block_random_value(&prev, &reveal, &v.public_key(), &epoch_id, 200, &commit).unwrap();
        assert_eq!(new_random, prev.xor(&output));
    }

    #[test]
    fn test_slash_evidence_borsh_roundtrip() {
        let evidence = RandaoSlashEvidence {
            epoch_id: [1u8; 32],
            block_height: 500,
            validator_account_id: "bad-validator.near".to_string(),
            stored_commit: RandaoCommit([0xAAu8; 32]),
            slash_reason: RandaoSlashReason::FailedToReveal,
        };
        let encoded = borsh::to_vec(&evidence).unwrap();
        let decoded: RandaoSlashEvidence = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.block_height, 500);
        assert_eq!(decoded.validator_account_id, "bad-validator.near");
    }
}
