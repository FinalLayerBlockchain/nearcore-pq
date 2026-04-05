use crate::Error;
use near_crypto::PublicKey;
use near_primitives::account::{AccessKey, AccessKeyPermission, Account};
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, Nonce, NonceIndex};
use near_store::{TrieAccess, get_access_key, get_account, get_gas_key_nonce};
use std::collections::HashMap;
use std::collections::hash_map::Entry;

/// Per-(account, public_key) state in the overlay.
pub(crate) struct KeyEntry {
    pub access_key: AccessKey,
    pub gas_key_nonces: HashMap<NonceIndex, Nonce>,
}

/// Per-account state in the overlay: the account itself plus per-key entries.
struct AccountEntry {
    account: Account,
    keys: HashMap<PublicKey, KeyEntry>,
}

/// Ephemeral overlay for signer account and access key data during a single
/// `prepare_transactions` call. Loads from the trie on first access and
/// accumulates mutations (balance deductions, nonce increments) locally
/// without writing back to the trie.
///
/// Account state is keyed by `AccountId` alone so that multiple public keys
/// for the same account share one account state (e.g., balance), preventing
/// double-spend across those keys.
pub(crate) struct SignerOverlay {
    entries: HashMap<AccountId, AccountEntry>,
}

impl SignerOverlay {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Returns the current nonce from the overlay if available. For gas key
    /// transactions (nonce_index is Some), returns the gas key nonce;
    /// otherwise returns the access key nonce. Returns `None` on cache miss.
    pub fn cached_nonce(
        &self,
        account_id: &AccountId,
        public_key: &PublicKey,
        nonce_index: Option<NonceIndex>,
    ) -> Option<Nonce> {
        let key_entry = self.entries.get(account_id)?.keys.get(public_key)?;
        if let Some(idx) = nonce_index {
            key_entry.gas_key_nonces.get(&idx).copied()
        } else {
            Some(key_entry.access_key.nonce)
        }
    }

    /// Returns mutable references to the account and per-key state, loading
    /// from the trie on first access.
    pub fn get_or_load_entry_mut(
        &mut self,
        trie: &dyn TrieAccess,
        account_id: &AccountId,
        public_key: &PublicKey,
        nonce_index: Option<NonceIndex>,
    ) -> Result<(&mut Account, &mut KeyEntry), Error> {
        // Ensure the account is loaded.
        let entry = match self.entries.entry(account_id.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let account = get_account(trie, account_id)
                    .map_err(|_| Error::InvalidTransactions)?
                    .ok_or(Error::InvalidTransactions)?;
                entry.insert(AccountEntry { account, keys: HashMap::new() })
            }
        };

        // Destructure to split the borrow between account and keys.
        let AccountEntry { account, keys } = entry;

        // Ensure the key entry is loaded.
        let key_entry = match keys.entry(public_key.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let access_key = match get_access_key(trie, account_id, public_key)
                    .map_err(|_| Error::InvalidTransactions)?
                {
                    Some(ak) => ak,
                    None => {
                        // PQC hex implicit: account_id == hex(sha256(pk_bytes))
                        let signer_str = account_id.as_str();
                        if signer_str.len() == 64 {
                            let mut hash_bytes = [0u8; 32];
                            let decoded = signer_str.as_bytes().chunks(2).enumerate().all(|(i, chunk)| {
                                let hi = (chunk[0] as char).to_digit(16);
                                let lo = (chunk[1] as char).to_digit(16);
                                if let (Some(h), Some(l)) = (hi, lo) {
                                    hash_bytes[i] = (h << 4 | l) as u8;
                                    true
                                } else { false }
                            });
                            if decoded && CryptoHash::hash_bytes(public_key.key_data()).0 == hash_bytes {
                                AccessKey { nonce: 0, permission: AccessKeyPermission::FullAccess }
                            } else {
                                return Err(Error::InvalidTransactions);
                            }
                        } else {
                            return Err(Error::InvalidTransactions);
                        }
                    }
                };
                entry.insert(KeyEntry { access_key, gas_key_nonces: HashMap::new() })
            }
        };

        // Ensure the requested gas key nonce is loaded.
        if let Some(idx) = nonce_index {
            if let Entry::Vacant(e) = key_entry.gas_key_nonces.entry(idx) {
                let nonce = get_gas_key_nonce(trie, account_id, public_key, idx)
                    .map_err(|_| Error::InvalidTransactions)?
                    .ok_or(Error::InvalidTransactions)?;
                e.insert(nonce);
            }
        }

        Ok((account, key_entry))
    }
}
