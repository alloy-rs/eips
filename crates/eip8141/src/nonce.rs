//! EIP-8250 keyed nonce helpers.

use alloc::vec::Vec;
use alloy_primitives::{Address, B256, U256, keccak256};

use crate::{Eip8141Error, MAX_NONCE_KEYS};

/// Validates the canonical EIP-8250 nonce key set representation.
///
/// A key set contains between one and sixteen strictly increasing keys. Key zero aliases the
/// sender account nonce and is only valid as the sole key.
pub fn validate_nonce_keys(nonce_keys: &[U256]) -> Result<(), Eip8141Error> {
    if nonce_keys.is_empty() || nonce_keys.len() > MAX_NONCE_KEYS {
        return Err(Eip8141Error::InvalidNonceKeyCount(nonce_keys.len()));
    }
    if nonce_keys.len() > 1 && nonce_keys[0].is_zero() {
        return Err(Eip8141Error::ZeroNonceKeyWithMultipleKeys);
    }
    if nonce_keys.windows(2).any(|keys| keys[0] >= keys[1]) {
        return Err(Eip8141Error::NonceKeysNotStrictlyIncreasing);
    }
    Ok(())
}

/// Returns the EIP-8250 nonce-manager storage slot for `(sender, nonce_key)`.
///
/// Key zero aliases the sender account nonce and therefore must not be passed to this helper.
pub fn nonce_manager_slot(sender: Address, nonce_key: U256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(sender.as_slice());
    preimage[32..].copy_from_slice(&nonce_key.to_be_bytes::<32>());
    keccak256(preimage)
}

/// Returns the canonical hash exposed by `TXPARAM_NONCE_KEYS_HASH`.
pub fn nonce_keys_hash(nonce_keys: &[U256]) -> B256 {
    let mut preimage = Vec::with_capacity((nonce_keys.len() + 1) * 32);
    preimage.extend_from_slice(&U256::from(nonce_keys.len()).to_be_bytes::<32>());
    for nonce_key in nonce_keys {
        preimage.extend_from_slice(&nonce_key.to_be_bytes::<32>());
    }
    keccak256(preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_canonical_nonce_key_sets() {
        assert!(validate_nonce_keys(&[U256::ZERO]).is_ok());
        assert!(validate_nonce_keys(&[U256::from(1), U256::from(2), U256::MAX]).is_ok());

        assert_eq!(validate_nonce_keys(&[]), Err(Eip8141Error::InvalidNonceKeyCount(0)));
        assert_eq!(
            validate_nonce_keys(&[U256::ZERO, U256::from(1)]),
            Err(Eip8141Error::ZeroNonceKeyWithMultipleKeys)
        );
        assert_eq!(
            validate_nonce_keys(&[U256::from(2), U256::from(2)]),
            Err(Eip8141Error::NonceKeysNotStrictlyIncreasing)
        );
        assert_eq!(
            validate_nonce_keys(&[U256::from(2), U256::from(1)]),
            Err(Eip8141Error::NonceKeysNotStrictlyIncreasing)
        );
        assert_eq!(
            validate_nonce_keys(&[U256::from(1); MAX_NONCE_KEYS + 1]),
            Err(Eip8141Error::InvalidNonceKeyCount(MAX_NONCE_KEYS + 1))
        );
    }

    #[test]
    fn nonce_manager_slot_uses_padded_sender_and_big_endian_key() {
        let sender = Address::from([0x11; 20]);
        let key = U256::from_be_bytes([0x22; 32]);
        let mut expected_preimage = [0u8; 64];
        expected_preimage[12..32].fill(0x11);
        expected_preimage[32..].fill(0x22);
        assert_eq!(nonce_manager_slot(sender, key), keccak256(expected_preimage));
    }

    #[test]
    fn nonce_key_hash_commits_to_count_and_full_width_keys() {
        let keys = [U256::from(1), U256::from(2)];
        let mut expected_preimage = [0u8; 96];
        expected_preimage[31] = 2;
        expected_preimage[63] = 1;
        expected_preimage[95] = 2;
        assert_eq!(nonce_keys_hash(&keys), keccak256(expected_preimage));
        assert_ne!(nonce_keys_hash(&keys), nonce_keys_hash(&keys[..1]));
    }
}
