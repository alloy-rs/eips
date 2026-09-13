//! Contains the [`BalAccountInfo`] struct, which holds the account-level fields an
//! [`AccountChanges`] entry commits to at the end of the block.

use crate::AccountChanges;
use alloy_primitives::{B256, U256};

/// The post-block account-level state recorded by an [`AccountChanges`] entry.
///
/// A block access list only records the fields a block actually changed, so every field here is
/// `Some` only when the entry carries a change for it. Fields left `None` are unchanged by the
/// block and must be taken from the account as it was before the block.
///
/// Values are read through the `*_post_state` accessors of [`AccountChanges`], which take the last
/// recorded change ("last write wins"). This matches canonical EIP-7928 ordering; call
/// [`AccountChanges::sort`] first if the entry may be out of order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct BalAccountInfo {
    /// The post-block balance, if the block changed it.
    pub balance: Option<U256>,
    /// The post-block nonce, if the block changed it.
    pub nonce: Option<u64>,
    /// The hash of the post-block code, if the block changed the code.
    ///
    /// [`KECCAK256_EMPTY`](alloy_primitives::KECCAK256_EMPTY) means the code was set to empty,
    /// which is distinct from `None`.
    pub code_hash: Option<B256>,
}

impl BalAccountInfo {
    /// Extracts the post-block account-level fields from the given [`AccountChanges`].
    pub fn from_changes(changes: &AccountChanges) -> Self {
        Self {
            balance: changes.balance_post_state(),
            nonce: changes.nonce_post_state(),
            code_hash: changes.code_hash_post_state(),
        }
    }

    /// Returns `true` if the block changed none of the account-level fields.
    ///
    /// Storage-only and read-only entries are empty; an empty entry must not overwrite the
    /// account's existing balance, nonce or code.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.balance.is_none() && self.nonce.is_none() && self.code_hash.is_none()
    }

    /// Returns `true` if the block changed every account-level field.
    ///
    /// A complete entry describes the account's post-block state on its own, so consumers
    /// reconstructing state do not have to read the account as it was before the block.
    #[inline]
    pub const fn is_complete(&self) -> bool {
        self.balance.is_some() && self.nonce.is_some() && self.code_hash.is_some()
    }
}

impl From<&AccountChanges> for BalAccountInfo {
    fn from(changes: &AccountChanges) -> Self {
        Self::from_changes(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BalanceChange, BlockAccessIndex, CodeChange, NonceChange};
    use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, bytes, keccak256};

    const fn index(value: u64) -> BlockAccessIndex {
        BlockAccessIndex::new(value)
    }

    #[test]
    fn changed_fields_take_the_last_recorded_value() {
        let code = bytes!("6002");
        let changes = AccountChanges::new(Address::repeat_byte(0xaa))
            .with_balance_change(BalanceChange::new(index(1), U256::from(10)))
            .with_balance_change(BalanceChange::new(index(3), U256::from(30)))
            .with_nonce_change(NonceChange::new(index(1), 5))
            .with_nonce_change(NonceChange::new(index(2), 7))
            .with_code_change(CodeChange::new(index(1), bytes!("6001")))
            .with_code_change(CodeChange::new(index(2), code.clone()));

        let info = BalAccountInfo::from_changes(&changes);

        assert!(info.is_complete());
        assert_eq!(info.balance, Some(U256::from(30)));
        assert_eq!(info.nonce, Some(7));
        assert_eq!(info.code_hash, Some(keccak256(&code)));
        assert_eq!(info, BalAccountInfo::from(&changes));
    }

    #[test]
    fn unchanged_fields_stay_absent() {
        let changes = AccountChanges::new(Address::repeat_byte(0xaa))
            .with_balance_change(BalanceChange::new(index(1), U256::from(10)));

        let info = BalAccountInfo::from_changes(&changes);

        assert!(!info.is_empty());
        assert!(!info.is_complete());
        assert_eq!(info, BalAccountInfo { balance: Some(U256::from(10)), ..Default::default() });
    }

    #[test]
    fn read_only_entries_are_empty() {
        let changes =
            AccountChanges::new(Address::repeat_byte(0xdd)).with_storage_read(U256::from(1));

        let info = BalAccountInfo::from_changes(&changes);

        assert!(info.is_empty());
        assert_eq!(info, BalAccountInfo::default());
    }

    #[test]
    fn cleared_code_hashes_to_the_empty_code_hash() {
        let changes = AccountChanges::new(Address::repeat_byte(0xcc))
            .with_code_change(CodeChange::new(index(1), Bytes::new()));

        let info = BalAccountInfo::from_changes(&changes);

        assert!(!info.is_empty());
        assert_eq!(info.code_hash, Some(KECCAK256_EMPTY));
    }
}
