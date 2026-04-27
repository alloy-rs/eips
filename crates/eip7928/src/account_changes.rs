//! Contains the [`AccountChanges`] struct, which represents storage writes, balance, nonce, code
//! changes and read for the account. All changes for a single account, grouped by field type.
//! This eliminates address redundancy across different change types.

use crate::{
    SlotChanges, balance_change::BalanceChange, code_change::CodeChange, nonce_change::NonceChange,
};
use alloc::vec::Vec;
use alloy_primitives::{Address, U256};

/// This struct is used to track the changes across accounts in a block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "rlp", derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AccountChanges {
    /// The address of the account whoose changes are stored.
    pub address: Address,
    /// List of slot changes for this account.
    pub storage_changes: Vec<SlotChanges>,
    /// List of storage reads for this account.
    pub storage_reads: Vec<U256>,
    /// List of balance changes for this account.
    pub balance_changes: Vec<BalanceChange>,
    /// List of nonce changes for this account.
    pub nonce_changes: Vec<NonceChange>,
    /// List of code changes for this account.
    pub code_changes: Vec<CodeChange>,
}

impl AccountChanges {
    /// Creates a new [`AccountChanges`] instance for the given address with empty vectors.
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            storage_changes: Vec::new(),
            storage_reads: Vec::new(),
            balance_changes: Vec::new(),
            nonce_changes: Vec::new(),
            code_changes: Vec::new(),
        }
    }

    /// Creates a new [`AccountChanges`] instance for the given address with specified capacity.
    pub fn with_capacity(address: Address, capacity: usize) -> Self {
        Self {
            address,
            storage_changes: Vec::with_capacity(capacity),
            storage_reads: Vec::with_capacity(capacity),
            balance_changes: Vec::with_capacity(capacity),
            nonce_changes: Vec::with_capacity(capacity),
            code_changes: Vec::with_capacity(capacity),
        }
    }

    /// Returns the address of the account.
    #[inline]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Returns the storage changes for this account.
    #[inline]
    pub fn storage_changes(&self) -> &[SlotChanges] {
        &self.storage_changes
    }

    /// Returns an iterator over the post-state value for each changed storage slot.
    ///
    /// The post-state value is taken from the last recorded change for each slot.
    #[inline]
    pub fn storage_post_states(&self) -> impl Iterator<Item = (U256, U256)> + '_ {
        self.storage_changes.iter().filter_map(|changes| {
            changes.changes.last().map(|change| (changes.slot, change.new_value))
        })
    }

    /// Returns the storage reads for this account.
    #[inline]
    pub fn storage_reads(&self) -> &[U256] {
        &self.storage_reads
    }

    /// Returns the balance changes for this account.
    #[inline]
    pub fn balance_changes(&self) -> &[BalanceChange] {
        &self.balance_changes
    }

    /// Returns the nonce changes for this account.
    #[inline]
    pub fn nonce_changes(&self) -> &[NonceChange] {
        &self.nonce_changes
    }

    /// Returns the code changes for this account.
    #[inline]
    pub fn code_changes(&self) -> &[CodeChange] {
        &self.code_changes
    }

    /// Sorts this account's changes in-place according to the account-local EIP-7928 ordering
    /// rules.
    ///
    /// This applies the account-local ordering required by the "Ordering, Uniqueness and
    /// Determinism" section of EIP-7928:
    ///
    /// - `storage_changes` are sorted lexicographically by storage key
    /// - each per-slot `StorageChange` list is sorted by block access index in ascending order
    /// - `storage_reads` are sorted lexicographically by storage key
    /// - `balance_changes`, `nonce_changes`, and `code_changes` are sorted by block access index in
    ///   ascending order
    ///
    /// Per-slot storage change ordering is delegated to [`SlotChanges::sort`].
    ///
    /// This method only canonicalizes ordering for a single account. It does not enforce the
    /// EIP-7928 uniqueness constraints for storage keys or block access indexes.
    pub fn sort(&mut self) {
        self.storage_changes.sort_unstable_by_key(|changes| changes.slot);
        for slot_changes in &mut self.storage_changes {
            slot_changes.sort();
        }

        self.storage_reads.sort_unstable();
        self.balance_changes.sort_unstable_by_key(|change| change.block_access_index);
        self.nonce_changes.sort_unstable_by_key(|change| change.block_access_index);
        self.code_changes.sort_unstable_by_key(|change| change.block_access_index);
    }

    /// Set the address.
    pub const fn with_address(mut self, address: Address) -> Self {
        self.address = address;
        self
    }

    /// Add a storage read slot.
    pub fn with_storage_read(mut self, key: U256) -> Self {
        self.storage_reads.push(key);
        self
    }

    /// Add a storage change (multiple writes to a slot grouped in `SlotChanges`).
    pub fn with_storage_change(mut self, change: SlotChanges) -> Self {
        self.storage_changes.push(change);
        self
    }

    /// Add a balance change.
    pub fn with_balance_change(mut self, change: BalanceChange) -> Self {
        self.balance_changes.push(change);
        self
    }

    /// Add a nonce change.
    pub fn with_nonce_change(mut self, change: NonceChange) -> Self {
        self.nonce_changes.push(change);
        self
    }

    /// Add a code change.
    pub fn with_code_change(mut self, change: CodeChange) -> Self {
        self.code_changes.push(change);
        self
    }

    /// Add multiple storage reads at once.
    pub fn extend_storage_reads<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = U256>,
    {
        self.storage_reads.extend(iter);
        self
    }

    /// Add multiple slot changes at once.
    pub fn extend_storage_changes<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = SlotChanges>,
    {
        self.storage_changes.extend(iter);
        self
    }
}

#[cfg(test)]
mod sort_tests {
    use crate::StorageChange;

    use super::*;
    use alloy_primitives::Bytes;

    #[test]
    fn sort_orders_account_local_eip7928_lists() {
        let mut account = AccountChanges {
            address: Address::from([0x11; 20]),
            storage_changes: vec![
                SlotChanges::new(
                    U256::from(3),
                    vec![
                        StorageChange::new(8, U256::from(0x80)),
                        StorageChange::new(2, U256::from(0x20)),
                    ],
                ),
                SlotChanges::new(
                    U256::from(1),
                    vec![
                        StorageChange::new(5, U256::from(0x50)),
                        StorageChange::new(1, U256::from(0x10)),
                    ],
                ),
            ],
            storage_reads: vec![U256::from(4), U256::from(2)],
            balance_changes: vec![
                BalanceChange::new(6, U256::from(600)),
                BalanceChange::new(3, U256::from(300)),
            ],
            nonce_changes: vec![NonceChange::new(7, 70), NonceChange::new(4, 40)],
            code_changes: vec![
                CodeChange::new(9, Bytes::from_static(&[0x60, 0x09])),
                CodeChange::new(5, Bytes::from_static(&[0x60, 0x05])),
            ],
        };

        account.sort();

        assert_eq!(
            account.storage_changes.iter().map(|changes| changes.slot).collect::<Vec<_>>(),
            vec![U256::from(1), U256::from(3)]
        );
        assert_eq!(
            account.storage_changes[0]
                .changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![1, 5]
        );
        assert_eq!(
            account.storage_changes[1]
                .changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![2, 8]
        );
        assert_eq!(account.storage_reads, vec![U256::from(2), U256::from(4)]);
        assert_eq!(
            account
                .balance_changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![3, 6]
        );
        assert_eq!(
            account
                .nonce_changes
                .iter()
                .map(|change| change.block_access_index)
                .collect::<Vec<_>>(),
            vec![4, 7]
        );
        assert_eq!(
            account.code_changes.iter().map(|change| change.block_access_index).collect::<Vec<_>>(),
            vec![5, 9]
        );
    }
}

#[cfg(test)]
mod post_state_tests {
    use crate::StorageChange;

    use super::*;

    #[test]
    fn storage_post_states_yields_last_change_per_slot() {
        let account = AccountChanges::new(Address::from([0x11; 20]))
            .with_storage_change(SlotChanges::new(
                U256::from(1),
                vec![
                    StorageChange::new(0, U256::from(0xaa)),
                    StorageChange::new(2, U256::from(0xbb)),
                ],
            ))
            .with_storage_change(SlotChanges::new(
                U256::from(3),
                vec![
                    StorageChange::new(1, U256::from(0xcc)),
                    StorageChange::new(3, U256::from(0xdd)),
                ],
            ));

        let post_states = account.storage_post_states().collect::<Vec<_>>();

        assert_eq!(
            post_states,
            vec![(U256::from(1), U256::from(0xbb)), (U256::from(3), U256::from(0xdd))]
        );
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use crate::StorageChange;

    use super::*;
    use alloy_primitives::Bytes;
    use serde_json;

    #[test]
    fn test_account_changes_serde() {
        let acc = AccountChanges {
            address: Address::from([0x11; 20]),
            storage_changes: vec![SlotChanges {
                slot: U256::from(1),
                changes: vec![StorageChange {
                    block_access_index: 0u64,
                    new_value: U256::from(100),
                }],
            }],
            storage_reads: vec![U256::from(2)],
            balance_changes: vec![BalanceChange {
                block_access_index: 1u64,
                post_balance: U256::from(1000),
            }],
            nonce_changes: vec![NonceChange { block_access_index: 2u64, new_nonce: 42 }],
            code_changes: vec![CodeChange {
                block_access_index: 3u64,
                new_code: Bytes::from(vec![0x60, 0x00]),
            }],
        };

        let json = serde_json::to_string(&acc).unwrap();
        let decoded: AccountChanges = serde_json::from_str(&json).unwrap();

        assert_eq!(acc, decoded);
    }

    #[test]
    fn test_vec_account_changes_serde() {
        let acc1 = AccountChanges::new(Address::from([0x11; 20]))
            .with_storage_read(U256::from(1))
            .with_balance_change(BalanceChange {
                block_access_index: 0u64,
                post_balance: U256::from(100),
            });

        let acc2 = AccountChanges::new(Address::from([0x22; 20]))
            .with_storage_change(SlotChanges {
                slot: U256::from(2),
                changes: vec![StorageChange {
                    block_access_index: 1u64,
                    new_value: U256::from(200),
                }],
            })
            .with_nonce_change(NonceChange { block_access_index: 2u64, new_nonce: 42 });

        let acc3 = AccountChanges::new(Address::from([0x33; 20])).with_code_change(CodeChange {
            block_access_index: 3u64,
            new_code: Bytes::from(vec![0x60, 0x00]),
        });

        let vec_acc = vec![acc1, acc2, acc3];

        let json = serde_json::to_string(&vec_acc).unwrap();
        let decoded: Vec<AccountChanges> = serde_json::from_str(&json).unwrap();

        assert_eq!(vec_acc, decoded);
    }
}
