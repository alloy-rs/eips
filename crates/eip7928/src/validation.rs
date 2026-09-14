//! Validation for decoded EIP-7928 block access lists.

use crate::{AccountChanges, BlockAccessIndex};
use alloy_primitives::{Address, U256};

/// A change list within an EIP-7928 account entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockAccessListChangeKind {
    /// Storage changes for one slot.
    Storage,
    /// Account balance changes.
    Balance,
    /// Account nonce changes.
    Nonce,
    /// Account code changes.
    Code,
}

impl core::fmt::Display for BlockAccessListChangeKind {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Storage => "storage",
            Self::Balance => "balance",
            Self::Nonce => "nonce",
            Self::Code => "code",
        })
    }
}

/// Error returned when a decoded EIP-7928 block access list is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum BlockAccessListValidationError {
    /// The same account occurs more than once.
    #[error("account {address} occurs more than once in the block access list")]
    DuplicateAccount {
        /// Duplicated account address.
        address: Address,
    },
    /// Account entries are not ordered lexicographically by address.
    #[error(
        "block access list account {address} appears after {previous}, violating canonical order"
    )]
    AccountsOutOfOrder {
        /// Previous account address.
        previous: Address,
        /// Out-of-order account address.
        address: Address,
    },
    /// The same storage key occurs more than once or in both storage lists.
    #[error("storage slot {slot:#x} occurs more than once for account {address}")]
    DuplicateStorageKey {
        /// Account containing the duplicated key.
        address: Address,
        /// Duplicated storage key.
        slot: U256,
    },
    /// Storage keys in one of the account's lists are not in canonical order.
    #[error(
        "storage slot {slot:#x} appears after {previous:#x} for account {address}, violating canonical order"
    )]
    StorageKeysOutOfOrder {
        /// Account containing the out-of-order key.
        address: Address,
        /// Previous storage key.
        previous: U256,
        /// Out-of-order storage key.
        slot: U256,
    },
    /// A storage change entry has no changes.
    #[error("storage slot {slot:#x} has an empty change list for account {address}")]
    EmptyStorageChanges {
        /// Account containing the empty entry.
        address: Address,
        /// Storage key with no changes.
        slot: U256,
    },
    /// The same block access index occurs more than once in one change list.
    #[error(
        "block access index {index} occurs more than once in a {kind} change list for account {address}"
    )]
    DuplicateBlockAccessIndex {
        /// Account containing the change list.
        address: Address,
        /// Kind of change list.
        kind: BlockAccessListChangeKind,
        /// Duplicated block access index.
        index: BlockAccessIndex,
    },
    /// A change list is not ordered by block access index.
    #[error(
        "block access index {index} appears after {previous} in a {kind} change list for account {address}"
    )]
    ChangeIndicesOutOfOrder {
        /// Account containing the change list.
        address: Address,
        /// Kind of change list.
        kind: BlockAccessListChangeKind,
        /// Previous block access index.
        previous: BlockAccessIndex,
        /// Out-of-order block access index.
        index: BlockAccessIndex,
    },
    /// A block access index does not fit the EIP-7928 `uint32` representation.
    #[error(
        "block access index {index} in a {kind} change list for account {address} exceeds uint32"
    )]
    BlockAccessIndexOutOfRange {
        /// Account containing the change list.
        address: Address,
        /// Kind of change list.
        kind: BlockAccessListChangeKind,
        /// Invalid block access index.
        index: BlockAccessIndex,
    },
    /// A block access index is greater than the block's post-execution index.
    #[error(
        "block access index {index} in a {kind} change list for account {address} exceeds the block maximum {max}"
    )]
    BlockAccessIndexExceedsBlock {
        /// Account containing the change list.
        address: Address,
        /// Kind of change list.
        kind: BlockAccessListChangeKind,
        /// Invalid block access index.
        index: BlockAccessIndex,
        /// Post-execution index for the block.
        max: BlockAccessIndex,
    },
}

/// Validates a decoded EIP-7928 block access list.
///
/// This enforces the ordering and uniqueness rules on accounts, storage keys, and change indices,
/// requires every storage change entry to be non-empty, and checks that every block access index
/// fits its `uint32` wire type and is at most the block's post-execution index
/// (`transaction_count + 1`).
pub fn validate_block_access_list(
    block_access_list: &[AccountChanges],
    transaction_count: usize,
) -> Result<(), BlockAccessListValidationError> {
    let max_block_access_index = BlockAccessIndex::new(
        u64::try_from(transaction_count).unwrap_or(u64::MAX).saturating_add(1),
    );
    let mut previous_address = None;

    for account in block_access_list {
        validate_account_order(previous_address, account.address)?;
        previous_address = Some(account.address);
        validate_account(account, max_block_access_index)?;
    }

    Ok(())
}

fn validate_account(
    account: &AccountChanges,
    max_block_access_index: BlockAccessIndex,
) -> Result<(), BlockAccessListValidationError> {
    let address = account.address;
    let mut previous_slot = None;
    for slot_changes in &account.storage_changes {
        validate_storage_key_order(address, &mut previous_slot, slot_changes.slot)?;
        if slot_changes.changes.is_empty() {
            return Err(BlockAccessListValidationError::EmptyStorageChanges {
                address,
                slot: slot_changes.slot,
            });
        }
        validate_change_indices(
            address,
            BlockAccessListChangeKind::Storage,
            slot_changes.changes.iter().map(|change| change.block_access_index),
            max_block_access_index,
        )?;
    }

    previous_slot = None;
    for &slot in &account.storage_reads {
        validate_storage_key_order(address, &mut previous_slot, slot)?;
    }
    validate_storage_disjointness(account)?;

    validate_change_indices(
        address,
        BlockAccessListChangeKind::Balance,
        account.balance_changes.iter().map(|change| change.block_access_index),
        max_block_access_index,
    )?;
    validate_change_indices(
        address,
        BlockAccessListChangeKind::Nonce,
        account.nonce_changes.iter().map(|change| change.block_access_index),
        max_block_access_index,
    )?;
    validate_change_indices(
        address,
        BlockAccessListChangeKind::Code,
        account.code_changes.iter().map(|change| change.block_access_index),
        max_block_access_index,
    )
}

fn validate_account_order(
    previous: Option<Address>,
    address: Address,
) -> Result<(), BlockAccessListValidationError> {
    if let Some(previous) = previous {
        if previous == address {
            return Err(BlockAccessListValidationError::DuplicateAccount { address });
        }
        if previous > address {
            return Err(BlockAccessListValidationError::AccountsOutOfOrder { previous, address });
        }
    }
    Ok(())
}

fn validate_storage_key_order(
    address: Address,
    previous: &mut Option<U256>,
    slot: U256,
) -> Result<(), BlockAccessListValidationError> {
    if let Some(previous) = *previous {
        if previous == slot {
            return Err(BlockAccessListValidationError::DuplicateStorageKey { address, slot });
        }
        if previous > slot {
            return Err(BlockAccessListValidationError::StorageKeysOutOfOrder {
                address,
                previous,
                slot,
            });
        }
    }
    *previous = Some(slot);
    Ok(())
}

fn validate_storage_disjointness(
    account: &AccountChanges,
) -> Result<(), BlockAccessListValidationError> {
    let mut changes = account.storage_changes.iter().peekable();
    let mut reads = account.storage_reads.iter().peekable();

    while let (Some(change), Some(read)) = (changes.peek(), reads.peek()) {
        match change.slot.cmp(read) {
            core::cmp::Ordering::Less => {
                changes.next();
            }
            core::cmp::Ordering::Greater => {
                reads.next();
            }
            core::cmp::Ordering::Equal => {
                return Err(BlockAccessListValidationError::DuplicateStorageKey {
                    address: account.address,
                    slot: **read,
                });
            }
        }
    }

    Ok(())
}

fn validate_change_indices(
    address: Address,
    kind: BlockAccessListChangeKind,
    indices: impl IntoIterator<Item = BlockAccessIndex>,
    max: BlockAccessIndex,
) -> Result<(), BlockAccessListValidationError> {
    let mut previous = None;
    for index in indices {
        if index.get() > u32::MAX as u64 {
            return Err(BlockAccessListValidationError::BlockAccessIndexOutOfRange {
                address,
                kind,
                index,
            });
        }
        if index > max {
            return Err(BlockAccessListValidationError::BlockAccessIndexExceedsBlock {
                address,
                kind,
                index,
                max,
            });
        }
        if let Some(previous) = previous {
            if previous == index {
                return Err(BlockAccessListValidationError::DuplicateBlockAccessIndex {
                    address,
                    kind,
                    index,
                });
            }
            if previous > index {
                return Err(BlockAccessListValidationError::ChangeIndicesOutOfOrder {
                    address,
                    kind,
                    previous,
                    index,
                });
            }
        }
        previous = Some(index);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BalanceChange, CodeChange, NonceChange, SlotChanges, StorageChange};
    use alloc::vec;
    use alloy_primitives::{Bytes, U256};

    const fn index(value: u64) -> BlockAccessIndex {
        BlockAccessIndex::new(value)
    }

    fn account(address: u8) -> AccountChanges {
        AccountChanges {
            address: Address::with_last_byte(address),
            storage_changes: vec![SlotChanges::new(
                U256::from(1),
                vec![StorageChange::new(index(0), U256::from(10))],
            )],
            storage_reads: vec![U256::from(2)],
            balance_changes: vec![BalanceChange::new(index(1), U256::from(20))],
            nonce_changes: vec![NonceChange::new(index(2), 1)],
            code_changes: vec![CodeChange::new(index(3), Bytes::new())],
        }
    }

    #[test]
    fn accepts_canonical_block_access_list() {
        let bal = crate::bal::Bal::new(vec![account(1), account(2)]);

        assert_eq!(validate_block_access_list(bal.as_slice(), 2), Ok(()));
        assert_eq!(bal.validate_structure(2), Ok(()));
    }

    #[test]
    fn rejects_duplicate_and_out_of_order_accounts() {
        let address = Address::with_last_byte(2);
        assert_eq!(
            validate_block_access_list(&[account(2), account(2)], 2),
            Err(BlockAccessListValidationError::DuplicateAccount { address })
        );

        let previous = Address::with_last_byte(2);
        let address = Address::with_last_byte(1);
        assert_eq!(
            validate_block_access_list(&[account(2), account(1)], 2),
            Err(BlockAccessListValidationError::AccountsOutOfOrder { previous, address })
        );
    }

    #[test]
    fn rejects_invalid_storage_entries() {
        let address = Address::with_last_byte(1);
        let slot = U256::from(1);
        let mut empty = account(1);
        empty.storage_changes[0].changes.clear();
        assert_eq!(
            validate_block_access_list(&[empty], 2),
            Err(BlockAccessListValidationError::EmptyStorageChanges { address, slot })
        );

        let mut duplicate = account(1);
        duplicate.storage_reads.insert(0, slot);
        assert_eq!(
            validate_block_access_list(&[duplicate], 2),
            Err(BlockAccessListValidationError::DuplicateStorageKey { address, slot })
        );

        let mut out_of_order = account(1);
        out_of_order.storage_reads = vec![U256::from(3), U256::from(2)];
        assert_eq!(
            validate_block_access_list(&[out_of_order], 2),
            Err(BlockAccessListValidationError::StorageKeysOutOfOrder {
                address,
                previous: U256::from(3),
                slot: U256::from(2),
            })
        );
    }

    #[test]
    fn rejects_invalid_change_indices() {
        let address = Address::with_last_byte(1);
        let mut duplicate = account(1);
        duplicate.balance_changes.push(BalanceChange::new(index(1), U256::from(30)));
        assert_eq!(
            validate_block_access_list(&[duplicate], 2),
            Err(BlockAccessListValidationError::DuplicateBlockAccessIndex {
                address,
                kind: BlockAccessListChangeKind::Balance,
                index: index(1),
            })
        );

        let mut out_of_order = account(1);
        out_of_order.nonce_changes =
            vec![NonceChange::new(index(2), 1), NonceChange::new(index(1), 2)];
        assert_eq!(
            validate_block_access_list(&[out_of_order], 2),
            Err(BlockAccessListValidationError::ChangeIndicesOutOfOrder {
                address,
                kind: BlockAccessListChangeKind::Nonce,
                previous: index(2),
                index: index(1),
            })
        );

        let mut exceeds_u32 = account(1);
        exceeds_u32.code_changes[0].block_access_index = index(u32::MAX as u64 + 1);
        assert_eq!(
            validate_block_access_list(&[exceeds_u32], usize::MAX),
            Err(BlockAccessListValidationError::BlockAccessIndexOutOfRange {
                address,
                kind: BlockAccessListChangeKind::Code,
                index: index(u32::MAX as u64 + 1),
            })
        );

        let mut exceeds_block = account(1);
        exceeds_block.storage_changes[0].changes[0].block_access_index = index(4);
        assert_eq!(
            validate_block_access_list(&[exceeds_block], 2),
            Err(BlockAccessListValidationError::BlockAccessIndexExceedsBlock {
                address,
                kind: BlockAccessListChangeKind::Storage,
                index: index(4),
                max: index(3),
            })
        );
    }
}
