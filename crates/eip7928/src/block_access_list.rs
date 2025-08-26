//! Contains the [`BlockAccessList`] type, which represents a simple list of account changes.

use crate::account_changes::AccountChanges;
use alloc::vec::Vec;

/// This struct is used to store `account_changes` in a block.
pub type BlockAccessList = Vec<AccountChanges>;

/// Computes the hash of the given block access list.
#[cfg(feature = "rlp")]
pub fn compute_block_access_list_hash(bal: &[AccountChanges]) -> alloy_primitives::B256 {
    alloy_primitives::keccak256(alloy_rlp::encode(bal))
}
