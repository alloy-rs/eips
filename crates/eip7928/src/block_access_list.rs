//! Contains the [`BlockAccessList`] type, which represents a simple list of account changes.

use crate::account_changes::AccountChanges;
use alloc::vec::{IntoIter, Vec};
use core::{ops::Deref, slice::Iter};
use std::ops::DerefMut;

/// Represents the full set of [`AccountChanges`] for a block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rlp", derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable))]
pub struct BlockAccessList(Vec<AccountChanges>);

impl From<BlockAccessList> for Vec<AccountChanges> {
    fn from(this: BlockAccessList) -> Self {
        this.0
    }
}

impl From<Vec<AccountChanges>> for BlockAccessList {
    fn from(list: Vec<AccountChanges>) -> Self {
        Self(list)
    }
}

impl Deref for BlockAccessList {
    type Target = [AccountChanges];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for BlockAccessList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for BlockAccessList {
    type Item = AccountChanges;
    type IntoIter = IntoIter<AccountChanges>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<AccountChanges> for BlockAccessList {
    fn from_iter<I: IntoIterator<Item = AccountChanges>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl BlockAccessList {
    /// Creates a new [`BlockAccessList`] from the provided account changes.
    pub const fn new(account_changes: Vec<AccountChanges>) -> Self {
        Self(account_changes)
    }

    /// Adds a new [`AccountChanges`] entry to the list.
    pub fn push(&mut self, account_changes: AccountChanges) {
        self.0.push(account_changes)
    }

    /// Returns `true` if the list contains no elements.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of account change entries contained in the list.
    #[inline]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the [`AccountChanges`] entries.
    #[inline]
    pub fn iter(&self) -> Iter<'_, AccountChanges> {
        self.0.iter()
    }

    /// Returns a slice of the contained [`AccountChanges`].
    #[inline]
    pub const fn as_slice(&self) -> &[AccountChanges] {
        self.0.as_slice()
    }

    /// Returns a vector of [`AccountChanges`].
    pub fn into_inner(self) -> Vec<AccountChanges> {
        self.0
    }
}

/// Computes the hash of the given block access list.
#[cfg(feature = "rlp")]
pub fn compute_block_access_list_hash(bal: &[AccountChanges]) -> alloy_primitives::B256 {
    let mut buf = Vec::new();
    alloy_rlp::encode_list(bal, &mut buf);
    alloy_primitives::keccak256(&buf)
}
