//! Contains the [`SlotChanges`] struct, which represents all changes made to a single storage slot
//! across

use crate::StorageChange;
use alloc::vec::Vec;
use alloy_primitives::StorageKey;

/// Represents all changes made to a single storage slot across multiple transactions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "rlp", derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SlotChanges {
    /// The storage slot key being modified.
    pub slot: StorageKey,
    /// A list of write operations to this slot, ordered by transaction index.
    #[cfg_attr(feature = "serde", serde(alias = "slotChanges"))]
    pub changes: Vec<StorageChange>,
}

impl SlotChanges {
    /// Creates a new [`SlotChanges`] instance for the given slot key and changes.
    ///
    /// Preallocates capacity for up to 300,000 changes.
    #[inline]
    pub const fn new(slot: StorageKey, changes: Vec<StorageChange>) -> Self {
        Self { slot, changes }
    }

    /// Appends a storage change to the list.
    #[inline]
    pub fn push(&mut self, change: StorageChange) {
        self.changes.push(change)
    }

    /// Returns `true` if no changes have been recorded.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the number of changes recorded for this slot.
    #[inline]
    pub fn len(&self) -> usize {
        self.changes.len()
    }
}
