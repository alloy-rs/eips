//! Contains the `StorageChange` struct, which represents a single storage write operation within a
//! transaction.

use crate::BlockAccessIndex;
use alloy_primitives::StorageValue;
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Represents a single storage write operation within a transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpDecodable, RlpEncodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct StorageChange {
    /// Index of the bal that stores the performed write.
    pub block_access_index: BlockAccessIndex,
    /// The new value written to the storage slot.
    pub new_value: StorageValue,
}

impl StorageChange {
    /// Creates a new `StorageChange`.
    #[inline]
    pub const fn new(block_access_index: BlockAccessIndex, new_value: StorageValue) -> Self {
        Self { block_access_index, new_value }
    }

    /// Returns true if the new value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.new_value == StorageValue::ZERO
    }

    /// Returns true if this change was made by the given transaction.
    #[inline]
    pub const fn is_from_tx(&self, block_index: BlockAccessIndex) -> bool {
        self.block_access_index == block_index
    }

    /// Returns a copy with a different storage value.
    #[inline]
    pub const fn with_value(&self, value: StorageValue) -> Self {
        Self { block_access_index: self.block_access_index, new_value: value }
    }
}
