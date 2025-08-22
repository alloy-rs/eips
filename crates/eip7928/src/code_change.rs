//! Contains the `CodeChange` struct, which represents a new code for an account.
//! Single code change: `tx_index` -> `new_code`
use crate::BlockAccessIndex;
use alloy_primitives::Bytes;
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// This struct is used to track the new codes of accounts in a block.
#[derive(Debug, Clone, Default, PartialEq, Eq, RlpDecodable, RlpEncodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CodeChange {
    /// The index of bal that stores this code change.
    pub block_access_index: BlockAccessIndex,
    /// The new code of the account.
    pub new_code: Bytes,
}
impl CodeChange {
    /// Creates a new `CodeChange`.
    pub fn new(block_access_index: BlockAccessIndex) -> Self {
        Self { block_access_index, new_code: Default::default() }
    }

    /// Returns the bal index.
    #[inline]
    pub const fn block_access_index(&self) -> BlockAccessIndex {
        self.block_access_index
    }

    /// Returns the new code.
    #[inline]
    pub const fn new_code(&self) -> &Bytes {
        &self.new_code
    }
}
