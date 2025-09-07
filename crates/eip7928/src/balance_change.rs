//! Contains the [`BalanceChange`] struct, which represents a post balance for an account.
//! Single balance change: `tx_index` -> `post_balance`

use crate::BlockAccessIndex;
use alloy_primitives::U256;

/// This struct is used to track the balance changes of accounts in a block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "rlp", derive(alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BalanceChange {
    /// The index of bal that stores balance change.
    #[cfg_attr(feature = "serde", serde(alias = "txIndex", with = "crate::quantity"))]
    pub block_access_index: BlockAccessIndex,
    /// The post-transaction balance of the account.
    pub post_balance: U256,
}

impl BalanceChange {
    /// Creates a new [`BalanceChange`].
    pub const fn new(block_access_index: BlockAccessIndex, post_balance: U256) -> Self {
        Self { block_access_index, post_balance }
    }

    /// Returns the bal index.
    #[inline]
    pub const fn block_access_index(&self) -> BlockAccessIndex {
        self.block_access_index
    }

    /// Returns the post-transaction balance.
    #[inline]
    pub const fn post_balance(&self) -> U256 {
        self.post_balance
    }
}
