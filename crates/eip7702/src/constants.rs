//! [EIP-7702] constants.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

/// Identifier for EIP7702's set code transaction.
///
/// See also [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).
pub const EIP7702_TX_TYPE_ID: u8 = 4;

/// Magic number used to calculate an EIP7702 authority.
///
/// See also [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).
pub const MAGIC: u8 = 0x05;

/// An additional gas cost per EIP7702 authorization list item.
///
/// See also [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).
pub const PER_AUTH_BASE_COST: u64 = 12500;

/// A gas refund for EIP7702 transactions if the authority account already exists in the trie.
///
/// The refund is `PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST`.
///
/// See also [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).
pub const PER_EMPTY_ACCOUNT_COST: u64 = 25000;
