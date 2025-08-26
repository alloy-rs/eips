//! Block-level access lists for Reth.
//! [EIP-7928]: https://eips.ethereum.org/EIPS/eip-7928
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

/// Module containing constants used throughout the block access list.
pub mod constants;
pub use constants::*;

/// Module for handling storage changes within a block.
pub mod storage_change;
pub use storage_change::*;

/// Module for managing storage slots and their changes.
pub mod slot_changes;
pub use slot_changes::*;

/// Module for handling balance changes within a block.
pub mod balance_change;

/// Module for handling nonce changes within a block.
pub mod nonce_change;

/// Module for handling code changes within a block.
pub mod code_change;

/// Module for managing account changes within a block.
pub mod account_changes;
pub use account_changes::*;

/// Module for managing block access lists.
pub mod block_access_list;
pub use block_access_list::*;
