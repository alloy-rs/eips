//! Contains the `BlockAccessList` struct, which represents a simple list of account changes.

use crate::account_changes::AccountChanges;
use alloc::vec::Vec;

/// This struct is used to store `account_changes` in a block.
pub type BlockAccessList = Vec<AccountChanges>;
