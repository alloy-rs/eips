//! Constants for eip-7928. Chosen to support a 630 million gas limit.

use alloy_primitives::{B256, b256};

/// Maximum number of transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 30_000;

/// Maximum number of unique storage slots modified in a block.
pub const MAX_SLOTS: usize = 300_000;

/// Maximum number of unique accounts accessed in a block.
pub const MAX_ACCOUNTS: usize = 300_000;

/// Maximum contract bytecode size in bytes.
pub const MAX_CODE_SIZE: usize = 24_576;

/// Item cost for block access list.
pub const ITEM_COST: usize = 2000;

/// Number of epochs the execution layer must retain block access lists for.
pub const BAL_RETENTION_PERIOD_EPOCHS: u64 = 33_024;

/// Returns the block access list retention period in slots for the given number of slots per epoch.
pub const fn bal_retention_period_slots(slots_per_epoch: u64) -> u64 {
    BAL_RETENTION_PERIOD_EPOCHS * slots_per_epoch
}

/// The empty block access list hash.
pub const EMPTY_BLOCK_ACCESS_LIST_HASH: B256 =
    b256!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_period_uses_configured_slots_per_epoch() {
        assert_eq!(bal_retention_period_slots(32), 1_056_768);
        assert_eq!(bal_retention_period_slots(8), 264_192);
    }
}
