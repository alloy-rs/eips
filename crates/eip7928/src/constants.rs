
/// Chosen to support a 630 million gas limit.

/// Maximum number of transactions per block.
pub const MAX_TXS: usize = 30_000;

/// Maximum number of unique storage slots modified in a block.
pub const MAX_SLOTS: usize = 300_000;

/// Maximum number of unique accounts accessed in a block.
pub const MAX_ACCOUNTS: usize = 300_000;

/// Maximum contract bytecode size in bytes.
pub const MAX_CODE_SIZE: usize = 24_576;

/// Type alias for block index for eip-7928.
pub type BlockAccessIndex = u64;
