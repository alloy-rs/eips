//! [EIP-8141] constants.
//!
//! [EIP-8141]: https://eips.ethereum.org/EIPS/eip-8141

use alloy_primitives::{Address, hex};

/// Identifier for EIP-8141 frame transactions.
pub const FRAME_TX_TYPE: u8 = 0x06;

/// Intrinsic gas cost for an EIP-8141 frame transaction.
pub const FRAME_TX_INTRINSIC_COST: u64 = 15_000;

/// Fixed gas cost charged per frame.
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;

/// Standard gas charged per frame transaction calldata token.
///
/// This matches `GasCosts.TX_DATA_TOKEN_STANDARD` in the execution-specs EIP-8141 draft.
pub const FRAME_TX_DATA_TOKEN_STANDARD_COST: u64 = 4;

/// EIP-7623 total-cost floor charged per frame transaction calldata token.
///
/// This is already the full gas cost per token; it is not a multiplier on
/// [`FRAME_TX_DATA_TOKEN_STANDARD_COST`].
pub const FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN: u64 = 10;

/// Protocol entry point caller used by `DEFAULT` and `VERIFY` frames.
pub const ENTRY_POINT: Address = Address::new(hex!("00000000000000000000000000000000000000aa"));

/// Address of the canonical expiry verifier.
pub const EXPIRY_VERIFIER: Address = Address::new(hex!("0000000000000000000000000000000000008141"));

/// Calldata length, in bytes, for expiry verifier frames.
pub const EXPIRY_DATA_LENGTH: usize = 8;

/// Maximum number of frames in a frame transaction.
pub const MAX_FRAMES: usize = 64;

/// Maximum validation work for public mempool admission.
pub const MAX_VERIFY_GAS: u64 = 100_000;

/// Maximum pending public-mempool transactions using any non-canonical paymaster.
pub const MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER: usize = 1;

/// Canonical expiry verifier runtime bytecode.
pub const EXPIRY_VERIFIER_RUNTIME: [u8; 26] =
    hex!("60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd");

/// Approval flag mask for extracting the allowed approval scope from frame flags.
pub const APPROVE_SCOPE_MASK: u8 = 0x03;

/// Atomic batch frame flag.
pub const ATOMIC_BATCH_FLAG: u8 = 0x04;
