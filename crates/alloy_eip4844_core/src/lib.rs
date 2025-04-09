//! [EIP-4844] types, constants and helper functions.
//!
//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844

/// Determines the maximum rate of change for blob fee
pub const BLOB_GASPRICE_UPDATE_FRACTION: u128 = 3_338_477u128; // 3338477

/// Minimum gas price for a data blob
pub const BLOB_TX_MIN_BLOB_GASPRICE: u128 = 1u128;

/// Gas consumption of a single data blob.
pub const DATA_GAS_PER_BLOB: u64 = 131_072u64; // 32*4096 = 131072 == 2^17 == 0x20000

/// Maximum data gas for data blobs in a single block.
pub const MAX_DATA_GAS_PER_BLOCK: u64 = 786_432u64; // 0xC0000 = 6 * 0x20000

/// Target data gas for data blobs in a single block.
pub const TARGET_DATA_GAS_PER_BLOCK: u64 = 393_216u64; // 0x60000 = 3 * 0x20000

/// Maximum number of data blobs in a single block.
pub const MAX_BLOBS_PER_BLOCK: usize = (MAX_DATA_GAS_PER_BLOCK / DATA_GAS_PER_BLOB) as usize; // 786432 / 131072  = 6

/// Target number of data blobs in a single block.
pub const TARGET_BLOBS_PER_BLOCK: u64 = TARGET_DATA_GAS_PER_BLOCK / DATA_GAS_PER_BLOB; // 393216 / 131072 = 3

/// Approximates `factor * e ** (numerator / denominator)` using Taylor expansion.
///
/// This is used to calculate the blob price.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`fake_exponential`).
///
/// # Panics
///
/// This function panics if `denominator` is zero.
#[inline]
pub const fn fake_exponential(factor: u128, numerator: u128, denominator: u128) -> u128 {
    assert!(denominator != 0, "attempt to divide by zero");

    let mut i = 1;
    let mut output = 0;
    let mut numerator_accum = factor * denominator;
    while numerator_accum > 0 {
        output += numerator_accum;

        // Denominator is asserted as not zero at the start of the function.
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += 1;
    }
    output / denominator
}
