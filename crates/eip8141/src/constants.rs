//! [EIP-8141] constants.
//!
//! [EIP-8141]: https://eips.ethereum.org/EIPS/eip-8141

use alloy_primitives::{Address, U256, hex};

/// Identifier for EIP-8141 frame transactions.
pub const FRAME_TX_TYPE: u8 = 0x06;

/// Intrinsic gas cost for an EIP-8141 frame transaction.
pub const FRAME_TX_INTRINSIC_COST: u64 = 12_000;

/// Fixed gas cost charged per frame.
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;

/// Cost of a nonzero-value frame with an explicit target other than the sender.
///
/// This is EIP-2780's `TX_VALUE_COST`, referenced by EIP-8141.
pub const TX_VALUE_COST: u64 = 6_000;

/// Standard gas charged per frame transaction calldata token.
///
/// This matches `GasCosts.TX_DATA_TOKEN_STANDARD` in the execution-specs EIP-8141 draft.
pub const FRAME_TX_DATA_TOKEN_STANDARD_COST: u64 = 4;

/// Total-cost floor charged per frame transaction calldata token.
///
/// EIP-7976 raises this from 10 to 16 and counts every calldata byte as four
/// floor tokens, producing a uniform 64 gas floor per byte.
pub const FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN: u64 = 16;

/// Protocol entry point caller used by `DEFAULT` and `VERIFY` frames.
pub const ENTRY_POINT: Address = Address::new(hex!("00000000000000000000000000000000000000aa"));

/// Address of the canonical expiry verifier.
pub const EXPIRY_VERIFIER: Address = Address::new(hex!("0000000000000000000000000000000000008141"));

/// Calldata length, in bytes, for expiry verifier frames.
pub const EXPIRY_DATA_LENGTH: usize = 8;

/// Maximum number of frames in a frame transaction.
pub const MAX_FRAMES: usize = 64;

/// Address of the EIP-8250 protocol-managed keyed nonce storage account.
pub const NONCE_MANAGER: Address = Address::new(hex!("0000000000000000000000000000000000008250"));

/// Canonical runtime bytecode installed at [`NONCE_MANAGER`].
pub const NONCE_MANAGER_CODE: [u8; 5] = hex!("60006000fd");

/// State gas charged when a keyed nonce storage slot is created for the first time.
pub const KEYED_NONCE_FIRST_USE_STATE_GAS: u64 = 97_920;

/// Exhausted EIP-8250 sequence value. Transactions must use a lower sequence.
pub const MAX_NONCE_SEQ: u64 = u64::MAX;

/// Maximum number of nonce keys selected by one frame transaction.
pub const MAX_NONCE_KEYS: usize = 16;

/// `TXPARAM` selector for the sender's account nonce in the transaction pre-state.
pub const TXPARAM_LEGACY_NONCE: u8 = 0x0d;

/// `TXPARAM` selector for the number of selected nonce keys.
pub const TXPARAM_NONCE_KEY_COUNT: u8 = 0x0e;

/// `TXPARAM` selector for the canonical hash of the selected nonce keys.
pub const TXPARAM_NONCE_KEYS_HASH: u8 = 0x0f;

/// `TXPARAM` selector for the first selected nonce key.
pub const TXPARAM_NONCE_KEY_0: u8 = 0x10;

/// Order of the secp256k1 curve used by EIP-8141 signatures.
pub const SECP256K1N: U256 =
    U256::from_be_bytes(hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));

/// Order of the NIST P-256 curve used by EIP-8141 signatures.
pub const SECP256R1N: U256 =
    U256::from_be_bytes(hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));

/// Byte length of a secp256k1 signature entry: `v || r || s`.
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;

/// Byte length of a P-256 signature entry: `r || s || qx || qy`.
pub const P256_SIGNATURE_LENGTH: usize = 128;

/// Maximum validation work for public mempool admission.
pub const MAX_VERIFY_GAS: u64 = 100_000;

/// Maximum state gas budget across a public-mempool validation prefix.
pub const MAX_VERIFY_STATE_GAS: u64 = 500_000;

/// Maximum pending public-mempool transactions using any non-canonical paymaster.
pub const MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER: usize = 1;

/// Canonical expiry verifier runtime bytecode.
pub const EXPIRY_VERIFIER_RUNTIME: [u8; 26] =
    hex!("60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd");

/// Approval flag mask for extracting the allowed approval scope from frame flags.
pub const APPROVE_SCOPE_MASK: u8 = 0x03;

/// Atomic batch frame flag.
pub const ATOMIC_BATCH_FLAG: u8 = 0x04;

/// Mask of all currently defined frame flag bits.
pub const FRAME_FLAGS_MASK: u8 = APPROVE_SCOPE_MASK | ATOMIC_BATCH_FLAG;
