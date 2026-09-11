//! [EIP-8141] frame transaction constants and types.
//!
//! Targets and signers use [`FrameAddress`] to distinguish an empty address from an explicit one.
//! The `serde` feature encodes protocol discriminants and gas counters as hex quantities, and
//! optional addresses and signature messages as hex byte strings (empty values are `"0x"`).
//!
//! Signature entries retain their raw witness and message bytes. Call
//! [`FrameSignature::validate_structure`] before cryptographic verification; decoding alone does
//! not establish transaction validity.
//!
//! ```
//! use alloy_eip8141::{FrameAddress, FrameSignature, SignatureMessage};
//! use alloy_primitives::{Signature, U256};
//!
//! // Construct a structurally valid entry; the signature still needs cryptographic verification.
//! let entry = FrameSignature::from_secp256k1(
//!     FrameAddress::Empty,
//!     SignatureMessage::TransactionHash,
//!     Signature::new(U256::from(1), U256::from(2), false),
//! )?;
//! assert!(entry.signs_transaction_hash());
//! # Ok::<(), alloy_eip8141::FrameError>(())
//! ```
//!
//! [EIP-8141]: https://eips.ethereum.org/EIPS/eip-8141
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[macro_use]
mod macros;

mod address;
pub use address::FrameAddress;

mod error;
pub use error::FrameError;

#[cfg(feature = "serde")]
mod serde_utils;

pub mod constants;
pub use constants::*;

mod frame;
pub use frame::*;

mod receipt;
pub use receipt::*;

mod signature;
pub use signature::*;
