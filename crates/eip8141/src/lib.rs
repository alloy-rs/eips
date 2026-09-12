//! [EIP-8141] frame transaction constants and types.
//!
//! Targets, signers, and signed messages are typed: [`FrameAddress`] distinguishes an omitted
//! address from an explicit one and [`SignatureMessage`] distinguishes the canonical transaction
//! hash from an explicit digest. Decoding rejects malformed lengths and the reserved zero digest
//! but not the remaining signature constraints: call [`FrameSignature::validate_structure`] or
//! [`FrameSignature::validate_structure_with_sender`] before cryptographic verification.
//!
//! The `serde` feature encodes protocol discriminants and gas counters as hex quantities, and
//! optional addresses and signature messages as hex byte strings (empty values are `"0x"`).
//!
//! ```
//! use alloy_eip8141::{FrameAddress, FrameSignature, SignatureMessage};
//! use alloy_primitives::{Signature, U256};
//!
//! // Construct a structurally valid entry; the signature still needs cryptographic verification.
//! let signature = Signature::new(U256::from(1), U256::from(2), false);
//! let entry = FrameSignature::from_secp256k1(
//!     FrameAddress::Empty,
//!     SignatureMessage::TransactionHash,
//!     signature,
//! )?;
//! assert!(entry.signs_transaction_hash());
//! assert_eq!(entry.secp256k1_signature(), Some(signature));
//! # Ok::<(), alloy_eip8141::Eip8141Error>(())
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
pub use error::Eip8141Error;

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
