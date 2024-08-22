//! [EIP-7702] constants, helpers, and types.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

mod auth_list;
pub use auth_list::*;

pub mod constants;
