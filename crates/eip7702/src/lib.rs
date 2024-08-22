//! [EIP-7702] constants, helpers, and types.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

#[cfg(not(feature = "std"))]
extern crate alloc;

mod auth_list;
pub use auth_list::*;

pub mod constants;
