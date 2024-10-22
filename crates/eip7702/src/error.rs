use alloy_primitives::U256;

/// EIP-7702 error.
#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum Eip7702Error {
    /// Invalid signature `s` value.
    #[display("invalid signature `s` value: {_0}")]
    InvalidSValue(U256),
    /// Signature error.
    #[from]
    Signature(alloy_primitives::SignatureError),
}
