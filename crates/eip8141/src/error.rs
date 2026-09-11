//! Errors returned when converting or validating EIP-8141 fields.

use alloy_primitives::Address;

/// An invalid EIP-8141 field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Eip8141Error {
    /// Unknown frame execution mode.
    #[error("invalid frame mode: {0}")]
    InvalidMode(u8),
    /// Unknown approval scope.
    #[error("invalid approval scope: {0}")]
    InvalidScope(u8),
    /// Unknown frame receipt status.
    #[error("invalid frame status: {0}")]
    InvalidStatus(u8),
    /// Unknown signature scheme.
    #[error("invalid signature scheme: {0}")]
    InvalidScheme(u8),
    /// An optional address must be empty or exactly 20 bytes.
    #[error("invalid address length: {0}")]
    InvalidAddressLength(usize),
    /// A signature message must be empty or exactly 32 bytes.
    #[error("invalid signature message length: {0}")]
    InvalidMessageLength(usize),
    /// An explicit zero digest is reserved for transaction-hash introspection.
    #[error("explicit signature message must be nonzero")]
    ZeroMessage,
    /// Arbitrary signatures must not specify a signer.
    #[error("arbitrary signature must have an empty signer")]
    UnexpectedSigner,
    /// A protocol signature has an incorrect byte length.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Required signature length.
        expected: usize,
        /// Actual signature length.
        actual: usize,
    },
    /// Secp256k1 parity must be zero or one.
    #[error("invalid signature parity: {0}")]
    InvalidParity(u8),
    /// A signature scalar is zero, out of range, or not low-s.
    #[error("signature scalars must be canonical and low-s")]
    InvalidSignatureScalar,
    /// A P-256 public key does not hash to the resolved signer.
    #[error("p256 public key resolves to {derived}, expected signer {expected}")]
    P256SignerMismatch {
        /// Signer resolved from the entry and the transaction sender.
        expected: Address,
        /// Address derived from the public key carried in the signature.
        derived: Address,
    },
}
