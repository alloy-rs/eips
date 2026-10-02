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

impl Eip8141Error {
    /// Returns true if this is [`Self::InvalidMode`].
    pub const fn is_invalid_mode(self) -> bool {
        matches!(self, Self::InvalidMode(_))
    }

    /// Returns true if this is [`Self::InvalidScope`].
    pub const fn is_invalid_scope(self) -> bool {
        matches!(self, Self::InvalidScope(_))
    }

    /// Returns true if this is [`Self::InvalidStatus`].
    pub const fn is_invalid_status(self) -> bool {
        matches!(self, Self::InvalidStatus(_))
    }

    /// Returns true if this is [`Self::InvalidScheme`].
    pub const fn is_invalid_scheme(self) -> bool {
        matches!(self, Self::InvalidScheme(_))
    }

    /// Returns true if this is [`Self::InvalidAddressLength`].
    pub const fn is_invalid_address_length(self) -> bool {
        matches!(self, Self::InvalidAddressLength(_))
    }

    /// Returns true if this is [`Self::InvalidMessageLength`].
    pub const fn is_invalid_message_length(self) -> bool {
        matches!(self, Self::InvalidMessageLength(_))
    }

    /// Returns true if this is [`Self::ZeroMessage`].
    pub const fn is_zero_message(self) -> bool {
        matches!(self, Self::ZeroMessage)
    }

    /// Returns true if this is [`Self::UnexpectedSigner`].
    pub const fn is_unexpected_signer(self) -> bool {
        matches!(self, Self::UnexpectedSigner)
    }

    /// Returns true if this is [`Self::InvalidSignatureLength`].
    pub const fn is_invalid_signature_length(self) -> bool {
        matches!(self, Self::InvalidSignatureLength { .. })
    }

    /// Returns true if this is [`Self::InvalidParity`].
    pub const fn is_invalid_parity(self) -> bool {
        matches!(self, Self::InvalidParity(_))
    }

    /// Returns true if this is [`Self::InvalidSignatureScalar`].
    pub const fn is_invalid_signature_scalar(self) -> bool {
        matches!(self, Self::InvalidSignatureScalar)
    }

    /// Returns true if this is [`Self::P256SignerMismatch`].
    pub const fn is_p256_signer_mismatch(self) -> bool {
        matches!(self, Self::P256SignerMismatch { .. })
    }
}
