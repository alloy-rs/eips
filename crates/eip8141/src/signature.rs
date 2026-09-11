use alloy_primitives::{Address, B256, Bytes, Signature, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

use crate::{FrameAddress, FrameError};

/// EIP-8141 transaction signature scheme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
pub enum SignatureScheme {
    /// Arbitrary witness bytes interpreted by EVM validation code.
    #[default]
    Arbitrary = 0x00,
    /// Secp256k1 signature.
    Secp256k1 = 0x01,
    /// P-256 signature.
    P256 = 0x02,
}

impl SignatureScheme {
    /// Attempts to convert a raw scheme byte into a [`SignatureScheme`].
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Arbitrary),
            0x01 => Some(Self::Secp256k1),
            0x02 => Some(Self::P256),
            _ => None,
        }
    }

    /// Returns the protocol signature verification gas cost.
    pub const fn verification_gas(self) -> u64 {
        match self {
            Self::Arbitrary => 100,
            Self::Secp256k1 => 2_800,
            Self::P256 => 6_700,
        }
    }
}

impl_u8_conversions!(SignatureScheme, InvalidScheme);

impl From<SignatureScheme> for u8 {
    fn from(value: SignatureScheme) -> Self {
        value as Self
    }
}

impl Encodable for SignatureScheme {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        u8::from(*self).encode(out);
    }

    fn length(&self) -> usize {
        u8::from(*self).length()
    }
}

impl Decodable for SignatureScheme {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from_u8(u8::decode(buf)?)
            .ok_or(alloy_rlp::Error::Custom("invalid EIP-8141 signature scheme"))
    }
}

/// The message authorized by an EIP-8141 signature entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum SignatureMessage {
    /// The signature signs the canonical transaction signature hash.
    TransactionHash,
    /// The signature signs an explicit non-zero 32-byte digest.
    Explicit(B256),
}

impl SignatureMessage {
    /// Encodes the message as the byte string carried by a signature entry.
    ///
    /// Returns an error for the reserved explicit zero digest.
    pub fn to_bytes(self) -> Result<Bytes, FrameError> {
        match self {
            Self::TransactionHash => Ok(Bytes::new()),
            Self::Explicit(message) if message.is_zero() => Err(FrameError::ZeroMessage),
            Self::Explicit(message) => Ok(Bytes::copy_from_slice(message.as_slice())),
        }
    }
}

impl TryFrom<&[u8]> for SignatureMessage {
    type Error = FrameError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(Self::TransactionHash);
        }
        let message =
            B256::try_from(value).map_err(|_| FrameError::InvalidMessageLength(value.len()))?;
        if message.is_zero() {
            return Err(FrameError::ZeroMessage);
        }
        Ok(Self::Explicit(message))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SignatureMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let message = match self {
            Self::TransactionHash => None,
            Self::Explicit(message) if message.is_zero() => {
                return Err(serde::ser::Error::custom(FrameError::ZeroMessage));
            }
            Self::Explicit(message) => Some(*message),
        };
        crate::serde_utils::serialize_optional_bytes(message, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SignatureMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match crate::serde_utils::deserialize_optional_bytes::<32, D>(deserializer)? {
            None => Ok(Self::TransactionHash),
            Some(message) if message.is_zero() => {
                Err(serde::de::Error::custom(FrameError::ZeroMessage))
            }
            Some(message) => Ok(Self::Explicit(message)),
        }
    }
}

/// A signature entry attached to an EIP-8141 frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameSignature {
    /// Signature scheme identifier.
    pub scheme: SignatureScheme,
    /// Scheme-dependent signer metadata. For `ARBITRARY`, this must be empty.
    pub signer: FrameAddress,
    /// Empty for the canonical transaction signature hash, or an explicit 32-byte digest.
    pub msg: Bytes,
    /// Raw signature bytes.
    pub signature: Bytes,
}

impl FrameSignature {
    /// Creates a new frame signature from raw field values.
    ///
    /// Call [`Self::validate_structure`] before using an untrusted entry, then perform the
    /// scheme-specific cryptographic verification. This constructor does not validate the fields.
    pub const fn new(
        scheme: SignatureScheme,
        signer: FrameAddress,
        msg: Bytes,
        signature: Bytes,
    ) -> Self {
        Self { scheme, signer, msg, signature }
    }

    /// Returns true if this signature signs the canonical transaction signature hash.
    pub fn signs_transaction_hash(&self) -> bool {
        self.msg.is_empty()
    }

    /// Returns the explicit non-zero signed message, if structurally valid.
    pub fn explicit_message(&self) -> Option<B256> {
        match self.message().ok()? {
            SignatureMessage::TransactionHash => None,
            SignatureMessage::Explicit(message) => Some(message),
        }
    }

    /// Returns the signed message, rejecting invalid lengths and the reserved zero digest.
    pub fn message(&self) -> Result<SignatureMessage, FrameError> {
        SignatureMessage::try_from(self.msg.as_ref())
    }

    /// Returns the explicit signer address for a protocol-validated scheme.
    ///
    /// An empty protocol signer resolves to the transaction sender; arbitrary signatures have no
    /// resolved signer. Use [`Self::resolved_signer`] when the transaction sender is available.
    pub const fn signer_address(&self) -> Option<Address> {
        match self.scheme {
            SignatureScheme::Arbitrary => None,
            _ => self.signer.address(),
        }
    }

    /// Resolves the signer, rejecting a nonempty signer on an arbitrary signature.
    pub fn resolved_signer(&self, sender: Address) -> Result<Option<Address>, FrameError> {
        match self.scheme {
            SignatureScheme::Arbitrary if !self.signer.is_empty() => {
                Err(FrameError::UnexpectedSigner)
            }
            SignatureScheme::Arbitrary => Ok(None),
            _ => Ok(Some(self.signer.address().unwrap_or(sender))),
        }
    }

    /// Checks the message, signer, signature length, parity, and canonical scalar bounds.
    ///
    /// This does not perform cryptographic verification: callers must still recover the secp256k1
    /// signer or verify P-256's public key and signature against the resolved signer and message.
    /// Decoding a signature entry does not imply that these checks have passed.
    pub fn validate_structure(&self) -> Result<(), FrameError> {
        self.message()?;
        let (expected, order) = match self.scheme {
            SignatureScheme::Arbitrary => {
                return if self.signer.is_empty() {
                    Ok(())
                } else {
                    Err(FrameError::UnexpectedSigner)
                };
            }
            SignatureScheme::Secp256k1 => (65, crate::SECP256K1N),
            SignatureScheme::P256 => (128, crate::SECP256R1N),
        };
        if self.signature.len() != expected {
            return Err(FrameError::InvalidSignatureLength {
                expected,
                actual: self.signature.len(),
            });
        }
        let offset = if self.scheme == SignatureScheme::Secp256k1 {
            if self.signature[0] > 1 {
                return Err(FrameError::InvalidParity(self.signature[0]));
            }
            1
        } else {
            0
        };
        let r = U256::from_be_slice(&self.signature[offset..offset + 32]);
        let s = U256::from_be_slice(&self.signature[offset + 32..offset + 64]);
        if r.is_zero() || r >= order || s.is_zero() || s > order >> 1 {
            return Err(FrameError::InvalidSignatureScalar);
        }
        Ok(())
    }

    /// Creates a structurally checked secp256k1 entry using EIP-8141's `v || r || s` layout.
    ///
    /// Unlike legacy signatures, the parity byte is zero or one and precedes the scalars.
    pub fn from_secp256k1(
        signer: FrameAddress,
        message: SignatureMessage,
        signature: Signature,
    ) -> Result<Self, FrameError> {
        let mut bytes = [0u8; 65];
        bytes[0] = u8::from(signature.v());
        bytes[1..33].copy_from_slice(&signature.r().to_be_bytes::<32>());
        bytes[33..].copy_from_slice(&signature.s().to_be_bytes::<32>());
        let entry =
            Self::new(SignatureScheme::Secp256k1, signer, message.to_bytes()?, bytes.into());
        entry.validate_structure()?;
        Ok(entry)
    }

    /// Returns the protocol signature verification gas cost.
    pub const fn verification_gas(&self) -> u64 {
        self.scheme.verification_gas()
    }
}

#[cfg(test)]
mod tests {
    use super::SignatureScheme;

    #[test]
    fn signature_verification_gas_matches_execution_specs() {
        assert_eq!(SignatureScheme::Arbitrary.verification_gas(), 100);
        assert_eq!(SignatureScheme::Secp256k1.verification_gas(), 2_800);
        assert_eq!(SignatureScheme::P256.verification_gas(), 6_700);
    }
}
