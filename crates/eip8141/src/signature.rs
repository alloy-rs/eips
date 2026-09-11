use alloy_primitives::{Address, B256, Bytes, Signature, U256};
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable, RlpEncodable};

use crate::{Eip8141Error, FrameAddress, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH};

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

    /// Returns the fixed signature length of a protocol-validated scheme.
    ///
    /// Arbitrary witnesses have no fixed length.
    pub const fn signature_length(self) -> Option<usize> {
        match self {
            Self::Arbitrary => None,
            Self::Secp256k1 => Some(SECP256K1_SIGNATURE_LENGTH),
            Self::P256 => Some(P256_SIGNATURE_LENGTH),
        }
    }
}

impl_u8_discriminant!(SignatureScheme, InvalidScheme, "invalid EIP-8141 signature scheme");

/// The message authorized by an EIP-8141 signature entry.
///
/// RLP encodes the transaction hash case as an empty byte string and an explicit digest as its 32
/// bytes, preserving the EIP-8141 wire format. Decoding rejects other lengths and the reserved
/// zero digest. JSON uses hex byte strings, including `"0x"` for the transaction hash case; `null`
/// also deserializes as the transaction hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum SignatureMessage {
    /// The signature signs the canonical transaction signature hash.
    #[default]
    TransactionHash,
    /// The signature signs an explicit non-zero 32-byte digest.
    ///
    /// Use [`Self::explicit`] to reject the reserved zero digest.
    Explicit(B256),
}

impl SignatureMessage {
    /// Creates an explicit message, rejecting the reserved zero digest.
    pub fn explicit(digest: B256) -> Result<Self, Eip8141Error> {
        if digest.is_zero() { Err(Eip8141Error::ZeroMessage) } else { Ok(Self::Explicit(digest)) }
    }

    /// Returns true if the signature signs the canonical transaction signature hash.
    pub const fn is_transaction_hash(self) -> bool {
        matches!(self, Self::TransactionHash)
    }

    /// Returns the explicit digest, or `None` for the transaction hash case.
    pub const fn digest(self) -> Option<B256> {
        match self {
            Self::TransactionHash => None,
            Self::Explicit(digest) => Some(digest),
        }
    }

    /// Returns the byte string carried by a signature entry: empty for the transaction hash.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::TransactionHash => &[],
            Self::Explicit(digest) => digest.as_slice(),
        }
    }
}

impl TryFrom<&[u8]> for SignatureMessage {
    type Error = Eip8141Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(Self::TransactionHash);
        }
        B256::try_from(value)
            .map_err(|_| Eip8141Error::InvalidMessageLength(value.len()))
            .and_then(Self::explicit)
    }
}

impl Encodable for SignatureMessage {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::TransactionHash => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
            Self::Explicit(digest) => digest.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::TransactionHash => 1,
            Self::Explicit(digest) => digest.length(),
        }
    }
}

impl Decodable for SignatureMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from(Header::decode_bytes(buf, false)?).map_err(|err| match err {
            Eip8141Error::ZeroMessage => {
                alloy_rlp::Error::Custom("EIP-8141 signature message must be nonzero")
            }
            _ => alloy_rlp::Error::Custom("invalid EIP-8141 signature message length"),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for SignatureMessage {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.arbitrary::<Option<B256>>()? {
            Some(digest) if !digest.is_zero() => Self::Explicit(digest),
            _ => Self::TransactionHash,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SignatureMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let digest = match self {
            Self::TransactionHash => None,
            Self::Explicit(digest) if digest.is_zero() => {
                return Err(serde::ser::Error::custom(Eip8141Error::ZeroMessage));
            }
            Self::Explicit(digest) => Some(*digest),
        };
        crate::serde_utils::serialize_optional_bytes(digest, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SignatureMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::serde_utils::deserialize_optional_bytes::<32, D>(deserializer)?
            .map_or(Ok(Self::TransactionHash), |digest| {
                Self::explicit(digest).map_err(serde::de::Error::custom)
            })
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
    /// The signed message: the canonical transaction signature hash or an explicit digest.
    pub msg: SignatureMessage,
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
        msg: SignatureMessage,
        signature: Bytes,
    ) -> Self {
        Self { scheme, signer, msg, signature }
    }

    /// Returns true if this signature signs the canonical transaction signature hash.
    pub const fn signs_transaction_hash(&self) -> bool {
        self.msg.is_transaction_hash()
    }

    /// Returns the explicit signed digest, or `None` for the transaction hash case.
    pub const fn explicit_message(&self) -> Option<B256> {
        self.msg.digest()
    }

    /// Returns the explicit signer address of a protocol-validated scheme.
    ///
    /// Returns `None` for an empty signer, which resolves to the transaction sender, and for
    /// arbitrary signatures, which have no signer. Use [`Self::resolved_signer`] when the
    /// transaction sender is available.
    pub const fn signer_address(&self) -> Option<Address> {
        match self.scheme {
            SignatureScheme::Arbitrary => None,
            _ => self.signer.address(),
        }
    }

    /// Resolves the signer, rejecting a nonempty signer on an arbitrary signature.
    pub const fn resolved_signer(&self, sender: Address) -> Result<Option<Address>, Eip8141Error> {
        match self.scheme {
            SignatureScheme::Arbitrary => {
                if self.signer.is_empty() {
                    Ok(None)
                } else {
                    Err(Eip8141Error::UnexpectedSigner)
                }
            }
            _ => Ok(Some(self.signer.resolve(sender))),
        }
    }

    /// Checks the signer, signature length, parity, and canonical scalar bounds.
    ///
    /// This does not perform cryptographic verification: callers must still recover the secp256k1
    /// signer or verify the P-256 signature against the resolved signer and message. Decoding a
    /// signature entry does not imply that these checks have passed.
    pub fn validate_structure(&self) -> Result<(), Eip8141Error> {
        let (expected, order) = match self.scheme {
            SignatureScheme::Arbitrary => {
                return if self.signer.is_empty() {
                    Ok(())
                } else {
                    Err(Eip8141Error::UnexpectedSigner)
                };
            }
            SignatureScheme::Secp256k1 => (SECP256K1_SIGNATURE_LENGTH, crate::SECP256K1N),
            SignatureScheme::P256 => (P256_SIGNATURE_LENGTH, crate::SECP256R1N),
        };
        if self.signature.len() != expected {
            return Err(Eip8141Error::InvalidSignatureLength {
                expected,
                actual: self.signature.len(),
            });
        }
        let offset = if self.scheme == SignatureScheme::Secp256k1 {
            if self.signature[0] > 1 {
                return Err(Eip8141Error::InvalidParity(self.signature[0]));
            }
            1
        } else {
            0
        };
        let r = U256::from_be_slice(&self.signature[offset..offset + 32]);
        let s = U256::from_be_slice(&self.signature[offset + 32..offset + 64]);
        if r.is_zero() || r >= order || s.is_zero() || s > order >> 1 {
            return Err(Eip8141Error::InvalidSignatureScalar);
        }
        Ok(())
    }

    /// Runs [`Self::validate_structure`] and checks that a P-256 public key hashes to the resolved
    /// signer.
    ///
    /// This covers every check of the specification's `validate_signature` that does not need a
    /// cryptographic backend.
    pub fn validate_structure_with_sender(&self, sender: Address) -> Result<(), Eip8141Error> {
        self.validate_structure()?;
        if let Some(derived) = self.p256_signer_address() {
            let expected = self.signer.resolve(sender);
            if derived != expected {
                return Err(Eip8141Error::P256SignerMismatch { expected, derived });
            }
        }
        Ok(())
    }

    /// Parses the `v || r || s` payload of a secp256k1 entry.
    ///
    /// Returns `None` unless the entry uses the secp256k1 scheme with a 65-byte signature whose
    /// parity byte is zero or one.
    pub fn secp256k1_signature(&self) -> Option<Signature> {
        if self.scheme != SignatureScheme::Secp256k1
            || self.signature.len() != SECP256K1_SIGNATURE_LENGTH
        {
            return None;
        }
        let parity = match self.signature[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(Signature::from_bytes_and_parity(&self.signature[1..], parity))
    }

    /// Derives the signer address committed to by the public key of a P-256 entry.
    ///
    /// Returns `None` unless the entry uses the P-256 scheme with a 128-byte signature.
    pub fn p256_signer_address(&self) -> Option<Address> {
        (self.scheme == SignatureScheme::P256 && self.signature.len() == P256_SIGNATURE_LENGTH)
            .then(|| Address::from_raw_public_key(&self.signature[64..]))
    }

    /// Creates a structurally checked secp256k1 entry using EIP-8141's `v || r || s` layout.
    ///
    /// Unlike legacy signatures, the parity byte is zero or one and precedes the scalars.
    pub fn from_secp256k1(
        signer: FrameAddress,
        msg: SignatureMessage,
        signature: Signature,
    ) -> Result<Self, Eip8141Error> {
        let mut bytes = [0u8; SECP256K1_SIGNATURE_LENGTH];
        bytes[0] = u8::from(signature.v());
        bytes[1..33].copy_from_slice(&signature.r().to_be_bytes::<32>());
        bytes[33..].copy_from_slice(&signature.s().to_be_bytes::<32>());
        let entry = Self::new(SignatureScheme::Secp256k1, signer, msg, bytes.into());
        entry.validate_structure()?;
        Ok(entry)
    }

    /// Returns the protocol signature verification gas cost.
    pub const fn verification_gas(&self) -> u64 {
        self.scheme.verification_gas()
    }
}
