use crate::{Eip8141Error, FrameAddress, LEAN_SPHINCS_PUBLIC_KEY_LENGTH};
use alloy_primitives::{Address, B256};
use alloy_rlp::{Decodable, Encodable, Header};

/// Signer metadata carried by a frame signature entry.
///
/// The signature scheme determines which variant is valid. RLP and serde encode the metadata
/// as a byte string of length 0, 20, or 32, respectively.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum FrameSigner {
    /// The signer field is empty.
    #[default]
    Empty,
    /// An explicit Ethereum address.
    Address(Address),
    /// The full leanSPHINCS public key, encoded as a 16-byte root and 16-byte public parameter.
    LeanSphincs(B256),
}

impl FrameSigner {
    /// Converts an optional frame address into signer metadata.
    pub const fn from_address(address: FrameAddress) -> Self {
        match address {
            FrameAddress::Empty => Self::Empty,
            FrameAddress::Address(address) => Self::Address(address),
        }
    }

    /// Returns the explicitly supplied Ethereum address, if any.
    pub const fn address(self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(address),
            _ => None,
        }
    }

    /// Returns whether the signer field is empty.
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns the signer bytes as carried on the wire.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Address(address) => address.0.as_slice(),
            Self::LeanSphincs(key) => key.as_slice(),
        }
    }
}

impl From<FrameAddress> for FrameSigner {
    fn from(address: FrameAddress) -> Self {
        Self::from_address(address)
    }
}

impl From<Address> for FrameSigner {
    fn from(address: Address) -> Self {
        Self::Address(address)
    }
}

impl TryFrom<&[u8]> for FrameSigner {
    type Error = Eip8141Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            0 => Ok(Self::Empty),
            20 => Ok(Self::Address(Address::from_slice(bytes))),
            LEAN_SPHINCS_PUBLIC_KEY_LENGTH => Ok(Self::LeanSphincs(B256::from_slice(bytes))),
            len => Err(Eip8141Error::InvalidSignerLength(len)),
        }
    }
}

impl Encodable for FrameSigner {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Empty => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
            Self::Address(address) => address.encode(out),
            Self::LeanSphincs(key) => key.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Empty => 1,
            Self::Address(_) => 21,
            Self::LeanSphincs(_) => 1 + LEAN_SPHINCS_PUBLIC_KEY_LENGTH,
        }
    }
}

impl Decodable for FrameSigner {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from(Header::decode_bytes(buf, false)?)
            .map_err(|_| alloy_rlp::Error::Custom("invalid EIP-8141 signer length"))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FrameSigner {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Empty => alloy_primitives::FixedBytes::<0>::ZERO.serialize(serializer),
            Self::Address(address) => address.0.serialize(serializer),
            Self::LeanSphincs(key) => key.serialize(serializer),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FrameSigner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::serde_utils::deserialize_byte_string::<LEAN_SPHINCS_PUBLIC_KEY_LENGTH, _, _, _>(
            deserializer,
            |bytes| Self::try_from(bytes),
        )
    }
}

/// The resolved signer of a protocol-validated frame signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedFrameSigner {
    /// The signer address for an elliptic-curve signature.
    Address(Address),
    /// The full public key for a leanSPHINCS signature.
    LeanSphincs(B256),
}

impl ResolvedFrameSigner {
    /// Returns the word exposed by `SIGPARAM`.
    pub fn into_word(self) -> B256 {
        match self {
            Self::Address(address) => address.into_word(),
            Self::LeanSphincs(key) => key,
        }
    }
}
