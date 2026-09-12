use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable, Header};

use crate::Eip8141Error;

/// An empty or explicit address in a frame transaction.
///
/// Empty targets resolve to the transaction sender. Empty signature signers resolve to the sender
/// for protocol-validated schemes and represent no signer for arbitrary signatures.
/// RLP encodes the empty case as an empty byte string, preserving the EIP-8141 wire format.
/// JSON uses hex byte strings, including `"0x"` for the empty case; `null` also deserializes as
/// empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum FrameAddress {
    /// The address is omitted.
    #[default]
    Empty,
    /// An explicit address, including the zero address.
    Address(Address),
}

impl FrameAddress {
    /// Returns the explicit address, if present.
    pub const fn address(self) -> Option<Address> {
        match self {
            Self::Empty => None,
            Self::Address(address) => Some(address),
        }
    }

    /// Returns the explicit address, or `sender` when the address is omitted.
    pub const fn resolve(self, sender: Address) -> Address {
        match self {
            Self::Empty => sender,
            Self::Address(address) => address,
        }
    }

    /// Returns whether the address is omitted.
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns the byte string carried on the wire: empty when the address is omitted.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Address(address) => address.0.as_slice(),
        }
    }
}

impl From<Address> for FrameAddress {
    fn from(value: Address) -> Self {
        Self::Address(value)
    }
}

impl From<Option<Address>> for FrameAddress {
    fn from(value: Option<Address>) -> Self {
        value.map_or(Self::Empty, Self::Address)
    }
}

impl TryFrom<&[u8]> for FrameAddress {
    type Error = Eip8141Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Ok(Self::Empty)
        } else {
            Address::try_from(value)
                .map(Self::Address)
                .map_err(|_| Eip8141Error::InvalidAddressLength(value.len()))
        }
    }
}

impl Encodable for FrameAddress {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Empty => out.put_u8(alloy_rlp::EMPTY_STRING_CODE),
            Self::Address(address) => address.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Empty => 1,
            Self::Address(address) => address.length(),
        }
    }
}

impl Decodable for FrameAddress {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from(Header::decode_bytes(buf, false)?)
            .map_err(|_| alloy_rlp::Error::Custom("invalid EIP-8141 address length"))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for FrameAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::serde_utils::serialize_optional_bytes(
            self.address().map(|address| address.into_array().into()),
            serializer,
        )
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FrameAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::serde_utils::deserialize_optional_bytes::<20, D>(deserializer)
            .map(|address| Self::from(address.map(Address::from)))
    }
}
