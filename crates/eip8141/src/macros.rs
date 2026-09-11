/// Implements the conversions shared by EIP-8141 `u8` discriminants.
///
/// Every discriminant gets `From<Self> for u8`, `TryFrom<u8>`, and quantity serde. Passing an RLP
/// error message additionally implements the single-byte RLP encoding used on the wire.
macro_rules! impl_u8_discriminant {
    ($ty:ty, $error:ident) => {
        impl From<$ty> for u8 {
            fn from(value: $ty) -> Self {
                value as Self
            }
        }

        impl TryFrom<u8> for $ty {
            type Error = crate::Eip8141Error;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                Self::try_from_u8(value).ok_or(crate::Eip8141Error::$error(value))
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                crate::serde_utils::quantity_u8::serialize(&u8::from(*self), serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = crate::serde_utils::quantity_u8::deserialize(deserializer)?;
                Self::try_from(value).map_err(serde::de::Error::custom)
            }
        }
    };
    ($ty:ty, $error:ident, $rlp_error:literal) => {
        impl_u8_discriminant!($ty, $error);

        impl alloy_rlp::Encodable for $ty {
            fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
                alloy_rlp::Encodable::encode(&u8::from(*self), out);
            }

            fn length(&self) -> usize {
                alloy_rlp::Encodable::length(&u8::from(*self))
            }
        }

        impl alloy_rlp::Decodable for $ty {
            fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
                Self::try_from_u8(<u8 as alloy_rlp::Decodable>::decode(buf)?)
                    .ok_or(alloy_rlp::Error::Custom($rlp_error))
            }
        }
    };
}
