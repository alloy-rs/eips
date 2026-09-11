//! Serde helpers following Alloy's quantity and byte-string conventions.

use alloy_primitives::{FixedBytes, U8, U64};
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub(crate) mod quantity {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        U64::from(*value).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        U64::deserialize(deserializer).map(|value| value.to())
    }
}

pub(crate) mod quantity_u8 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(value: &u8, serializer: S) -> Result<S::Ok, S::Error> {
        U8::from(*value).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        U8::deserialize(deserializer).map(|value| value.to())
    }
}

pub(crate) fn serialize_optional_bytes<const N: usize, S: Serializer>(
    value: Option<FixedBytes<N>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => value.serialize(serializer),
        None => FixedBytes::<0>::ZERO.serialize(serializer),
    }
}

pub(crate) fn deserialize_optional_bytes<'de, const N: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FixedBytes<N>>, D::Error> {
    struct OptionalBytesVisitor<const N: usize>;

    impl<'de, const N: usize> de::Visitor<'de> for OptionalBytesVisitor<N> {
        type Value = Option<FixedBytes<N>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an empty byte string or exactly {N} bytes")
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.is_empty() {
                Ok(None)
            } else {
                FixedBytes::try_from(bytes).map(Some).map_err(E::custom)
            }
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value == "0x" || value.is_empty() {
                Ok(None)
            } else {
                value.parse().map(Some).map_err(E::custom)
            }
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let Some(first) = seq.next_element()? else { return Ok(None) };
            let mut bytes = [0u8; N];
            if N == 0 {
                return Err(de::Error::invalid_length(1, &self));
            }
            bytes[0] = first;
            for (i, byte) in bytes.iter_mut().enumerate().skip(1) {
                *byte = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            Ok(Some(bytes.into()))
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_any(OptionalBytesVisitor::<N>)
    } else {
        deserializer.deserialize_bytes(OptionalBytesVisitor::<N>)
    }
}
