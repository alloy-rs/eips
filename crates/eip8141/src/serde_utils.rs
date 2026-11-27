//! Serde helpers following Alloy's quantity and byte-string conventions.

use alloy_primitives::{FixedBytes, U8, U64, hex};
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

/// Deserializes an optional fixed-size byte string.
///
/// Empty byte strings, `"0x"`, and `null` all yield `None`.
pub(crate) fn deserialize_optional_bytes<'de, const N: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FixedBytes<N>>, D::Error> {
    deserialize_byte_string::<N, _, _, _>(deserializer, |bytes| {
        if bytes.is_empty() { Ok(None) } else { FixedBytes::try_from(bytes).map(Some) }
    })
}

/// Deserializes bytes into a stack buffer when the input format supplies hex or a sequence.
pub(crate) fn deserialize_byte_string<'de, const N: usize, D, T, E>(
    deserializer: D,
    convert: fn(&[u8]) -> Result<T, E>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    E: fmt::Display,
{
    struct ByteStringVisitor<const N: usize, T, E>(fn(&[u8]) -> Result<T, E>);

    impl<'de, const N: usize, T, E: fmt::Display> de::Visitor<'de> for ByteStringVisitor<N, T, E> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a byte string of at most {N} bytes")
        }

        fn visit_none<F: de::Error>(self) -> Result<T, F> {
            self.visit_bytes(&[])
        }

        fn visit_unit<F: de::Error>(self) -> Result<T, F> {
            self.visit_bytes(&[])
        }

        fn visit_bytes<F: de::Error>(self, bytes: &[u8]) -> Result<T, F> {
            (self.0)(bytes).map_err(F::custom)
        }

        fn visit_str<F: de::Error>(self, value: &str) -> Result<T, F> {
            // The existing empty hex sentinel is lowercase.
            if value == "0X" {
                return Err(F::invalid_length(0, &self));
            }
            let value =
                value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
            let len = value.len() / 2;
            let mut bytes = [0u8; N];
            let bytes = bytes.get_mut(..len).ok_or_else(|| F::invalid_length(len, &self))?;
            hex::decode_to_slice(value, bytes).map_err(F::custom)?;
            self.visit_bytes(bytes)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
            let mut bytes = [0u8; N];
            for (len, byte) in bytes.iter_mut().enumerate() {
                let Some(value) = seq.next_element()? else {
                    return self.visit_bytes(&bytes[..len]);
                };
                *byte = value;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            self.visit_bytes(&bytes)
        }
    }

    let visitor = ByteStringVisitor::<N, _, _>(convert);
    if deserializer.is_human_readable() {
        deserializer.deserialize_any(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
