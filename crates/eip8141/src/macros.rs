/// Adds fallible byte conversion and quantity serde to a protocol discriminant.
macro_rules! impl_u8_conversions {
    ($ty:ty, $error:ident) => {
        impl TryFrom<u8> for $ty {
            type Error = crate::FrameError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                Self::try_from_u8(value).ok_or(crate::FrameError::$error(value))
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
}
