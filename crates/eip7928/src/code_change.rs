//! Contains the [`CodeChange`] struct, which represents a new code for an account.
//! Single code change: `tx_index` -> `new_code`
use crate::BlockAccessIndex;
use alloy_primitives::{B256, Bytes, KECCAK256_EMPTY, keccak256};
use core::hash::{Hash, Hasher};
#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// This struct is used to track the new codes of accounts in a block.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CodeChange {
    /// The index of bal that stores this code change.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "index", alias = "blockAccessIndex", alias = "txIndex")
    )]
    pub block_access_index: BlockAccessIndex,
    /// The new code of the account.
    #[cfg_attr(feature = "serde", serde(rename = "code", alias = "newCode"))]
    new_code: Bytes,
    /// Lazily computed hash of the immutable code bytes.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "borsh", borsh(skip))]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    hash: OnceLock<B256>,
}
impl CodeChange {
    /// Creates a new [`CodeChange`].
    pub const fn new(block_access_index: BlockAccessIndex, new_code: Bytes) -> Self {
        Self { block_access_index, new_code, hash: OnceLock::new() }
    }

    /// Returns the bal index.
    #[inline]
    pub const fn block_access_index(&self) -> BlockAccessIndex {
        self.block_access_index
    }

    /// Returns the new code.
    #[inline]
    pub const fn new_code(&self) -> &Bytes {
        &self.new_code
    }

    /// Consumes the change and returns the new code.
    #[inline]
    pub fn into_code(self) -> Bytes {
        self.new_code
    }

    /// Returns the Keccak-256 hash of the new code, computing it only when needed.
    #[inline]
    pub fn code_hash(&self) -> B256 {
        #[allow(clippy::useless_conversion)]
        *self.hash.get_or_init(|| {
            if self.new_code.is_empty() { KECCAK256_EMPTY } else { keccak256(&self.new_code) }
                .into()
        })
    }
}

impl PartialEq for CodeChange {
    fn eq(&self, other: &Self) -> bool {
        self.block_access_index == other.block_access_index && self.new_code == other.new_code
    }
}

impl Eq for CodeChange {}

impl Hash for CodeChange {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block_access_index.hash(state);
        self.new_code.hash(state);
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Encodable for CodeChange {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.block_access_index.length() + self.new_code.length(),
        }
        .encode(out);
        self.block_access_index.encode(out);
        self.new_code.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.block_access_index.length() + self.new_code.length();
        alloy_rlp::length_of_length(payload_length) + payload_length
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Decodable for CodeChange {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // Keep the wire layout independent of the cache.
        #[derive(alloy_rlp::RlpDecodable)]
        struct Fields {
            block_access_index: BlockAccessIndex,
            new_code: Bytes,
        }
        let fields = Fields::decode(buf)?;
        Ok(Self::new(fields.block_access_index, fields.new_code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes;

    #[test]
    fn lazy_hash_and_clone() {
        for code in [Bytes::new(), bytes!("6000")] {
            let change = CodeChange::new(BlockAccessIndex::new(1), code.clone());
            let uncached = change.clone();
            assert!(change.hash.get().is_none());
            assert_eq!(change.code_hash(), keccak256(&code));
            assert_eq!(change.hash.get(), Some(&keccak256(&code)));
            assert_eq!(change, uncached);
            assert_eq!(change.clone().hash.get(), change.hash.get());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn concurrent_hash_and_hash_trait() {
        use std::{collections::hash_map::DefaultHasher, thread};
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let hash_value = || {
            let mut hasher = DefaultHasher::new();
            change.hash(&mut hasher);
            hasher.finish()
        };
        let before = hash_value();
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| assert_eq!(change.code_hash(), keccak256(change.new_code())));
            }
        });
        assert_eq!(hash_value(), before);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn rlp_ignores_cache() {
        use alloy_rlp::{Decodable, Encodable};
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let encoded = alloy_rlp::encode(&change);
        assert_eq!(encoded, [0xc4, 0x01, 0x82, 0x60, 0x00]);
        change.code_hash();
        assert_eq!(alloy_rlp::encode(&change), encoded);
        assert_eq!(change.length(), encoded.len());
        let decoded = CodeChange::decode(&mut encoded.as_slice()).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
        assert!(CodeChange::decode(&mut &[0xc5, 0x01, 0x82, 0x60, 0x00, 0x80][..]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_ignores_cache() {
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        change.code_hash();
        let json = serde_json::to_string(&change).unwrap();
        assert_eq!(json, r#"{"index":"0x1","code":"0x6000"}"#);
        let decoded: CodeChange = serde_json::from_str(&json).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
    }

    #[cfg(feature = "borsh")]
    #[test]
    fn borsh_ignores_cache() {
        let change = CodeChange::new(BlockAccessIndex::new(1), bytes!("6000"));
        let encoded = borsh::to_vec(&change).unwrap();
        change.code_hash();
        assert_eq!(borsh::to_vec(&change).unwrap(), encoded);
        assert_eq!(
            encoded,
            borsh::to_vec(&(change.block_access_index, change.new_code())).unwrap()
        );
        let decoded: CodeChange = borsh::from_slice(&encoded).unwrap();
        assert!(decoded.hash.get().is_none());
        assert_eq!(decoded, change);
    }

    /// Consumes the change and returns the new code.
    #[inline]
    pub fn into_code(self) -> Bytes {
        self.new_code
    }
}
