//! Contains the [`BlockAccessList`] type, which represents a simple list of account changes.

use crate::account_changes::AccountChanges;
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// This struct is used to store `account_changes` in a block.
pub type BlockAccessList = Vec<AccountChanges>;

/// Computes the hash of the given block access list.
#[cfg(feature = "rlp")]
pub fn compute_block_access_list_hash(bal: &[AccountChanges]) -> alloy_primitives::B256 {
    let mut buf = Vec::new();
    alloy_rlp::encode_list(bal, &mut buf);
    alloy_primitives::keccak256(&buf)
}

/// Computes the total number of items in the block access list, counting each account and unique
/// storage slot.
pub fn total_bal_items(bal: &[AccountChanges]) -> u64 {
    let mut bal_items: u64 = 0;

    for account in bal {
        // Count address
        bal_items += 1;

        // Collect unique storage slots across reads + writes
        let mut unique_slots = alloy_primitives::map::HashSet::new();

        for change in account.storage_changes() {
            unique_slots.insert(change.slot);
        }

        for slot in account.storage_reads() {
            unique_slots.insert(*slot);
        }

        // Count unique storage keys
        bal_items += unique_slots.len() as u64;
    }
    bal_items
}

/// Block-Level Access List wrapper type with helper methods for metrics and validation.
pub mod bal {
    use super::OnceLock;
    use crate::account_changes::AccountChanges;
    use alloc::vec::{IntoIter, Vec};
    use alloy_primitives::Bytes;
    use core::{
        ops::{Deref, Index},
        slice::Iter,
    };

    /// A wrapper around [`Vec<AccountChanges>`] that provides helper methods for
    /// computing metrics and statistics about the block access list.
    ///
    /// This type implements `Deref` to `[AccountChanges]` for easy access to the
    /// underlying data while providing additional utility methods for BAL analysis.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(
        feature = "rlp",
        derive(alloy_rlp::RlpEncodableWrapper, alloy_rlp::RlpDecodableWrapper)
    )]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
    pub struct Bal(Vec<AccountChanges>);

    impl From<Bal> for Vec<AccountChanges> {
        fn from(this: Bal) -> Self {
            this.0
        }
    }

    impl From<Vec<AccountChanges>> for Bal {
        fn from(list: Vec<AccountChanges>) -> Self {
            Self(list)
        }
    }

    #[cfg(feature = "rlp")]
    impl alloy_primitives::Sealable for Bal {
        fn hash_slow(&self) -> alloy_primitives::B256 {
            self.compute_hash()
        }
    }

    impl Deref for Bal {
        type Target = [AccountChanges];

        fn deref(&self) -> &Self::Target {
            self.as_slice()
        }
    }

    impl IntoIterator for Bal {
        type Item = AccountChanges;
        type IntoIter = IntoIter<AccountChanges>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<'a> IntoIterator for &'a Bal {
        type Item = &'a AccountChanges;
        type IntoIter = Iter<'a, AccountChanges>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    impl FromIterator<AccountChanges> for Bal {
        fn from_iter<I: IntoIterator<Item = AccountChanges>>(iter: I) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    impl<I> Index<I> for Bal
    where
        I: core::slice::SliceIndex<[AccountChanges]>,
    {
        type Output = I::Output;

        #[inline]
        fn index(&self, index: I) -> &Self::Output {
            &self.0[index]
        }
    }

    impl Bal {
        /// Creates a new [`Bal`] from the provided account changes.
        pub const fn new(account_changes: Vec<AccountChanges>) -> Self {
            Self(account_changes)
        }

        /// Adds a new [`AccountChanges`] entry to the list.
        pub fn push(&mut self, account_changes: AccountChanges) {
            self.0.push(account_changes)
        }

        /// Returns `true` if the list contains no elements.
        #[inline]
        pub const fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Returns the number of account change entries contained in the list.
        #[inline]
        pub const fn len(&self) -> usize {
            self.0.len()
        }

        /// Returns an iterator over the [`AccountChanges`] entries.
        #[inline]
        pub fn iter(&self) -> Iter<'_, AccountChanges> {
            self.0.iter()
        }

        /// Returns a slice of the contained [`AccountChanges`].
        #[inline]
        pub const fn as_slice(&self) -> &[AccountChanges] {
            self.0.as_slice()
        }

        /// Returns a vector of [`AccountChanges`].
        pub fn into_inner(self) -> Vec<AccountChanges> {
            self.0
        }

        /// Sorts this block access list in-place according to the canonical EIP-7928 ordering
        /// rules.
        ///
        /// This applies the ordering required by the "Ordering, Uniqueness and Determinism"
        /// section of EIP-7928:
        ///
        /// - accounts are sorted lexicographically by address
        /// - `storage_changes` are sorted lexicographically by storage key
        /// - each per-slot `StorageChange` list is sorted by block access index in ascending order
        /// - `storage_reads` are sorted lexicographically by storage key
        /// - `balance_changes`, `nonce_changes`, and `code_changes` are sorted by block access
        ///   index in ascending order
        ///
        /// The account-local ordering is delegated to [`AccountChanges::sort`], so callers may
        /// sort account internals independently when a parallel sort strategy is useful.
        ///
        /// This method only canonicalizes ordering. It does not enforce the EIP-7928 uniqueness
        /// constraints for accounts, storage keys, or block access indexes.
        pub fn sort(&mut self) {
            self.0.sort_unstable_by_key(|account| account.address);

            for account in &mut self.0 {
                account.sort();
            }
        }

        /// Returns the total number of accounts with changes in this BAL.
        #[inline]
        pub const fn account_count(&self) -> usize {
            self.0.len()
        }

        /// Returns the total number of storage changes across all accounts.
        pub fn total_storage_changes(&self) -> usize {
            self.0.iter().map(|a| a.storage_changes.len()).sum()
        }

        /// Returns the total number of storage reads across all accounts.
        pub fn total_storage_reads(&self) -> usize {
            self.0.iter().map(|a| a.storage_reads.len()).sum()
        }

        /// Returns the total number of storage slots (both changes and reads) across all accounts.
        pub fn total_slots(&self) -> usize {
            self.0.iter().map(|a| a.storage_changes.len() + a.storage_reads.len()).sum()
        }

        /// Returns the total number of balance changes across all accounts.
        pub fn total_balance_changes(&self) -> usize {
            self.0.iter().map(|a| a.balance_changes.len()).sum()
        }

        /// Returns the total number of nonce changes across all accounts.
        pub fn total_nonce_changes(&self) -> usize {
            self.0.iter().map(|a| a.nonce_changes.len()).sum()
        }

        /// Returns the total number of code changes across all accounts.
        pub fn total_code_changes(&self) -> usize {
            self.0.iter().map(|a| a.code_changes.len()).sum()
        }

        /// Returns a summary of all change counts for metrics reporting.
        pub fn change_counts(&self) -> BalChangeCounts {
            let mut counts = BalChangeCounts::default();
            for account in &self.0 {
                counts.accounts += 1;
                counts.storage += account.storage_changes.len();
                counts.balance += account.balance_changes.len();
                counts.nonce += account.nonce_changes.len();
                counts.code += account.code_changes.len();
            }
            counts
        }

        /// Computes the total number of items in this block access list, counting each account and
        /// unique storage slot.
        pub fn total_bal_items(&self) -> u64 {
            super::total_bal_items(&self.0)
        }

        /// Computes the hash of this block access list.
        #[cfg(feature = "rlp")]
        pub fn compute_hash(&self) -> alloy_primitives::B256 {
            if self.0.is_empty() {
                return crate::constants::EMPTY_BLOCK_ACCESS_LIST_HASH;
            }
            super::compute_block_access_list_hash(&self.0)
        }
    }

    /// Summary of change counts in a BAL for metrics reporting.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct BalChangeCounts {
        /// Number of accounts with changes.
        pub accounts: usize,
        /// Total number of storage changes.
        pub storage: usize,
        /// Total number of balance changes.
        pub balance: usize,
        /// Total number of nonce changes.
        pub nonce: usize,
        /// Total number of code changes.
        pub code: usize,
    }

    /// A decoded block access list with lazy hash computation.
    ///
    /// This type wraps a decoded [`Bal`] along with the original raw RLP bytes,
    /// allowing efficient hash computation on demand without re-encoding.
    #[derive(Clone, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct DecodedBal {
        /// The decoded block access list.
        decoded: Bal,
        /// The original raw RLP bytes.
        raw: Bytes,
        /// Lazily computed hash of the block access list.
        #[cfg_attr(feature = "serde", serde(skip, default))]
        hash: OnceLock<alloy_primitives::B256>,
    }

    impl PartialEq for DecodedBal {
        fn eq(&self, other: &Self) -> bool {
            self.decoded == other.decoded && self.raw == other.raw
        }
    }

    impl Eq for DecodedBal {}

    impl DecodedBal {
        /// Creates a new [`DecodedBal`] from decoded data and raw bytes.
        pub const fn new(decoded: Bal, raw: Bytes) -> Self {
            Self { decoded, raw, hash: OnceLock::new() }
        }

        /// Creates a new [`DecodedBal`] by decoding from raw RLP bytes.
        #[cfg(feature = "rlp")]
        pub fn from_rlp_bytes(raw: Bytes) -> Result<Self, alloy_rlp::Error> {
            let mut slice = raw.as_ref();
            let decoded = <Bal as alloy_rlp::Decodable>::decode(&mut slice)?;
            if !slice.is_empty() {
                return Err(alloy_rlp::Error::UnexpectedLength);
            }
            Ok(Self::new(decoded, raw))
        }

        /// Returns a reference to the decoded block access list.
        pub const fn as_bal(&self) -> &Bal {
            &self.decoded
        }

        /// Returns the original raw RLP bytes.
        pub const fn as_raw(&self) -> &Bytes {
            &self.raw
        }

        /// Returns the decoded BAL as a sealed borrowed value.
        #[cfg(feature = "rlp")]
        pub fn as_sealed_bal(&self) -> alloy_primitives::Sealed<&Bal> {
            alloy_primitives::Sealable::seal_ref_unchecked(&self.decoded, self.hash())
        }

        /// Splits this struct into the decoded BAL and raw bytes.
        pub fn split(self) -> (Bal, Bytes) {
            (self.decoded, self.raw)
        }

        /// Splits this struct into the decoded BAL, raw bytes, and hash.
        pub fn into_parts(self) -> (Bal, Bytes, alloy_primitives::B256) {
            let hash = self.hash();
            let (decoded, raw) = self.split();
            (decoded, raw, hash)
        }

        /// Consumes this struct and returns the decoded BAL together with its hash.
        #[cfg(feature = "rlp")]
        pub fn into_sealed(self) -> alloy_primitives::Sealed<Bal> {
            let seal = self.hash();
            let (decoded, _) = self.split();
            alloy_primitives::Sealable::seal_unchecked(decoded, seal)
        }

        /// Returns the hash of this block access list.
        ///
        /// The hash is computed lazily on first call and cached for subsequent calls.
        pub fn hash(&self) -> alloy_primitives::B256 {
            #[allow(clippy::useless_conversion)]
            *self.hash.get_or_init(|| alloy_primitives::keccak256(self.raw.as_ref()).into())
        }
    }

    #[cfg(feature = "rlp")]
    impl alloy_rlp::Decodable for DecodedBal {
        fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
            let original = *buf;
            let decoded = <Bal as alloy_rlp::Decodable>::decode(buf)?;
            let consumed = original.len() - buf.len();
            let raw = Bytes::copy_from_slice(&original[..consumed]);
            Ok(Self::new(decoded, raw))
        }
    }

    #[cfg(feature = "rlp")]
    impl alloy_rlp::Encodable for DecodedBal {
        fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
            out.put_slice(&self.raw);
        }

        fn length(&self) -> usize {
            self.raw.len()
        }
    }
}

#[cfg(test)]
mod hash_tests {
    use super::bal::{Bal, DecodedBal};
    use crate::{
        AccountChanges, BalanceChange, CodeChange, NonceChange, SlotChanges, StorageChange,
    };
    use alloy_primitives::{Address, Bytes, U256};

    #[test]
    fn decoded_bal_hash_uses_raw_bytes_without_rlp_feature() {
        let raw = Bytes::from_static(&[0xc0]);
        let decoded = DecodedBal::new(Bal::default(), raw.clone());

        assert_eq!(decoded.hash(), alloy_primitives::keccak256(raw.as_ref()));

        let (bal, split_raw, split_hash) = decoded.into_parts();
        assert!(bal.is_empty());
        assert_eq!(split_raw, raw);
        assert_eq!(split_hash, alloy_primitives::keccak256(raw.as_ref()));
    }

    #[test]
    fn bal_sort_orders_all_eip7928_lists() {
        let address_1 = Address::from([0x11; 20]);
        let address_2 = Address::from([0x22; 20]);
        let mut bal = Bal::new(vec![
            AccountChanges {
                address: address_2,
                storage_changes: vec![
                    SlotChanges::new(
                        U256::from(3),
                        vec![
                            StorageChange::new(8, U256::from(0x80)),
                            StorageChange::new(2, U256::from(0x20)),
                        ],
                    ),
                    SlotChanges::new(
                        U256::from(1),
                        vec![
                            StorageChange::new(5, U256::from(0x50)),
                            StorageChange::new(1, U256::from(0x10)),
                        ],
                    ),
                ],
                storage_reads: vec![U256::from(4), U256::from(2)],
                balance_changes: vec![
                    BalanceChange::new(6, U256::from(600)),
                    BalanceChange::new(3, U256::from(300)),
                ],
                nonce_changes: vec![NonceChange::new(7, 70), NonceChange::new(4, 40)],
                code_changes: vec![
                    CodeChange::new(9, Bytes::from_static(&[0x60, 0x09])),
                    CodeChange::new(5, Bytes::from_static(&[0x60, 0x05])),
                ],
            },
            AccountChanges {
                address: address_1,
                storage_changes: vec![
                    SlotChanges::new(
                        U256::from(2),
                        vec![
                            StorageChange::new(4, U256::from(0x40)),
                            StorageChange::new(0, U256::from(0x00)),
                        ],
                    ),
                    SlotChanges::new(
                        U256::from(1),
                        vec![
                            StorageChange::new(3, U256::from(0x30)),
                            StorageChange::new(1, U256::from(0x10)),
                        ],
                    ),
                ],
                storage_reads: vec![U256::from(5), U256::from(3)],
                balance_changes: vec![
                    BalanceChange::new(5, U256::from(500)),
                    BalanceChange::new(2, U256::from(200)),
                ],
                nonce_changes: vec![NonceChange::new(8, 80), NonceChange::new(1, 10)],
                code_changes: vec![
                    CodeChange::new(4, Bytes::from_static(&[0x60, 0x04])),
                    CodeChange::new(2, Bytes::from_static(&[0x60, 0x02])),
                ],
            },
        ]);

        bal.sort();

        assert_eq!(bal[0].address, address_1);
        assert_eq!(bal[1].address, address_2);

        for account in bal.iter() {
            assert!(account.storage_changes.windows(2).all(|slots| slots[0].slot <= slots[1].slot));
            for slot_changes in &account.storage_changes {
                assert!(
                    slot_changes
                        .changes
                        .windows(2)
                        .all(|changes| changes[0].block_access_index
                            <= changes[1].block_access_index)
                );
            }
            assert!(account.storage_reads.windows(2).all(|slots| slots[0] <= slots[1]));
            assert!(
                account
                    .balance_changes
                    .windows(2)
                    .all(|changes| changes[0].block_access_index <= changes[1].block_access_index)
            );
            assert!(
                account
                    .nonce_changes
                    .windows(2)
                    .all(|changes| changes[0].block_access_index <= changes[1].block_access_index)
            );
            assert!(
                account
                    .code_changes
                    .windows(2)
                    .all(|changes| changes[0].block_access_index <= changes[1].block_access_index)
            );
        }
    }
}

#[cfg(all(test, feature = "rlp"))]
mod tests {
    use super::bal::{Bal, DecodedBal};
    use crate::{
        AccountChanges, BalanceChange, CodeChange, NonceChange, SlotChanges, StorageChange,
        constants::EMPTY_BLOCK_ACCESS_LIST_HASH,
    };
    use alloy_primitives::{Address, Bytes, U256};

    fn sample_bal() -> Bal {
        Bal::new(vec![
            AccountChanges::new(Address::from([0x11; 20]))
                .with_storage_read(U256::from(0x10))
                .with_storage_change(SlotChanges::new(
                    U256::from(0x01),
                    vec![StorageChange::new(0, U256::from(0xaa))],
                ))
                .with_balance_change(BalanceChange::new(1, U256::from(1_000)))
                .with_nonce_change(NonceChange::new(2, 7))
                .with_code_change(CodeChange::new(3, Bytes::from(vec![0x60, 0x00]))),
            AccountChanges::new(Address::from([0x22; 20]))
                .with_storage_read(U256::from(0x20))
                .with_storage_change(SlotChanges::new(
                    U256::from(0x02),
                    vec![StorageChange::new(4, U256::from(0xbb))],
                )),
        ])
    }

    #[test]
    fn bal_compute_hash_returns_empty_hash_for_empty_bal() {
        let bal = Bal::default();

        assert_eq!(bal.compute_hash(), EMPTY_BLOCK_ACCESS_LIST_HASH);
    }

    #[test]
    fn bal_compute_hash_matches_free_function_for_non_empty_bal() {
        let bal = sample_bal();

        assert_eq!(bal.compute_hash(), super::compute_block_access_list_hash(bal.as_slice()));
        assert_ne!(bal.compute_hash(), EMPTY_BLOCK_ACCESS_LIST_HASH);
    }

    #[test]
    fn decoded_bal_from_rlp_bytes_preserves_raw_and_hash() {
        let bal = sample_bal();
        let raw = Bytes::from(alloy_rlp::encode(&bal));
        let decoded = DecodedBal::from_rlp_bytes(raw.clone()).unwrap();

        assert_eq!(decoded.as_bal(), &bal);
        assert_eq!(decoded.as_raw(), &raw);
        assert_eq!(decoded.hash(), bal.compute_hash());
        assert_eq!(decoded.hash(), alloy_primitives::keccak256(raw.as_ref()));
        assert_eq!(decoded.as_sealed_bal().hash(), bal.compute_hash());
        assert_eq!(decoded.as_sealed_bal().inner(), &decoded.as_bal());

        let (split_bal, split_raw) = decoded.clone().split();
        assert_eq!(split_bal, bal);
        assert_eq!(split_raw, raw);

        let (split_bal, split_raw, split_hash) = decoded.clone().into_parts();
        assert_eq!(split_bal, bal);
        assert_eq!(split_raw, raw);
        assert_eq!(split_hash, bal.compute_hash());

        let sealed = decoded.into_sealed();
        assert_eq!(sealed.hash(), bal.compute_hash());
        assert_eq!(sealed.inner(), &bal);
    }

    #[test]
    fn decoded_bal_decode_consumes_exact_raw_rlp_item() {
        let bal = sample_bal();
        let raw = alloy_rlp::encode(&bal);
        let mut buf = raw.as_ref();
        let decoded = <DecodedBal as alloy_rlp::Decodable>::decode(&mut buf).unwrap();

        assert!(buf.is_empty());
        assert_eq!(decoded.as_bal(), &bal);
        assert_eq!(decoded.as_raw().as_ref(), raw.as_slice());
        assert_eq!(alloy_rlp::encode(&decoded), raw);
    }
}
