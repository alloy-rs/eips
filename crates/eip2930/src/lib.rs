//! [EIP-2930] types.
//!
//! [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper};
use core::{mem, ops::Deref};

/// A list of addresses and storage keys that the transaction plans to access.
/// Accesses outside the list are possible, but become more expensive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct AccessListItem {
    /// Account addresses that would be loaded at the start of execution
    pub address: Address,
    /// Keys of storage that would be loaded at the start of execution
    pub storage_keys: Vec<B256>,
}

impl AccessListItem {
    /// Calculates a heuristic for the in-memory size of the [AccessListItem].
    #[inline]
    pub const fn size(&self) -> usize {
        mem::size_of::<Address>() + self.storage_keys.capacity() * mem::size_of::<B256>()
    }
}

/// AccessList as defined in EIP-2930
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpDecodableWrapper, RlpEncodableWrapper)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct AccessList(pub Vec<AccessListItem>);

impl From<Vec<AccessListItem>> for AccessList {
    fn from(list: Vec<AccessListItem>) -> Self {
        Self(list)
    }
}

impl From<AccessList> for Vec<AccessListItem> {
    fn from(this: AccessList) -> Self {
        this.0
    }
}

impl Deref for AccessList {
    type Target = Vec<AccessListItem>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AccessList {
    /// Removes duplicate addresses and storage keys from this access list.
    ///
    /// Duplicate address entries are merged into the first entry for that address. Storage keys
    /// from later entries are appended to the first entry, and duplicate storage keys are removed
    /// while preserving their first-occurrence order.
    ///
    /// This method preserves the relative order of addresses and storage keys. Call [`Self::sort`]
    /// afterwards if deterministic ordering is required.
    ///
    /// EIP-2930 charges duplicate addresses and storage keys individually, so deduplicating a
    /// transaction's access list can change its intrinsic gas cost.
    pub fn dedup(&mut self) {
        let items = mem::take(&mut self.0);
        let mut deduped = Vec::<AccessListItem>::with_capacity(items.len());
        let mut address_positions = BTreeMap::<_, usize>::new();

        for item in items {
            if let Some(&idx) = address_positions.get(&item.address) {
                deduped[idx].storage_keys.extend(item.storage_keys);
            } else {
                address_positions.insert(item.address, deduped.len());
                deduped.push(item);
            }
        }

        for item in &mut deduped {
            let mut seen = BTreeSet::<B256>::new();
            item.storage_keys.retain(|key| seen.insert(*key));
        }

        self.0 = deduped;
    }

    /// Sorts this access list in-place by address and each address's storage keys.
    ///
    /// This method only provides deterministic ordering. It preserves duplicate addresses and
    /// storage keys; call [`Self::dedup`] to remove them.
    pub fn sort(&mut self) {
        for item in &mut self.0 {
            item.storage_keys.sort_unstable();
        }
        self.0.sort_unstable_by(|a, b| {
            a.address.cmp(&b.address).then_with(|| a.storage_keys.cmp(&b.storage_keys))
        });
    }

    /// Converts the list into a vec, expected by revm
    pub fn flattened(&self) -> Vec<(Address, Vec<U256>)> {
        self.flatten().collect()
    }

    /// Consumes the type and converts the list into a vec, expected by revm
    pub fn into_flattened(self) -> Vec<(Address, Vec<U256>)> {
        self.into_flatten().collect()
    }

    /// Consumes the type and returns an iterator over the list's addresses and storage keys.
    pub fn into_flatten(self) -> impl Iterator<Item = (Address, Vec<U256>)> {
        self.0.into_iter().map(|item| {
            (
                item.address,
                item.storage_keys.into_iter().map(|slot| U256::from_be_bytes(slot.0)).collect(),
            )
        })
    }

    /// Returns an iterator over the list's addresses and storage keys.
    pub fn flatten(&self) -> impl Iterator<Item = (Address, Vec<U256>)> + '_ {
        self.0.iter().map(|item| {
            (
                item.address,
                item.storage_keys.iter().map(|slot| U256::from_be_bytes(slot.0)).collect(),
            )
        })
    }

    /// Returns the position of the given address in the access list, if present.
    fn index_of_address(&self, address: Address) -> Option<usize> {
        self.iter().position(|item| item.address == address)
    }

    /// Returns the total number of storage keys in this access list.
    pub fn storage_keys_count(&self) -> usize {
        self.iter().map(|i| i.storage_keys.len()).sum::<usize>()
    }

    /// Checks if a specific storage slot within an account is present in the access list.
    ///
    /// Returns a tuple with flags for the presence of the account and the slot.
    pub fn contains_storage(&self, address: Address, slot: B256) -> (bool, bool) {
        self.index_of_address(address)
            .map_or((false, false), |idx| (true, self.contains_storage_key_at_index(slot, idx)))
    }

    /// Checks if the access list contains the specified address.
    pub fn contains_address(&self, address: Address) -> bool {
        self.iter().any(|item| item.address == address)
    }

    /// Checks if the storage keys at the given index within an account are present in the access
    /// list.
    fn contains_storage_key_at_index(&self, slot: B256, index: usize) -> bool {
        self.get(index).is_some_and(|entry| entry.storage_keys.contains(&slot))
    }

    /// Adds an address to the access list and returns `true` if the operation results in a change,
    /// indicating that the address was not previously present.
    pub fn add_address(&mut self, address: Address) -> bool {
        !self.contains_address(address) && {
            self.0.push(AccessListItem { address, storage_keys: Vec::new() });
            true
        }
    }

    /// Calculates a heuristic for the in-memory size of the [AccessList].
    #[inline]
    pub fn size(&self) -> usize {
        // take into account capacity
        self.0.iter().map(AccessListItem::size).sum::<usize>()
            + self.0.capacity() * mem::size_of::<AccessListItem>()
    }
}

/// Access list with gas used appended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct AccessListWithGasUsed {
    /// List with accounts accessed during transaction.
    pub access_list: AccessList,
    /// Estimated gas used with access list.
    pub gas_used: U256,
}

/// `AccessListResult` for handling errors from `eth_createAccessList`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct AccessListResult {
    /// List with accounts accessed during transaction.
    pub access_list: AccessList,
    /// Estimated gas used with access list.
    pub gas_used: U256,
    /// Optional error message if the transaction failed.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub error: Option<String>,
}

impl AccessListResult {
    /// Ensures the result is OK, returning [`AccessListWithGasUsed`] if so, or an error message if
    /// not.
    pub fn ensure_ok(self) -> Result<AccessListWithGasUsed, String> {
        match self.error {
            Some(err) => Err(err),
            None => {
                Ok(AccessListWithGasUsed { access_list: self.access_list, gas_used: self.gas_used })
            }
        }
    }

    /// Checks if there is an error in the result.
    #[inline]
    pub const fn is_err(&self) -> bool {
        self.error.is_some()
    }

    /// Returns `true` if there is no error in the result.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn access_list_item_rlp_roundtrip() {
        let item = AccessListItem {
            address: Address::left_padding_from(&[1]),
            storage_keys: vec![B256::with_last_byte(2)],
        };
        let mut buf = Vec::new();
        item.encode(&mut buf);
        let decoded = AccessListItem::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(buf.len(), item.length());
        assert_eq!(decoded, item);
    }

    #[test]
    fn access_list_rlp_roundtrip() {
        let list = AccessList(vec![
            AccessListItem {
                address: Address::left_padding_from(&[1]),
                storage_keys: vec![B256::with_last_byte(2), B256::with_last_byte(3)],
            },
            AccessListItem { address: Address::left_padding_from(&[4]), storage_keys: vec![] },
        ]);
        let mut buf = Vec::new();
        list.encode(&mut buf);
        let decoded = AccessList::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(buf.len(), list.length());
        assert_eq!(decoded, list);
    }

    #[test]
    fn access_list_dedup_merges_addresses_and_storage_keys() {
        let address_1 = Address::with_last_byte(1);
        let address_2 = Address::with_last_byte(2);
        let slot_1 = B256::with_last_byte(1);
        let slot_2 = B256::with_last_byte(2);
        let slot_3 = B256::with_last_byte(3);
        let mut list = AccessList(vec![
            AccessListItem { address: address_2, storage_keys: vec![slot_3, slot_1, slot_3] },
            AccessListItem { address: address_1, storage_keys: vec![slot_2] },
            AccessListItem { address: address_2, storage_keys: vec![slot_2, slot_1] },
        ]);

        list.dedup();

        assert_eq!(
            list,
            AccessList(vec![
                AccessListItem { address: address_2, storage_keys: vec![slot_3, slot_1, slot_2] },
                AccessListItem { address: address_1, storage_keys: vec![slot_2] },
            ])
        );
    }

    #[test]
    fn access_list_sort_orders_addresses_and_storage_keys() {
        let address_1 = Address::with_last_byte(1);
        let address_2 = Address::with_last_byte(2);
        let slot_1 = B256::with_last_byte(1);
        let slot_2 = B256::with_last_byte(2);
        let mut list = AccessList(vec![
            AccessListItem { address: address_2, storage_keys: vec![slot_2, slot_1, slot_1] },
            AccessListItem { address: address_1, storage_keys: vec![slot_2] },
            AccessListItem { address: address_2, storage_keys: vec![slot_1] },
        ]);

        list.sort();

        assert_eq!(
            list,
            AccessList(vec![
                AccessListItem { address: address_1, storage_keys: vec![slot_2] },
                AccessListItem { address: address_2, storage_keys: vec![slot_1] },
                AccessListItem { address: address_2, storage_keys: vec![slot_1, slot_1, slot_2] },
            ])
        );
    }

    #[test]
    fn empty_access_list_rlp_roundtrip() {
        let list = AccessList::default();
        let mut buf = Vec::new();
        list.encode(&mut buf);
        let decoded = AccessList::decode(&mut buf.as_ref()).unwrap();
        assert_eq!(buf.len(), list.length());
        assert_eq!(decoded, list);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn access_list_serde() {
        let list = AccessList(vec![
            AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
            AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
        ]);
        let json = serde_json::to_string(&list).unwrap();
        let list2 = serde_json::from_str::<AccessList>(&json).unwrap();
        assert_eq!(list, list2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn access_list_with_gas_used() {
        let list = AccessListResult {
            access_list: AccessList(vec![
                AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
                AccessListItem { address: Address::ZERO, storage_keys: vec![B256::ZERO] },
            ]),
            gas_used: U256::from(100),
            error: None,
        };
        let json = serde_json::to_string(&list).unwrap();
        let list2 = serde_json::from_str(&json).unwrap();
        assert_eq!(list, list2);
    }
}
