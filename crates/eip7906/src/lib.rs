//! [EIP-7906] transaction assertion constants and selector types.
//!
//! [EIP-7906]: <https://eips.ethereum.org/EIPS/eip-7906>
#![cfg_attr(not(feature = "std"), no_std)]

/// `TXTRACE` opcode byte.
pub const TXTRACE_OPCODE: u8 = 0xB7;
/// `TXDIFF` opcode byte.
pub const TXDIFF_OPCODE: u8 = 0xB8;
/// `EVENTDATACOPY` opcode byte.
pub const EVENTDATACOPY_OPCODE: u8 = 0xB9;

/// Fixed gas charged by `TXTRACE` and transaction-local `TXDIFF` queries.
pub const TXTRACE_GAS_COST: u64 = 100;
/// Fixed gas charged by `EVENTDATACOPY`, before memory expansion and copying.
pub const EVENTDATACOPY_GAS_COST: u64 = 3;

/// `account_change_flags` bit indicating a net nonce change.
pub const ACCOUNT_NONCE_CHANGED: u8 = 0b0001;
/// `account_change_flags` bit indicating a net balance change.
pub const ACCOUNT_BALANCE_CHANGED: u8 = 0b0010;
/// `account_change_flags` bit indicating at least one net storage change.
pub const ACCOUNT_STORAGE_CHANGED: u8 = 0b0100;
/// `account_change_flags` bit indicating a net code-hash change.
pub const ACCOUNT_CODE_HASH_CHANGED: u8 = 0b1000;

/// A `TXTRACE` selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxTraceParam {
    /// Number of accounts with a net balance change.
    BalancesChanged = 0x00,
    /// Number of account storage slots with a net value change.
    SlotsChanged = 0x01,
    /// Number of contracts deployed during the transaction.
    ContractsDeployed = 0x02,
    /// Address for a balance-change entry.
    BalanceChangeAddress = 0x03,
    /// Pre-transaction balance for a balance-change entry.
    BalanceBefore = 0x04,
    /// Current balance for a balance-change entry.
    BalanceAfter = 0x05,
    /// Address for a storage-change entry.
    SlotChangeAddress = 0x06,
    /// Key for a storage-change entry.
    SlotKey = 0x07,
    /// Pre-transaction value for a storage-change entry.
    SlotValueBefore = 0x08,
    /// Current value for a storage-change entry.
    SlotValueAfter = 0x09,
    /// Address for a deployed-contract entry.
    DeployedAddress = 0x0A,
    /// Current code hash for a deployed-contract entry.
    DeployedCodeHash = 0x0B,
    /// Number of events emitted by the transaction.
    EventsCount = 0x0C,
    /// Emitting address for an event entry.
    EventAddress = 0x0D,
    /// Number of topics in an event entry.
    EventTopicCount = 0x0E,
    /// Topic zero for an event entry.
    EventTopic0 = 0x0F,
    /// Topic one for an event entry.
    EventTopic1 = 0x10,
    /// Topic two for an event entry.
    EventTopic2 = 0x11,
    /// Topic three for an event entry.
    EventTopic3 = 0x12,
    /// Non-indexed data length for an event entry.
    EventDataLength = 0x13,
    /// Amount deducted from the gas payer before execution.
    GasPreCharge = 0x14,
    /// Address charged the gas pre-payment.
    GasPayerAddress = 0x15,
}

impl TxTraceParam {
    /// Returns whether this selector requires its index operand to be zero.
    pub const fn requires_zero_index(self) -> bool {
        matches!(
            self,
            Self::BalancesChanged
                | Self::SlotsChanged
                | Self::ContractsDeployed
                | Self::EventsCount
                | Self::GasPreCharge
                | Self::GasPayerAddress
        )
    }
}

/// A `TXDIFF` selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TxDiffParam {
    /// Pre-transaction value of one storage slot.
    SlotValueBefore = 0x00,
    /// Current value of one storage slot.
    SlotValueAfter = 0x01,
    /// Pre-transaction balance of one account.
    BalanceBefore = 0x02,
    /// Current balance of one account.
    BalanceAfter = 0x03,
    /// Pre-transaction code hash of one account.
    CodeHashBefore = 0x04,
    /// Current code hash of one account.
    CodeHashAfter = 0x05,
    /// Number of changed slots for one address.
    AddressSlotsCount = 0x06,
    /// Global `TXTRACE` slot index for one address-local index.
    AddressSlotIndex = 0x07,
    /// Number of events emitted by one address.
    AddressEventsCount = 0x08,
    /// Global `TXTRACE` event index for one address-local index.
    AddressEventIndex = 0x09,
    /// Bitmask of net account changes.
    AccountChangeFlags = 0x0A,
    /// Number of events carrying one value in topics one through three.
    TopicEventsCount = 0x0B,
    /// Global `TXTRACE` event index for one topic-local index.
    TopicEventIndex = 0x0C,
}

impl TxDiffParam {
    /// Returns whether this selector reads and warms a storage slot.
    pub const fn is_storage_lookup(self) -> bool {
        matches!(self, Self::SlotValueBefore | Self::SlotValueAfter)
    }

    /// Returns whether this selector reads and warms an account.
    pub const fn is_account_lookup(self) -> bool {
        matches!(
            self,
            Self::BalanceBefore | Self::BalanceAfter | Self::CodeHashBefore | Self::CodeHashAfter
        )
    }

    /// Returns whether this selector is answered only from the transaction-local diff.
    pub const fn is_transaction_local(self) -> bool {
        !self.is_storage_lookup() && !self.is_account_lookup()
    }

    /// Returns whether this selector requires its third operand to be zero.
    pub const fn requires_zero_third_operand(self) -> bool {
        matches!(
            self,
            Self::BalanceBefore
                | Self::BalanceAfter
                | Self::CodeHashBefore
                | Self::CodeHashAfter
                | Self::AddressSlotsCount
                | Self::AddressEventsCount
                | Self::AccountChangeFlags
                | Self::TopicEventsCount
        )
    }
}

macro_rules! selector_conversions {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                value as Self
            }
        }

        impl TryFrom<u8> for $name {
            type Error = u8;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == Self::$variant as u8 => Ok(Self::$variant),)+
                    _ => Err(value),
                }
            }
        }
    };
}

selector_conversions!(TxTraceParam {
    BalancesChanged,
    SlotsChanged,
    ContractsDeployed,
    BalanceChangeAddress,
    BalanceBefore,
    BalanceAfter,
    SlotChangeAddress,
    SlotKey,
    SlotValueBefore,
    SlotValueAfter,
    DeployedAddress,
    DeployedCodeHash,
    EventsCount,
    EventAddress,
    EventTopicCount,
    EventTopic0,
    EventTopic1,
    EventTopic2,
    EventTopic3,
    EventDataLength,
    GasPreCharge,
    GasPayerAddress,
});

selector_conversions!(TxDiffParam {
    SlotValueBefore,
    SlotValueAfter,
    BalanceBefore,
    BalanceAfter,
    CodeHashBefore,
    CodeHashAfter,
    AddressSlotsCount,
    AddressSlotIndex,
    AddressEventsCount,
    AddressEventIndex,
    AccountChangeFlags,
    TopicEventsCount,
    TopicEventIndex,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_ranges_are_complete_and_reject_reserved_values() {
        for value in 0x00..=0x15 {
            assert_eq!(u8::from(TxTraceParam::try_from(value).unwrap()), value);
        }
        assert_eq!(TxTraceParam::try_from(0x16), Err(0x16));

        for value in 0x00..=0x0C {
            assert_eq!(u8::from(TxDiffParam::try_from(value).unwrap()), value);
        }
        assert_eq!(TxDiffParam::try_from(0x0D), Err(0x0D));
    }

    #[test]
    fn lookup_classes_match_eip2929_gas_rules() {
        assert!(TxDiffParam::SlotValueBefore.is_storage_lookup());
        assert!(TxDiffParam::CodeHashAfter.is_account_lookup());
        assert!(TxDiffParam::AccountChangeFlags.is_transaction_local());
        assert!(!TxDiffParam::AddressSlotIndex.requires_zero_third_operand());
        assert!(TxDiffParam::AddressSlotsCount.requires_zero_third_operand());
    }

    #[test]
    fn account_change_bits_do_not_overlap() {
        assert_eq!(
            ACCOUNT_NONCE_CHANGED
                | ACCOUNT_BALANCE_CHANGED
                | ACCOUNT_STORAGE_CHANGED
                | ACCOUNT_CODE_HASH_CHANGED,
            0x0F
        );
    }
}
