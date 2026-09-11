use alloc::vec::Vec;

use alloy_primitives::Address;
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// EIP-8141 top-level frame status code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
pub enum FrameStatus {
    /// Frame reverted or otherwise failed.
    #[default]
    Failure = 0x00,
    /// Frame completed successfully.
    Success = 0x01,
    /// Frame was skipped because an atomic batch failed.
    SkippedAtomicBatch = 0x02,
}

impl FrameStatus {
    /// Attempts to convert a raw status byte into a [`FrameStatus`].
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Failure),
            0x01 => Some(Self::Success),
            0x02 => Some(Self::SkippedAtomicBatch),
            _ => None,
        }
    }
}

impl_u8_discriminant!(FrameStatus, InvalidStatus, "invalid EIP-8141 frame status");

/// Gas used by a frame, reported independently for each gas dimension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameGasUsed {
    /// Execution gas used by the frame, before transaction-level refunds.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity"))]
    pub execution: u64,
    /// State gas attributed to the frame after refills and rollbacks.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity"))]
    pub state: u64,
}

/// Receipt information for a single frame.
///
/// The `serde` representation mirrors the consensus encoding and nests `gasUsed` as an object
/// with `execution` and `state` fields. It is not the JSON-RPC receipt shape.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameReceipt<Log = alloy_primitives::Log> {
    /// Top-level frame status code.
    pub status: FrameStatus,
    /// Gas used by this frame in the execution and state dimensions.
    pub gas_used: FrameGasUsed,
    /// Logs emitted by this frame.
    pub logs: Vec<Log>,
}

/// EIP-8141 receipt payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameReceiptPayload<Log = alloy_primitives::Log> {
    /// Cumulative gas used by the block after this transaction.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity"))]
    pub cumulative_gas_used: u64,
    /// Account that paid the transaction fee.
    pub payer: Address,
    /// Per-frame receipt entries.
    pub frame_receipts: Vec<FrameReceipt<Log>>,
}

impl<Log> FrameReceiptPayload<Log> {
    /// Maps the log type in every frame receipt.
    pub fn map_logs<U>(self, mut f: impl FnMut(Log) -> U) -> FrameReceiptPayload<U> {
        FrameReceiptPayload {
            cumulative_gas_used: self.cumulative_gas_used,
            payer: self.payer,
            frame_receipts: self
                .frame_receipts
                .into_iter()
                .map(|receipt| FrameReceipt {
                    status: receipt.status,
                    gas_used: receipt.gas_used,
                    logs: receipt.logs.into_iter().map(&mut f).collect(),
                })
                .collect(),
        }
    }
}
