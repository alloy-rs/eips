use alloc::vec::Vec;

use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

/// EIP-8141 top-level frame status code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl From<FrameStatus> for u8 {
    fn from(value: FrameStatus) -> Self {
        value as Self
    }
}

impl Encodable for FrameStatus {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        u8::from(*self).encode(out);
    }

    fn length(&self) -> usize {
        u8::from(*self).length()
    }
}

impl Decodable for FrameStatus {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from_u8(u8::decode(buf)?)
            .ok_or(alloy_rlp::Error::Custom("invalid EIP-8141 frame status"))
    }
}

/// Receipt information for a single frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameReceipt<Log = alloy_primitives::Log> {
    /// Top-level frame status code.
    pub status: FrameStatus,
    /// Gas used by this frame.
    pub gas_used: u64,
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

#[cfg(test)]
mod tests {
    use super::FrameStatus;

    #[test]
    fn frame_status_codes_match_execution_specs() {
        assert_eq!(u8::from(FrameStatus::Failure), 0);
        assert_eq!(u8::from(FrameStatus::Success), 1);
        assert_eq!(u8::from(FrameStatus::SkippedAtomicBatch), 2);
        assert_eq!(FrameStatus::try_from_u8(2), Some(FrameStatus::SkippedAtomicBatch));
        assert_eq!(FrameStatus::try_from_u8(3), None);
    }
}
