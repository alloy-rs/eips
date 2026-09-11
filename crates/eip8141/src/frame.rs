use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

use crate::FrameAddress;

/// EIP-8141 frame execution mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
pub enum FrameMode {
    /// Execute the frame as the protocol entry point.
    #[default]
    Default = 0,
    /// Execute transaction validation.
    Verify = 1,
    /// Execute as the transaction sender.
    Sender = 2,
}

impl FrameMode {
    /// Attempts to convert a raw mode byte into a [`FrameMode`].
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Default),
            1 => Some(Self::Verify),
            2 => Some(Self::Sender),
            _ => None,
        }
    }
}

impl_u8_discriminant!(FrameMode, InvalidMode, "invalid EIP-8141 frame mode");

/// EIP-8141 approval scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
pub enum ApprovalScope {
    /// No approval scope.
    #[default]
    None = 0x00,
    /// Approves gas payment.
    Payment = 0x01,
    /// Approves execution as the sender.
    Execution = 0x02,
    /// Approves both execution and gas payment.
    ExecutionAndPayment = 0x03,
}

impl ApprovalScope {
    /// Attempts to convert a raw scope byte into an [`ApprovalScope`].
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Payment),
            0x02 => Some(Self::Execution),
            0x03 => Some(Self::ExecutionAndPayment),
            _ => None,
        }
    }
}

impl_u8_discriminant!(ApprovalScope, InvalidScope);

/// The independent execution and state gas budgets carried by an EIP-8141 frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameLimits {
    /// Maximum execution gas available to the frame.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity"))]
    pub execution: u64,
    /// Maximum state gas available to the frame.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity"))]
    pub state: u64,
}

/// A single EIP-8141 transaction frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Frame {
    /// The frame execution mode.
    pub mode: FrameMode,
    /// Frame flags. Bits 0-1 encode approval scope, bit 2 encodes atomic batching.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::quantity_u8"))]
    pub flags: u8,
    /// Target account. An empty address resolves to the transaction sender.
    pub target: FrameAddress,
    /// Independent execution and state gas limits for this frame.
    pub limits: FrameLimits,
    /// Wei value transferred by this frame. Non-zero value is valid only for `SENDER` frames.
    pub value: U256,
    /// Calldata provided to the top-level frame call.
    pub data: Bytes,
}

impl Frame {
    /// Creates a new frame from raw field values, including both gas limits.
    pub const fn new(
        mode: FrameMode,
        flags: u8,
        target: FrameAddress,
        limits: FrameLimits,
        value: U256,
        data: Bytes,
    ) -> Self {
        Self { mode, flags, target, limits, value, data }
    }

    /// Returns the target address, or `None` when the frame resolves to the transaction sender.
    pub const fn target_address(&self) -> Option<Address> {
        self.target.address()
    }

    /// Resolves the target, substituting the transaction sender for an empty target.
    pub const fn resolved_target(&self, sender: Address) -> Address {
        self.target.resolve(sender)
    }

    /// Returns the allowed approval scope encoded in this frame's flags.
    pub const fn allowed_scope(&self) -> ApprovalScope {
        match self.flags & crate::APPROVE_SCOPE_MASK {
            0 => ApprovalScope::None,
            1 => ApprovalScope::Payment,
            2 => ApprovalScope::Execution,
            _ => ApprovalScope::ExecutionAndPayment,
        }
    }

    /// Returns true if this frame has the atomic batch flag set.
    pub const fn is_atomic_batch(&self) -> bool {
        self.flags & crate::ATOMIC_BATCH_FLAG != 0
    }

    /// Returns true if any reserved flag bit is set, which makes the transaction invalid.
    pub const fn has_reserved_flags(&self) -> bool {
        self.flags & !crate::FRAME_FLAGS_MASK != 0
    }

    /// Returns true if this frame is an expiry verifier frame.
    ///
    /// Classification depends only on the frame mode and target. Call
    /// [`Self::has_valid_expiry_verifier_fields`] separately when validating the transaction.
    pub fn is_expiry_verifier(&self) -> bool {
        self.mode == FrameMode::Verify && self.target_address() == Some(crate::EXPIRY_VERIFIER)
    }

    /// Returns true if the constrained fields of an expiry verifier frame are valid.
    pub fn has_valid_expiry_verifier_fields(&self) -> bool {
        self.flags == 0
            && self.limits.state == 0
            && self.value.is_zero()
            && self.data.len() == crate::EXPIRY_DATA_LENGTH
    }
}

/// Fee parameters carried by an EIP-8141 transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct TransactionFees {
    /// Maximum priority fee per gas.
    pub max_priority_fee_per_gas: U256,
    /// Maximum total fee per gas.
    pub max_fee_per_gas: U256,
    /// Maximum fee per blob gas.
    pub max_fee_per_blob_gas: U256,
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameMode};
    use alloy_primitives::{Bytes, U256};

    fn expiry_frame() -> Frame {
        Frame {
            mode: FrameMode::Verify,
            target: crate::EXPIRY_VERIFIER.into(),
            data: Bytes::from(vec![0; crate::EXPIRY_DATA_LENGTH]),
            ..Default::default()
        }
    }

    #[test]
    fn expiry_verifier_classification_is_separate_from_field_validation() {
        let mut frame = expiry_frame();
        assert!(frame.is_expiry_verifier());
        assert!(frame.has_valid_expiry_verifier_fields());

        frame.flags = 1;
        frame.value = U256::from(1);
        frame.data = Bytes::new();

        assert!(frame.is_expiry_verifier());
        assert!(!frame.has_valid_expiry_verifier_fields());
    }
}
