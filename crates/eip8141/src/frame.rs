use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

/// EIP-8141 frame execution mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl From<FrameMode> for u8 {
    fn from(value: FrameMode) -> Self {
        value as Self
    }
}

impl Encodable for FrameMode {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        u8::from(*self).encode(out);
    }

    fn length(&self) -> usize {
        u8::from(*self).length()
    }
}

impl Decodable for FrameMode {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::try_from_u8(u8::decode(buf)?)
            .ok_or(alloy_rlp::Error::Custom("invalid EIP-8141 frame mode"))
    }
}

/// EIP-8141 approval scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl From<ApprovalScope> for u8 {
    fn from(value: ApprovalScope) -> Self {
        value as Self
    }
}

/// The two gas budgets carried by an EIP-8141 frame.
///
/// Unlike legacy transactions, frame transactions do not use the EIP-8037
/// reservoir split. Execution gas and state gas are declared independently
/// and each budget is enforced separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameLimits {
    /// Maximum execution gas available to the frame.
    pub execution: u64,
    /// Maximum state gas available to the frame.
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
    pub flags: u8,
    /// Encoded target account. Empty bytes resolve to the transaction sender.
    pub target: Bytes,
    /// Execution and state gas limits for this frame.
    pub limits: FrameLimits,
    /// Wei value transferred by this frame. Non-zero value is valid only for `SENDER` frames.
    pub value: U256,
    /// Calldata provided to the top-level frame call.
    pub data: Bytes,
}

impl Frame {
    /// Creates a new frame from raw field values.
    pub const fn new(
        mode: FrameMode,
        flags: u8,
        target: Bytes,
        execution_gas: u64,
        value: U256,
        data: Bytes,
    ) -> Self {
        Self {
            mode,
            flags,
            target,
            limits: FrameLimits { execution: execution_gas, state: 0 },
            value,
            data,
        }
    }

    /// Creates a new frame from raw field values, allowing both execution and state gas to be set.
    pub const fn new_with_dynamic_limits(
        mode: FrameMode,
        flags: u8,
        target: Bytes,
        execution_gas: u64,
        state_gas: u64,
        value: U256,
        data: Bytes,
    ) -> Self {
        Self {
            mode,
            flags,
            target,
            limits: FrameLimits { execution: execution_gas, state: state_gas },
            value,
            data,
        }
    }

    /// Returns the target address, or `None` when the frame resolves to the transaction sender.
    pub fn target_address(&self) -> Option<Address> {
        if self.target.is_empty() {
            None
        } else if self.target.len() == 20 {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&self.target);
            Some(Address::from(bytes))
        } else {
            None
        }
    }

    /// Returns true if the target is encoded as either empty bytes or a 20-byte address.
    pub fn has_valid_target_encoding(&self) -> bool {
        self.target.is_empty() || self.target.len() == 20
    }

    /// Returns the allowed approval scope encoded in this frame's flags.
    pub const fn allowed_scope(&self) -> u8 {
        self.flags & crate::APPROVE_SCOPE_MASK
    }

    /// Returns true if this frame has the atomic batch flag set.
    pub const fn is_atomic_batch(&self) -> bool {
        self.flags & crate::ATOMIC_BATCH_FLAG != 0
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
        self.flags == 0 && self.value.is_zero() && self.data.len() == crate::EXPIRY_DATA_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameMode};
    use alloy_primitives::{Bytes, U256};

    fn expiry_frame() -> Frame {
        Frame {
            mode: FrameMode::Verify,
            target: Bytes::copy_from_slice(crate::EXPIRY_VERIFIER.as_slice()),
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
