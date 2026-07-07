use alloc::vec::Vec;

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::{BufMut, Encodable, RlpDecodable, RlpEncodable};

use crate::{Frame, FrameSignature};

/// An unsigned EIP-8141 frame transaction payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameTransaction {
    /// Chain ID in which the transaction is valid.
    pub chain_id: U256,
    /// Sender nonce.
    pub nonce: u64,
    /// Intended transaction sender.
    pub sender: Address,
    /// Ordered frames to execute.
    pub frames: Vec<Frame>,
    /// Signatures available to validation and execution code.
    pub signatures: Vec<FrameSignature>,
    /// EIP-1559 max priority fee per gas.
    pub max_priority_fee_per_gas: u128,
    /// EIP-1559 max fee per gas.
    pub max_fee_per_gas: u128,
    /// EIP-4844 max fee per blob gas. Must be zero if `blob_versioned_hashes` is empty.
    pub max_fee_per_blob_gas: u128,
    /// EIP-4844 blob versioned hashes.
    pub blob_versioned_hashes: Vec<B256>,
}

impl FrameTransaction {
    /// Computes the canonical EIP-8141 signature hash.
    ///
    /// Raw signature bytes are elided for signatures whose `msg` field is empty.
    pub fn signature_hash(&self) -> B256 {
        let mut tx = self.clone();
        for signature in &mut tx.signatures {
            if signature.msg.is_empty() {
                signature.signature = Bytes::new();
            }
        }

        let mut out = Vec::with_capacity(1 + tx.length());
        out.put_u8(crate::FRAME_TX_TYPE);
        tx.encode(&mut out);
        keccak256(out)
    }

    /// Returns the sum of protocol signature verification gas costs, if all schemes are known.
    pub fn signature_verification_gas(&self) -> Option<u64> {
        self.signatures
            .iter()
            .try_fold(0u64, |acc, sig| sig.verification_gas().and_then(|gas| acc.checked_add(gas)))
    }

    /// Returns the sum of all frame gas limits, or `None` on overflow.
    pub fn total_frame_gas(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |acc, frame| acc.checked_add(frame.gas_limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn frame_transaction_rlp_roundtrip() {
        let tx = FrameTransaction {
            chain_id: U256::from(1),
            nonce: 7,
            sender: Address::from([0x11; 20]),
            frames: vec![Frame {
                mode: crate::FrameMode::Verify.into(),
                flags: crate::ApprovalScope::ExecutionAndPayment.into(),
                target: Bytes::new(),
                gas_limit: 21_000,
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: vec![FrameSignature {
                scheme: crate::SignatureScheme::Secp256k1.into(),
                signer: Bytes::copy_from_slice(&[0x11; 20]),
                msg: Bytes::new(),
                signature: Bytes::copy_from_slice(&[0x22; 65]),
            }],
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 10,
            max_fee_per_blob_gas: 0,
            blob_versioned_hashes: Vec::new(),
        };

        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded = FrameTransaction::decode(&mut buf.as_ref()).unwrap();

        assert_eq!(buf.len(), tx.length());
        assert_eq!(decoded, tx);
    }

    #[test]
    fn signature_hash_elides_transaction_hash_signatures() {
        let mut tx = FrameTransaction {
            chain_id: U256::from(1),
            nonce: 0,
            sender: Address::from([0x11; 20]),
            frames: Vec::new(),
            signatures: vec![FrameSignature {
                scheme: crate::SignatureScheme::Arbitrary.into(),
                signer: Bytes::new(),
                msg: Bytes::new(),
                signature: Bytes::copy_from_slice(&[0x22; 32]),
            }],
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 10,
            max_fee_per_blob_gas: 0,
            blob_versioned_hashes: Vec::new(),
        };

        let first = tx.signature_hash();
        tx.signatures[0].signature = Bytes::copy_from_slice(&[0x33; 64]);
        let second = tx.signature_hash();

        assert_eq!(first, second);
    }
}
