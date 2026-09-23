//! Generated round trips for EIP-8141 wire and serde representations.

use alloy_eip8141::*;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::{Decodable, Encodable};
use proptest::prelude::*;

fn gas() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0), Just(1), Just(u64::MAX), any::<u64>()]
}

fn value() -> impl Strategy<Value = U256> {
    prop_oneof![
        Just(U256::ZERO),
        Just(U256::MAX),
        any::<[u8; 32]>().prop_map(|bytes| U256::from_be_slice(&bytes)),
    ]
}

fn address() -> impl Strategy<Value = Address> {
    prop_oneof![Just(Address::ZERO), any::<[u8; 20]>().prop_map(Address::from),]
}

fn frame_address() -> impl Strategy<Value = FrameAddress> {
    prop_oneof![Just(FrameAddress::Empty), address().prop_map(FrameAddress::from)]
}

fn message() -> impl Strategy<Value = SignatureMessage> {
    prop_oneof![
        Just(SignatureMessage::TransactionHash),
        any::<[u8; 32]>()
            .prop_filter("explicit digest must be nonzero", |bytes| bytes.iter().any(|&b| b != 0))
            .prop_map(|bytes| SignatureMessage::Explicit(B256::from(bytes))),
    ]
}

fn bytes() -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..260).prop_map(Bytes::from)
}

fn frame() -> impl Strategy<Value = Frame> {
    (0u8..3, any::<u8>(), frame_address(), gas(), gas(), value(), bytes()).prop_map(
        |(mode, flags, target, execution, state, value, data)| {
            Frame::new(
                FrameMode::try_from(mode).unwrap(),
                flags,
                target,
                FrameLimits { execution, state },
                value,
                data,
            )
        },
    )
}

fn signature() -> impl Strategy<Value = FrameSignature> {
    (0u8..3, frame_address(), message(), bytes()).prop_map(|(scheme, signer, msg, signature)| {
        FrameSignature::new(SignatureScheme::try_from(scheme).unwrap(), signer, msg, signature)
    })
}

fn fees() -> impl Strategy<Value = TransactionFees> {
    (value(), value(), value()).prop_map(
        |(max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas)| TransactionFees {
            max_priority_fee_per_gas,
            max_fee_per_gas,
            max_fee_per_blob_gas,
        },
    )
}

fn receipt() -> impl Strategy<Value = FrameReceipt<Bytes>> {
    (0u8..3, gas(), gas(), prop::collection::vec(bytes(), 0..5)).prop_map(
        |(status, execution, state, logs)| FrameReceipt {
            status: FrameStatus::try_from(status).unwrap(),
            gas_used: FrameGasUsed { execution, state },
            logs,
        },
    )
}

fn receipt_payload() -> impl Strategy<Value = FrameReceiptPayload<Bytes>> {
    (gas(), address(), prop::collection::vec(receipt(), 0..5)).prop_map(
        |(cumulative_gas_used, payer, frame_receipts)| FrameReceiptPayload {
            cumulative_gas_used,
            payer,
            frame_receipts,
        },
    )
}

fn assert_rlp_roundtrip<T: Encodable + Decodable + PartialEq + core::fmt::Debug>(value: T) {
    let encoded = alloy_rlp::encode(&value);
    assert_eq!(encoded.len(), value.length());
    let mut remaining = encoded.as_slice();
    assert_eq!(T::decode(&mut remaining).unwrap(), value);
    assert!(remaining.is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn frames_and_fees_roundtrip_rlp(frame in frame(), fees in fees()) {
        assert_rlp_roundtrip(frame);
        assert_rlp_roundtrip(fees);
    }

    #[test]
    fn signatures_roundtrip_rlp(signature in signature()) {
        assert_rlp_roundtrip(signature);
    }

    #[test]
    fn mixed_signing_lists_elide_only_transaction_hash_witnesses(
        signatures in prop::collection::vec(signature(), 0..12)
    ) {
        let expected: Vec<_> = signatures.iter().cloned().map(|mut entry| {
            if entry.signs_transaction_hash() {
                entry.signature = Bytes::new();
            }
            entry
        }).collect();
        let view = SigningFrameSignatures::new(&signatures);
        let encoded = alloy_rlp::encode(view);
        let expected_encoded = alloy_rlp::encode(&expected);
        prop_assert_eq!(encoded.len(), view.length());
        prop_assert_eq!(encoded.as_slice(), expected_encoded.as_slice());
        prop_assert_eq!(alloy_rlp::decode_exact::<Vec<FrameSignature>>(&encoded).unwrap(), expected);
    }

    #[test]
    fn receipts_roundtrip_rlp(payload in receipt_payload()) {
        assert_rlp_roundtrip(payload);
    }

    #[test]
    fn malformed_optional_byte_lengths_are_rejected(bytes in prop::collection::vec(any::<u8>(), 1..40)) {
        let encoded = alloy_rlp::encode(Bytes::from(bytes.clone()));
        if bytes.len() != 20 {
            prop_assert!(FrameAddress::decode(&mut encoded.as_slice()).is_err());
        }
        if bytes.len() != 32 || bytes.iter().all(|&b| b == 0) {
            prop_assert!(SignatureMessage::decode(&mut encoded.as_slice()).is_err());
        }
    }
}

#[cfg(feature = "serde")]
fn assert_serde_roundtrip<
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug,
>(
    value: T,
) {
    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(serde_json::from_str::<T>(&json).unwrap(), value);
    let binary = bincode::serialize(&value).unwrap();
    assert_eq!(bincode::deserialize::<T>(&binary).unwrap(), value);
}

#[cfg(feature = "serde")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn frames_and_fees_roundtrip_serde(frame in frame(), fees in fees()) {
        assert_serde_roundtrip(frame);
        assert_serde_roundtrip(fees);
    }

    #[test]
    fn signatures_roundtrip_serde(signature in signature()) {
        assert_serde_roundtrip(signature);
    }

    #[test]
    fn receipts_roundtrip_serde(payload in receipt_payload()) {
        assert_serde_roundtrip(payload);
    }
}
