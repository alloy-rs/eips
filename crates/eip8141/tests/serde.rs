//! JSON and binary serde compatibility for EIP-8141 fields.
#![cfg(feature = "serde")]

use alloy_eip8141::*;
use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(value: T) -> Value {
    let encoded = serde_json::to_string(&value).unwrap();
    assert_eq!(serde_json::from_str::<T>(&encoded).unwrap(), value);
    let binary = bincode::serialize(&value).unwrap();
    assert_eq!(bincode::deserialize::<T>(&binary).unwrap(), value);
    serde_json::from_str(&encoded).unwrap()
}

#[test]
fn discriminants_use_quantities() {
    for (i, mode) in
        [FrameMode::Default, FrameMode::Verify, FrameMode::Sender].into_iter().enumerate()
    {
        assert_eq!(roundtrip(mode), json!(format!("0x{i:x}")));
    }
    for (i, status) in [FrameStatus::Failure, FrameStatus::Success, FrameStatus::SkippedAtomicBatch]
        .into_iter()
        .enumerate()
    {
        assert_eq!(roundtrip(status), json!(format!("0x{i:x}")));
    }
    for (i, scheme) in
        [SignatureScheme::Arbitrary, SignatureScheme::Secp256k1, SignatureScheme::P256]
            .into_iter()
            .enumerate()
    {
        assert_eq!(roundtrip(scheme), json!(format!("0x{i:x}")));
    }
    for (i, scope) in [
        ApprovalScope::None,
        ApprovalScope::Payment,
        ApprovalScope::Execution,
        ApprovalScope::ExecutionAndPayment,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(roundtrip(scope), json!(format!("0x{i:x}")));
    }
    for value in [json!("0x3"), json!("0xff"), json!("0x100"), json!("Verify")] {
        assert!(serde_json::from_value::<FrameMode>(value.clone()).is_err());
        assert!(serde_json::from_value::<FrameStatus>(value.clone()).is_err());
        assert!(serde_json::from_value::<SignatureScheme>(value).is_err());
    }
    assert!(serde_json::from_value::<ApprovalScope>(json!("0x4")).is_err());
}

#[test]
fn frame_json_fixture() {
    let expected = json!({
        "mode":"0x2", "flags":"0x4", "target":"0x",
        "limits":{"execution":"0xffffffffffffffff","state":"0x0"},
        "value":"0x1", "data":"0xabcd"
    });
    let frame = Frame::new(
        FrameMode::Sender,
        4,
        FrameAddress::Empty,
        FrameLimits { execution: u64::MAX, state: 0 },
        U256::from(1),
        Bytes::from_static(&[0xab, 0xcd]),
    );
    assert_eq!(roundtrip(frame.clone()), expected);
    let mut null_target = expected.clone();
    null_target["target"] = json!(null);
    assert_eq!(serde_json::from_value::<Frame>(null_target).unwrap(), frame);
    let mut malformed = expected;
    malformed["target"] = json!("0x01");
    assert!(serde_json::from_value::<Frame>(malformed).is_err());
}

#[test]
fn receipt_and_fee_json_fixtures() {
    let receipt = FrameReceiptPayload::<alloy_primitives::Log> {
        cumulative_gas_used: u64::MAX,
        payer: Address::ZERO,
        frame_receipts: vec![FrameReceipt {
            status: FrameStatus::SkippedAtomicBatch,
            gas_used: FrameGasUsed { execution: 0, state: 0 },
            logs: vec![],
        }],
    };
    assert_eq!(
        roundtrip(receipt),
        json!({
            "cumulativeGasUsed":"0xffffffffffffffff",
            "payer":Address::ZERO,
            "frameReceipts":[{"status":"0x2","gasUsed":{"execution":"0x0","state":"0x0"},"logs":[]}]
        })
    );
    let fees = TransactionFees {
        max_priority_fee_per_gas: U256::from(1),
        max_fee_per_gas: U256::MAX,
        max_fee_per_blob_gas: U256::ZERO,
    };
    assert_eq!(
        roundtrip(fees),
        json!({"maxPriorityFeePerGas":"0x1","maxFeePerGas":U256::MAX,"maxFeePerBlobGas":"0x0"})
    );
    roundtrip(FrameReceipt {
        status: FrameStatus::Success,
        gas_used: FrameGasUsed::default(),
        logs: vec!["generic log".to_owned()],
    });
}

#[test]
fn optional_addresses_and_messages_use_byte_strings() {
    assert_eq!(roundtrip(FrameAddress::Empty), json!("0x"));
    assert_eq!(roundtrip(FrameAddress::from(Address::ZERO)), json!(Address::ZERO));
    assert_eq!(
        roundtrip(FrameAddress::from(Address::repeat_byte(1))),
        json!(Address::repeat_byte(1))
    );
    assert_eq!(roundtrip(SignatureMessage::TransactionHash), json!("0x"));
    assert_eq!(
        roundtrip(SignatureMessage::Explicit(B256::repeat_byte(1))),
        json!(B256::repeat_byte(1))
    );
    for empty in [json!(null), json!(""), json!([])] {
        assert_eq!(
            serde_json::from_value::<FrameAddress>(empty.clone()).unwrap(),
            FrameAddress::Empty
        );
        assert_eq!(
            serde_json::from_value::<SignatureMessage>(empty).unwrap(),
            SignatureMessage::TransactionHash
        );
    }
    assert!(serde_json::from_value::<FrameAddress>(json!(vec![1; 20])).is_ok());
    assert!(serde_json::from_value::<SignatureMessage>(json!(vec![1; 32])).is_ok());
    for size in [1, 19, 21, 31, 33] {
        let bytes = Bytes::from(vec![1; size]);
        assert!(serde_json::from_value::<FrameAddress>(json!(bytes)).is_err());
        assert!(serde_json::from_value::<SignatureMessage>(json!(bytes)).is_err());
        assert!(serde_json::from_value::<FrameAddress>(json!(vec![1; size])).is_err());
    }
    assert!(serde_json::from_value::<SignatureMessage>(json!(B256::ZERO)).is_err());
    assert!(serde_json::to_value(SignatureMessage::Explicit(B256::ZERO)).is_err());
    assert!(
        serde_json::from_value::<SignatureMessage>(json!({"Explicit":B256::repeat_byte(1)}))
            .is_err()
    );
}

#[test]
fn signature_message_matches_entry_representation() {
    for msg in [SignatureMessage::TransactionHash, SignatureMessage::Explicit(B256::repeat_byte(1))]
    {
        let signature = FrameSignature::new(
            SignatureScheme::Arbitrary,
            FrameAddress::Empty,
            msg,
            Bytes::from_static(&[1, 2]),
        );
        let value = roundtrip(signature);
        assert_eq!(value["scheme"], json!("0x0"));
        assert_eq!(value["signer"], json!("0x"));
        assert_eq!(value["msg"], serde_json::to_value(msg).unwrap());
    }
}

#[test]
fn receipt_with_logs_roundtrips_json() {
    let receipt = FrameReceipt {
        status: FrameStatus::Success,
        gas_used: FrameGasUsed { execution: 1, state: 0 },
        logs: vec![alloy_primitives::Log::new_unchecked(
            Address::repeat_byte(1),
            vec![B256::repeat_byte(2)],
            Bytes::from_static(&[3, 4]),
        )],
    };
    let value = serde_json::to_value(&receipt).unwrap();
    assert_eq!(value["logs"][0]["address"], json!(Address::repeat_byte(1)));
    assert_eq!(value["logs"][0]["topics"], json!([B256::repeat_byte(2)]));
    assert_eq!(value["logs"][0]["data"], json!("0x0304"));
    assert_eq!(serde_json::from_value::<FrameReceipt>(value).unwrap(), receipt);
}
