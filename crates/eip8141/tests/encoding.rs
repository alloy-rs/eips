//! Wire-format and validation regressions for frame transaction types.

use alloy_eip8141::*;
use alloy_primitives::{Address, B256, Bytes, Signature, U256, hex};
use alloy_rlp::{Decodable, Encodable};

fn roundtrip<T: Encodable + Decodable + PartialEq + core::fmt::Debug>(value: T) {
    let encoded = alloy_rlp::encode(&value);
    assert_eq!(encoded.len(), value.length());
    let mut bytes = encoded.as_slice();
    assert_eq!(T::decode(&mut bytes).unwrap(), value);
    assert!(bytes.is_empty());
}

#[test]
fn rlp_fixtures() {
    assert_eq!(alloy_rlp::encode(Frame::default()), hex!("c8808080c280808080"));
    assert_eq!(alloy_rlp::encode(FrameSignature::default()), hex!("c480808080"));
    let receipt = FrameReceiptPayload::<alloy_primitives::Log> {
        cumulative_gas_used: 0,
        payer: Address::ZERO,
        frame_receipts: vec![FrameReceipt {
            status: FrameStatus::Success,
            gas_used: FrameGasUsed::default(),
            logs: vec![],
        }],
    };
    assert_eq!(
        alloy_rlp::encode(&receipt),
        hex!("dd80940000000000000000000000000000000000000000c6c501c28080c0")
    );
    roundtrip(receipt);
}

#[test]
fn rlp_length_boundaries() {
    for size in [0, 1, 55, 56, 255, 256, 1024] {
        roundtrip(Frame::new(
            FrameMode::Sender,
            4,
            Address::repeat_byte(0x11).into(),
            FrameLimits { execution: u64::MAX, state: u64::MAX },
            U256::MAX,
            Bytes::from(vec![0xa5; size]),
        ));
        roundtrip(FrameSignature::new(
            SignatureScheme::Arbitrary,
            FrameAddress::Empty,
            Bytes::new(),
            Bytes::from(vec![0xa5; size]),
        ));
    }
    roundtrip(TransactionFees {
        max_priority_fee_per_gas: U256::MAX,
        max_fee_per_gas: U256::MAX,
        max_fee_per_blob_gas: U256::MAX,
    });
}

#[test]
fn optional_addresses_preserve_encoding_and_reject_invalid_lengths() {
    for address in [FrameAddress::Empty, Address::ZERO.into(), Address::repeat_byte(1).into()] {
        let raw =
            address.address().map_or_else(Bytes::new, |a| Bytes::copy_from_slice(a.as_slice()));
        assert_eq!(alloy_rlp::encode(address), alloy_rlp::encode(raw));
        roundtrip(address);
    }
    assert_ne!(FrameAddress::Empty, FrameAddress::from(Address::ZERO));
    for size in [1, 19, 21, 32] {
        let bytes = vec![1; size];
        assert_eq!(
            FrameAddress::try_from(bytes.as_slice()),
            Err(FrameError::InvalidAddressLength(size))
        );
        let encoded = alloy_rlp::encode(Bytes::from(bytes));
        assert!(FrameAddress::decode(&mut encoded.as_slice()).is_err());
    }
    // The third list element is a one-byte target: it must not become the sender sentinel.
    assert!(Frame::decode(&mut hex!("c8808001c280808080").as_slice()).is_err());
    assert!(FrameAddress::decode(&mut hex!("c0").as_slice()).is_err());
}

#[test]
fn invalid_discriminants_and_noncanonical_rlp() {
    for input in [&[3u8][..], &[0x81, 1][..], &[0xc0][..]] {
        assert!(FrameMode::decode(&mut &*input).is_err());
        assert!(FrameStatus::decode(&mut &*input).is_err());
        assert!(SignatureScheme::decode(&mut &*input).is_err());
    }
    assert_eq!(FrameMode::try_from(3), Err(FrameError::InvalidMode(3)));
    assert_eq!(FrameStatus::try_from(3), Err(FrameError::InvalidStatus(3)));
    assert_eq!(SignatureScheme::try_from(3), Err(FrameError::InvalidScheme(3)));
    assert_eq!(ApprovalScope::try_from(4), Err(FrameError::InvalidScope(4)));
    for flags in 0..=u8::MAX {
        let frame = Frame { flags, ..Default::default() };
        assert_eq!(u8::from(frame.allowed_scope()), flags & APPROVE_SCOPE_MASK);
    }
}

#[test]
fn message_and_signer_resolution() {
    let mut sig = FrameSignature::default();
    assert_eq!(sig.message(), Ok(SignatureMessage::TransactionHash));
    assert_eq!(sig.resolved_signer(Address::ZERO), Ok(None));
    sig.signer = Address::ZERO.into();
    assert_eq!(sig.resolved_signer(Address::ZERO), Err(FrameError::UnexpectedSigner));
    assert_eq!(sig.validate_structure(), Err(FrameError::UnexpectedSigner));
    for scheme in [SignatureScheme::Secp256k1, SignatureScheme::P256] {
        sig.scheme = scheme;
        assert_eq!(sig.resolved_signer(Address::repeat_byte(1)), Ok(Some(Address::ZERO)));
        sig.signer = FrameAddress::Empty;
        assert_eq!(sig.resolved_signer(Address::repeat_byte(1)), Ok(Some(Address::repeat_byte(1))));
        sig.signer = Address::ZERO.into();
    }
    for length in [1, 31, 33] {
        sig.msg = Bytes::from(vec![1; length]);
        assert_eq!(sig.message(), Err(FrameError::InvalidMessageLength(length)));
    }
    sig.msg = Bytes::from(vec![0; 32]);
    assert_eq!(sig.message(), Err(FrameError::ZeroMessage));
    assert_eq!(SignatureMessage::Explicit(B256::ZERO).to_bytes(), Err(FrameError::ZeroMessage));
    sig.msg = Bytes::from(vec![1; 32]);
    assert_eq!(sig.message(), Ok(SignatureMessage::Explicit(B256::repeat_byte(1))));
    assert_eq!(sig.explicit_message(), Some(B256::repeat_byte(1)));
}

fn scalar_entry(scheme: SignatureScheme, r: U256, s: U256) -> FrameSignature {
    let (mut signature, offset) = match scheme {
        SignatureScheme::Secp256k1 => (vec![0; 65], 1),
        SignatureScheme::P256 => (vec![0; 128], 0),
        _ => unreachable!(),
    };
    signature[offset..offset + 32].copy_from_slice(&r.to_be_bytes::<32>());
    signature[offset + 32..offset + 64].copy_from_slice(&s.to_be_bytes::<32>());
    FrameSignature::new(scheme, FrameAddress::Empty, Bytes::new(), signature.into())
}

#[test]
fn signature_structure_boundaries() {
    for (scheme, order) in
        [(SignatureScheme::Secp256k1, SECP256K1N), (SignatureScheme::P256, SECP256R1N)]
    {
        let half = order / U256::from(2);
        assert!(scalar_entry(scheme, U256::from(1), half).validate_structure().is_ok());
        for (r, s) in [
            (U256::ZERO, half),
            (order, half),
            (U256::from(1), U256::ZERO),
            (U256::from(1), half + U256::from(1)),
        ] {
            assert_eq!(
                scalar_entry(scheme, r, s).validate_structure(),
                Err(FrameError::InvalidSignatureScalar)
            );
        }
        let mut sig = scalar_entry(scheme, U256::from(1), half);
        let expected = sig.signature.len();
        for actual in [0, expected - 1, expected + 1] {
            sig.signature = Bytes::from(vec![0; actual]);
            assert_eq!(
                sig.validate_structure(),
                Err(FrameError::InvalidSignatureLength { expected, actual })
            );
        }
    }
    let mut sig = scalar_entry(SignatureScheme::Secp256k1, U256::from(1), U256::from(1));
    let mut bytes = sig.signature.to_vec();
    bytes[0] = 27;
    sig.signature = bytes.into();
    assert_eq!(sig.validate_structure(), Err(FrameError::InvalidParity(27)));
}

#[test]
fn secp256k1_constructor_uses_parity_first() {
    for parity in [false, true] {
        let entry = FrameSignature::from_secp256k1(
            FrameAddress::Empty,
            SignatureMessage::Explicit(B256::repeat_byte(7)),
            Signature::new(U256::from(2), U256::from(3), parity),
        )
        .unwrap();
        assert_eq!(entry.signature[0], u8::from(parity));
        assert_eq!(entry.signature[32], 2);
        assert_eq!(entry.signature[64], 3);
        assert_eq!(entry.msg.as_ref(), &[7; 32]);
        roundtrip(entry);
    }
    assert_eq!(
        FrameSignature::from_secp256k1(
            FrameAddress::Empty,
            SignatureMessage::TransactionHash,
            Signature::new(U256::from(1), SECP256K1N - U256::from(1), false),
        ),
        Err(FrameError::InvalidSignatureScalar)
    );
}

#[cfg(feature = "borsh")]
#[test]
fn typed_addresses_roundtrip_borsh() {
    for target in [FrameAddress::Empty, Address::ZERO.into(), Address::repeat_byte(1).into()] {
        let frame = Frame { target, ..Default::default() };
        assert_eq!(borsh::from_slice::<Frame>(&borsh::to_vec(&frame).unwrap()).unwrap(), frame);
        let signature = FrameSignature { signer: target, ..Default::default() };
        assert_eq!(
            borsh::from_slice::<FrameSignature>(&borsh::to_vec(&signature).unwrap()).unwrap(),
            signature
        );
    }
}

#[test]
fn map_logs_preserves_receipt_fields_and_frame_order() {
    let receipt = FrameReceiptPayload {
        cumulative_gas_used: 123,
        payer: Address::repeat_byte(1),
        frame_receipts: vec![
            FrameReceipt {
                status: FrameStatus::Success,
                gas_used: FrameGasUsed { execution: 5, state: 2 },
                logs: vec![1, 2],
            },
            FrameReceipt {
                status: FrameStatus::SkippedAtomicBatch,
                gas_used: FrameGasUsed::default(),
                logs: vec![],
            },
            FrameReceipt {
                status: FrameStatus::Failure,
                gas_used: FrameGasUsed { execution: 7, state: 0 },
                logs: vec![3],
            },
        ],
    };
    let mut seen = Vec::new();
    let mapped = receipt.clone().map_logs(|value| {
        seen.push(value);
        value.to_string()
    });
    assert_eq!(seen, vec![1, 2, 3]);
    assert_eq!(mapped.cumulative_gas_used, receipt.cumulative_gas_used);
    assert_eq!(mapped.payer, receipt.payer);
    for (before, after) in receipt.frame_receipts.iter().zip(&mapped.frame_receipts) {
        assert_eq!(before.status, after.status);
        assert_eq!(before.gas_used, after.gas_used);
    }
    assert_eq!(mapped.frame_receipts[0].logs, vec!["1", "2"]);
    assert!(mapped.frame_receipts[1].logs.is_empty());
    assert_eq!(mapped.frame_receipts[2].logs, vec!["3"]);
}
