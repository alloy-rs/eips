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
    roundtrip(Frame::new(
        FrameMode::Sender,
        ATOMIC_BATCH_FLAG,
        Address::repeat_byte(0x11).into(),
        FrameLimits { execution: u64::MAX, state: 1 },
        U256::MAX,
        Bytes::from(vec![0xa5; 100]),
    ));
    roundtrip(FrameSignature::new(
        SignatureScheme::P256,
        Address::repeat_byte(0x22).into(),
        SignatureMessage::Explicit(B256::repeat_byte(0x33)),
        Bytes::from(vec![0xa5; P256_SIGNATURE_LENGTH]),
    ));
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
            Err(Eip8141Error::InvalidAddressLength(size))
        );
        let encoded = alloy_rlp::encode(Bytes::from(bytes));
        assert!(FrameAddress::decode(&mut encoded.as_slice()).is_err());
    }
    // The third list element is a one-byte target: it must not become the sender sentinel.
    assert!(Frame::decode(&mut hex!("c8808001c280808080").as_slice()).is_err());
    assert!(FrameAddress::decode(&mut hex!("c0").as_slice()).is_err());
}

#[test]
fn signature_messages_preserve_encoding_and_reject_invalid_values() {
    assert_eq!(alloy_rlp::encode(SignatureMessage::TransactionHash), hex!("80"));
    let explicit = SignatureMessage::Explicit(B256::repeat_byte(1));
    assert_eq!(alloy_rlp::encode(explicit), alloy_rlp::encode(B256::repeat_byte(1)));
    assert_eq!(explicit.as_bytes(), &[1; 32]);
    assert!(SignatureMessage::TransactionHash.as_bytes().is_empty());
    roundtrip(SignatureMessage::TransactionHash);
    roundtrip(explicit);
    for length in [1, 31, 33] {
        let bytes = vec![1; length];
        assert_eq!(
            SignatureMessage::try_from(bytes.as_slice()),
            Err(Eip8141Error::InvalidMessageLength(length))
        );
        let encoded = alloy_rlp::encode(Bytes::from(bytes));
        assert!(SignatureMessage::decode(&mut encoded.as_slice()).is_err());
    }
    assert_eq!(SignatureMessage::explicit(B256::ZERO), Err(Eip8141Error::ZeroMessage));
    assert_eq!(SignatureMessage::try_from(&[0; 32][..]), Err(Eip8141Error::ZeroMessage));
    assert!(SignatureMessage::decode(&mut alloy_rlp::encode(B256::ZERO).as_slice()).is_err());
    let zero = FrameSignature { msg: SignatureMessage::Explicit(B256::ZERO), ..Default::default() };
    assert!(FrameSignature::decode(&mut alloy_rlp::encode(&zero).as_slice()).is_err());
}

#[test]
fn invalid_discriminants_and_noncanonical_rlp() {
    for input in [&[3u8][..], &[0x81, 1][..], &[0xc0][..]] {
        assert!(FrameMode::decode(&mut &*input).is_err());
        assert!(FrameStatus::decode(&mut &*input).is_err());
        assert!(SignatureScheme::decode(&mut &*input).is_err());
    }
    assert_eq!(FrameMode::try_from(3), Err(Eip8141Error::InvalidMode(3)));
    assert_eq!(FrameStatus::try_from(3), Err(Eip8141Error::InvalidStatus(3)));
    assert_eq!(SignatureScheme::try_from(3), Err(Eip8141Error::InvalidScheme(3)));
    assert_eq!(ApprovalScope::try_from(4), Err(Eip8141Error::InvalidScope(4)));
    for flags in 0..=u8::MAX {
        let frame = Frame { flags, ..Default::default() };
        assert_eq!(u8::from(frame.allowed_scope()), flags & APPROVE_SCOPE_MASK);
        assert_eq!(frame.is_atomic_batch(), flags & ATOMIC_BATCH_FLAG != 0);
        assert_eq!(frame.has_reserved_flags(), flags >= 8);
    }
}

#[test]
fn target_and_signer_resolution() {
    let sender = Address::repeat_byte(1);
    let mut frame = Frame::default();
    assert_eq!(frame.resolved_target(sender), sender);
    frame.target = Address::ZERO.into();
    assert_eq!(frame.resolved_target(sender), Address::ZERO);

    let mut sig = FrameSignature::default();
    assert_eq!(sig.resolved_signer(sender), Ok(None));
    sig.signer = Address::ZERO.into();
    assert_eq!(sig.signer_address(), None);
    assert_eq!(sig.resolved_signer(sender), Err(Eip8141Error::UnexpectedSigner));
    assert_eq!(sig.validate_structure(), Err(Eip8141Error::UnexpectedSigner));
    for scheme in [SignatureScheme::Secp256k1, SignatureScheme::P256] {
        sig.scheme = scheme;
        sig.signer = Address::ZERO.into();
        assert_eq!(sig.signer_address(), Some(Address::ZERO));
        assert_eq!(sig.resolved_signer(sender), Ok(Some(Address::ZERO)));
        sig.signer = FrameAddress::Empty;
        assert_eq!(sig.signer_address(), None);
        assert_eq!(sig.resolved_signer(sender), Ok(Some(sender)));
    }
}

fn scalar_entry(scheme: SignatureScheme, r: U256, s: U256) -> FrameSignature {
    let offset = usize::from(scheme == SignatureScheme::Secp256k1);
    let mut signature = vec![0; scheme.signature_length().unwrap()];
    signature[offset..offset + 32].copy_from_slice(&r.to_be_bytes::<32>());
    signature[offset + 32..offset + 64].copy_from_slice(&s.to_be_bytes::<32>());
    FrameSignature::new(
        scheme,
        FrameAddress::Empty,
        SignatureMessage::TransactionHash,
        signature.into(),
    )
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
                Err(Eip8141Error::InvalidSignatureScalar)
            );
        }
        let mut sig = scalar_entry(scheme, U256::from(1), half);
        let expected = sig.signature.len();
        for actual in [0, expected - 1, expected + 1] {
            sig.signature = Bytes::from(vec![0; actual]);
            assert_eq!(
                sig.validate_structure(),
                Err(Eip8141Error::InvalidSignatureLength { expected, actual })
            );
        }
    }
    let mut sig = scalar_entry(SignatureScheme::Secp256k1, U256::from(1), U256::from(1));
    let mut bytes = sig.signature.to_vec();
    bytes[0] = 27;
    sig.signature = bytes.into();
    assert_eq!(sig.validate_structure(), Err(Eip8141Error::InvalidParity(27)));
    assert_eq!(sig.secp256k1_signature(), None);
}

#[test]
fn secp256k1_entries_use_parity_first() {
    for parity in [false, true] {
        let signature = Signature::new(U256::from(2), U256::from(3), parity);
        let entry = FrameSignature::from_secp256k1(
            FrameAddress::Empty,
            SignatureMessage::Explicit(B256::repeat_byte(7)),
            signature,
        )
        .unwrap();
        assert_eq!(entry.signature[0], u8::from(parity));
        assert_eq!(entry.signature[32], 2);
        assert_eq!(entry.signature[64], 3);
        assert_eq!(entry.msg, SignatureMessage::Explicit(B256::repeat_byte(7)));
        assert_eq!(entry.secp256k1_signature(), Some(signature));
        assert_eq!(entry.p256_signer_address(), None);
        roundtrip(entry);
    }
    assert_eq!(
        FrameSignature::from_secp256k1(
            FrameAddress::Empty,
            SignatureMessage::TransactionHash,
            Signature::new(U256::from(1), SECP256K1N - U256::from(1), false),
        ),
        Err(Eip8141Error::InvalidSignatureScalar)
    );
}

#[test]
fn p256_public_key_must_match_resolved_signer() {
    let sender = Address::repeat_byte(1);
    let mut entry = scalar_entry(SignatureScheme::P256, U256::from(1), U256::from(1));
    let mut bytes = entry.signature.to_vec();
    bytes[64..].fill(0x42);
    entry.signature = bytes.into();
    let derived = Address::from_raw_public_key(&[0x42; 64]);
    assert_eq!(entry.p256_signer_address(), Some(derived));
    assert_eq!(entry.secp256k1_signature(), None);
    assert_eq!(
        entry.validate_structure_with_sender(sender),
        Err(Eip8141Error::P256SignerMismatch { expected: sender, derived })
    );
    assert_eq!(entry.validate_structure_with_sender(derived), Ok(()));
    entry.signer = derived.into();
    assert_eq!(entry.validate_structure_with_sender(sender), Ok(()));
    let secp = scalar_entry(SignatureScheme::Secp256k1, U256::from(1), U256::from(1));
    assert_eq!(secp.validate_structure_with_sender(sender), Ok(()));
}

#[cfg(feature = "borsh")]
#[test]
fn typed_fields_roundtrip_borsh() {
    for address in [FrameAddress::Empty, Address::ZERO.into(), Address::repeat_byte(1).into()] {
        let frame = Frame { target: address, ..Default::default() };
        assert_eq!(borsh::from_slice::<Frame>(&borsh::to_vec(&frame).unwrap()).unwrap(), frame);
        for msg in
            [SignatureMessage::TransactionHash, SignatureMessage::Explicit(B256::repeat_byte(1))]
        {
            let signature = FrameSignature { signer: address, msg, ..Default::default() };
            assert_eq!(
                borsh::from_slice::<FrameSignature>(&borsh::to_vec(&signature).unwrap()).unwrap(),
                signature
            );
        }
    }
}
