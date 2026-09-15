//! RLP signing-preimage views preserve metadata and elide only transaction-hash signatures.

use alloy_eip8141::{
    FrameAddress, FrameSignature, SignatureMessage, SignatureScheme, SigningFrameSignatures,
};
use alloy_primitives::{Address, B256, Bytes, hex};
use alloy_rlp::Encodable;

fn signing_entry(entry: &FrameSignature) -> FrameSignature {
    let mut entry = entry.clone();
    if entry.signs_transaction_hash() {
        entry.signature = Bytes::new();
    }
    entry
}

#[test]
fn signing_rlp_fixtures() {
    let mut entry = FrameSignature { signature: hex!("aabb").into(), ..Default::default() };
    assert_eq!(alloy_rlp::encode(&entry), hex!("c680808082aabb"));
    assert_eq!(alloy_rlp::encode(entry.as_signing()), hex!("c480808080"));
    entry.msg = SignatureMessage::Explicit(B256::repeat_byte(0x11));
    assert_eq!(
        alloy_rlp::encode(entry.as_signing()),
        hex!("e68080a0111111111111111111111111111111111111111111111111111111111111111182aabb")
    );
    assert_eq!(alloy_rlp::encode(SigningFrameSignatures::new(&[])), hex!("c0"));
}

#[test]
fn signing_entry_preserves_metadata_and_explicit_signatures() {
    for scheme in [SignatureScheme::Arbitrary, SignatureScheme::Secp256k1, SignatureScheme::P256] {
        for signer in [FrameAddress::Empty, Address::ZERO.into(), Address::repeat_byte(0x22).into()]
        {
            for msg in [
                SignatureMessage::TransactionHash,
                SignatureMessage::Explicit(B256::repeat_byte(0x33)),
            ] {
                for len in [0, 1, 54, 55, 56, 65, 128, 255, 256, 65_535] {
                    let mut entry =
                        FrameSignature::new(scheme, signer, msg, vec![0x81; len].into());
                    let original = alloy_rlp::encode(&entry);
                    let view = entry.as_signing();
                    let encoded = alloy_rlp::encode(view);
                    assert_eq!(view.length(), encoded.len());
                    assert_eq!(encoded, alloy_rlp::encode(signing_entry(&entry)));
                    assert_eq!(alloy_rlp::encode(&entry), original);

                    // Changing the witness affects the preimage only for an explicit message.
                    entry.signature = vec![0x82; len + 1].into();
                    if msg.is_transaction_hash() {
                        assert_eq!(alloy_rlp::encode(entry.as_signing()), encoded);
                    } else {
                        assert_ne!(alloy_rlp::encode(entry.as_signing()), encoded);
                    }
                }
            }
        }
    }
}

#[test]
fn signing_list_lengths_follow_transformed_entries() {
    // Eleven and twelve empty entries straddle the outer list's 55-byte boundary.
    for count in [0, 1, 11, 12, 64] {
        for len in [0, 1, 55, 56, 255, 256, 1_024] {
            let mut entries =
                vec![
                    FrameSignature { signature: vec![0x81; len].into(), ..Default::default() };
                    count
                ];
            for explicit_messages in [false, true] {
                if explicit_messages {
                    for entry in entries.iter_mut().step_by(2) {
                        entry.msg = SignatureMessage::Explicit(B256::repeat_byte(0x33));
                    }
                }
                let original = alloy_rlp::encode(&entries);
                let transformed: Vec<_> = entries.iter().map(signing_entry).collect();
                let view = SigningFrameSignatures::new(&entries);
                let encoded = alloy_rlp::encode(view);
                assert_eq!(view.length(), encoded.len());
                assert_eq!(encoded, alloy_rlp::encode(&transformed));
                assert_eq!(
                    alloy_rlp::decode_exact::<Vec<FrameSignature>>(&encoded).unwrap(),
                    transformed
                );
                assert_eq!(alloy_rlp::encode(&entries), original);
            }
        }
    }
}
