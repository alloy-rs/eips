//! Signature lengths are committed without committing to circular witness bytes.
use alloy_eip8141::{FrameSignature, SignatureMessage, SigningFrameSignatures};
use alloy_primitives::{B256, hex};
use alloy_rlp::Encodable;

#[test]
fn signing_rlp_commits_to_lengths_as_integers() {
    let mut sig = FrameSignature { signature: hex!("aabb").into(), ..Default::default() };
    assert_eq!(alloy_rlp::encode(sig.as_signing()), hex!("c480808002"));
    sig.signature = vec![0; 128].into();
    assert_eq!(alloy_rlp::encode(sig.as_signing()), hex!("c58080808180"));
    sig.signature = vec![0; 256].into();
    assert_eq!(alloy_rlp::encode(sig.as_signing()), hex!("c6808080820100"));
}

#[test]
fn witness_contents_are_elided_but_lengths_and_explicit_messages_are_bound() {
    let mut sig = FrameSignature { signature: vec![0; 65].into(), ..Default::default() };
    let original = alloy_rlp::encode(sig.as_signing());
    sig.signature = vec![0xff; 65].into();
    assert_eq!(original, alloy_rlp::encode(sig.as_signing()));
    sig.signature = vec![0xff; 66].into();
    assert_ne!(original, alloy_rlp::encode(sig.as_signing()));
    sig.msg = SignatureMessage::Explicit(B256::repeat_byte(1));
    let explicit = alloy_rlp::encode(sig.as_signing());
    sig.signature = vec![0; 66].into();
    assert_ne!(explicit, alloy_rlp::encode(sig.as_signing()));
}

#[test]
fn signing_list_lengths_cover_rlp_boundaries() {
    for count in [0, 1, 11, 12, 64] {
        for len in [0, 1, 55, 56, 127, 128, 255, 256, 65_535] {
            let entries =
                vec![
                    FrameSignature { signature: vec![0; len].into(), ..Default::default() };
                    count
                ];
            let view = SigningFrameSignatures::new(&entries);
            assert_eq!(alloy_rlp::encode(view).len(), view.length());
        }
    }
}
