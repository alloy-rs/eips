//! Tests for the EIP-8141 leanSPHINCS scheme and its pinned EthLib verifier.

use alloy_eip8141::*;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rlp::Encodable;

const VECTOR_LENGTH: usize = LEAN_SPHINCS_PUBLIC_KEY_LENGTH + 32 + LEAN_SPHINCS_SIGNATURE_LENGTH;

// Each fixture is public_key || message || signature from the corresponding EthLib
// verify_valid_* vector at 03b7e4ddba3c6f09cbfe290930116d9dae75e708.
const VECTORS: [&[u8; VECTOR_LENGTH]; 3] = [
    include_bytes!("fixtures/lean_sphincs_known_answer.bin"),
    include_bytes!("fixtures/lean_sphincs_zero_message.bin"),
    include_bytes!("fixtures/lean_sphincs_zero_seed.bin"),
];

fn vector(bytes: &[u8; VECTOR_LENGTH]) -> (B256, B256, &[u8]) {
    let (key, rest) = bytes.split_at(LEAN_SPHINCS_PUBLIC_KEY_LENGTH);
    let (message, signature) = rest.split_at(32);
    (B256::from_slice(key), B256::from_slice(message), signature)
}

#[test]
fn ethlib_known_answers() {
    for bytes in VECTORS {
        let (key, message, signature) = vector(bytes);
        assert!(verify_lean_sphincs(&key, &message, signature));

        let entry = FrameSignature::from_lean_sphincs(
            key,
            SignatureMessage::TransactionHash,
            Bytes::copy_from_slice(signature),
        )
        .unwrap();
        assert!(entry.verify_lean_sphincs(&message));
        assert!(!entry.verify_lean_sphincs(&B256::repeat_byte(0xff)));

        if !message.is_zero() {
            let explicit =
                FrameSignature { msg: SignatureMessage::explicit(message).unwrap(), ..entry };
            assert!(explicit.verify_lean_sphincs(&B256::ZERO));
        } else {
            let explicit = FrameSignature { msg: SignatureMessage::Explicit(message), ..entry };
            assert!(!explicit.verify_lean_sphincs(&message));
        }
    }
}

#[test]
fn verifier_rejects_changed_inputs() {
    let (key, message, signature) = vector(VECTORS[0]);
    let mut changed = signature.to_vec();
    for offset in [0, 16, 32, 176, 4240, 4244, 5268, 5396, 5400, 6424, 6552, 6556, 7580, 7739] {
        changed[offset] ^= 1;
        assert!(!verify_lean_sphincs(&key, &message, &changed), "byte {offset}");
        changed[offset] ^= 1;
    }
    changed.push(0);
    assert!(!verify_lean_sphincs(&key, &message, &changed));
    assert!(!verify_lean_sphincs(&key, &message, &signature[..signature.len() - 1]));

    let mut changed_key = key;
    for offset in [0, 16] {
        changed_key[offset] ^= 1;
        assert!(!verify_lean_sphincs(&changed_key, &message, signature));
        changed_key[offset] ^= 1;
    }
    let mut changed_message = message;
    changed_message[31] ^= 1;
    assert!(!verify_lean_sphincs(&key, &changed_message, signature));
}

#[test]
fn scheme_binding_and_signing_encoding() {
    let key = B256::repeat_byte(0x42);
    let sender = Address::repeat_byte(0x41);
    let mut entry = FrameSignature::from_lean_sphincs(
        key,
        SignatureMessage::TransactionHash,
        vec![0; LEAN_SPHINCS_SIGNATURE_LENGTH].into(),
    )
    .unwrap();

    assert!(entry.scheme.is_lean_sphincs());
    assert_eq!(u8::from(entry.scheme), 3);
    assert_eq!(entry.verification_gas(), 12_600);
    assert_eq!(entry.scheme.signature_length(), Some(7_740));
    assert_eq!(entry.signature_tokens(), 7_740 * 4);
    assert_eq!(entry.lean_sphincs_public_key(), Some(&key));
    assert_eq!(entry.signer_address(), None);
    assert_eq!(entry.resolved_signer(sender).unwrap().unwrap().into_word(), key);
    assert_eq!(entry.validate_structure_with_sender(sender), Ok(()));

    let encoded = alloy_rlp::encode(&entry);
    assert_eq!(encoded.len(), entry.length());
    assert_eq!(&encoded[..5], &[0xf9, 0x1e, 0x62, 3, 0xa0]);
    assert_eq!(&encoded[5..37], key.as_slice());
    assert_eq!(&encoded[37..41], &[0x80, 0xb9, 0x1e, 0x3c]);
    assert_eq!(alloy_rlp::decode_exact::<FrameSignature>(&encoded).unwrap(), entry);
    let mut signing = vec![0xe6, 3, 0xa0];
    signing.extend_from_slice(key.as_slice());
    signing.extend_from_slice(&[0x80, 0x82, 0x1e, 0x3c]);
    assert_eq!(alloy_rlp::encode(entry.as_signing()), signing);
    entry.signature = vec![0xff; 7_740].into();
    assert_eq!(alloy_rlp::encode(entry.as_signing()), signing);
    entry.signer = FrameSigner::LeanSphincs(B256::ZERO);
    assert_ne!(alloy_rlp::encode(entry.as_signing()), signing);
    assert_eq!(entry.validate_structure(), Ok(()));

    entry.msg = SignatureMessage::Explicit(B256::repeat_byte(1));
    entry.signature = vec![0; 7_740].into();
    assert_eq!(entry.signature_tokens(), 7_740);
    let mut expected = alloy_rlp::encode(&entry);
    assert_eq!(alloy_rlp::encode(entry.as_signing()), expected);
    expected.pop();
    assert!(alloy_rlp::decode_exact::<FrameSignature>(&expected).is_err());
}

#[test]
fn rejects_invalid_signer_scheme_pairs_and_signature_lengths() {
    let mut entry = FrameSignature { scheme: SignatureScheme::LeanSphincs, ..Default::default() };
    for signer in [FrameSigner::Empty, FrameSigner::Address(Address::ZERO)] {
        entry.signer = signer;
        let err = Eip8141Error::InvalidSignerLength(signer.as_bytes().len());
        assert_eq!(entry.resolved_signer(Address::ZERO), Err(err));
        assert_eq!(entry.validate_structure(), Err(err));
        assert!(!entry.verify_lean_sphincs(&B256::ZERO));
    }

    entry.signer = FrameSigner::LeanSphincs(B256::ZERO);
    for actual in [0, 7_739, 7_741] {
        entry.signature = vec![0; actual].into();
        assert_eq!(
            entry.validate_structure(),
            Err(Eip8141Error::InvalidSignatureLength { expected: 7_740, actual })
        );
    }

    for scheme in [SignatureScheme::Secp256k1, SignatureScheme::P256, SignatureScheme::Arbitrary] {
        entry.scheme = scheme;
        let err = if scheme.is_arbitrary() {
            Eip8141Error::UnexpectedSigner
        } else {
            Eip8141Error::InvalidSignerLength(32)
        };
        assert_eq!(entry.resolved_signer(Address::ZERO), Err(err));
        assert_eq!(entry.validate_structure(), Err(err));
        assert!(!entry.verify_lean_sphincs(&B256::ZERO));
    }

    for len in [1, 19, 21, 31, 33] {
        let encoded = alloy_rlp::encode(Bytes::from(vec![1; len]));
        assert!(alloy_rlp::decode_exact::<FrameSigner>(&encoded).is_err());
    }
}

#[cfg(feature = "borsh")]
#[test]
fn signer_discriminants_preserve_legacy_borsh_encoding() {
    for address in [FrameAddress::Empty, FrameAddress::Address(Address::repeat_byte(0x42))] {
        assert_eq!(
            borsh::to_vec(&FrameSigner::from(address)).unwrap(),
            borsh::to_vec(&address).unwrap()
        );
    }
    let signer = FrameSigner::LeanSphincs(B256::repeat_byte(0x42));
    let bytes = borsh::to_vec(&signer).unwrap();
    assert_eq!(bytes[0], 2);
    assert_eq!(borsh::from_slice::<FrameSigner>(&bytes).unwrap(), signer);
}
