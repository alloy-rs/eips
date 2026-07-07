use alloy_primitives::{Address, B256, Bytes};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// EIP-8141 transaction signature scheme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "borsh", borsh(use_discriminant = true))]
pub enum SignatureScheme {
    /// Arbitrary witness bytes interpreted by EVM validation code.
    #[default]
    Arbitrary = 0x00,
    /// Secp256k1 signature.
    Secp256k1 = 0x01,
    /// P-256 signature.
    P256 = 0x02,
}

impl SignatureScheme {
    /// Attempts to convert a raw scheme byte into a [`SignatureScheme`].
    pub const fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Arbitrary),
            0x01 => Some(Self::Secp256k1),
            0x02 => Some(Self::P256),
            _ => None,
        }
    }

    /// Returns the protocol signature verification gas cost.
    pub const fn verification_gas(self) -> u64 {
        match self {
            Self::Arbitrary => 0,
            Self::Secp256k1 => 2_800,
            Self::P256 => 6_700,
        }
    }
}

impl From<SignatureScheme> for u8 {
    fn from(value: SignatureScheme) -> Self {
        value as Self
    }
}

/// The message authorized by an EIP-8141 signature entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum SignatureMessage {
    /// The signature signs the canonical transaction signature hash.
    TransactionHash,
    /// The signature signs an explicit non-zero 32-byte digest.
    Explicit(B256),
}

/// A signature entry attached to an EIP-8141 frame transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct FrameSignature {
    /// Raw signature scheme identifier.
    pub scheme: u8,
    /// Scheme-dependent signer metadata. For `ARBITRARY`, this must be empty.
    pub signer: Bytes,
    /// Empty for the canonical transaction signature hash, or an explicit 32-byte digest.
    pub msg: Bytes,
    /// Raw signature bytes.
    pub signature: Bytes,
}

impl FrameSignature {
    /// Creates a new frame signature from raw field values.
    pub const fn new(scheme: u8, signer: Bytes, msg: Bytes, signature: Bytes) -> Self {
        Self { scheme, signer, msg, signature }
    }

    /// Returns the parsed signature scheme, if valid.
    pub const fn signature_scheme(&self) -> Option<SignatureScheme> {
        SignatureScheme::try_from_u8(self.scheme)
    }

    /// Returns true if this signature signs the canonical transaction signature hash.
    pub fn signs_transaction_hash(&self) -> bool {
        self.msg.is_empty()
    }

    /// Returns the explicit signed message, if one is present.
    pub fn explicit_message(&self) -> Option<B256> {
        if self.msg.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.msg);
            Some(B256::from(bytes))
        } else {
            None
        }
    }

    /// Returns the signer as an address for protocol-validated schemes.
    pub fn signer_address(&self) -> Option<Address> {
        if self.signer.len() == 20 {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&self.signer);
            Some(Address::from(bytes))
        } else {
            None
        }
    }

    /// Returns the protocol signature verification gas cost, if the scheme is known.
    pub const fn verification_gas(&self) -> Option<u64> {
        match self.signature_scheme() {
            Some(scheme) => Some(scheme.verification_gas()),
            None => None,
        }
    }
}
