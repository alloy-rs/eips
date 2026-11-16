//! Verification for the leanSPHINCS parameter set referenced by EIP-8141.
//!
//! See [EthLib at the revision pinned by the EIP](https://github.com/ethereum/EthLib/tree/03b7e4ddba3c6f09cbfe290930116d9dae75e708/EthLib/Cryptography/Sphincs).

use alloy_primitives::{B256, keccak256_uncached};

use crate::LEAN_SPHINCS_SIGNATURE_LENGTH;

const NODE_BYTES: usize = 16;
type Node = [u8; NODE_BYTES];

const FORS_TREES: usize = 24;
const FORS_HEIGHT: usize = 10;
const FORS_OPENING_BYTES: usize = (1 + FORS_HEIGHT) * NODE_BYTES;
const FORS_SIGNATURE_BYTES: usize = FORS_TREES * FORS_OPENING_BYTES;
const FORS_KEY_BYTES: usize = FORS_TREES * 2 * NODE_BYTES;

const TREE_HEIGHTS: [usize; 3] = [8, 8, 10];
const INDEX_BITS: usize = TREE_HEIGHTS[0] + TREE_HEIGHTS[1] + TREE_HEIGHTS[2];
const CHAINS: usize = 64;
const CHAIN_END: u8 = 3;
const COUNTER_BYTES: usize = 4;
const TARGET_SUM: u32 = 128;

const CHAIN: u8 = 1;
const LEAF: u8 = 2;
const PARENT: u8 = 3;
const ENCODING: u8 = 4;
const MESSAGE: u8 = 12;
const FORS_LEAF: u8 = 15;
const FORS_PARENT: u8 = 17;

const _: () = assert!(
    NODE_BYTES
        + FORS_SIGNATURE_BYTES
        + TREE_HEIGHTS.len() * (COUNTER_BYTES + CHAINS * NODE_BYTES)
        + INDEX_BITS * NODE_BYTES
        == LEAN_SPHINCS_SIGNATURE_LENGTH
);

/// Verifies a bare EIP-8141 leanSPHINCS signature against a 32-byte digest.
///
/// The public key is the 16-byte root followed by the 16-byte public parameter. Verification
/// uses the parameter set and encodings pinned by the EIP and does not allocate.
pub fn verify_lean_sphincs(public_key: &B256, message: &B256, signature: &[u8]) -> bool {
    if signature.len() != LEAN_SPHINCS_SIGNATURE_LENGTH {
        return false;
    }

    let (root, parameter) = public_key.as_slice().split_at(NODE_BYTES);
    let mut verifier = Verifier::new(parameter);
    let (randomizer, remaining) = signature.split_at(NODE_BYTES);
    let (fors_signature, mut layers) = remaining.split_at(FORS_SIGNATURE_BYTES);

    // The index and all FORS leaves occupy the first 266 bits of the digest. The last leaf
    // comes from the second Keccak output.
    let mut digest = [0; (INDEX_BITS + FORS_TREES * FORS_HEIGHT).div_ceil(8)];
    let (first, last) = digest.split_at_mut(32);
    first.copy_from_slice(
        verifier.hash(address(MESSAGE, 0, 0, 0, 0), message.as_slice(), randomizer).as_slice(),
    );
    last.copy_from_slice(
        &verifier.hash(address(MESSAGE, 0, 0, 1, 0), message.as_slice(), randomizer).as_slice()
            [..last.len()],
    );
    let mut index = u32::from_le_bytes(*digest.first_chunk().unwrap()) & ((1 << INDEX_BITS) - 1);
    let fors_key = verifier.fors_key(index, &digest, fors_signature);

    let mut layer_message: &[u8] = &fors_key;
    let mut layer_root = [0; NODE_BYTES];
    for (layer, height) in TREE_HEIGHTS.into_iter().enumerate() {
        let (layer_signature, rest) =
            layers.split_at(COUNTER_BYTES + (CHAINS + height) * NODE_BYTES);
        layers = rest;
        let leaf_index = index & ((1 << height) - 1);
        index >>= height;
        let Some(root) =
            verifier.layer_root(layer as u8, index, leaf_index, layer_message, layer_signature)
        else {
            return false;
        };
        layer_root = root;
        layer_message = &layer_root;
    }

    layer_root == root
}

/// Each hash takes the public parameter, a 16-byte address, and its payload. The longest
/// payload is the concatenation of the 64 WOTS+C chain ends.
struct Verifier {
    input: [u8; 2 * NODE_BYTES + CHAINS * NODE_BYTES],
}

impl Verifier {
    fn new(parameter: &[u8]) -> Self {
        let mut input = [0; 2 * NODE_BYTES + CHAINS * NODE_BYTES];
        input[..NODE_BYTES].copy_from_slice(parameter);
        Self { input }
    }

    fn hash(&mut self, address: Node, first: &[u8], second: &[u8]) -> B256 {
        let end = 2 * NODE_BYTES + first.len();
        let len = end + second.len();
        self.input[NODE_BYTES..2 * NODE_BYTES].copy_from_slice(&address);
        self.input[2 * NODE_BYTES..end].copy_from_slice(first);
        self.input[end..len].copy_from_slice(second);
        keccak256_uncached(&self.input[..len])
    }

    fn hash_node(&mut self, address: Node, first: &[u8], second: &[u8]) -> Node {
        *self.hash(address, first, second).as_slice().first_chunk().unwrap()
    }

    fn fors_key(&mut self, index: u32, digest: &[u8], signature: &[u8]) -> [u8; FORS_KEY_BYTES] {
        let mut key = [0; FORS_KEY_BYTES];
        for (tree, (opening, pair)) in signature
            .chunks_exact(FORS_OPENING_BYTES)
            .zip(key.chunks_exact_mut(2 * NODE_BYTES))
            .enumerate()
        {
            let bit = INDEX_BITS + tree * FORS_HEIGHT;
            let byte = bit / 8;
            let leaf = u32::from(u16::from_le_bytes([digest[byte], digest[byte + 1]]));
            let mut node_index = (leaf >> (bit % 8)) & ((1 << FORS_HEIGHT) - 1);
            let tree = tree as u32;

            let (secret, path) = opening.split_at(NODE_BYTES);
            let mut node = self.hash_node(
                address(FORS_LEAF, 0, 0, tree + 64 * node_index, index),
                secret,
                &[],
            );
            let (siblings, other_half) = path.split_at((FORS_HEIGHT - 1) * NODE_BYTES);
            for (level, sibling) in siblings.chunks_exact(NODE_BYTES).enumerate() {
                let (left, right) = ordered(node_index, &node, sibling);
                node_index >>= 1;
                let position = (level + 1) as u32 + 16 * node_index;
                node = self.hash_node(
                    address(FORS_PARENT, 0, 0, tree + 64 * position, index),
                    left,
                    right,
                );
            }

            // There is no level-10 hash. The last sibling is the other level-9 node.
            let (left, right) = ordered(node_index, &node, other_half);
            pair[..NODE_BYTES].copy_from_slice(left);
            pair[NODE_BYTES..].copy_from_slice(right);
        }
        key
    }

    fn layer_root(
        &mut self,
        layer: u8,
        tree: u32,
        leaf: u32,
        message: &[u8],
        signature: &[u8],
    ) -> Option<Node> {
        let (counter, remaining) = signature.split_at(COUNTER_BYTES);
        let (chain_values, siblings) = remaining.split_at(CHAINS * NODE_BYTES);
        let codeword = self.hash_node(address(ENCODING, layer, tree, 0, leaf), message, counter);

        // Each byte contains four base-4 digits in little-endian order.
        let digits = u128::from_le_bytes(codeword);
        const LOW_BITS: u128 = u128::MAX / 3;
        let sum = (digits & LOW_BITS).count_ones() + 2 * (digits & !LOW_BITS).count_ones();
        if sum != TARGET_SUM {
            return None;
        }

        let mut ends = [0; CHAINS * NODE_BYTES];
        for (chain, (value, end)) in chain_values
            .as_chunks::<NODE_BYTES>()
            .0
            .iter()
            .zip(ends.as_chunks_mut::<NODE_BYTES>().0.iter_mut())
            .enumerate()
        {
            let start = (codeword[chain / 4] >> (2 * (chain % 4))) & CHAIN_END;
            *end = *value;
            for step in start..CHAIN_END {
                let address = address(CHAIN | (step << 5), layer, tree, chain as u32, leaf);
                *end = self.hash_node(address, end, &[]);
            }
        }
        let mut node = self.hash_node(address(LEAF, layer, tree, 0, leaf), &ends, &[]);
        let mut node_index = leaf;
        for (level, sibling) in siblings.chunks_exact(NODE_BYTES).enumerate() {
            let (left, right) = ordered(node_index, &node, sibling);
            node_index >>= 1;
            node = self.hash_node(
                address(PARENT, layer, tree, (level + 1) as u32, node_index),
                left,
                right,
            );
        }
        Some(node)
    }
}

const fn ordered<'a>(index: u32, node: &'a Node, sibling: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if index & 1 == 0 { (node, sibling) } else { (sibling, node) }
}

/// Layout: lo (4), hi (3), type and step (1), layer (1), tree (4), zero (3).
fn address(kind: u8, layer: u8, tree: u32, hi: u32, lo: u32) -> Node {
    let mut bytes = [0; NODE_BYTES];
    bytes[..4].copy_from_slice(&lo.to_le_bytes());
    bytes[4..7].copy_from_slice(&hi.to_le_bytes()[..3]);
    bytes[7] = kind;
    bytes[8] = layer;
    bytes[9..13].copy_from_slice(&tree.to_le_bytes());
    bytes
}
