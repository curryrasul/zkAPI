// Merkle tree verification for zkAPI.
//
// Uses a fixed-depth binary Merkle tree with depth 32.
// Internal node hash: Poseidon(DOMAIN_NODE, left, right).

use core::poseidon::poseidon_hash_span;
use super::domains::DOMAIN_NODE;

/// Compute the hash of an internal Merkle tree node.
pub fn node_hash(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span(array![DOMAIN_NODE, left, right].span())
}

/// Verify that `leaf` is included in the tree with the given `root`.
///
/// `index_bits` contains 32 felt252 values, each 0 or 1, representing the
/// path from the leaf to the root (bit 0 = lowest level).
/// `siblings` contains the 32 sibling hashes along the path.
pub fn verify_merkle_path(
    root: felt252,
    leaf: felt252,
    index_bits: Span<felt252>,
    siblings: Span<felt252>,
) {
    assert(index_bits.len() == 32, 'invalid index bits len');
    assert(siblings.len() == 32, 'invalid siblings len');

    let mut current = leaf;
    let mut i: u32 = 0;
    loop {
        if i == 32 {
            break;
        }
        let bit = *index_bits.at(i);
        assert(bit == 0 || bit == 1, 'invalid index bit');
        let sibling = *siblings.at(i);
        if bit == 0 {
            current = node_hash(current, sibling);
        } else {
            current = node_hash(sibling, current);
        }
        i += 1;
    };
    assert(current == root, 'merkle proof invalid');
}
