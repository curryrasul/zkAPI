// XMSS authentication path verification.
//
// Uses the same Merkle construction as the note tree but with a separate
// domain tag (DOMAIN_XMSS_NODE) and the XMSS tree height of 20.

use core::poseidon::poseidon_hash_span;
use zkapi_cairo::constants::XMSS_TREE_HEIGHT;
use zkapi_cairo::domains::DOMAIN_XMSS_NODE;

/// Compute the hash of an internal XMSS tree node.
fn xmss_node_hash(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span(array![DOMAIN_XMSS_NODE, left, right].span())
}

/// Verify that `leaf` at position `leaf_index` is included in the XMSS tree
/// with the given `root`.
///
/// `auth_path` must contain exactly XMSS_TREE_HEIGHT (20) sibling hashes.
/// `leaf_index` is decomposed into bits internally to determine the path
/// direction at each level.
pub fn verify_auth_path(
    leaf: felt252, leaf_index: u32, auth_path: Span<felt252>, root: felt252,
) {
    assert(auth_path.len() == XMSS_TREE_HEIGHT, 'invalid auth path len');
    assert(leaf_index < 1048576, 'leaf index >= 2^20'); // 2^20 = 1_048_576

    let mut current = leaf;
    let mut idx = leaf_index;
    let mut i: u32 = 0;
    loop {
        if i == XMSS_TREE_HEIGHT {
            break;
        }
        let sibling = *auth_path.at(i);
        let bit = idx % 2;
        if bit == 0 {
            current = xmss_node_hash(current, sibling);
        } else {
            current = xmss_node_hash(sibling, current);
        }
        idx = idx / 2;
        i += 1;
    };
    assert(current == root, 'xmss auth path invalid');
}
