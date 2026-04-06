// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Errors} from "./Errors.sol";

/// @title MerkleUpdateLib – Fixed-depth binary Merkle tree helpers
/// @notice Uses a keccak256 stub for the Poseidon node hash until a real
///         Poseidon implementation is integrated.
library MerkleUpdateLib {
    /// @notice Depth of the active-note Merkle tree.
    uint256 internal constant MERKLE_DEPTH = 32;

    /// @notice The Stark field prime: P = 2^251 + 17 * 2^192 + 1.
    uint256 internal constant STARK_FIELD_PRIME =
        3618502788666131213697322783095070105623107215331596699973092056135872020481;

    /// @notice Domain separator for node hashing.
    ///         domain("zkapi.node") = big-endian integer of ASCII bytes.
    ///         "zkapi.node" = 0x7a6b6170692e6e6f6465
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e6e6f6465;

    /// @notice Compute a Merkle node hash.
    /// @dev TODO: Replace this keccak256 stub with the actual Poseidon
    ///      implementation that matches the Cairo program.
    function poseidonNodeHash(
        uint256 domain,
        uint256 left,
        uint256 right
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(domain, left, right))) % STARK_FIELD_PRIME;
    }

    /// @notice Compute the Merkle root from a leaf and its sibling path.
    /// @param index  The leaf index (note_id).
    /// @param leaf   The leaf value.
    /// @param siblings  The 32 sibling hashes from leaf to root.
    /// @return root  The computed Merkle root.
    function computeRoot(
        uint32 index,
        uint256 leaf,
        uint256[32] calldata siblings
    ) internal pure returns (uint256 root) {
        root = leaf;
        uint32 idx = index;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            if (idx & 1 == 0) {
                root = poseidonNodeHash(DOMAIN_NODE, root, siblings[i]);
            } else {
                root = poseidonNodeHash(DOMAIN_NODE, siblings[i], root);
            }
            idx >>= 1;
        }
    }

    /// @notice Verify that the current root matches (index, oldLeaf, siblings),
    ///         then compute the new root after replacing oldLeaf with newLeaf.
    /// @param currentRoot The expected current Merkle root.
    /// @param index       The leaf index.
    /// @param oldLeaf     The current leaf value at `index`.
    /// @param newLeaf     The replacement leaf value.
    /// @param siblings    The 32 sibling hashes.
    /// @return newRoot    The Merkle root after replacement.
    function verifyAndUpdate(
        uint256 currentRoot,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings
    ) internal pure returns (uint256 newRoot) {
        uint256 computedOldRoot = computeRoot(index, oldLeaf, siblings);
        if (computedOldRoot != currentRoot) {
            revert Errors.StaleRoot();
        }
        newRoot = computeRoot(index, newLeaf, siblings);
    }
}
