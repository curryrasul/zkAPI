// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StarkPoseidon} from "./StarkPoseidon.sol";

/// @title NoteLeafLib – Compute the active-tree leaf for a note
/// @notice Uses the same Starknet/Cairo-compatible Poseidon hash as the Rust
///         and Cairo implementations.
library NoteLeafLib {
    /// @notice Domain separator for leaf hashing.
    ///         domain("zkapi.leaf") = big-endian integer of ASCII bytes.
    ///         "zkapi.leaf" = 0x7a6b6170692e6c656166
    uint256 internal constant DOMAIN_LEAF = 0x7a6b6170692e6c656166;

    /// @notice Compute the leaf value for a note.
    /// @dev leaf = Poseidon(domain("zkapi.leaf"), noteId, commitment, depositAmount, expiryTs)
    /// @param noteId        The sequential note index.
    /// @param commitment    The registration commitment C.
    /// @param depositAmount The deposit amount D.
    /// @param expiryTs      The expiry timestamp.
    /// @return leaf         The computed leaf value.
    function computeLeaf(uint32 noteId, bytes32 commitment, uint128 depositAmount, uint64 expiryTs)
        internal
        pure
        returns (uint256)
    {
        return StarkPoseidon.hash5(
            DOMAIN_LEAF, uint256(noteId), uint256(commitment), uint256(depositAmount), uint256(expiryTs)
        );
    }
}
