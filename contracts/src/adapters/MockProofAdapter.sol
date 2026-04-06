// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title MockProofAdapter – Test adapter that accepts all proofs
/// @notice When `acceptAll` is true (default) every proof is accepted, which
///         lets contract business-logic tests run without real STARK proofs.
///         When `acceptAll` is false, the adapter only accepts proof envelopes
///         whose keccak256 hash has been pre-registered.
contract MockProofAdapter is IZkApiProofAdapter {
    /// @notice When true, all proofs are accepted unconditionally.
    bool public acceptAll;

    /// @notice Set of pre-registered valid proof hashes (used when acceptAll is false).
    mapping(bytes32 => bool) public validProofHashes;

    /// @notice The deployer / admin.
    address public admin;

    constructor() {
        acceptAll = true;
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    function _onlyAdmin() internal view {
        if (msg.sender != admin) revert Errors.Unauthorized();
    }

    /// @notice Toggle accept-all mode.
    function setAcceptAll(bool _acceptAll) external onlyAdmin {
        acceptAll = _acceptAll;
    }

    /// @notice Register a proof hash as valid (for non-acceptAll mode).
    function registerProofHash(bytes32 proofHash) external onlyAdmin {
        validProofHashes[proofHash] = true;
    }

    /// @notice Remove a previously registered proof hash.
    function removeProofHash(bytes32 proofHash) external onlyAdmin {
        validProofHashes[proofHash] = false;
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidRequest(
        Types.RequestPublicInputs calldata,
        /* inputs */
        bytes calldata proofEnvelope
    )
        external
        view
        override
    {
        _assertValid(proofEnvelope);
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidWithdrawal(
        Types.WithdrawalPublicInputs calldata,
        /* inputs */
        bytes calldata proofEnvelope
    )
        external
        view
        override
    {
        _assertValid(proofEnvelope);
    }

    function _assertValid(bytes calldata proofEnvelope) internal view {
        if (acceptAll) return;

        if (proofEnvelope.length != 32) revert Errors.InvalidProof();
        bytes32 hash = keccak256(proofEnvelope);
        if (!validProofHashes[hash]) revert Errors.InvalidProof();
    }
}
