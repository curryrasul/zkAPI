// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title IFactRegistry – Minimal interface for a Cairo fact registry.
interface IFactRegistry {
    /// @notice Returns true if the given fact hash has been registered.
    function isValid(bytes32 fact) external view returns (bool);
}

/// @title FactRegistryAdapter – Production proof adapter using a fact registry
/// @notice Reconstructs the expected fact hash from public inputs and the
///         pinned Cairo program hash, then asserts the fact exists in the
///         registry.
contract FactRegistryAdapter is IZkApiProofAdapter {
    /// @notice The fact registry contract.
    IFactRegistry public immutable factRegistry;

    /// @notice Allowed Cairo program hash for request proofs (statement type 1).
    bytes32 public immutable requestProgramHash;

    /// @notice Allowed Cairo program hash for withdrawal proofs (statement type 2).
    bytes32 public immutable withdrawalProgramHash;

    constructor(
        address _factRegistry,
        bytes32 _requestProgramHash,
        bytes32 _withdrawalProgramHash
    ) {
        factRegistry = IFactRegistry(_factRegistry);
        requestProgramHash = _requestProgramHash;
        withdrawalProgramHash = _withdrawalProgramHash;
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidRequest(
        Types.RequestPublicInputs calldata inputs,
        bytes calldata /* proofEnvelope */
    ) external view override {
        if (inputs.statementType != 1) revert Errors.InvalidStatementType();

        bytes32 outputHash = _hashRequestOutputs(inputs);
        bytes32 fact = keccak256(abi.encodePacked(requestProgramHash, outputHash));

        if (!factRegistry.isValid(fact)) revert Errors.InvalidProof();
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidWithdrawal(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata /* proofEnvelope */
    ) external view override {
        if (inputs.statementType != 2) revert Errors.InvalidStatementType();

        bytes32 outputHash = _hashWithdrawalOutputs(inputs);
        bytes32 fact = keccak256(abi.encodePacked(withdrawalProgramHash, outputHash));

        if (!factRegistry.isValid(fact)) revert Errors.InvalidProof();
    }

    /// @dev Reconstruct the output hash for a request proof from its public inputs.
    ///      The fields are encoded in the same order as the Cairo program emits them.
    function _hashRequestOutputs(
        Types.RequestPublicInputs calldata inputs
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                inputs.statementType,
                inputs.protocolVersion,
                inputs.chainId,
                inputs.contractAddress,
                inputs.activeRoot,
                inputs.stateSigEpoch,
                inputs.stateSigRoot,
                inputs.requestNullifier,
                inputs.anonCommitmentX,
                inputs.anonCommitmentY,
                inputs.expiryTs,
                inputs.solvencyBound
            )
        );
    }

    /// @dev Reconstruct the output hash for a withdrawal proof from its public inputs.
    function _hashWithdrawalOutputs(
        Types.WithdrawalPublicInputs calldata inputs
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                inputs.statementType,
                inputs.protocolVersion,
                inputs.chainId,
                inputs.contractAddress,
                inputs.activeRoot,
                inputs.noteId,
                inputs.finalBalance,
                inputs.destination,
                inputs.withdrawalNullifier,
                inputs.isGenesis,
                inputs.hasClearance,
                inputs.stateSigEpoch,
                inputs.stateSigRoot,
                inputs.clearSigEpoch,
                inputs.clearSigRoot
            )
        );
    }
}
