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
    uint256 internal constant STARK_FIELD_PRIME =
        0x0800000000000011000000000000000000000000000000000000000000000001;

    bytes internal constant REQUEST_OUTPUT_DOMAIN = "zkapi.req.outputs.v1";
    bytes internal constant WITHDRAWAL_OUTPUT_DOMAIN = "zkapi.wd.outputs.v1";

    /// @notice The fact registry contract.
    IFactRegistry public immutable factRegistry;

    /// @notice Allowed Cairo program hash for request proofs (statement type 1).
    bytes32 public immutable requestProgramHash;

    /// @notice Allowed Cairo program hash for withdrawal proofs (statement type 2).
    bytes32 public immutable withdrawalProgramHash;

    constructor(address _factRegistry, bytes32 _requestProgramHash, bytes32 _withdrawalProgramHash) {
        factRegistry = IFactRegistry(_factRegistry);
        requestProgramHash = _requestProgramHash;
        withdrawalProgramHash = _withdrawalProgramHash;
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidRequest(
        Types.RequestPublicInputs calldata inputs,
        bytes calldata /* proofEnvelope */
    )
        external
        view
        override
    {
        if (inputs.statementType != 1) revert Errors.InvalidStatementType();

        bytes32 outputHash = _hashRequestOutputs(inputs);
        bytes32 fact = keccak256(abi.encodePacked(requestProgramHash, outputHash));

        if (!factRegistry.isValid(fact)) revert Errors.InvalidProof();
    }

    /// @inheritdoc IZkApiProofAdapter
    function assertValidWithdrawal(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata /* proofEnvelope */
    )
        external
        view
        override
    {
        if (inputs.statementType != 2) revert Errors.InvalidStatementType();

        bytes32 outputHash = _hashWithdrawalOutputs(inputs);
        bytes32 fact = keccak256(abi.encodePacked(withdrawalProgramHash, outputHash));

        if (!factRegistry.isValid(fact)) revert Errors.InvalidProof();
    }

    /// @dev Reconstruct the output hash for a request proof from its public inputs.
    ///      The fields are encoded in the same order as the Cairo program emits them.
    function _hashRequestOutputs(Types.RequestPublicInputs calldata inputs) internal pure returns (bytes32) {
        return _hashToFelt(
            REQUEST_OUTPUT_DOMAIN,
            abi.encodePacked(
                bytes32(uint256(inputs.statementType)),
                bytes32(uint256(inputs.protocolVersion)),
                bytes32(uint256(inputs.chainId)),
                bytes32(uint256(uint160(inputs.contractAddress))),
                bytes32(inputs.activeRoot),
                bytes32(uint256(inputs.stateSigEpoch)),
                bytes32(inputs.stateSigRoot),
                bytes32(inputs.requestNullifier),
                bytes32(inputs.anonCommitmentX),
                bytes32(inputs.anonCommitmentY),
                bytes32(uint256(inputs.expiryTs)),
                bytes32(uint256(inputs.solvencyBound))
            )
        );
    }

    /// @dev Reconstruct the output hash for a withdrawal proof from its public inputs.
    function _hashWithdrawalOutputs(Types.WithdrawalPublicInputs calldata inputs) internal pure returns (bytes32) {
        return _hashToFelt(
            WITHDRAWAL_OUTPUT_DOMAIN,
            abi.encodePacked(
                bytes32(uint256(inputs.statementType)),
                bytes32(uint256(inputs.protocolVersion)),
                bytes32(uint256(inputs.chainId)),
                bytes32(uint256(uint160(inputs.contractAddress))),
                bytes32(inputs.activeRoot),
                bytes32(uint256(inputs.noteId)),
                bytes32(uint256(inputs.finalBalance)),
                bytes32(uint256(uint160(inputs.destination))),
                bytes32(inputs.withdrawalNullifier),
                bytes32(inputs.isGenesis ? uint256(1) : uint256(0)),
                bytes32(inputs.hasClearance ? uint256(1) : uint256(0)),
                bytes32(uint256(inputs.stateSigEpoch)),
                bytes32(inputs.stateSigRoot),
                bytes32(uint256(inputs.clearSigEpoch)),
                bytes32(inputs.clearSigRoot)
            )
        );
    }

    function _hashToFelt(bytes memory domain, bytes memory payload) internal pure returns (bytes32) {
        uint32 counter = 0;
        while (true) {
            bytes32 digest = keccak256(abi.encodePacked(domain, uint64(payload.length), payload, counter));
            if (uint256(digest) < STARK_FIELD_PRIME) {
                return digest;
            }
            unchecked {
                counter += 1;
            }
        }
        revert Errors.InvalidProof();
    }
}
