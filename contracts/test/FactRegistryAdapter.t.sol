// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {FactRegistryAdapter, IFactRegistry} from "../src/adapters/FactRegistryAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";

contract MockFactRegistry is IFactRegistry {
    mapping(bytes32 => bool) public validFacts;

    function register(bytes32 fact) external {
        validFacts[fact] = true;
    }

    function isValid(bytes32 fact) external view returns (bool) {
        return validFacts[fact];
    }
}

contract FactRegistryAdapterHarness is FactRegistryAdapter {
    constructor(address registry, bytes32 requestProgramHash, bytes32 withdrawalProgramHash)
        FactRegistryAdapter(registry, requestProgramHash, withdrawalProgramHash)
    {}

    function hashRequestOutputs(Types.RequestPublicInputs calldata inputs) external pure returns (bytes32) {
        return _hashRequestOutputs(inputs);
    }

    function hashWithdrawalOutputs(Types.WithdrawalPublicInputs calldata inputs) external pure returns (bytes32) {
        return _hashWithdrawalOutputs(inputs);
    }
}

contract FactRegistryAdapterTest is Test {
    MockFactRegistry registry;
    FactRegistryAdapterHarness adapter;

    bytes32 constant REQUEST_PROGRAM_HASH = bytes32(uint256(0x1111));
    bytes32 constant WITHDRAWAL_PROGRAM_HASH = bytes32(uint256(0x2222));
    bytes32 constant RUST_REQUEST_OUTPUT_HASH =
        0x03964139c5f6f84608232748c75a34ce4c7d828c52b0d044ac404ae7e66644c6;
    bytes32 constant RUST_WITHDRAWAL_OUTPUT_HASH =
        0x04c7faba541192c69c4c3817847f7829c4581910a5bb8fa8381969893ec6ecf3;

    function setUp() public {
        registry = new MockFactRegistry();
        adapter = new FactRegistryAdapterHarness(
            address(registry), REQUEST_PROGRAM_HASH, WITHDRAWAL_PROGRAM_HASH
        );
    }

    function test_requestFactUsesCanonicalOutputHash() public {
        Types.RequestPublicInputs memory inputs = Types.RequestPublicInputs({
            statementType: 1,
            protocolVersion: 1,
            chainId: 31337,
            contractAddress: address(0x1234),
            activeRoot: 5,
            stateSigEpoch: 6,
            stateSigRoot: 7,
            requestNullifier: 8,
            anonCommitmentX: 9,
            anonCommitmentY: 10,
            expiryTs: 11,
            solvencyBound: 12
        });

        bytes32 outputHash = adapter.hashRequestOutputs(inputs);
        assertEq(outputHash, RUST_REQUEST_OUTPUT_HASH);
        bytes32 fact = keccak256(abi.encodePacked(REQUEST_PROGRAM_HASH, outputHash));
        registry.register(fact);
        adapter.assertValidRequest(inputs, "");

        inputs.requestNullifier = 99;
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidRequest(inputs, "");
    }

    function test_withdrawalFactUsesCanonicalOutputHash() public {
        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            statementType: 2,
            protocolVersion: 1,
            chainId: 31337,
            contractAddress: address(0x1234),
            activeRoot: 5,
            noteId: 6,
            finalBalance: 7,
            destination: address(0xBEEF),
            withdrawalNullifier: 8,
            isGenesis: true,
            hasClearance: false,
            stateSigEpoch: 0,
            stateSigRoot: 0,
            clearSigEpoch: 0,
            clearSigRoot: 0
        });

        bytes32 outputHash = adapter.hashWithdrawalOutputs(inputs);
        assertEq(outputHash, RUST_WITHDRAWAL_OUTPUT_HASH);
        bytes32 fact = keccak256(abi.encodePacked(WITHDRAWAL_PROGRAM_HASH, outputHash));
        registry.register(fact);
        adapter.assertValidWithdrawal(inputs, "");

        inputs.destination = address(0xCAFE);
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, "");
    }

    function test_wrongStatementTypesRejectedBeforeFactLookup() public {
        Types.RequestPublicInputs memory requestInputs;
        requestInputs.statementType = 2;
        vm.expectRevert(Errors.InvalidStatementType.selector);
        adapter.assertValidRequest(requestInputs, "");

        Types.WithdrawalPublicInputs memory withdrawalInputs;
        withdrawalInputs.statementType = 1;
        vm.expectRevert(Errors.InvalidStatementType.selector);
        adapter.assertValidWithdrawal(withdrawalInputs, "");
    }
}
