// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

import {ZkApiVault} from "../src/ZkApiVault.sol";
import {MockProofAdapter} from "../src/adapters/MockProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
// MerkleUpdateLib and NoteLeafLib constants are replicated locally in the test
// to avoid "unused import" warnings; we re-implement the hash functions below.
import {Events} from "../src/libraries/Events.sol";

/// @title ZkApiVaultTest - Comprehensive Foundry tests for ZkApiVault
/// @notice Covers all scenarios from spec section 13.2
contract ZkApiVaultTest is Test, Events {
    // -----------------------------------------------------------------------
    //  Constants
    // -----------------------------------------------------------------------

    uint256 constant STARK_FIELD_PRIME =
        3618502788666131213697322783095070105623107215331596699973092056135872020481;
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e6e6f6465;
    uint256 constant DOMAIN_LEAF = 0x7a6b6170692e6c656166;
    uint256 constant MERKLE_DEPTH = 32;

    uint64 constant NOTE_TTL = 30 days;
    uint128 constant REQUEST_CHARGE_CAP = 1 ether;
    uint128 constant POLICY_CHARGE_CAP = 0.5 ether;
    uint64 constant CHALLENGE_PERIOD = 24 hours;

    // -----------------------------------------------------------------------
    //  State
    // -----------------------------------------------------------------------

    ERC20Mock token;
    MockProofAdapter adapter;
    ZkApiVault vault;

    address owner = address(0xAA);
    address treasury = address(0xBB);
    address user = address(0xCC);
    address destination = address(0xDD);

    // Pre-computed empty tree siblings and root
    uint256[32] emptySiblings;
    uint256 emptyRoot;

    // -----------------------------------------------------------------------
    //  Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        // Compute empty tree levels: level[0] = 0, level[i+1] = H(DOMAIN_NODE, level[i], level[i])
        uint256[33] memory levels;
        levels[0] = 0;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            levels[i + 1] = _poseidonNodeHash(DOMAIN_NODE, levels[i], levels[i]);
        }
        emptyRoot = levels[MERKLE_DEPTH];

        // For an empty tree, the sibling at depth i (for index 0) is levels[i]
        // because all leaves are zero, so the sibling subtree at each level is
        // the "all-zero" subtree of that depth.
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            emptySiblings[i] = levels[i];
        }

        // Deploy contracts
        token = new ERC20Mock();
        vm.prank(owner);
        adapter = new MockProofAdapter();

        vm.prank(owner);
        vault = new ZkApiVault(
            address(token),
            treasury,
            NOTE_TTL,
            REQUEST_CHARGE_CAP,
            POLICY_CHARGE_CAP,
            true, // policyEnabled
            address(adapter),
            owner
        );

        // Fund user with tokens and approve vault
        token.mint(user, 1000 ether);
        vm.prank(user);
        token.approve(address(vault), type(uint256).max);

        // Verify the vault's initial root matches our computed empty root
        assertEq(vault.currentRoot(), emptyRoot, "empty root mismatch");
    }

    // -----------------------------------------------------------------------
    //  Helpers: Merkle
    // -----------------------------------------------------------------------

    function _poseidonNodeHash(
        uint256 domain,
        uint256 left,
        uint256 right
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(domain, left, right))) % STARK_FIELD_PRIME;
    }

    function _computeLeaf(
        uint32 noteId,
        bytes32 commitment,
        uint128 depositAmount,
        uint64 expiryTs
    ) internal pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encodePacked(
                        DOMAIN_LEAF,
                        uint256(noteId),
                        uint256(commitment),
                        uint256(depositAmount),
                        uint256(expiryTs)
                    )
                )
            ) % STARK_FIELD_PRIME;
    }

    /// @dev Compute Merkle root from leaf, index, and siblings.
    function _computeRoot(
        uint32 index,
        uint256 leaf,
        uint256[32] memory siblings
    ) internal pure returns (uint256 root) {
        root = leaf;
        uint32 idx = index;
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            if (idx & 1 == 0) {
                root = _poseidonNodeHash(DOMAIN_NODE, root, siblings[i]);
            } else {
                root = _poseidonNodeHash(DOMAIN_NODE, siblings[i], root);
            }
            idx >>= 1;
        }
    }

    /// @dev Build the siblings array for inserting a leaf at `index` into a tree
    ///      that currently has `count` leaves (indices 0..count-1 are occupied).
    ///      For simplicity, the tests deposit notes sequentially starting at index 0.
    ///      This function computes the correct sibling path by tracking all leaves.
    ///
    ///      NOTE: This only works correctly for small note counts used in tests.
    ///      For index 0 in an empty tree, the siblings are just emptySiblings.
    function _siblingsForEmptySlot(uint32 /* index */) internal view returns (uint256[32] memory sibs) {
        // For index 0 in a pristine tree, siblings are the empty tree levels.
        // This is the only case we need for single-deposit tests.
        // For multi-deposit tests we track the root after each deposit.
        for (uint256 i = 0; i < MERKLE_DEPTH; i++) {
            sibs[i] = emptySiblings[i];
        }
    }

    /// @dev After inserting leaf `newLeaf` at `index` using `oldSiblings`,
    ///      compute the siblings needed for a subsequent operation on the SAME index
    ///      (e.g. removing a leaf). The siblings don't change for the same index,
    ///      only the root changes.
    ///
    ///      For the same index, siblings remain the same because we only changed
    ///      the leaf at that index, not any sibling subtree.
    function _siblingsAfterInsert(
        uint256[32] memory oldSiblings
    ) internal pure returns (uint256[32] memory) {
        // Siblings for a given index remain constant regardless of the leaf value
        // at that index. They only change if OTHER leaves in sibling subtrees change.
        return oldSiblings;
    }

    // -----------------------------------------------------------------------
    //  Helpers: Struct builders
    // -----------------------------------------------------------------------

    function _buildWithdrawalInputs(
        uint32 noteId,
        uint128 finalBalance,
        address dest,
        bool hasClearance,
        bool isGenesis
    ) internal view returns (Types.WithdrawalPublicInputs memory) {
        return
            Types.WithdrawalPublicInputs({
                statementType: 2,
                protocolVersion: 1,
                chainId: uint64(block.chainid),
                contractAddress: address(vault),
                activeRoot: vault.currentRoot(),
                noteId: noteId,
                finalBalance: finalBalance,
                destination: dest,
                withdrawalNullifier: uint256(keccak256(abi.encodePacked("nullifier", noteId, finalBalance))),
                isGenesis: isGenesis,
                hasClearance: hasClearance,
                stateSigEpoch: isGenesis ? 0 : uint32(1),
                stateSigRoot: isGenesis ? 0 : uint256(0xABCD),
                clearSigEpoch: hasClearance ? uint32(1) : uint32(0),
                clearSigRoot: hasClearance ? uint256(0x1234) : uint256(0)
            });
    }

    function _buildRequestInputs(
        uint256 requestNullifier
    ) internal view returns (Types.RequestPublicInputs memory) {
        return
            Types.RequestPublicInputs({
                statementType: 1,
                protocolVersion: 1,
                chainId: uint64(block.chainid),
                contractAddress: address(vault),
                activeRoot: vault.currentRoot(),
                stateSigEpoch: 0,
                stateSigRoot: 0,
                requestNullifier: requestNullifier,
                anonCommitmentX: 0,
                anonCommitmentY: 0,
                expiryTs: uint64(block.timestamp) + 3600,
                solvencyBound: 1 ether
            });
    }

    /// @dev Helper: deposit a note and return the siblings used (for later removal).
    function _depositNote(
        bytes32 commitment,
        uint128 amount
    ) internal returns (uint32 noteId, uint256[32] memory siblings, uint64 expiryTs) {
        noteId = vault.nextNoteId();
        siblings = _siblingsForEmptySlot(noteId);
        vm.prank(user);
        vault.deposit(commitment, amount, siblings);
        expiryTs = uint64(block.timestamp) + NOTE_TTL;
    }

    /// @dev Register epoch 1 with known state and clear sig roots.
    function _registerEpoch1() internal {
        vm.prank(owner);
        vault.rotateServerRoots(1, 0xABCD, 0x1234);
    }

    // -----------------------------------------------------------------------
    //  1. deposit creates an active note and updates the root
    // -----------------------------------------------------------------------

    function test_deposit_createsActiveNote() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;

        uint256 rootBefore = vault.currentRoot();
        assertEq(rootBefore, emptyRoot);

        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        vm.prank(user);
        vault.deposit(commitment, amount, siblings);

        // Note should be active
        (
            bytes32 noteCommitment,
            uint128 depositAmount,
            uint64 expiryTs,
            Types.NoteStatus status
        ) = vault.notes(0);
        assertEq(noteCommitment, commitment);
        assertEq(depositAmount, amount);
        assertEq(expiryTs, uint64(block.timestamp) + NOTE_TTL);
        assertEq(uint8(status), uint8(Types.NoteStatus.Active));

        // Root should have changed
        uint256 rootAfter = vault.currentRoot();
        assertTrue(rootAfter != emptyRoot, "root should change after deposit");

        // Verify root is correct
        uint256 expectedLeaf = _computeLeaf(0, commitment, amount, expiryTs);
        uint256 expectedRoot = _computeRoot(0, expectedLeaf, siblings);
        assertEq(rootAfter, expectedRoot, "root mismatch after deposit");

        // nextNoteId should be incremented
        assertEq(vault.nextNoteId(), 1);

        // Token should be transferred
        assertEq(token.balanceOf(address(vault)), amount);
    }

    function test_deposit_emitsEvent() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        uint64 expectedExpiry = uint64(block.timestamp) + NOTE_TTL;
        uint256 expectedLeaf = _computeLeaf(0, commitment, amount, expectedExpiry);
        uint256 expectedRoot = _computeRoot(0, expectedLeaf, siblings);

        vm.expectEmit(true, true, false, true);
        emit NoteDeposited(0, commitment, amount, expectedExpiry, expectedRoot);

        vm.prank(user);
        vault.deposit(commitment, amount, siblings);
    }

    // -----------------------------------------------------------------------
    //  2. mutualClose removes the leaf and settles correctly
    // -----------------------------------------------------------------------

    function test_mutualClose_settlesCorrectly() public {
        // Register epoch for signature validation
        _registerEpoch1();

        // Deposit
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        uint256 rootBeforeClose = vault.currentRoot();

        // Build withdrawal inputs with clearance
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 7 ether, destination, true, false
        );
        // Fix the root to match current
        inputs.activeRoot = rootBeforeClose;

        // Mutual close
        vault.mutualClose(inputs, "", siblings);

        // Note should be Closed
        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Closed));

        // Root should return to empty root (only note was removed)
        assertEq(vault.currentRoot(), emptyRoot, "root should return to empty after removing only leaf");

        // User gets finalBalance, treasury gets the rest
        assertEq(token.balanceOf(destination), 7 ether, "user should get finalBalance");
        assertEq(token.balanceOf(treasury), 3 ether, "treasury should get operator share");

        // Nullifier should be consumed
        assertTrue(vault.usedNullifiers(inputs.withdrawalNullifier));
    }

    function test_mutualClose_fullRefund() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 5 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        vault.mutualClose(inputs, "", siblings);

        // Full refund to user, nothing to treasury
        assertEq(token.balanceOf(destination), 5 ether);
        assertEq(token.balanceOf(treasury), 0);
    }

    function test_mutualClose_zeroRefund() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 5 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 0, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        vault.mutualClose(inputs, "", siblings);

        assertEq(token.balanceOf(destination), 0);
        assertEq(token.balanceOf(treasury), 5 ether);
    }

    // -----------------------------------------------------------------------
    //  3. escape-hatch initiation freezes the note immediately
    // -----------------------------------------------------------------------

    function test_escapeHatch_freezesNote() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        uint256 rootBeforeEscape = vault.currentRoot();

        // Build escape withdrawal inputs (no clearance, genesis)
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 6 ether, destination, false, true
        );
        inputs.activeRoot = rootBeforeEscape;

        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        // Note should be PendingWithdrawal
        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.PendingWithdrawal));

        // Leaf should be zeroed (root returns to empty root since it's the only note)
        assertEq(vault.currentRoot(), emptyRoot, "leaf should be zeroed");

        // Pending withdrawal data should exist
        (
            bool exists,
            uint256 nullifier,
            uint128 finalBalance,
            address dest,
            uint64 challengeDeadline
        ) = vault.pendingWithdrawals(noteId);
        assertTrue(exists);
        assertEq(nullifier, inputs.withdrawalNullifier);
        assertEq(finalBalance, 6 ether);
        assertEq(dest, destination);
        assertEq(challengeDeadline, uint64(block.timestamp) + CHALLENGE_PERIOD);

        // Nullifier should be consumed
        assertTrue(vault.usedNullifiers(inputs.withdrawalNullifier));

        // No tokens should have moved yet
        assertEq(token.balanceOf(address(vault)), amount);
    }

    // -----------------------------------------------------------------------
    //  4. challenge restores the leaf exactly
    // -----------------------------------------------------------------------

    function test_challenge_restoresLeaf() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        uint256 rootAfterDeposit = vault.currentRoot();

        // Initiate escape withdrawal
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 6 ether, destination, false, true
        );
        wInputs.activeRoot = rootAfterDeposit;

        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Root should now be emptyRoot (leaf zeroed)
        assertEq(vault.currentRoot(), emptyRoot);

        // Challenge: build request inputs with matching nullifier
        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();

        // The siblings for restoring at index 0 in an empty tree are emptySiblings
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);

        // Note should be restored to Active
        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Active));

        // Root should be restored to what it was after deposit
        assertEq(vault.currentRoot(), rootAfterDeposit, "root should be restored");

        // Pending withdrawal should be cleared
        (bool exists, , , , ) = vault.pendingWithdrawals(noteId);
        assertFalse(exists);

        // Nullifier should be un-consumed
        assertFalse(vault.usedNullifiers(wInputs.withdrawalNullifier));
    }

    // -----------------------------------------------------------------------
    //  5. finalize after deadline settles correctly
    // -----------------------------------------------------------------------

    function test_finalize_afterDeadline_settlesCorrectly() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 4 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        // Warp past challenge period
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Finalize
        vault.finalizeEscapeWithdrawal(noteId);

        // Note should be Closed
        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Closed));

        // Settlement: user gets 4 ether, treasury gets 6 ether
        assertEq(token.balanceOf(destination), 4 ether, "user gets finalBalance");
        assertEq(token.balanceOf(treasury), 6 ether, "treasury gets operator share");

        // Pending withdrawal data should be cleared
        (bool exists, , , , ) = vault.pendingWithdrawals(noteId);
        assertFalse(exists);
    }

    // -----------------------------------------------------------------------
    //  6. claimExpired transfers full deposit to treasury
    // -----------------------------------------------------------------------

    function test_claimExpired_transfersToTreasury() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, uint64 expiryTs) = _depositNote(commitment, amount);

        // Warp past expiry
        vm.warp(expiryTs);

        vault.claimExpired(noteId, siblings);

        // Note should be Closed
        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Closed));

        // Full deposit goes to treasury
        assertEq(token.balanceOf(treasury), amount, "full deposit to treasury");
        assertEq(token.balanceOf(address(vault)), 0, "vault should be empty");

        // Root should return to empty (only leaf was removed)
        assertEq(vault.currentRoot(), emptyRoot);
    }

    function test_claimExpired_revertsBeforeExpiry() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, uint64 expiryTs) = _depositNote(commitment, amount);

        // Time is before expiry
        vm.warp(expiryTs - 1);

        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(noteId, siblings);
    }

    // -----------------------------------------------------------------------
    //  7. invalid proof rejection (toggle MockProofAdapter's acceptAll)
    // -----------------------------------------------------------------------

    function test_invalidProof_mutualClose() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Disable acceptAll on the mock adapter
        vm.prank(owner);
        adapter.setAcceptAll(false);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        // Should revert with InvalidProof because envelope doesn't match
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_invalidProof_initiateEscape() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        vm.prank(owner);
        adapter.setAcceptAll(false);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.InvalidProof.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    function test_invalidProof_challengeEscape() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape (adapter still accepts all)
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Now disable adapter
        vm.prank(owner);
        adapter.setAcceptAll(false);

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();

        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    // -----------------------------------------------------------------------
    //  8. double finalize rejection
    // -----------------------------------------------------------------------

    function test_doubleFinalize_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 4 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        // Warp past deadline and finalize once
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        vault.finalizeEscapeWithdrawal(noteId);

        // Second finalize should revert (note is now Closed, not PendingWithdrawal)
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(noteId);
    }

    // -----------------------------------------------------------------------
    //  9. challenge after deadline rejection
    // -----------------------------------------------------------------------

    function test_challengeAfterDeadline_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Warp to exactly the deadline (>= means expired)
        (, , , , uint64 challengeDeadline) = vault.pendingWithdrawals(noteId);
        vm.warp(challengeDeadline);

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    function test_challengeAfterDeadline_pastDeadline_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Warp well past deadline
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1 hours);

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    // -----------------------------------------------------------------------
    //  10. root mismatch rejection
    // -----------------------------------------------------------------------

    function test_rootMismatch_mutualClose() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        // Set a stale/wrong root
        inputs.activeRoot = emptyRoot;

        vm.expectRevert(Errors.StaleRoot.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_rootMismatch_initiateEscape() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        // Set wrong root
        inputs.activeRoot = 12345;

        vm.expectRevert(Errors.StaleRoot.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    // -----------------------------------------------------------------------
    //  11. zero amount deposit rejection
    // -----------------------------------------------------------------------

    function test_zeroDeposit_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        vm.prank(user);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.deposit(commitment, 0, siblings);
    }

    function test_zeroCommitment_reverts() public {
        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        vm.prank(user);
        vm.expectRevert(Errors.InvalidCommitment.selector);
        vault.deposit(bytes32(0), 10 ether, siblings);
    }

    function test_commitmentAboveFieldPrime_reverts() public {
        uint256[32] memory siblings = _siblingsForEmptySlot(0);
        // Value >= STARK_FIELD_PRIME
        bytes32 bigCommitment = bytes32(STARK_FIELD_PRIME);

        vm.prank(user);
        vm.expectRevert(Errors.InvalidFelt.selector);
        vault.deposit(bigCommitment, 10 ether, siblings);
    }

    // -----------------------------------------------------------------------
    //  12. epoch management (rotateServerRoots)
    // -----------------------------------------------------------------------

    function test_rotateServerRoots_basic() public {
        vm.prank(owner);
        vault.rotateServerRoots(1, 0xAAAA, 0xBBBB);

        assertEq(vault.currentEpoch(), 1);
        assertEq(vault.stateSigRootByEpoch(1), 0xAAAA);
        assertEq(vault.clearSigRootByEpoch(1), 0xBBBB);
    }

    function test_rotateServerRoots_monotonic() public {
        vm.prank(owner);
        vault.rotateServerRoots(1, 0xAAAA, 0xBBBB);

        vm.prank(owner);
        vault.rotateServerRoots(5, 0xCCCC, 0xDDDD);

        assertEq(vault.currentEpoch(), 5);
        assertEq(vault.stateSigRootByEpoch(5), 0xCCCC);
        assertEq(vault.clearSigRootByEpoch(5), 0xDDDD);

        // Old epoch still stored
        assertEq(vault.stateSigRootByEpoch(1), 0xAAAA);
    }

    function test_rotateServerRoots_nonMonotonic_reverts() public {
        vm.prank(owner);
        vault.rotateServerRoots(5, 0xAAAA, 0xBBBB);

        // Epoch 3 < 5 should fail
        vm.prank(owner);
        vm.expectRevert(Errors.EpochNotFound.selector);
        vault.rotateServerRoots(3, 0xCCCC, 0xDDDD);
    }

    function test_rotateServerRoots_sameEpoch_reverts() public {
        vm.prank(owner);
        vault.rotateServerRoots(1, 0xAAAA, 0xBBBB);

        // Same epoch should fail
        vm.prank(owner);
        vm.expectRevert(Errors.EpochNotFound.selector);
        vault.rotateServerRoots(1, 0xCCCC, 0xDDDD);
    }

    function test_rotateServerRoots_epochZero_reverts() public {
        // epoch 0 with currentEpoch 0 should fail
        vm.prank(owner);
        vm.expectRevert(Errors.EpochNotFound.selector);
        vault.rotateServerRoots(0, 0xAAAA, 0xBBBB);
    }

    function test_rotateServerRoots_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vault.rotateServerRoots(1, 0xAAAA, 0xBBBB);
    }

    function test_rotateServerRoots_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit ServerRootsRotated(1, 0xAAAA, 0xBBBB);

        vm.prank(owner);
        vault.rotateServerRoots(1, 0xAAAA, 0xBBBB);
    }

    // -----------------------------------------------------------------------
    //  Additional edge cases and access control
    // -----------------------------------------------------------------------

    function test_mutualClose_noClearance_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Build inputs without clearance but call mutualClose
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.InvalidStatementType.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_escape_withClearance_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Build inputs with clearance but call initiateEscapeWithdrawal
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.InvalidStatementType.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    function test_mutualClose_wrongStatementType_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();
        inputs.statementType = 1; // wrong type

        vm.expectRevert(Errors.InvalidStatementType.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_mutualClose_replayedNullifier_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        // First close should succeed
        vault.mutualClose(inputs, "", siblings);

        // Second close should revert - root changed after first close zeroed the leaf
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_mutualClose_invalidBalance_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 11 ether, destination, true, false // finalBalance > depositAmount
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.InvalidBalance.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_mutualClose_invalidEpoch_reverts() public {
        // Do NOT register any epoch

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        // State sig epoch 1 not registered
        vm.expectRevert(Errors.EpochNotFound.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_finalize_beforeDeadline_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 4 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        // Don't warp - still within challenge period
        vm.expectRevert(Errors.ChallengeNotExpired.selector);
        vault.finalizeEscapeWithdrawal(noteId);
    }

    function test_finalize_nonPendingNote_reverts() public {
        // Try to finalize a note that was never initiated for escape
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        _depositNote(commitment, amount);

        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
    }

    function test_claimExpired_closedNote_reverts() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Close the note first via mutual close
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, amount, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();
        vault.mutualClose(inputs, "", siblings);

        // Try to claim expired on a closed note
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.claimExpired(noteId, siblings);
    }

    // -----------------------------------------------------------------------
    //  Pause tests
    // -----------------------------------------------------------------------

    function test_pause_blocksDeposit() public {
        vm.prank(owner);
        vault.pause();

        bytes32 commitment = bytes32(uint256(42));
        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        vm.prank(user);
        vm.expectRevert(Errors.Paused.selector);
        vault.deposit(commitment, 10 ether, siblings);
    }

    function test_pause_blocksMutualClose() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        vm.prank(owner);
        vault.pause();

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, true, false
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.Paused.selector);
        vault.mutualClose(inputs, "", siblings);
    }

    function test_unpause_allowsDeposit() public {
        vm.prank(owner);
        vault.pause();

        vm.prank(owner);
        vault.unpause();

        bytes32 commitment = bytes32(uint256(42));
        uint256[32] memory siblings = _siblingsForEmptySlot(0);

        vm.prank(user);
        vault.deposit(commitment, 10 ether, siblings);

        assertEq(vault.nextNoteId(), 1);
    }

    // -----------------------------------------------------------------------
    //  Admin tests
    // -----------------------------------------------------------------------

    function test_setProofAdapter() public {
        address newAdapter = address(0xFF);
        vm.prank(owner);
        vault.setProofAdapter(newAdapter);
        assertEq(vault.proofAdapter(), newAdapter);
    }

    function test_setProofAdapter_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vault.setProofAdapter(address(0xFF));
    }

    function test_setTreasury() public {
        address newTreasury = address(0xEE);
        vm.prank(owner);
        vault.setTreasury(newTreasury);
        assertEq(vault.treasury(), newTreasury);
    }

    function test_setTreasury_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vault.setTreasury(address(0xEE));
    }

    // -----------------------------------------------------------------------
    //  Challenge: wrong statement type
    // -----------------------------------------------------------------------

    function test_challenge_wrongStatementType_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Challenge with wrong statement type
        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        rInputs.statementType = 2; // wrong, should be 1

        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.InvalidStatementType.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    // -----------------------------------------------------------------------
    //  Challenge: wrong nullifier
    // -----------------------------------------------------------------------

    function test_challenge_wrongNullifier_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Challenge with wrong nullifier
        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(999); // mismatched nullifier
        rInputs.activeRoot = vault.currentRoot();

        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    // -----------------------------------------------------------------------
    //  Challenge: note not pending
    // -----------------------------------------------------------------------

    function test_challenge_noteNotPending_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        _depositNote(commitment, amount);

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(123);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(0);

        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.challengeEscapeWithdrawal(0, rInputs, "", restoreSiblings);
    }

    // -----------------------------------------------------------------------
    //  Escape-hatch: genesis withdrawal (no epoch needed)
    // -----------------------------------------------------------------------

    function test_escape_genesis_noEpochNeeded() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, amount, destination, false, true // isGenesis = true
        );
        inputs.activeRoot = vault.currentRoot();

        // Should succeed without any epoch registered
        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.PendingWithdrawal));
    }

    // -----------------------------------------------------------------------
    //  Escape-hatch: non-genesis needs epoch
    // -----------------------------------------------------------------------

    function test_escape_nonGenesis_needsEpoch() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, amount, destination, false, false // isGenesis = false, no clearance
        );
        inputs.activeRoot = vault.currentRoot();
        // stateSigEpoch = 1, but no epoch registered

        vm.expectRevert(Errors.EpochNotFound.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    // -----------------------------------------------------------------------
    //  Immutables and constructor
    // -----------------------------------------------------------------------

    function test_constructorParams() public view {
        assertEq(address(vault.billingToken()), address(token));
        assertEq(vault.treasury(), treasury);
        assertEq(vault.noteTtl(), NOTE_TTL);
        assertEq(vault.requestChargeCap(), REQUEST_CHARGE_CAP);
        assertEq(vault.policyChargeCap(), POLICY_CHARGE_CAP);
        assertTrue(vault.policyEnabled());
        assertEq(vault.proofAdapter(), address(adapter));
        assertEq(vault.owner(), owner);
        assertEq(vault.PROTOCOL_VERSION(), 1);
        assertEq(vault.CHALLENGE_PERIOD(), CHALLENGE_PERIOD);
        assertEq(vault.MERKLE_DEPTH(), 32);
    }

    // -----------------------------------------------------------------------
    //  Merkle: bad siblings cause StaleRoot
    // -----------------------------------------------------------------------

    function test_deposit_badSiblings_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint256[32] memory badSiblings;
        // Fill with junk data that won't match the empty tree
        for (uint256 i = 0; i < 32; i++) {
            badSiblings[i] = uint256(keccak256(abi.encodePacked("junk", i)));
        }

        vm.prank(user);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.deposit(commitment, 10 ether, badSiblings);
    }

    // -----------------------------------------------------------------------
    //  Full lifecycle: deposit -> escape -> challenge -> mutualClose
    // -----------------------------------------------------------------------

    function test_fullLifecycle_escapeChallengeThenMutualClose() public {
        _registerEpoch1();

        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        uint256 rootAfterDeposit = vault.currentRoot();

        // Step 1: Initiate escape withdrawal
        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 3 ether, destination, false, true
        );
        wInputs.activeRoot = rootAfterDeposit;
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        // Step 2: Challenge it (restores the leaf)
        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);

        // Root should be back to rootAfterDeposit
        assertEq(vault.currentRoot(), rootAfterDeposit);

        // Step 3: Now do a mutual close
        Types.WithdrawalPublicInputs memory mcInputs = _buildWithdrawalInputs(
            noteId, 7 ether, destination, true, false
        );
        mcInputs.activeRoot = vault.currentRoot();
        // Need a different nullifier since the old one was un-consumed
        mcInputs.withdrawalNullifier = uint256(keccak256(abi.encodePacked("nullifier2", noteId)));

        vault.mutualClose(mcInputs, "", siblings);

        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Closed));

        assertEq(token.balanceOf(destination), 7 ether);
        assertEq(token.balanceOf(treasury), 3 ether);
    }

    // -----------------------------------------------------------------------
    //  Full lifecycle: deposit -> escape -> finalize
    // -----------------------------------------------------------------------

    function test_fullLifecycle_escapeAndFinalize() public {
        bytes32 commitment = bytes32(uint256(99));
        uint128 amount = 20 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        // Initiate escape withdrawal
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 12 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        // Warp to just past deadline
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        // Finalize
        vault.finalizeEscapeWithdrawal(noteId);

        assertEq(token.balanceOf(destination), 12 ether);
        assertEq(token.balanceOf(treasury), 8 ether);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    // -----------------------------------------------------------------------
    //  Finalize at exact deadline boundary
    // -----------------------------------------------------------------------

    function test_finalize_atExactDeadline_succeeds() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        (, , , , uint64 challengeDeadline) = vault.pendingWithdrawals(noteId);

        // Warp to exactly the deadline - finalize uses `<` so at deadline it should succeed
        vm.warp(challengeDeadline);

        vault.finalizeEscapeWithdrawal(noteId);

        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Closed));
    }

    // -----------------------------------------------------------------------
    //  Challenge just before deadline (within period)
    // -----------------------------------------------------------------------

    function test_challenge_justBeforeDeadline_succeeds() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        uint256 rootAfterDeposit = vault.currentRoot();

        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = rootAfterDeposit;
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        (, , , , uint64 challengeDeadline) = vault.pendingWithdrawals(noteId);

        // Warp to 1 second before deadline
        vm.warp(challengeDeadline - 1);

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);

        (, , , Types.NoteStatus status) = vault.notes(noteId);
        assertEq(uint8(status), uint8(Types.NoteStatus.Active));
        assertEq(vault.currentRoot(), rootAfterDeposit);
    }

    // -----------------------------------------------------------------------
    //  Escape: invalid balance (finalBalance > depositAmount)
    // -----------------------------------------------------------------------

    function test_escape_invalidBalance_reverts() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 11 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.InvalidBalance.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    // -----------------------------------------------------------------------
    //  Escape: replayed nullifier
    // -----------------------------------------------------------------------

    function test_escape_replayedNullifier_reverts() public {
        bytes32 commitment1 = bytes32(uint256(42));
        bytes32 commitment2 = bytes32(uint256(43));
        uint128 amount = 10 ether;

        // Deposit note 0
        (uint32 noteId0, uint256[32] memory siblings0, ) = _depositNote(commitment1, amount);

        // Initiate escape on note 0
        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId0, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(inputs, "", siblings0);

        // Finalize note 0
        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);
        vault.finalizeEscapeWithdrawal(noteId0);

        // Deposit note 1
        // After note 0 was zeroed out and note 1 is at index 1, we need correct siblings.
        // Since note 0 leaf is zeroed, siblings for index 1 need the zero-value at level 0 as sibling[0],
        // and the rest are empty tree levels.
        uint256[32] memory siblings1;
        siblings1[0] = 0; // sibling at level 0 is the leaf at index 0, which is now zero
        for (uint256 i = 1; i < MERKLE_DEPTH; i++) {
            siblings1[i] = emptySiblings[i];
        }

        vm.prank(user);
        vault.deposit(commitment2, amount, siblings1);

        // Try to use the same nullifier for note 1
        Types.WithdrawalPublicInputs memory inputs2 = _buildWithdrawalInputs(
            1, 5 ether, destination, false, true
        );
        inputs2.activeRoot = vault.currentRoot();
        inputs2.withdrawalNullifier = inputs.withdrawalNullifier; // reuse nullifier

        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.initiateEscapeWithdrawal(inputs2, "", siblings1);
    }

    // -----------------------------------------------------------------------
    //  Pause: blocks escape, challenge, finalize, claimExpired
    // -----------------------------------------------------------------------

    function test_pause_blocksEscapeInit() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        vm.prank(owner);
        vault.pause();

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();

        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(inputs, "", siblings);
    }

    function test_pause_blocksFinalize() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory inputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        inputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(inputs, "", siblings);

        vm.prank(owner);
        vault.pause();

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        vm.expectRevert(Errors.Paused.selector);
        vault.finalizeEscapeWithdrawal(noteId);
    }

    function test_pause_blocksClaimExpired() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, uint64 expiryTs) = _depositNote(commitment, amount);

        vm.prank(owner);
        vault.pause();

        vm.warp(expiryTs);

        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(noteId, siblings);
    }

    function test_pause_blocksChallenge() public {
        bytes32 commitment = bytes32(uint256(42));
        uint128 amount = 10 ether;
        (uint32 noteId, uint256[32] memory siblings, ) = _depositNote(commitment, amount);

        Types.WithdrawalPublicInputs memory wInputs = _buildWithdrawalInputs(
            noteId, 5 ether, destination, false, true
        );
        wInputs.activeRoot = vault.currentRoot();
        vault.initiateEscapeWithdrawal(wInputs, "", siblings);

        vm.prank(owner);
        vault.pause();

        Types.RequestPublicInputs memory rInputs = _buildRequestInputs(wInputs.withdrawalNullifier);
        rInputs.activeRoot = vault.currentRoot();
        uint256[32] memory restoreSiblings = _siblingsForEmptySlot(noteId);

        vm.expectRevert(Errors.Paused.selector);
        vault.challengeEscapeWithdrawal(noteId, rInputs, "", restoreSiblings);
    }

    function test_pause_onlyOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vault.pause();
    }

    function test_unpause_onlyOwner() public {
        vm.prank(owner);
        vault.pause();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vault.unpause();
    }
}
