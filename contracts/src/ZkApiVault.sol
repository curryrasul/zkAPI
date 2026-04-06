// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {Events} from "./libraries/Events.sol";
import {MerkleUpdateLib} from "./libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "./libraries/NoteLeafLib.sol";
import {IZkApiProofAdapter} from "./interfaces/IZkApiProofAdapter.sol";

/// @title ZkApiVault – On-chain settlement contract for zkAPI v1
/// @notice Manages note deposits, mutual closes, escape-hatch withdrawals,
///         challenges, expiry claims, and server signing-root epochs.
contract ZkApiVault is ReentrancyGuard, Ownable, Events {
    using SafeERC20 for IERC20;

    // -----------------------------------------------------------------------
    //  Constants
    // -----------------------------------------------------------------------

    /// @notice Protocol version pinned for this deployment.
    uint16 public constant PROTOCOL_VERSION = 1;

    /// @notice Challenge period for escape-hatch withdrawals.
    uint64 public constant CHALLENGE_PERIOD = 24 hours;

    /// @notice Merkle tree depth (mirrored from MerkleUpdateLib for convenience).
    uint256 public constant MERKLE_DEPTH = 32;

    // -----------------------------------------------------------------------
    //  Immutable deployment parameters
    // -----------------------------------------------------------------------

    /// @notice The ERC20 token used for billing.
    IERC20 public immutable billingToken;

    /// @notice Time-to-live for notes, in seconds, added to block.timestamp at deposit.
    uint64 public immutable noteTtl;

    /// @notice Maximum per-request charge (informational, enforced in Cairo).
    uint128 public immutable requestChargeCap;

    /// @notice Maximum per-policy charge (informational, enforced in Cairo).
    uint128 public immutable policyChargeCap;

    /// @notice Whether policy-based charges are enabled.
    bool public immutable policyEnabled;

    // -----------------------------------------------------------------------
    //  Configurable state (owner-controlled)
    // -----------------------------------------------------------------------

    /// @notice Address of the proof-verification adapter.
    address public proofAdapter;

    /// @notice Address that receives the operator's share of closed notes.
    address public treasury;

    /// @notice Emergency pause flag.
    bool public paused;

    // -----------------------------------------------------------------------
    //  Merkle & note state
    // -----------------------------------------------------------------------

    /// @notice Current Merkle root of the active-note tree.
    uint256 public currentRoot;

    /// @notice Next note index to allocate on deposit.
    uint32 public nextNoteId;

    /// @notice Note metadata by noteId.
    mapping(uint32 => Types.Note) public notes;

    /// @notice Pending escape-hatch withdrawal data by noteId.
    mapping(uint32 => Types.PendingWithdrawalData) public pendingWithdrawals;

    // -----------------------------------------------------------------------
    //  XMSS epoch state
    // -----------------------------------------------------------------------

    /// @notice The latest published epoch number.
    uint32 public currentEpoch;

    /// @notice State-signature XMSS root by epoch.
    mapping(uint32 => uint256) public stateSigRootByEpoch;

    /// @notice Clearance-signature XMSS root by epoch.
    mapping(uint32 => uint256) public clearSigRootByEpoch;

    // -----------------------------------------------------------------------
    //  Nullifier set
    // -----------------------------------------------------------------------

    /// @notice Tracks consumed nullifiers to prevent replay.
    mapping(uint256 => bool) public usedNullifiers;

    // -----------------------------------------------------------------------
    //  Modifiers
    // -----------------------------------------------------------------------

    modifier whenNotPaused() {
        if (paused) revert Errors.Paused();
        _;
    }

    // -----------------------------------------------------------------------
    //  Constructor
    // -----------------------------------------------------------------------

    /// @param _billingToken    ERC20 token for note deposits.
    /// @param _treasury        Initial treasury address.
    /// @param _noteTtl         Note time-to-live in seconds.
    /// @param _requestChargeCap  Maximum per-request charge.
    /// @param _policyChargeCap   Maximum per-policy charge.
    /// @param _policyEnabled     Whether policy charges are active.
    /// @param _proofAdapter      Initial proof adapter address.
    /// @param _owner             Contract owner (for Ownable).
    constructor(
        address _billingToken,
        address _treasury,
        uint64 _noteTtl,
        uint128 _requestChargeCap,
        uint128 _policyChargeCap,
        bool _policyEnabled,
        address _proofAdapter,
        address _owner
    ) Ownable(_owner) {
        billingToken = IERC20(_billingToken);
        treasury = _treasury;
        noteTtl = _noteTtl;
        requestChargeCap = _requestChargeCap;
        policyChargeCap = _policyChargeCap;
        policyEnabled = _policyEnabled;
        proofAdapter = _proofAdapter;

        // The initial root is the root of an all-zero tree.
        // For a tree of depth 32 with zero leaves, the root is computed
        // iteratively: level 0 = 0, level i+1 = H(level_i, level_i).
        currentRoot = _computeEmptyTreeRoot();
    }

    // -----------------------------------------------------------------------
    //  Deposit
    // -----------------------------------------------------------------------

    /// @notice Deposit tokens and create a new note.
    /// @param commitment  Registration commitment C (must be < STARK_FIELD_PRIME and != 0).
    /// @param amount      Deposit amount in token base units (must be > 0).
    /// @param siblings    Merkle sibling path for the new note's leaf slot.
    function deposit(
        bytes32 commitment,
        uint128 amount,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert Errors.ZeroAmount();
        if (commitment == bytes32(0)) revert Errors.InvalidCommitment();
        if (uint256(commitment) >= MerkleUpdateLib.STARK_FIELD_PRIME) revert Errors.InvalidFelt();

        uint32 noteId = nextNoteId;
        uint64 expiryTs = uint64(block.timestamp) + noteTtl;

        // Compute the new leaf.
        uint256 newLeaf = NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);

        // Verify current root has zero leaf at noteId, then compute new root.
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(
            currentRoot,
            noteId,
            0, // old leaf is zero (empty slot)
            newLeaf,
            siblings
        );

        // Effects
        currentRoot = newRoot;
        notes[noteId] = Types.Note({
            commitment: commitment,
            depositAmount: amount,
            expiryTs: expiryTs,
            status: Types.NoteStatus.Active
        });
        nextNoteId = noteId + 1;

        // Interactions
        billingToken.safeTransferFrom(msg.sender, address(this), uint256(amount));

        emit NoteDeposited(noteId, commitment, amount, expiryTs, newRoot);
    }

    // -----------------------------------------------------------------------
    //  Mutual Close
    // -----------------------------------------------------------------------

    /// @notice Close a note cooperatively with server clearance.
    /// @param inputs        Withdrawal proof public inputs.
    /// @param proofEnvelope Proof data for the adapter.
    /// @param siblings      Merkle sibling path.
    function mutualClose(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proofEnvelope,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        // Verify proof via adapter
        IZkApiProofAdapter(proofAdapter).assertValidWithdrawal(inputs, proofEnvelope);

        // Validate statement type
        if (inputs.statementType != 2) revert Errors.InvalidStatementType();

        // Must have clearance for mutual close
        if (!inputs.hasClearance) revert Errors.InvalidStatementType();

        // Root freshness
        if (inputs.activeRoot != currentRoot) revert Errors.StaleRoot();

        uint32 noteId = inputs.noteId;
        Types.Note storage note = notes[noteId];

        // Note must be active
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();

        // Validate server signature roots
        _validateStateSigRoot(inputs.isGenesis, inputs.stateSigEpoch, inputs.stateSigRoot);
        _validateClearSigRoot(inputs.clearSigEpoch, inputs.clearSigRoot);

        // Balance check
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();

        // Nullifier replay check
        if (usedNullifiers[inputs.withdrawalNullifier]) revert Errors.ReplayedNullifier();
        usedNullifiers[inputs.withdrawalNullifier] = true;

        // Compute the old leaf and zero it out
        uint256 oldLeaf = NoteLeafLib.computeLeaf(
            noteId,
            note.commitment,
            note.depositAmount,
            note.expiryTs
        );
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(
            currentRoot,
            noteId,
            oldLeaf,
            0, // zero out the leaf
            siblings
        );

        // Effects
        currentRoot = newRoot;
        note.status = Types.NoteStatus.Closed;

        // Interactions: pay user then treasury
        uint128 finalBalance = inputs.finalBalance;
        address destination = inputs.destination;
        uint128 operatorShare = note.depositAmount - finalBalance;

        if (finalBalance > 0) {
            billingToken.safeTransfer(destination, uint256(finalBalance));
        }
        if (operatorShare > 0) {
            billingToken.safeTransfer(treasury, uint256(operatorShare));
        }

        emit MutualClose(noteId, inputs.withdrawalNullifier, finalBalance, destination);
    }

    // -----------------------------------------------------------------------
    //  Escape-Hatch Withdrawal: Initiate
    // -----------------------------------------------------------------------

    /// @notice Begin an escape-hatch withdrawal (no server clearance).
    /// @param inputs        Withdrawal proof public inputs.
    /// @param proofEnvelope Proof data for the adapter.
    /// @param siblings      Merkle sibling path.
    function initiateEscapeWithdrawal(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proofEnvelope,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        // Verify proof via adapter
        IZkApiProofAdapter(proofAdapter).assertValidWithdrawal(inputs, proofEnvelope);

        // Validate statement type
        if (inputs.statementType != 2) revert Errors.InvalidStatementType();

        // Escape hatch: no clearance
        if (inputs.hasClearance) revert Errors.InvalidStatementType();

        // Root freshness
        if (inputs.activeRoot != currentRoot) revert Errors.StaleRoot();

        uint32 noteId = inputs.noteId;
        Types.Note storage note = notes[noteId];

        // Note must be active
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();

        // Validate state signature root (clearance not needed for escape)
        _validateStateSigRoot(inputs.isGenesis, inputs.stateSigEpoch, inputs.stateSigRoot);

        // Balance check
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();

        // Nullifier replay check
        if (usedNullifiers[inputs.withdrawalNullifier]) revert Errors.ReplayedNullifier();
        usedNullifiers[inputs.withdrawalNullifier] = true;

        // Compute old leaf and zero it immediately to freeze the note
        uint256 oldLeaf = NoteLeafLib.computeLeaf(
            noteId,
            note.commitment,
            note.depositAmount,
            note.expiryTs
        );
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(
            currentRoot,
            noteId,
            oldLeaf,
            0,
            siblings
        );

        uint64 challengeDeadline = uint64(block.timestamp) + CHALLENGE_PERIOD;

        // Effects
        currentRoot = newRoot;
        note.status = Types.NoteStatus.PendingWithdrawal;
        pendingWithdrawals[noteId] = Types.PendingWithdrawalData({
            exists: true,
            withdrawalNullifier: inputs.withdrawalNullifier,
            finalBalance: inputs.finalBalance,
            destination: inputs.destination,
            challengeDeadline: challengeDeadline
        });

        emit EscapeWithdrawalInitiated(
            noteId,
            inputs.withdrawalNullifier,
            inputs.finalBalance,
            inputs.destination,
            challengeDeadline,
            newRoot
        );
    }

    // -----------------------------------------------------------------------
    //  Escape-Hatch Withdrawal: Challenge
    // -----------------------------------------------------------------------

    /// @notice Challenge an escape-hatch withdrawal by presenting a more recent
    ///         request proof whose nullifier matches the pending withdrawal.
    /// @param noteId        The note under pending withdrawal.
    /// @param inputs        Request proof public inputs.
    /// @param proofEnvelope Proof data for the adapter.
    /// @param siblings      Merkle sibling path to restore the original leaf.
    function challengeEscapeWithdrawal(
        uint32 noteId,
        Types.RequestPublicInputs calldata inputs,
        bytes calldata proofEnvelope,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];

        // Note must be pending withdrawal
        if (note.status != Types.NoteStatus.PendingWithdrawal) revert Errors.NotPendingWithdrawal();

        // Must be within challenge period
        if (block.timestamp >= pending.challengeDeadline) revert Errors.ChallengeExpired();

        // Verify request proof via adapter
        IZkApiProofAdapter(proofAdapter).assertValidRequest(inputs, proofEnvelope);

        // Validate statement type
        if (inputs.statementType != 1) revert Errors.InvalidStatementType();

        // Validate state signature root
        // For request proofs, stateSigEpoch == 0 && stateSigRoot == 0 is the genesis encoding
        if (inputs.stateSigEpoch != 0) {
            uint256 storedRoot = stateSigRootByEpoch[inputs.stateSigEpoch];
            if (storedRoot == 0) revert Errors.EpochNotFound();
            if (storedRoot != inputs.stateSigRoot) revert Errors.EpochNotFound();
        }

        // The request nullifier must match the pending withdrawal nullifier
        if (inputs.requestNullifier != pending.withdrawalNullifier) revert Errors.ReplayedNullifier();

        // The current root should have zero at the note leaf (it was zeroed during initiation).
        // Restore the original leaf.
        uint256 originalLeaf = NoteLeafLib.computeLeaf(
            noteId,
            note.commitment,
            note.depositAmount,
            note.expiryTs
        );
        uint256 restoredRoot = MerkleUpdateLib.verifyAndUpdate(
            currentRoot,
            noteId,
            0, // currently zero
            originalLeaf,
            siblings
        );

        // Effects
        currentRoot = restoredRoot;
        note.status = Types.NoteStatus.Active;

        // Clear pending withdrawal data
        uint256 nullifier = pending.withdrawalNullifier;
        delete pendingWithdrawals[noteId];

        // Un-consume the nullifier so the user can attempt a proper withdrawal later
        usedNullifiers[nullifier] = false;

        emit EscapeWithdrawalChallenged(noteId, nullifier, restoredRoot);
    }

    // -----------------------------------------------------------------------
    //  Escape-Hatch Withdrawal: Finalize
    // -----------------------------------------------------------------------

    /// @notice Finalize an escape-hatch withdrawal after the challenge period.
    /// @param noteId The note to finalize.
    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant whenNotPaused {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];

        // Note must be pending withdrawal
        if (note.status != Types.NoteStatus.PendingWithdrawal) revert Errors.NotPendingWithdrawal();

        // Challenge period must have elapsed
        if (block.timestamp < pending.challengeDeadline) revert Errors.ChallengeNotExpired();

        // Cache before clearing
        uint256 nullifier = pending.withdrawalNullifier;
        uint128 finalBalance = pending.finalBalance;
        address destination = pending.destination;
        uint128 operatorShare = note.depositAmount - finalBalance;

        // Effects
        note.status = Types.NoteStatus.Closed;
        delete pendingWithdrawals[noteId];

        // Interactions: pay user then treasury (same as mutual close)
        if (finalBalance > 0) {
            billingToken.safeTransfer(destination, uint256(finalBalance));
        }
        if (operatorShare > 0) {
            billingToken.safeTransfer(treasury, uint256(operatorShare));
        }

        emit EscapeWithdrawalFinalized(noteId, nullifier, finalBalance, destination);
    }

    // -----------------------------------------------------------------------
    //  Claim Expired
    // -----------------------------------------------------------------------

    /// @notice Claim an expired note's deposit for the treasury.
    /// @param noteId   The expired note.
    /// @param siblings Merkle sibling path.
    function claimExpired(
        uint32 noteId,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        Types.Note storage note = notes[noteId];

        // Note must be active
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();

        // Must be past expiry
        if (block.timestamp < note.expiryTs) revert Errors.NoteNotExpired();

        // Zero the leaf
        uint256 oldLeaf = NoteLeafLib.computeLeaf(
            noteId,
            note.commitment,
            note.depositAmount,
            note.expiryTs
        );
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(
            currentRoot,
            noteId,
            oldLeaf,
            0,
            siblings
        );

        uint128 depositAmount = note.depositAmount;

        // Effects
        currentRoot = newRoot;
        note.status = Types.NoteStatus.Closed;

        // Interactions: full deposit goes to treasury
        billingToken.safeTransfer(treasury, uint256(depositAmount));

        emit ExpiredClaimed(noteId, depositAmount, newRoot);
    }

    // -----------------------------------------------------------------------
    //  Admin: Proof Adapter
    // -----------------------------------------------------------------------

    /// @notice Set the proof adapter contract address.
    /// @param newAdapter The new adapter address.
    function setProofAdapter(address newAdapter) external onlyOwner {
        proofAdapter = newAdapter;
        emit ProofAdapterSet(newAdapter);
    }

    // -----------------------------------------------------------------------
    //  Admin: Treasury
    // -----------------------------------------------------------------------

    /// @notice Set the treasury address.
    /// @param newTreasury The new treasury address.
    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    // -----------------------------------------------------------------------
    //  Admin: Server Signing Roots
    // -----------------------------------------------------------------------

    /// @notice Publish a new XMSS epoch with state and clearance roots.
    /// @dev Epoch numbers must increase strictly monotonically.
    /// @param epoch     The new epoch number.
    /// @param stateRoot The state-signature XMSS root for this epoch.
    /// @param clearRoot The clearance-signature XMSS root for this epoch.
    function rotateServerRoots(
        uint32 epoch,
        uint256 stateRoot,
        uint256 clearRoot
    ) external onlyOwner {
        // Epoch must be strictly greater than the current epoch
        // (also prevents re-registration of an existing epoch)
        if (epoch <= currentEpoch && currentEpoch != 0) revert Errors.EpochNotFound();
        // For the very first epoch, allow epoch > 0
        if (currentEpoch == 0 && epoch == 0) revert Errors.EpochNotFound();

        // Prevent overwriting an already-registered epoch
        if (stateSigRootByEpoch[epoch] != 0) revert Errors.EpochNotFound();

        currentEpoch = epoch;
        stateSigRootByEpoch[epoch] = stateRoot;
        clearSigRootByEpoch[epoch] = clearRoot;

        emit ServerRootsRotated(epoch, stateRoot, clearRoot);
    }

    // -----------------------------------------------------------------------
    //  Admin: Pause
    // -----------------------------------------------------------------------

    /// @notice Pause the contract (blocks deposits and withdrawals).
    function pause() external onlyOwner {
        paused = true;
    }

    /// @notice Unpause the contract.
    function unpause() external onlyOwner {
        paused = false;
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// @dev Validate the state-signature root for a withdrawal or request.
    ///      When isGenesis is true, epoch and root checks are skipped.
    function _validateStateSigRoot(
        bool isGenesis,
        uint32 epoch,
        uint256 root
    ) internal view {
        if (isGenesis) return;
        uint256 storedRoot = stateSigRootByEpoch[epoch];
        if (storedRoot == 0) revert Errors.EpochNotFound();
        if (storedRoot != root) revert Errors.EpochNotFound();
    }

    /// @dev Validate the clearance-signature root for a mutual close.
    function _validateClearSigRoot(uint32 epoch, uint256 root) internal view {
        uint256 storedRoot = clearSigRootByEpoch[epoch];
        if (storedRoot == 0) revert Errors.EpochNotFound();
        if (storedRoot != root) revert Errors.EpochNotFound();
    }

    /// @dev Compute the root of an all-zero Merkle tree of depth 32.
    ///      level_0 = 0, level_{i+1} = H(DOMAIN_NODE, level_i, level_i)
    function _computeEmptyTreeRoot() internal pure returns (uint256) {
        uint256 node = 0;
        for (uint256 i = 0; i < MerkleUpdateLib.MERKLE_DEPTH; i++) {
            node = MerkleUpdateLib.poseidonNodeHash(
                MerkleUpdateLib.DOMAIN_NODE,
                node,
                node
            );
        }
        return node;
    }
}
