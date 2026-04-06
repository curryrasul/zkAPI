// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Types – Shared data structures for zkAPI
library Types {
    /// @notice Lifecycle status of a note.
    enum NoteStatus {
        Uninitialized, // 0
        Active, // 1
        PendingWithdrawal, // 2
        Closed // 3
    }

    /// @notice On-chain metadata for a deposited note.
    struct Note {
        bytes32 commitment;
        uint128 depositAmount;
        uint64 expiryTs;
        NoteStatus status;
    }

    /// @notice Temporary state kept while an escape-hatch withdrawal is open.
    struct PendingWithdrawalData {
        bool exists;
        uint256 withdrawalNullifier;
        uint128 finalBalance;
        address destination;
        uint64 challengeDeadline;
    }

    /// @notice Public inputs for a request proof (statement type 1).
    struct RequestPublicInputs {
        uint8 statementType;
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint32 stateSigEpoch;
        uint256 stateSigRoot;
        uint256 requestNullifier;
        uint256 anonCommitmentX;
        uint256 anonCommitmentY;
        uint64 expiryTs;
        uint128 solvencyBound;
    }

    /// @notice Public inputs for a withdrawal proof (statement type 2).
    struct WithdrawalPublicInputs {
        uint8 statementType;
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint32 noteId;
        uint128 finalBalance;
        address destination;
        uint256 withdrawalNullifier;
        bool isGenesis;
        bool hasClearance;
        uint32 stateSigEpoch;
        uint256 stateSigRoot;
        uint32 clearSigEpoch;
        uint256 clearSigRoot;
    }
}
