//! Public input structs for request and withdrawal proofs.
//!
//! These structs must match the Cairo public outputs field-for-field,
//! and the Solidity Types.sol definitions exactly.

use serde::{Deserialize, Serialize};

use crate::Felt252;

/// Public inputs for a request proof.
///
/// The Cairo request program emits these as public outputs in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestPublicInputs {
    /// Must be 1 for request proofs.
    pub statement_type: u8,
    pub protocol_version: u16,
    pub chain_id: u64,
    /// Ethereum address as felt (< 2^160).
    pub contract_address: Felt252,
    pub active_root: Felt252,
    /// 0 for genesis path.
    pub state_sig_epoch: u32,
    /// 0 for genesis path.
    pub state_sig_root: Felt252,
    pub request_nullifier: Felt252,
    pub anon_commitment_x: Felt252,
    pub anon_commitment_y: Felt252,
    pub expiry_ts: u64,
    pub solvency_bound: u128,
}

/// Public inputs for a withdrawal proof.
///
/// The Cairo withdrawal program emits these as public outputs in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalPublicInputs {
    /// Must be 2 for withdrawal proofs.
    pub statement_type: u8,
    pub protocol_version: u16,
    pub chain_id: u64,
    /// Ethereum address as felt (< 2^160).
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub note_id: u32,
    pub final_balance: u128,
    /// Ethereum address (20 bytes).
    pub destination: [u8; 20],
    pub withdrawal_nullifier: Felt252,
    pub is_genesis: bool,
    pub has_clearance: bool,
    /// 0 for genesis path.
    pub state_sig_epoch: u32,
    /// 0 for genesis path.
    pub state_sig_root: Felt252,
    /// 0 when has_clearance is false.
    pub clear_sig_epoch: u32,
    /// 0 when has_clearance is false.
    pub clear_sig_root: Felt252,
}
