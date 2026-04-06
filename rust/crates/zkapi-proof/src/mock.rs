//! Mock proof adapter for testing.
//!
//! Provides a trivially-accepting verifier and a fixed proof envelope so that
//! integration tests can exercise the full pipeline without a real STARK prover.

use zkapi_types::{RequestPublicInputs, WithdrawalPublicInputs};

/// 32-byte constant used as a recognisable mock proof blob in tests.
pub const MOCK_PROOF_ENVELOPE: [u8; 32] = [0x42; 32];

/// A mock prover/verifier that always succeeds.
///
/// Every `verify_*` call returns `true` regardless of the proof bytes.
/// This must never be used outside test/development builds.
pub struct MockProver;

impl MockProver {
    /// Verify a request proof.
    ///
    /// Always returns `true` -- the mock prover performs no cryptographic
    /// checks on the proof blob.
    pub fn verify_request(_inputs: &RequestPublicInputs, _proof: &[u8]) -> bool {
        true
    }

    /// Verify a withdrawal proof.
    ///
    /// Always returns `true` -- the mock prover performs no cryptographic
    /// checks on the proof blob.
    pub fn verify_withdrawal(_inputs: &WithdrawalPublicInputs, _proof: &[u8]) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_types::Felt252;

    #[test]
    fn test_mock_proof_envelope_is_32_bytes() {
        assert_eq!(MOCK_PROOF_ENVELOPE.len(), 32);
        assert!(MOCK_PROOF_ENVELOPE.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_mock_verifier_accepts_request() {
        let inputs = RequestPublicInputs {
            statement_type: 1,
            protocol_version: 1,
            chain_id: 1,
            contract_address: Felt252::ZERO,
            active_root: Felt252::ZERO,
            state_sig_epoch: 0,
            state_sig_root: Felt252::ZERO,
            request_nullifier: Felt252::ZERO,
            anon_commitment_x: Felt252::ZERO,
            anon_commitment_y: Felt252::ZERO,
            expiry_ts: 0,
            solvency_bound: 0,
        };
        assert!(MockProver::verify_request(&inputs, &MOCK_PROOF_ENVELOPE));
        assert!(MockProver::verify_request(&inputs, &[]));
    }

    #[test]
    fn test_mock_verifier_accepts_withdrawal() {
        let inputs = WithdrawalPublicInputs {
            statement_type: 2,
            protocol_version: 1,
            chain_id: 1,
            contract_address: Felt252::ZERO,
            active_root: Felt252::ZERO,
            note_id: 0,
            final_balance: 0,
            destination: [0u8; 20],
            withdrawal_nullifier: Felt252::ZERO,
            is_genesis: true,
            has_clearance: false,
            state_sig_epoch: 0,
            state_sig_root: Felt252::ZERO,
            clear_sig_epoch: 0,
            clear_sig_root: Felt252::ZERO,
        };
        assert!(MockProver::verify_withdrawal(&inputs, &MOCK_PROOF_ENVELOPE));
        assert!(MockProver::verify_withdrawal(&inputs, &[]));
    }
}
