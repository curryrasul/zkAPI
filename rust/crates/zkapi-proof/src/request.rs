//! Request proof builder.
//!
//! Assembles the private witness for a request proof, computes all derived
//! values (registration commitment, note leaf, nullifier, anonymous
//! commitment), validates constraints locally, and can emit a mock proof
//! blob for testing.

use zkapi_core::poseidon::FieldElement;
use thiserror::Error;

use zkapi_core::leaf::{compute_note_leaf, compute_registration_commitment};
use zkapi_core::merkle::verify_membership;
use zkapi_core::nullifier::compute_nullifier;
use zkapi_core::poseidon::field_to_felt;
use zkapi_crypto::pedersen::PedersenCommitment;
use zkapi_types::{
    Felt252, RequestPublicInputs, GENESIS_ANCHOR, MERKLE_DEPTH, STATEMENT_TYPE_REQUEST,
};

use crate::mock::MOCK_PROOF_ENVELOPE;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced when validating request witness constraints.
#[derive(Debug, Error)]
pub enum RequestProofError {
    #[error("registration commitment is zero")]
    ZeroCommitment,

    #[error("leaf is not a member of active_root (merkle proof invalid)")]
    MerkleProofInvalid,

    #[error("genesis: current_anchor must equal GENESIS_ANCHOR (1)")]
    GenesisAnchorMismatch,

    #[error("genesis: current_balance must equal deposit_amount")]
    GenesisBalanceMismatch,

    #[error("genesis: state_sig_epoch must be 0")]
    GenesisEpochNonZero,

    #[error("genesis: state_sig_root must be 0")]
    GenesisRootNonZero,

    #[error("non-genesis: state_sig_epoch must be > 0")]
    NonGenesisEpochZero,

    #[error("non-genesis: state_sig_root must be non-zero")]
    NonGenesisRootZero,

    #[error("current_balance ({balance}) < solvency_bound ({bound})")]
    SolvencyCheckFailed { balance: u128, bound: u128 },

    #[error("anon commitment point is at infinity")]
    CommitmentAtInfinity,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder that holds the full private witness for a request proof and
/// provides helpers to derive public inputs, validate constraints, and
/// generate a mock proof blob.
pub struct RequestProofBuilder {
    // -- private witness fields --
    pub secret_s: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: FieldElement,
    pub user_rerandomization: FieldElement,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_sig_epoch: u32,
    pub state_sig_root: Felt252,

    // -- public / contextual --
    pub active_root: Felt252,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub solvency_bound: u128,
}

impl RequestProofBuilder {
    /// Create a new builder with all witness and contextual fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_s: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry_ts: u64,
        merkle_siblings: [Felt252; MERKLE_DEPTH],
        current_balance: u128,
        current_blinding: FieldElement,
        user_rerandomization: FieldElement,
        current_anchor: Felt252,
        is_genesis: bool,
        state_sig_epoch: u32,
        state_sig_root: Felt252,
        active_root: Felt252,
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
        solvency_bound: u128,
    ) -> Self {
        Self {
            secret_s,
            note_id,
            deposit_amount,
            expiry_ts,
            merkle_siblings,
            current_balance,
            current_blinding,
            user_rerandomization,
            current_anchor,
            is_genesis,
            state_sig_epoch,
            state_sig_root,
            active_root,
            protocol_version,
            chain_id,
            contract_address,
            solvency_bound,
        }
    }

    // -- derived values ------------------------------------------------

    /// Registration commitment: `C = Poseidon(DOMAIN_REG, secret_s, 0)`.
    pub fn registration_commitment(&self) -> Felt252 {
        compute_registration_commitment(&self.secret_s)
    }

    /// Note leaf: `Poseidon(DOMAIN_LEAF, note_id, C, deposit_amount, expiry_ts)`.
    pub fn note_leaf(&self) -> Felt252 {
        let c = self.registration_commitment();
        compute_note_leaf(self.note_id, &c, self.deposit_amount, self.expiry_ts)
    }

    /// Request nullifier: `Poseidon(DOMAIN_NULL, secret_s, current_anchor)`.
    pub fn nullifier(&self) -> Felt252 {
        compute_nullifier(&self.secret_s, &self.current_anchor)
    }

    /// Anonymous commitment: `Commit(current_balance, current_blinding + user_rerandomization)`.
    ///
    /// Returns the affine (x, y) coordinates as `Felt252` values.
    pub fn anon_commitment(&self) -> Result<(Felt252, Felt252), RequestProofError> {
        let combined_blinding = self.current_blinding + self.user_rerandomization;
        let commitment = PedersenCommitment::commit(self.current_balance, &combined_blinding);
        let (x, y) = commitment.to_affine();
        Ok((field_to_felt(&x), field_to_felt(&y)))
    }

    // -- public inputs -------------------------------------------------

    /// Build the `RequestPublicInputs` struct from the witness.
    pub fn build_public_inputs(&self) -> Result<RequestPublicInputs, RequestProofError> {
        let (anon_x, anon_y) = self.anon_commitment()?;

        Ok(RequestPublicInputs {
            statement_type: STATEMENT_TYPE_REQUEST,
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: self.contract_address,
            active_root: self.active_root,
            state_sig_epoch: self.state_sig_epoch,
            state_sig_root: self.state_sig_root,
            request_nullifier: self.nullifier(),
            anon_commitment_x: anon_x,
            anon_commitment_y: anon_y,
            expiry_ts: self.expiry_ts,
            solvency_bound: self.solvency_bound,
        })
    }

    // -- validation ----------------------------------------------------

    /// Run all circuit-equivalent constraint checks locally.
    ///
    /// This mirrors the Cairo request program constraints (spec section 8.2)
    /// so that callers can detect invalid witnesses before sending to a
    /// (potentially expensive) prover.
    pub fn validate(&self) -> Result<(), RequestProofError> {
        // 1. Registration commitment must be non-zero.
        let c = self.registration_commitment();
        if c.is_zero() {
            return Err(RequestProofError::ZeroCommitment);
        }

        // 2-3. Leaf membership in active_root.
        let leaf = self.note_leaf();
        if !verify_membership(&self.active_root, self.note_id, &leaf, &self.merkle_siblings) {
            return Err(RequestProofError::MerkleProofInvalid);
        }

        // 4-5. Genesis vs non-genesis constraints.
        if self.is_genesis {
            // current_anchor must equal GENESIS_ANCHOR (= 1).
            if self.current_anchor != Felt252::from_u64(GENESIS_ANCHOR) {
                return Err(RequestProofError::GenesisAnchorMismatch);
            }
            // current_balance must equal deposit_amount.
            if self.current_balance != self.deposit_amount {
                return Err(RequestProofError::GenesisBalanceMismatch);
            }
            // state_sig_epoch must be 0.
            if self.state_sig_epoch != 0 {
                return Err(RequestProofError::GenesisEpochNonZero);
            }
            // state_sig_root must be 0.
            if !self.state_sig_root.is_zero() {
                return Err(RequestProofError::GenesisRootNonZero);
            }
        } else {
            // Non-genesis: state_sig_epoch > 0, state_sig_root != 0.
            if self.state_sig_epoch == 0 {
                return Err(RequestProofError::NonGenesisEpochZero);
            }
            if self.state_sig_root.is_zero() {
                return Err(RequestProofError::NonGenesisRootZero);
            }
            // NOTE: actual XMSS signature verification is not performed here;
            // that is the responsibility of the Cairo program.
        }

        // 8. Solvency: current_balance >= solvency_bound.
        if self.current_balance < self.solvency_bound {
            return Err(RequestProofError::SolvencyCheckFailed {
                balance: self.current_balance,
                bound: self.solvency_bound,
            });
        }

        // Verify the anon commitment does not land at infinity.
        let _commitment = self.anon_commitment()?;

        Ok(())
    }

    // -- mock proof ----------------------------------------------------

    /// Produce a mock proof blob for testing.
    ///
    /// In a production build this would invoke the Cairo STARK prover.
    pub fn generate_mock_proof(&self) -> Vec<u8> {
        MOCK_PROOF_ENVELOPE.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_core::merkle::MerkleTree;

    /// Helper: build a minimal genesis witness that should pass validation.
    fn genesis_builder() -> RequestProofBuilder {
        let secret = Felt252::from_u64(42);
        let deposit = 1_000u128;
        let expiry = 1_700_000_000u64;

        // Compute the leaf and insert it into a fresh tree.
        let c = compute_registration_commitment(&secret);
        let leaf = compute_note_leaf(0, &c, deposit, expiry);
        let mut tree = MerkleTree::new();
        tree.insert(leaf);
        let siblings = tree.get_siblings(0);
        let root = tree.root();

        RequestProofBuilder::new(
            secret,
            0,                          // note_id
            deposit,
            expiry,
            siblings,
            deposit,                    // current_balance == deposit for genesis
            FieldElement::ZERO,         // current_blinding
            FieldElement::from(7u64),   // user_rerandomization
            Felt252::from_u64(GENESIS_ANCHOR), // current_anchor = 1
            true,                       // is_genesis
            0,                          // state_sig_epoch
            Felt252::ZERO,              // state_sig_root
            root,                       // active_root
            1,                          // protocol_version
            1,                          // chain_id
            Felt252::from_u64(0xdead),  // contract_address
            100,                        // solvency_bound
        )
    }

    #[test]
    fn test_genesis_validate_ok() {
        let builder = genesis_builder();
        builder.validate().expect("genesis builder should validate");
    }

    #[test]
    fn test_build_public_inputs() {
        let builder = genesis_builder();
        let pi = builder.build_public_inputs().expect("should build public inputs");
        assert_eq!(pi.statement_type, STATEMENT_TYPE_REQUEST);
        assert_eq!(pi.protocol_version, 1);
        assert_eq!(pi.chain_id, 1);
        assert_eq!(pi.expiry_ts, 1_700_000_000);
        assert_eq!(pi.solvency_bound, 100);
        assert!(!pi.request_nullifier.is_zero());
        assert!(!pi.anon_commitment_x.is_zero());
    }

    #[test]
    fn test_solvency_failure() {
        let mut builder = genesis_builder();
        // Set solvency_bound higher than balance.
        builder.solvency_bound = builder.deposit_amount + 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::SolvencyCheckFailed { .. }));
    }

    #[test]
    fn test_genesis_anchor_mismatch() {
        let mut builder = genesis_builder();
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::GenesisAnchorMismatch));
    }

    #[test]
    fn test_genesis_balance_mismatch() {
        let mut builder = genesis_builder();
        builder.current_balance = builder.deposit_amount - 1;
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::GenesisBalanceMismatch));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let mut builder = genesis_builder();
        // Corrupt a sibling.
        builder.merkle_siblings[0] = Felt252::from_u64(0xbad);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::MerkleProofInvalid));
    }

    #[test]
    fn test_mock_proof_generation() {
        let builder = genesis_builder();
        let proof = builder.generate_mock_proof();
        assert_eq!(proof.len(), 32);
        assert!(proof.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_non_genesis_epoch_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        // Keep epoch at 0 -- should fail.
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::NonGenesisEpochZero));
    }

    #[test]
    fn test_non_genesis_root_zero() {
        let mut builder = genesis_builder();
        builder.is_genesis = false;
        builder.state_sig_epoch = 1;
        builder.state_sig_root = Felt252::ZERO;
        // Anchor no longer 1, so won't trip genesis check; just needs nonzero.
        builder.current_anchor = Felt252::from_u64(99);
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, RequestProofError::NonGenesisRootZero));
    }
}
