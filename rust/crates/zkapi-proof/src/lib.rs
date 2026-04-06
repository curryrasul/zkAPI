//! Proof generation and verification orchestration for zkAPI.
//!
//! This crate provides builders that assemble the private witness fields,
//! compute derived values (commitments, nullifiers, leaves), validate all
//! circuit constraints locally, and serialize typed proof envelopes for the
//! Rust client/server pipeline.
//!
//! The production on-chain verification boundary remains the Cairo STARK
//! adapter/fact-registry path. Off-chain, the server replays the witness from
//! the serialized envelope before executing a request.

pub mod mock;
pub mod request;
pub mod withdrawal;

pub use request::{verify_request_proof, RequestProofBuilder, RequestProofEnvelope};
pub use withdrawal::{
    verify_withdrawal_proof, WithdrawalProofBuilder, WithdrawalProofEnvelope,
};
