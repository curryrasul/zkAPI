//! Proof generation and verification orchestration for zkAPI.
//!
//! This crate provides builders that assemble the private witness fields,
//! compute derived values (commitments, nullifiers, leaves), validate all
//! circuit constraints locally, and produce mock proof blobs for testing.
//!
//! In a production build the `generate_mock_proof` method would be replaced
//! by a call to the Cairo STARK prover.

pub mod mock;
pub mod request;
pub mod withdrawal;

pub use request::RequestProofBuilder;
pub use withdrawal::WithdrawalProofBuilder;
