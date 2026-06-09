//! Proof generation and verification orchestration for zkAPI.
//!
//! This crate provides builders that assemble the private witness fields,
//! compute derived values (commitments, nullifiers, leaves), validate all
//! circuit constraints locally, and serialize flat Cairo arguments for the
//! Stwo proof bridge.
//!
//! The production runtime boundary is an opaque proof artifact plus canonical
//! public-output hash. The old witness-envelope replay path is available only
//! behind the `dev-witness-envelope` feature.

pub mod artifact;
pub mod mock;
pub mod request;
pub mod stwo;
pub mod withdrawal;

pub use artifact::{ProofArtifact, ProofBackend};
pub use request::RequestProofBuilder;
#[cfg(feature = "dev-witness-envelope")]
pub use request::{verify_request_proof, RequestProofEnvelope};
pub use stwo::{ensure_stwo_runner_ready, ScarbStwoProver, StwoBridgeError};
pub use withdrawal::WithdrawalProofBuilder;
#[cfg(feature = "dev-witness-envelope")]
pub use withdrawal::{verify_withdrawal_proof, WithdrawalProofEnvelope};
