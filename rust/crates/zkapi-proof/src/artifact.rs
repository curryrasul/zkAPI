//! Production proof artifact types.
//!
//! These types intentionally carry opaque proof bytes plus canonical public
//! binding data only. Private witness envelopes remain behind the
//! `dev-witness-envelope` feature.

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

/// Supported proof artifact backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackend {
    /// Real Stwo/Stwo-Cairo proof artifact.
    StwoCairo,
}

/// Opaque production proof artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub backend: ProofBackend,
    pub public_output_hash: Felt252,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

impl ProofArtifact {
    pub fn stwo_cairo(public_output_hash: Felt252, proof: Vec<u8>) -> Self {
        Self {
            backend: ProofBackend::StwoCairo,
            public_output_hash,
            proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_artifact_serializes_without_witness_field_names() {
        let artifact = ProofArtifact::stwo_cairo(Felt252::from_u64(7), vec![1, 2, 3, 4]);
        let json = serde_json::to_string(&artifact).unwrap();

        for forbidden in ["secret_s", "current_blinding", "current_anchor"] {
            assert!(
                !json.contains(forbidden),
                "production artifact leaked witness field name {forbidden}"
            );
        }
    }
}
