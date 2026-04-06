//! XMSS signature types.

use serde::{Deserialize, Serialize};

use crate::{Felt252, WOTS_LEN, XMSS_TREE_HEIGHT};

/// An XMSS signature consisting of a WOTS+ one-time signature
/// and a Merkle authentication path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XmssSignature {
    pub epoch: u32,
    pub leaf_index: u32,
    pub wots_sig: Vec<Felt252>,
    pub auth_path: Vec<Felt252>,
}

impl XmssSignature {
    /// Validate structural correctness.
    pub fn validate(&self) -> Result<(), String> {
        if self.wots_sig.len() != WOTS_LEN {
            return Err(format!(
                "WOTS+ signature length mismatch: expected {}, got {}",
                WOTS_LEN,
                self.wots_sig.len()
            ));
        }
        let height = self.auth_path.len();
        if height == 0 || height > 32 {
            return Err(format!(
                "XMSS auth path length {} out of range [1, 32]",
                height
            ));
        }
        if self.leaf_index >= (1u32 << height) {
            return Err(format!(
                "XMSS leaf index {} exceeds tree capacity {}",
                self.leaf_index,
                1u32 << height
            ));
        }
        Ok(())
    }
}
