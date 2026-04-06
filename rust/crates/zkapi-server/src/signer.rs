//! Server signing module that manages XMSS keypairs.
//!
//! The server maintains two XMSS trees:
//! - state keypair: signs state transitions (next commitment + anchor)
//! - clear keypair: signs clearance messages for mutual close

use zkapi_core::poseidon::FieldElement;

use zkapi_crypto::xmss::XmssKeypair;
use zkapi_types::{Felt252, XmssSignature};

use crate::error::ServerError;

/// Server-side signer holding both state and clearance XMSS keypairs.
pub struct ServerSigner {
    state_keypair: XmssKeypair,
    clear_keypair: XmssKeypair,
    state_epoch: u32,
    clear_epoch: u32,
}

impl ServerSigner {
    /// Create a new server signer from seeds and an epoch number.
    ///
    /// `state_seed` is used to derive the state-signing XMSS tree.
    /// `clear_seed` is used to derive the clearance-signing XMSS tree.
    /// `epoch` is the initial epoch number assigned to both trees.
    pub fn new(state_seed: FieldElement, clear_seed: FieldElement, epoch: u32) -> Self {
        Self::with_height(state_seed, clear_seed, epoch, zkapi_types::XMSS_TREE_HEIGHT)
    }

    /// Create a signer with a custom tree height (for testing).
    pub fn with_height(
        state_seed: FieldElement,
        clear_seed: FieldElement,
        epoch: u32,
        height: usize,
    ) -> Self {
        let state_keypair = XmssKeypair::generate_with_height(&state_seed, height);
        let clear_keypair = XmssKeypair::generate_with_height(&clear_seed, height);
        Self {
            state_keypair,
            clear_keypair,
            state_epoch: epoch,
            clear_epoch: epoch,
        }
    }

    /// Sign a state message using the state XMSS keypair.
    ///
    /// Returns the signature with the correct epoch set, plus the leaf index used.
    pub fn sign_state(&self, message: &Felt252) -> Result<(XmssSignature, u32), ServerError> {
        let (mut sig, leaf_index) = self
            .state_keypair
            .sign(message)
            .ok_or(ServerError::CapacityExhausted)?;
        sig.epoch = self.state_epoch;
        Ok((sig, leaf_index))
    }

    /// Sign a clearance message using the clearance XMSS keypair.
    ///
    /// Returns the signature with the correct epoch set, plus the leaf index used.
    pub fn sign_clearance(&self, message: &Felt252) -> Result<(XmssSignature, u32), ServerError> {
        let (mut sig, leaf_index) = self
            .clear_keypair
            .sign(message)
            .ok_or(ServerError::CapacityExhausted)?;
        sig.epoch = self.clear_epoch;
        Ok((sig, leaf_index))
    }

    /// Get the state XMSS tree root as a Felt252.
    pub fn state_root(&self) -> Felt252 {
        self.state_keypair.root_felt()
    }

    /// Get the clearance XMSS tree root as a Felt252.
    pub fn clear_root(&self) -> Felt252 {
        self.clear_keypair.root_felt()
    }

    /// Get the current state epoch.
    pub fn epoch(&self) -> u32 {
        self.state_epoch
    }

    /// Get the current clear epoch.
    pub fn clear_epoch(&self) -> u32 {
        self.clear_epoch
    }

    /// Check remaining state signatures.
    pub fn state_remaining(&self) -> u32 {
        self.state_keypair.remaining()
    }

    /// Check remaining clearance signatures.
    pub fn clear_remaining(&self) -> u32 {
        self.clear_keypair.remaining()
    }
}
