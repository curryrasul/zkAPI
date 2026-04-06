//! Challenge watcher stub.
//!
//! In production, this module would connect to the chain to monitor
//! for on-chain challenge events and pending withdrawals. For now it
//! provides a minimal interface that queries the local nullifier store.

use std::sync::Arc;

use zkapi_types::Felt252;

use crate::nullifier_store::{NullifierStore, TranscriptRecord};

/// Monitors the chain for challenge events related to pending withdrawals.
///
/// In the current stub implementation, it only queries the local store.
/// A production implementation would subscribe to on-chain events and
/// cross-reference with the server's transcript database.
pub struct ChallengeWatcher {
    store: Arc<NullifierStore>,
}

impl ChallengeWatcher {
    /// Create a new challenge watcher backed by the given nullifier store.
    pub fn new(store: Arc<NullifierStore>) -> Self {
        Self { store }
    }

    /// Check if a nullifier has a pending withdrawal recorded locally.
    ///
    /// In production this would also check on-chain state for the
    /// challenge period status and deadline.
    pub async fn check_pending_withdrawal(
        &self,
        nullifier: &Felt252,
    ) -> Option<TranscriptRecord> {
        self.store.lookup_by_nullifier(nullifier)
    }

    /// Scan all nullifiers for any that may need challenge responses.
    ///
    /// In production this would compare local transcripts against
    /// on-chain challenge events and flag any discrepancies.
    pub async fn scan_for_challenges(&self) -> Vec<TranscriptRecord> {
        self.store.get_all_nullifiers()
    }
}
