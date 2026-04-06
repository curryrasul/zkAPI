//! Client configuration.

use zkapi_types::Felt252;

/// Configuration for the client SDK, matching the deployed contract parameters.
pub struct ClientConfig {
    /// Protocol version (must be 1 for v1).
    pub protocol_version: u16,
    /// Chain ID of the target network.
    pub chain_id: u64,
    /// Address of the deployed ZkApiVault contract.
    pub contract_address: Felt252,
    /// Maximum charge the server may apply per ordinary request.
    pub request_charge_cap: u128,
    /// Maximum charge the server may apply under policy rejection.
    pub policy_charge_cap: u128,
    /// Whether policy-based charge enforcement is active on this deployment.
    pub policy_enabled: bool,
    /// Base URL of the zkAPI server (e.g. "http://localhost:8080").
    pub server_url: String,
    /// Directory for persisting wallet state and journals.
    pub state_dir: String,
}
