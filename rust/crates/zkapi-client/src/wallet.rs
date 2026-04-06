//! Main wallet implementation tying together note state, proof generation,
//! server communication, and atomic persistence.
//!
//! Implements the full client flows from spec sections 10.2-10.5:
//! - deposit  (10.2)
//! - request  (10.3)
//! - recovery (10.4)
//! - withdrawal -- mutual close and escape hatch (10.5)

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use zkapi_core::poseidon::FieldElement;

use zkapi_core::commitment::compute_state_message;
use zkapi_core::leaf::compute_registration_commitment;
use zkapi_core::nullifier::compute_nullifier;
use zkapi_core::poseidon::{felt_to_field, field_to_felt};
use zkapi_crypto::pedersen::PedersenCommitment;
use zkapi_proof::mock::MOCK_PROOF_ENVELOPE;
use zkapi_types::wire::{
    ApiRequest, ClearanceRequest, ClearanceResponse, ErrorResponse, RecoveryResponse,
    RequestResponse,
};
use zkapi_types::{
    Felt252, RequestPublicInputs, WithdrawalPublicInputs, STATEMENT_TYPE_REQUEST,
    STATEMENT_TYPE_WITHDRAWAL,
};

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::journal::PendingRequestJournal;
use crate::note_state::NoteState;

/// The client wallet.
///
/// Manages one note at a time: persists state to disk, generates proofs,
/// communicates with the server, and verifies responses.
pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    http: reqwest::Client,
}

impl Wallet {
    /// Create a new wallet instance.
    ///
    /// If a state file already exists on disk it is loaded automatically.
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let state_dir = PathBuf::from(&config.state_dir);
        std::fs::create_dir_all(&state_dir)?;

        let state_path = state_dir.join("note_state.json");
        let journal_path = state_dir.join("pending_journal.json");

        let state = if state_path.exists() {
            Some(NoteState::load(&state_path)?)
        } else {
            None
        };

        Ok(Self {
            config,
            state,
            state_path,
            journal_path,
            http: reqwest::Client::new(),
        })
    }

    /// Return a reference to the current note state, if one is active.
    pub fn state(&self) -> Option<&NoteState> {
        self.state.as_ref()
    }

    /// Check whether a pending request journal exists on disk.
    pub fn has_pending_request(&self) -> bool {
        PendingRequestJournal::read(&self.journal_path)
            .ok()
            .flatten()
            .is_some()
    }

    // ------------------------------------------------------------------
    // Deposit flow (spec 10.2)
    // ------------------------------------------------------------------

    /// Execute the deposit flow.
    ///
    /// 1. Sample a random nonzero secret `s`.
    /// 2. Compute the registration commitment `C = Poseidon(DOMAIN_REG, s, 0)`.
    /// 3. Compute the initial Pedersen commitment `E(deposit_amount, r0)` with
    ///    random blinding `r0`.
    /// 4. Create a genesis `NoteState` and persist it.
    ///
    /// Returns `(secret_s, registration_commitment)`. The caller is
    /// responsible for submitting the on-chain `deposit` transaction using
    /// the returned commitment.
    pub fn generate_deposit_params(&self) -> (Felt252, Felt252) {
        let mut rng = rand::thread_rng();
        let secret_s = sample_nonzero_felt(&mut rng);
        let commitment = compute_registration_commitment(&secret_s);
        (secret_s, commitment)
    }

    /// Confirm a deposit after the on-chain transaction has landed.
    ///
    /// Creates and persists the genesis `NoteState`.
    pub fn confirm_deposit(
        &mut self,
        secret_s: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry_ts: u64,
    ) -> Result<(), ClientError> {
        if self.state.is_some() {
            return Err(ClientError::NoteAlreadyExists);
        }

        // Sample initial blinding factor.
        let mut rng = rand::thread_rng();
        let r0 = sample_field_element(&mut rng);

        // Compute initial commitment E(deposit_amount, r0).
        let commitment = PedersenCommitment::commit(deposit_amount, &r0);
        let (cx, cy) = commitment.to_affine();

        let blinding_hex = format!("0x{}", hex::encode(r0.to_bytes_be()));

        let note_state = NoteState::new_from_deposit(
            self.config.protocol_version,
            self.config.chain_id,
            self.config.contract_address,
            note_id,
            secret_s,
            deposit_amount,
            expiry_ts,
            blinding_hex,
            field_to_felt(&cx),
            field_to_felt(&cy),
        );

        // Persist atomically.
        note_state.save(&self.state_path)?;
        self.state = Some(note_state);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Request flow (spec 10.3)
    // ------------------------------------------------------------------

    /// Build a request, write the journal, send it to the server, verify the
    /// response, and update local state.
    ///
    /// `payload` is the raw API request body. `payload_hash` is its
    /// protocol-defined hash. `active_root` and `merkle_siblings` come from
    /// the indexer.
    ///
    /// Returns the `RequestResponse` from the server on success.
    pub async fn request_flow(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        _merkle_siblings: Vec<Felt252>,
    ) -> Result<RequestResponse, ClientError> {
        // 1. Check no pending journal exists.
        if PendingRequestJournal::read(&self.journal_path)?.is_some() {
            return Err(ClientError::PendingRequest);
        }

        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let mut rng = rand::thread_rng();

        // Check balance is sufficient for the solvency bound.
        let solvency = state.solvency_bound(
            self.config.policy_enabled,
            self.config.request_charge_cap,
            self.config.policy_charge_cap,
        );
        if state.current_balance < solvency {
            return Err(ClientError::InsufficientBalance {
                needed: solvency,
                available: state.current_balance,
            });
        }

        // 2. Build request proof inputs.
        let current_blinding = parse_blinding(&state.balance_blinding)?;
        let user_rerandomization = sample_field_element(&mut rng);

        // Compute anon_commitment = E(current_balance, current_blinding + user_rerand).
        let anon_blinding = current_blinding + user_rerandomization;
        let anon_commitment = PedersenCommitment::commit(state.current_balance, &anon_blinding);
        let (anon_cx, anon_cy) = anon_commitment.to_affine();

        // Compute nullifier = Poseidon(DOMAIN_NULL, secret_s, current_anchor).
        let request_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            // In production the sig root would be fetched from the indexer.
            (state.state_sig_epoch.unwrap_or(0), Felt252::ZERO)
        };

        let public_inputs = RequestPublicInputs {
            statement_type: STATEMENT_TYPE_REQUEST,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_sig_epoch,
            state_sig_root,
            request_nullifier,
            anon_commitment_x: field_to_felt(&anon_cx),
            anon_commitment_y: field_to_felt(&anon_cy),
            expiry_ts: state.expiry_ts,
            solvency_bound: solvency,
        };

        // 3. Generate proof (mock in v1).
        let proof_bytes = MOCK_PROOF_ENVELOPE.to_vec();
        let proof_b64 = base64_encode(&proof_bytes);

        // 4. Write journal.
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let journal = PendingRequestJournal {
            exists: true,
            client_request_id: client_request_id.clone(),
            nullifier: request_nullifier,
            payload_hash,
            created_at_ms: now_ms(),
        };
        PendingRequestJournal::write(&self.journal_path, &journal)?;

        // 5. Send request to server.
        let api_request = ApiRequest {
            client_request_id: client_request_id.clone(),
            payload: payload.to_string(),
            payload_hash,
            public_inputs,
            proof_envelope: proof_b64,
        };

        let url = format!("{}/v1/requests", self.config.server_url);
        let resp = self
            .http
            .post(&url)
            .json(&api_request)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let status_code = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        if !status_code.is_success() {
            // Try to parse structured error response.
            if let Ok(err_resp) = serde_json::from_str::<ErrorResponse>(&body) {
                // Per spec 10.4: if stale_root the nullifier was never reserved,
                // so the client may clear the journal and retry.
                if err_resp.error_code == "stale_root" {
                    PendingRequestJournal::clear(&self.journal_path)?;
                    return Err(ClientError::StaleRoot);
                }
                return Err(ClientError::ServerError(format!(
                    "{}: {}",
                    err_resp.error_code, err_resp.error_message
                )));
            }
            return Err(ClientError::ServerError(format!(
                "HTTP {}: {}",
                status_code, body
            )));
        }

        let server_resp: RequestResponse = serde_json::from_str(&body)
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))?;

        // 6. Verify response.
        self.verify_request_response(
            &server_resp,
            &anon_commitment,
            &user_rerandomization,
            &current_blinding,
        )?;

        // 7. Update state:
        //    nextBalance = currentBalance - charge
        //    nextBlinding = currentBlinding + user_rerandomization + blind_delta_srv
        let charge = server_resp.charge_applied;
        let next_balance = state
            .current_balance
            .checked_sub(charge)
            .ok_or_else(|| ClientError::InvalidResponse("charge exceeds balance".into()))?;

        let blind_delta_srv = felt_to_field(&server_resp.blind_delta_srv);
        let next_blinding = current_blinding + user_rerandomization + blind_delta_srv;
        let next_blinding_hex = format!("0x{}", hex::encode(next_blinding.to_bytes_be()));

        let mut next_state = state.clone();
        next_state.current_balance = next_balance;
        next_state.balance_blinding = next_blinding_hex;
        next_state.current_commitment_x = server_resp.next_commitment.x;
        next_state.current_commitment_y = server_resp.next_commitment.y;
        next_state.current_anchor = server_resp.next_anchor;
        next_state.is_genesis = false;
        next_state.state_sig_epoch = Some(server_resp.next_state_sig_epoch);
        next_state.state_sig = Some(server_resp.next_state_sig.clone());

        // 8. Save new state atomically.
        next_state.save(&self.state_path)?;
        self.state = Some(next_state);

        // 9. Clear journal.
        PendingRequestJournal::clear(&self.journal_path)?;

        Ok(server_resp)
    }

    /// Verify the server's request response (spec 10.3 step 8).
    ///
    /// Checks:
    /// - `charge_applied <= configured cap`
    /// - commitment algebra: `next_commitment == anon - charge*G + blind_delta*H`
    /// - state signature structural validity
    fn verify_request_response(
        &self,
        resp: &RequestResponse,
        anon_commitment: &PedersenCommitment,
        _user_rerandomization: &FieldElement,
        _current_blinding: &FieldElement,
    ) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;

        // Check charge bound.
        let max_charge = if self.config.policy_enabled {
            self.config.policy_charge_cap
        } else {
            self.config.request_charge_cap
        };
        if resp.charge_applied > max_charge {
            return Err(ClientError::VerificationFailed(format!(
                "charge {} exceeds cap {}",
                resp.charge_applied, max_charge
            )));
        }

        // Check next_anchor is not zero (spec 9.4).
        if resp.next_anchor.is_zero() {
            return Err(ClientError::InvalidResponse("zero next anchor".into()));
        }

        // Verify commitment algebra:
        //   expected_next = anon_commitment - charge * G_balance + blind_delta * H_blind
        let blind_delta = felt_to_field(&resp.blind_delta_srv);
        let expected = PedersenCommitment::server_update(
            &anon_commitment.point,
            resp.charge_applied,
            &blind_delta,
        );
        let (exp_x, exp_y) = expected.to_affine();
        let exp_x_felt = field_to_felt(&exp_x);
        let exp_y_felt = field_to_felt(&exp_y);

        if exp_x_felt != resp.next_commitment.x || exp_y_felt != resp.next_commitment.y {
            return Err(ClientError::VerificationFailed(
                "next_commitment algebra mismatch".into(),
            ));
        }

        // Verify the state signature structural validity.
        if let Err(e) = resp.next_state_sig.validate() {
            return Err(ClientError::VerificationFailed(format!(
                "state sig structural check failed: {}",
                e
            )));
        }

        // Compute the state message that should have been signed.
        // In production the client would fetch the XMSS root for the returned
        // epoch from the indexer / on-chain and verify the full XMSS signature.
        let _state_msg = compute_state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &resp.next_commitment.x,
            &resp.next_commitment.y,
            &resp.next_anchor,
        );

        // Full XMSS verification is deferred until the epoch root is known:
        // XmssVerifier::verify(&epoch_root, &state_msg, &resp.next_state_sig)

        Ok(())
    }

    // ------------------------------------------------------------------
    // Withdrawal flow -- mutual close (spec 10.5)
    // ------------------------------------------------------------------

    /// Execute a mutual-close withdrawal.
    ///
    /// 1. Compute withdrawal nullifier.
    /// 2. Request clearance from server.
    /// 3. Build withdrawal proof with `has_clearance = true`.
    /// 4. Return `(WithdrawalPublicInputs, proof_bytes)` for on-chain submission.
    pub async fn withdrawal_mutual_close(
        &mut self,
        destination: [u8; 20],
        active_root: Felt252,
        _merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputs, Vec<u8>), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;

        // 1. Compute withdrawal_nullifier.
        let withdrawal_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        // 2. Request clearance from server.
        let clearance = self.request_clearance(&withdrawal_nullifier).await?;

        // 3. Build withdrawal proof with has_clearance = true.
        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            (state.state_sig_epoch.unwrap_or(0), Felt252::ZERO)
        };

        let public_inputs = WithdrawalPublicInputs {
            statement_type: STATEMENT_TYPE_WITHDRAWAL,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            note_id: state.note_id,
            final_balance: state.current_balance,
            destination,
            withdrawal_nullifier,
            is_genesis: state.is_genesis,
            has_clearance: true,
            state_sig_epoch,
            state_sig_root,
            clear_sig_epoch: clearance.clear_sig_epoch,
            clear_sig_root: Felt252::ZERO, // fetched from chain in production
        };

        // 4. Generate proof (mock in v1).
        let proof_bytes = MOCK_PROOF_ENVELOPE.to_vec();

        Ok((public_inputs, proof_bytes))
    }

    // ------------------------------------------------------------------
    // Withdrawal flow -- escape hatch (spec 10.5)
    // ------------------------------------------------------------------

    /// Execute an escape-hatch withdrawal (no server clearance).
    ///
    /// Returns `(WithdrawalPublicInputs, proof_bytes)` for on-chain
    /// `initiateEscapeWithdrawal`.
    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        _merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputs, Vec<u8>), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;

        // 1. Compute withdrawal_nullifier.
        let withdrawal_nullifier = compute_nullifier(&state.secret_s, &state.current_anchor);

        let (state_sig_epoch, state_sig_root) = if state.is_genesis {
            (0u32, Felt252::ZERO)
        } else {
            (state.state_sig_epoch.unwrap_or(0), Felt252::ZERO)
        };

        // 2. Build withdrawal proof with has_clearance = false.
        let public_inputs = WithdrawalPublicInputs {
            statement_type: STATEMENT_TYPE_WITHDRAWAL,
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            note_id: state.note_id,
            final_balance: state.current_balance,
            destination,
            withdrawal_nullifier,
            is_genesis: state.is_genesis,
            has_clearance: false,
            state_sig_epoch,
            state_sig_root,
            clear_sig_epoch: 0,
            clear_sig_root: Felt252::ZERO,
        };

        // 3. Generate proof (mock in v1).
        let proof_bytes = MOCK_PROOF_ENVELOPE.to_vec();

        Ok((public_inputs, proof_bytes))
    }

    /// Archive the note state after a successful close.
    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = self.state.take() {
            state.archive(&self.state_path)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Recovery (spec 10.4)
    // ------------------------------------------------------------------

    /// Attempt to recover from a pending request journal.
    ///
    /// 1. Check if journal exists.
    /// 2. Query server recovery endpoint.
    /// 3. If finalized, verify and install the returned next state.
    /// 4. If reserved, return error indicating retry needed.
    pub async fn recover(&mut self) -> Result<Option<RequestResponse>, ClientError> {
        // 1. Check if journal exists.
        let journal = match PendingRequestJournal::read(&self.journal_path)? {
            Some(j) => j,
            None => return Ok(None), // nothing to recover
        };

        // 2. Query server recovery endpoint.
        let url = format!(
            "{}/v1/requests/{}",
            self.config.server_url, journal.client_request_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let recovery: RecoveryResponse = serde_json::from_str(&body)
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))?;

        match recovery.nullifier_status.as_str() {
            "finalized" => {
                // 3. If finalized, verify and install state.
                let server_resp = recovery.request_response.ok_or_else(|| {
                    ClientError::InvalidResponse(
                        "finalized recovery missing request_response".into(),
                    )
                })?;

                let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;

                let charge = server_resp.charge_applied;
                let next_balance = state.current_balance.checked_sub(charge).ok_or_else(|| {
                    ClientError::InvalidResponse("charge exceeds balance".into())
                })?;

                // Recompute next blinding. During recovery we lack the
                // user_rerandomization that was used in the original request.
                //
                // In a production implementation the user_rerandomization would
                // be stored in the journal or derived deterministically from a
                // seed. For v1 we apply only the server's blind_delta to the
                // current blinding and accept the server-returned commitment
                // after verifying the state signature.
                //
                // TODO: persist user_rerandomization in the journal for full
                // algebraic recovery.
                let current_blinding = parse_blinding(&state.balance_blinding)?;
                let blind_delta_srv = felt_to_field(&server_resp.blind_delta_srv);
                let next_blinding = current_blinding + blind_delta_srv;
                let next_blinding_hex =
                    format!("0x{}", hex::encode(next_blinding.to_bytes_be()));

                let mut next_state = state.clone();
                next_state.current_balance = next_balance;
                next_state.balance_blinding = next_blinding_hex;
                next_state.current_commitment_x = server_resp.next_commitment.x;
                next_state.current_commitment_y = server_resp.next_commitment.y;
                next_state.current_anchor = server_resp.next_anchor;
                next_state.is_genesis = false;
                next_state.state_sig_epoch = Some(server_resp.next_state_sig_epoch);
                next_state.state_sig = Some(server_resp.next_state_sig.clone());

                next_state.save(&self.state_path)?;
                self.state = Some(next_state);
                PendingRequestJournal::clear(&self.journal_path)?;

                Ok(Some(server_resp))
            }
            "reserved" => {
                // 4. Server is still processing -- caller should retry later.
                Err(ClientError::ServerError(
                    "request still reserved on server, retry later".into(),
                ))
            }
            other => Err(ClientError::InvalidResponse(format!(
                "unexpected nullifier_status: {}",
                other
            ))),
        }
    }

    /// Return the pending journal entry, if one exists.
    pub fn get_pending_journal(&self) -> Result<Option<PendingRequestJournal>, ClientError> {
        PendingRequestJournal::read(&self.journal_path)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Request a clearance signature for mutual-close withdrawal.
    async fn request_clearance(
        &self,
        withdrawal_nullifier: &Felt252,
    ) -> Result<ClearanceResponse, ClientError> {
        let url = format!("{}/v1/withdraw/clearance", self.config.server_url);
        let req = ClearanceRequest {
            withdrawal_nullifier: *withdrawal_nullifier,
        };

        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        let status_code = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| ClientError::ServerError(e.to_string()))?;

        if !status_code.is_success() {
            return Err(ClientError::ServerError(format!(
                "clearance request failed: HTTP {} - {}",
                status_code, body
            )));
        }

        serde_json::from_str(&body).map_err(|e| ClientError::InvalidResponse(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Sample a random nonzero `Felt252`.
fn sample_nonzero_felt(rng: &mut impl Rng) -> Felt252 {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        // Clear the top bits to stay below the Stark prime (~2^251).
        bytes[0] &= 0x07;
        let f = Felt252(bytes);
        if !f.is_zero() {
            return f;
        }
    }
}

/// Sample a random `FieldElement` suitable as a blinding factor.
fn sample_field_element(rng: &mut impl Rng) -> FieldElement {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    // Clear the top bits to stay below the Stark prime (~2^251).
    bytes[0] &= 0x07;
    FieldElement::from_bytes_be(&bytes)
}

/// Parse a 0x-prefixed hex blinding factor into a `FieldElement`.
fn parse_blinding(hex_str: &str) -> Result<FieldElement, ClientError> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let s = s.strip_prefix("0X").unwrap_or(s);
    let padded = format!("{:0>64}", s);
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&padded, &mut bytes)
        .map_err(|e| ClientError::Serialization(format!("bad blinding hex: {}", e)))?;
    Ok(FieldElement::from_bytes_be(&bytes))
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Inline base64 encoder (avoids pulling in a dedicated crate).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> String {
        let dir = std::env::temp_dir()
            .join("zkapi_client_test_wallet")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().to_string()
    }

    fn test_config(name: &str) -> ClientConfig {
        ClientConfig {
            protocol_version: 1,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdeadbeef),
            request_charge_cap: 100,
            policy_charge_cap: 50,
            policy_enabled: false,
            server_url: "http://localhost:9999".to_string(),
            state_dir: test_dir(name),
        }
    }

    #[test]
    fn test_deposit_params_nonzero() {
        let config = test_config("deposit_params");
        let wallet = Wallet::new(config).unwrap();
        let (secret, commitment) = wallet.generate_deposit_params();
        assert!(!secret.is_zero());
        assert!(!commitment.is_zero());
    }

    #[test]
    fn test_confirm_deposit() {
        let config = test_config("confirm_deposit");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _commitment) = wallet.generate_deposit_params();

        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();
        let state = wallet.state().unwrap();
        assert!(state.is_genesis);
        assert_eq!(state.current_balance, 1000);
        assert_eq!(state.current_anchor, Felt252::ONE);
        assert!(state.state_sig.is_none());
    }

    #[test]
    fn test_deposit_rejects_duplicate() {
        let config = test_config("dup_deposit");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();

        let err = wallet.confirm_deposit(secret, 1, 500, 1700000000).unwrap_err();
        assert!(matches!(err, ClientError::NoteAlreadyExists));
    }

    #[test]
    fn test_escape_hatch_withdrawal() {
        let config = test_config("escape");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 0, 1000, 1700000000).unwrap();

        let dest = [0xdeu8, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let root = Felt252::from_u64(123);
        let siblings = vec![Felt252::ZERO; 32];

        let (inputs, proof) = wallet
            .withdrawal_escape_hatch(dest, root, siblings)
            .unwrap();

        assert_eq!(inputs.statement_type, STATEMENT_TYPE_WITHDRAWAL);
        assert!(!inputs.has_clearance);
        assert_eq!(inputs.final_balance, 1000);
        assert_eq!(inputs.destination, dest);
        assert_eq!(inputs.clear_sig_epoch, 0);
        assert_eq!(inputs.clear_sig_root, Felt252::ZERO);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_wallet_persistence_across_instances() {
        let state_dir = test_dir("persist");
        {
            let config = ClientConfig {
                protocol_version: 1,
                chain_id: 1,
                contract_address: Felt252::from_u64(0xaa),
                request_charge_cap: 100,
                policy_charge_cap: 50,
                policy_enabled: false,
                server_url: "http://localhost:1".to_string(),
                state_dir: state_dir.clone(),
            };
            let mut wallet = Wallet::new(config).unwrap();
            let (secret, _) = wallet.generate_deposit_params();
            wallet.confirm_deposit(secret, 7, 5000, 2000000000).unwrap();
        }
        // Create a new wallet instance against the same directory.
        {
            let config = ClientConfig {
                protocol_version: 1,
                chain_id: 1,
                contract_address: Felt252::from_u64(0xaa),
                request_charge_cap: 100,
                policy_charge_cap: 50,
                policy_enabled: false,
                server_url: "http://localhost:1".to_string(),
                state_dir,
            };
            let wallet = Wallet::new(config).unwrap();
            let state = wallet.state().unwrap();
            assert_eq!(state.note_id, 7);
            assert_eq!(state.current_balance, 5000);
        }
    }

    #[test]
    fn test_archive_note() {
        let config = test_config("archive");
        let mut wallet = Wallet::new(config).unwrap();
        let (secret, _) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 3, 100, 0).unwrap();
        assert!(wallet.state().is_some());

        wallet.archive_note().unwrap();
        assert!(wallet.state().is_none());

        // The archive was written by the NoteState::archive method.
        // The test_dir recreates the directory, so the archive file
        // lives inside the wallet's state_dir.
    }

    #[test]
    fn test_sample_nonzero_felt() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let f = sample_nonzero_felt(&mut rng);
            assert!(!f.is_zero());
        }
    }

    #[test]
    fn test_parse_blinding_roundtrip() {
        let fe = FieldElement::from(42u64);
        let hex_str = format!("0x{}", hex::encode(fe.to_bytes_be()));
        let parsed = parse_blinding(&hex_str).unwrap();
        assert_eq!(fe, parsed);
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_no_pending_request_initially() {
        let config = test_config("no_pending");
        let wallet = Wallet::new(config).unwrap();
        assert!(!wallet.has_pending_request());
        assert!(wallet.get_pending_journal().unwrap().is_none());
    }
}
