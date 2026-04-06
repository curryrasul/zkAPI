// Pedersen balance commitment on the Stark curve.
//
// E(B, r) = B * G_balance + r * H_blind
//
// NON-PQ EXCEPTION: This is the one accepted non-post-quantum component
// in zkAPI v1.  Homomorphic addition and rerandomization require an
// elliptic-curve commitment, which is inherently not post-quantum.
// This exception is explicitly documented per the protocol specification.
//
// G_BALANCE and H_BLIND are fixed independent generators derived offline
// via hash-to-curve using labels "zkapi.bal.g" and "zkapi.bal.h".
// The placeholder coordinates below MUST be replaced with the actual
// derived values before production use.

use core::ec::{EcPointTrait, EcStateTrait, NonZeroEcPoint};

// ---------------------------------------------------------------------------
// Generator points (PLACEHOLDERS -- replace with actual derived values)
// ---------------------------------------------------------------------------

// G_balance generator x-coordinate (placeholder).
const G_BALANCE_X: felt252 =
    0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804;

// H_blind generator x-coordinate (placeholder).
const H_BLIND_X: felt252 =
    0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;

/// Compute the Pedersen balance commitment E(balance, blinding).
///
/// Returns the commitment as an (x, y) pair.
/// Panics if the resulting point is the point at infinity.
pub fn compute_commitment(balance: felt252, blinding: felt252) -> (felt252, felt252) {
    // Recover generator points from their x-coordinates.
    let g_nz: NonZeroEcPoint = EcPointTrait::new_nz_from_x(G_BALANCE_X)
        .expect('G_BALANCE not on curve');
    let h_nz: NonZeroEcPoint = EcPointTrait::new_nz_from_x(H_BLIND_X)
        .expect('H_BLIND not on curve');

    // E = balance * G_balance + blinding * H_blind
    let mut state = EcStateTrait::init();
    state.add_mul(balance, g_nz);
    state.add_mul(blinding, h_nz);

    let result_nz = state.finalize_nz().expect('commitment is point at infinity');
    result_nz.coordinates()
}

/// Verify that the given point (px, py) equals the commitment
/// E(balance, blinding) = balance * G_balance + blinding * H_blind.
pub fn verify_commitment_opening(
    px: felt252, py: felt252, balance: felt252, blinding: felt252,
) {
    let (cx, cy) = compute_commitment(balance, blinding);
    assert(px == cx, 'commitment x mismatch');
    assert(py == cy, 'commitment y mismatch');
}
