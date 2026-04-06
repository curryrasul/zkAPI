// Pedersen balance commitment on the Stark curve.
//
// E(B, r) = B * G_balance + r * H_blind
//
// NON-PQ EXCEPTION: This is the one accepted non-post-quantum component
// in zkAPI v1.  Homomorphic addition and rerandomization require an
// elliptic-curve commitment, which is inherently not post-quantum.
// This exception is explicitly documented per the protocol specification.
//
// G_BALANCE and H_BLIND are fixed independent generators derived by the Rust
// reference implementation from the labels "zkapi.bal.g" and "zkapi.bal.h".
// These exact affine coordinates are mirrored here so Cairo and Rust commit to
// the same curve points.

use core::ec::{EcPointTrait, EcStateTrait, NonZeroEcPoint};

// ---------------------------------------------------------------------------
// Generator points
// ---------------------------------------------------------------------------

// G_balance generator coordinates.
const G_BALANCE_X: felt252 = 0x53650b4a2cbf80864a1894814abdf4934b4ef43d76a706910f7f00c0a21afe0;
const G_BALANCE_Y: felt252 = 0x55d2a6c23b4df3e262e0b1bbf6fe31eb1b7ebfddc872c863363be9b00b1a296;

// H_blind generator coordinates.
const H_BLIND_X: felt252 = 0x3069b52abc79afae06c83bb31d22950113be4ef840dcd3fd10e838c877e6da0;
const H_BLIND_Y: felt252 = 0x1efd6a8a9529d70de816b1b5f2cd0c81f32b1bba07d98d5b728e1ec37ea4b83;

/// Compute the Pedersen balance commitment E(balance, blinding).
///
/// Returns the commitment as an (x, y) pair.
/// Panics if the resulting point is the point at infinity.
pub fn compute_commitment(balance: felt252, blinding: felt252) -> (felt252, felt252) {
    // Recover generator points from their exact affine coordinates.
    let g_nz: NonZeroEcPoint = EcPointTrait::new_nz(G_BALANCE_X, G_BALANCE_Y)
        .expect('G_BALANCE not on curve');
    let h_nz: NonZeroEcPoint = EcPointTrait::new_nz(H_BLIND_X, H_BLIND_Y)
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
pub fn verify_commitment_opening(px: felt252, py: felt252, balance: felt252, blinding: felt252) {
    let (cx, cy) = compute_commitment(balance, blinding);
    assert(px == cx, 'commitment x mismatch');
    assert(py == cy, 'commitment y mismatch');
}

#[cfg(test)]
mod tests {
    use super::{compute_commitment, verify_commitment_opening};

    #[test]
    fn test_commitment_matches_rust_vector() {
        let (x, y) = compute_commitment(1000, 42);
        assert(
            x == 0x5d1a6479b89911d4ad8a2317997bc93bb94377bedcb7c40314883883892d3c,
            'unexpected commitment x',
        );
        assert(
            y == 0x649e8a7082e97e3a54c406eb864111a867137884873d04b1ba6d2526508bfa0,
            'unexpected commitment y',
        );
    }

    #[test]
    fn test_verify_opening_roundtrip() {
        let (x, y) = compute_commitment(77, 5);
        verify_commitment_opening(x, y, 77, 5);
    }
}
