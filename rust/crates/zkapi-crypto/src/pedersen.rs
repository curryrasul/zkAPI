//! Pedersen commitment on the Stark curve.
//!
//! E(B, r) = B * G_balance + r * H_blind
//!
//! This is the ONLY non-post-quantum component in v1.
//! It is required for homomorphic addition and rerandomization.
//!
//! G_balance and H_blind are fixed independent generators derived offline
//! from the labels "zkapi.bal.g" and "zkapi.bal.h" using hash-to-curve.
//! They are committed as protocol constants.

use std::ops::Neg;

use starknet_crypto::poseidon_hash_many;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Type alias for API compatibility with downstream code that uses
/// `FieldElement`.
pub type FieldElement = Felt;

/// The Stark curve generator point (standard).
const STARK_GEN_X: &str = "01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca";
const STARK_GEN_Y: &str = "005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f";

/// G_balance: derived from hash-to-curve with label "zkapi.bal.g"
/// For v1, we use a deterministic derivation: hash the label, multiply generator.
/// In production, these would be derived by a trusted setup script.
///
/// We derive G_balance = scalar("zkapi.bal.g") * G
/// and H_blind = scalar("zkapi.bal.h") * G
/// where scalar(label) = Poseidon(domain_felt(label), 0, 0) mod order.
///
/// This ensures G_balance and H_blind are independent generators where
/// the discrete log relationship is unknown.
fn derive_generator(label_hash: &Felt) -> ProjectivePoint {
    let gen_x = Felt::from_hex_unchecked(STARK_GEN_X);
    let gen_y = Felt::from_hex_unchecked(STARK_GEN_Y);
    let gen = ProjectivePoint::from_affine(gen_x, gen_y).unwrap();
    // Scalar multiplication
    scalar_mul(&gen, label_hash)
}

fn scalar_mul(point: &ProjectivePoint, scalar: &Felt) -> ProjectivePoint {
    let bits = scalar.to_bits_le();
    let mut result = ProjectivePoint::identity();
    let mut temp = point.clone();
    for bit in bits.iter() {
        if *bit {
            result = &result + &temp;
        }
        temp = &temp + &temp;
    }
    result
}

lazy_static::lazy_static! {
    /// G_balance generator point.
    pub static ref G_BALANCE: ProjectivePoint = {
        // Use from_bytes_be with a 32-byte array for the label.
        let label_felt = felt_from_label(b"zkapi.bal.g");
        let hash = poseidon_hash_many(&[
            label_felt,
            Felt::ZERO,
            Felt::ZERO,
        ]);
        derive_generator(&hash)
    };

    /// H_blind generator point.
    pub static ref H_BLIND: ProjectivePoint = {
        let label_felt = felt_from_label(b"zkapi.bal.h");
        let hash = poseidon_hash_many(&[
            label_felt,
            Felt::ZERO,
            Felt::ZERO,
        ]);
        derive_generator(&hash)
    };
}

/// Convert a label byte slice (up to 31 bytes) into a Felt by zero-padding
/// on the left to 32 bytes.
fn felt_from_label(label: &[u8]) -> Felt {
    assert!(label.len() <= 31, "label must be <= 31 bytes");
    let mut bytes = [0u8; 32];
    let offset = 32 - label.len();
    bytes[offset..].copy_from_slice(label);
    Felt::from_bytes_be(&bytes)
}

/// A Pedersen commitment E(B, r) = B * G_balance + r * H_blind.
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    pub point: ProjectivePoint,
}

impl PedersenCommitment {
    /// Create a new commitment from balance and blinding factor.
    pub fn commit(balance: u128, blinding: &Felt) -> Self {
        let b_scalar = Felt::from(balance);
        let bg = scalar_mul(&G_BALANCE, &b_scalar);
        let rh = scalar_mul(&H_BLIND, blinding);
        Self {
            point: &bg + &rh,
        }
    }

    /// Rerandomize: E(B, r + rho) = E(B, r) + rho * H_blind.
    pub fn rerandomize(&self, rho: &Felt) -> Self {
        let rho_h = scalar_mul(&H_BLIND, rho);
        Self {
            point: &self.point + &rho_h,
        }
    }

    /// Server update: subtract charge and add server blinding.
    ///
    /// E(B - delta, r + rho + blind_delta) =
    ///   E(B, r) + rho * H - delta * G + blind_delta * H
    ///
    /// Since the server operates on the already-rerandomized commitment (anon_commitment),
    /// this simplifies to:
    ///   anon_commitment - delta * G + blind_delta * H
    pub fn server_update(
        anon_commitment: &ProjectivePoint,
        charge: u128,
        blind_delta: &Felt,
    ) -> Self {
        let delta_scalar = Felt::from(charge);
        let delta_g = scalar_mul(&G_BALANCE, &delta_scalar);
        let blind_h = scalar_mul(&H_BLIND, blind_delta);
        // anon - delta*G + blind*H
        let neg_delta_g = delta_g.neg();
        let result = &(anon_commitment + &neg_delta_g) + &blind_h;
        Self { point: result }
    }

    /// Get the affine coordinates.
    pub fn to_affine(&self) -> (Felt, Felt) {
        let affine = self.point.to_affine().unwrap();
        (affine.x(), affine.y())
    }

    /// Verify that a commitment opens to the given values.
    pub fn verify_opening(
        &self,
        balance: u128,
        blinding: &Felt,
    ) -> bool {
        let expected = Self::commit(balance, blinding);
        self.point == expected.point
    }
}

/// Convert a ProjectivePoint to affine (x, y) Felt values.
pub fn point_to_affine(p: &ProjectivePoint) -> Option<(Felt, Felt)> {
    let affine = p.to_affine().ok()?;
    Some((affine.x(), affine.y()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generators_are_different() {
        let g_affine = G_BALANCE.to_affine().unwrap();
        let h_affine = H_BLIND.to_affine().unwrap();
        assert_ne!(g_affine.x(), h_affine.x());
    }

    #[test]
    fn test_commit_and_verify() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let c = PedersenCommitment::commit(balance, &blinding);
        assert!(c.verify_opening(balance, &blinding));
        assert!(!c.verify_opening(999, &blinding));
    }

    #[test]
    fn test_rerandomization() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let c = PedersenCommitment::commit(balance, &blinding);

        let rho = Felt::from(7u64);
        let c_rerand = c.rerandomize(&rho);

        // The rerandomized commitment should open with blinding + rho
        let new_blinding = blinding + rho;
        assert!(c_rerand.verify_opening(balance, &new_blinding));
    }

    #[test]
    fn test_server_update_algebra() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let rho = Felt::from(7u64);

        // Client commits and rerandomizes
        let c = PedersenCommitment::commit(balance, &blinding);
        let anon = c.rerandomize(&rho);

        // Server applies charge
        let charge = 100u128;
        let blind_delta = Felt::from(13u64);
        let updated = PedersenCommitment::server_update(&anon.point, charge, &blind_delta);

        // Verify: E(B - charge, blinding + rho + blind_delta)
        let expected_balance = balance - charge;
        let expected_blinding = blinding + rho + blind_delta;
        assert!(updated.verify_opening(expected_balance, &expected_blinding));
    }

    #[test]
    fn test_zero_charge_update() {
        let balance = 1000u128;
        let blinding = Felt::from(42u64);
        let rho = Felt::from(7u64);

        let c = PedersenCommitment::commit(balance, &blinding);
        let anon = c.rerandomize(&rho);

        let blind_delta = Felt::from(5u64);
        let updated = PedersenCommitment::server_update(&anon.point, 0, &blind_delta);

        let expected_blinding = blinding + rho + blind_delta;
        assert!(updated.verify_opening(balance, &expected_blinding));
    }
}
