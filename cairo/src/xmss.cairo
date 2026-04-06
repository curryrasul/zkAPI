// XMSS hash-based signature module.
//
// Implements WOTS+ one-time signatures over Poseidon and an XMSS-style
// Merkle authentication tree for post-quantum state signatures.

pub mod params;
pub mod wots;
pub mod tree;
pub mod verify;
