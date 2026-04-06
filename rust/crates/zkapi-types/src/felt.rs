//! Felt252 type for Stark field elements.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A field element in the Stark prime field.
///
/// Stored as 32 bytes big-endian. Must be < STARK_PRIME.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Felt252(pub [u8; 32]);

impl Felt252 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub const ONE: Self = {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        Self(bytes)
    };

    /// Create from a u64 value.
    pub fn from_u64(val: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&val.to_be_bytes());
        Self(bytes)
    }

    /// Create from a u128 value.
    pub fn from_u128(val: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&val.to_be_bytes());
        Self(bytes)
    }

    /// Create from big-endian hex string (with or without 0x prefix).
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = s.strip_prefix("0X").unwrap_or(s);
        if s.len() > 64 {
            return Err("hex string too long for felt252".to_string());
        }
        let padded = format!("{:0>64}", s);
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex: {}", e))?;
        }
        Ok(Self(bytes))
    }

    /// Convert to 0x-prefixed lowercase hex string.
    pub fn to_hex(&self) -> String {
        let hex: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
        // Strip leading zeros but keep at least one digit
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0x0".to_string()
        } else {
            format!("0x{}", trimmed)
        }
    }

    /// Return the raw big-endian bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this felt is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Try to extract as u64 (fails if value doesn't fit).
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[..24] != [0u8; 24] {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[24..32]);
        Some(u64::from_be_bytes(buf))
    }

    /// Try to extract as u128 (fails if value doesn't fit).
    pub fn to_u128(&self) -> Option<u128> {
        if self.0[..16] != [0u8; 16] {
            return None;
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[16..32]);
        Some(u128::from_be_bytes(buf))
    }
}

impl fmt::Debug for Felt252 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Felt252({})", self.to_hex())
    }
}

impl fmt::Display for Felt252 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Felt252 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Felt252 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let f = Felt252::from_u64(42);
        assert_eq!(f.to_u64(), Some(42));
    }

    #[test]
    fn test_from_u128() {
        let val: u128 = (1u128 << 100) + 7;
        let f = Felt252::from_u128(val);
        assert_eq!(f.to_u128(), Some(val));
    }

    #[test]
    fn test_hex_roundtrip() {
        let f = Felt252::from_hex("0xdeadbeef").unwrap();
        assert_eq!(f.to_hex(), "0xdeadbeef");
    }

    #[test]
    fn test_zero() {
        assert!(Felt252::ZERO.is_zero());
        assert_eq!(Felt252::ZERO.to_hex(), "0x0");
    }

    #[test]
    fn test_serde_json() {
        let f = Felt252::from_u64(255);
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "\"0xff\"");
        let back: Felt252 = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}
