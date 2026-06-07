//! Hash strategies for Merkle trees.
//!
//! Provides pluggable hash backends. Implement [`HashStrategy`] to use a
//! custom hash function with [`crate::tree::MerkleTree`].

use sha2::{Sha256, Digest};
use blake3::Hasher as Blake3HasherInner;

/// A byte-array hash result (32 bytes).
pub type Hash = [u8; 32];

/// Trait for hash strategies used in Merkle tree construction.
pub trait HashStrategy: Clone + Default + Send + Sync {
    /// Hash a single slice of data.
    fn hash(data: &[u8]) -> Hash;

    /// Hash two hashes together (default concatenates then hashes).
    fn hash_pair(a: &Hash, b: &Hash) -> Hash {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(a);
        combined[32..].copy_from_slice(b);
        Self::hash(&combined)
    }

    /// Hash four hashes together (for quad trees).
    fn hash_quad(a: &Hash, b: &Hash, c: &Hash, d: &Hash) -> Hash {
        let mut combined = [0u8; 128];
        combined[..32].copy_from_slice(a);
        combined[32..64].copy_from_slice(b);
        combined[64..96].copy_from_slice(c);
        combined[96..].copy_from_slice(d);
        Self::hash(&combined)
    }
}

/// SHA-256 hash strategy.
#[derive(Clone, Default)]
pub struct Sha256Hasher;

impl HashStrategy for Sha256Hasher {
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// BLAKE3 hash strategy.
#[derive(Clone, Default)]
pub struct Blake3Hasher;

impl HashStrategy for Blake3Hasher {
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Blake3HasherInner::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(result.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Sha256Hasher::hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_different_inputs() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Sha256Hasher::hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn blake3_deterministic() {
        let a = Blake3Hasher::hash(b"hello");
        let b = Blake3Hasher::hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_vs_blake3_different() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Blake3Hasher::hash(b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_pair_differs_from_single() {
        let a = Sha256Hasher::hash(b"hello");
        let b = Sha256Hasher::hash(b"world");
        let pair = Sha256Hasher::hash_pair(&a, &b);
        assert_ne!(pair, a);
        assert_ne!(pair, b);
    }
}
