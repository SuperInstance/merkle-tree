//! Leaf node utilities.

use crate::hash::merkle_hash;

/// A leaf in the Merkle tree with its hash and optional data reference.
#[derive(Clone, Debug)]
pub struct Leaf {
    /// Hash of the leaf data.
    hash: [u8; 32],
    /// Index of this leaf in the tree.
    index: usize,
}

impl Leaf {
    /// Create a new leaf from raw data.
    pub fn new(data: &[u8], index: usize) -> Self {
        let mut prefixed = vec![0u8]; // domain separator for leaf
        prefixed.extend_from_slice(data);
        Self {
            hash: merkle_hash(&prefixed),
            index,
        }
    }

    /// Create a leaf from an existing hash.
    pub fn from_hash(hash: [u8; 32], index: usize) -> Self {
        Self { hash, index }
    }

    /// Get the leaf hash.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Get the leaf index.
    pub fn index(&self) -> usize {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_deterministic() {
        let l1 = Leaf::new(b"hello", 0);
        let l2 = Leaf::new(b"hello", 1);
        assert_eq!(l1.hash(), l2.hash()); // same data = same hash
    }

    #[test]
    fn test_leaf_different_data() {
        let l1 = Leaf::new(b"hello", 0);
        let l2 = Leaf::new(b"world", 0);
        assert_ne!(l1.hash(), l2.hash());
    }
}
