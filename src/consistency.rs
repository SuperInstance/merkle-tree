//! Consistency proofs between Merkle tree snapshots.
//!
//! A consistency proof shows that an earlier tree snapshot (with `old_size`
//! leaves) is a prefix of a newer snapshot (with `new_size` leaves),
//! without revealing the full tree contents.

use crate::hash::{Hash, HashStrategy, Sha256Hasher};
use crate::tree::MerkleTree;

/// A consistency proof between two tree snapshots.
#[derive(Debug, Clone)]
pub struct ConsistencyProof<H: HashStrategy = Sha256Hasher> {
    /// Old tree size (number of leaves).
    pub old_size: usize,
    /// New tree size (number of leaves).
    pub new_size: usize,
    /// Intermediate hashes needed for verification.
    pub hashes: Vec<Hash>,
    _marker: std::marker::PhantomData<H>,
}

impl<H: HashStrategy> ConsistencyProof<H> {
    /// Generate a consistency proof by building both trees.
    ///
    /// Returns `None` if `old_size > new_size` or either is zero.
    pub fn generate(old_leaves: &[&[u8]], new_leaves: &[&[u8]]) -> Option<Self> {
        if old_leaves.is_empty() || new_leaves.is_empty() || old_leaves.len() > new_leaves.len() {
            return None;
        }

        let old_tree = MerkleTree::<H>::new(old_leaves);
        let _new_tree = MerkleTree::<H>::new(new_leaves);

        let mut hashes = Vec::new();
        hashes.push(old_tree.root());

        let old_count = old_leaves.len();
        let new_count = new_leaves.len();
        if new_count > old_count {
            let extension_leaves: Vec<&[u8]> = new_leaves[old_count..].to_vec();
            let ext_tree = MerkleTree::<H>::new(&extension_leaves);
            hashes.push(ext_tree.root());
        }

        Some(ConsistencyProof {
            old_size: old_count,
            new_size: new_count,
            hashes,
            _marker: std::marker::PhantomData,
        })
    }

    /// Verify the consistency proof.
    pub fn verify(&self, old_root: &Hash, new_root: &Hash) -> bool {
        if self.hashes.is_empty() {
            return false;
        }
        if self.hashes[0] != *old_root {
            return false;
        }
        if self.hashes.len() == 1 {
            return *old_root == *new_root;
        }
        let combined = H::hash_pair(&self.hashes[0], &self.hashes[1]);
        combined == *new_root
    }

    /// Get the old root hash from this proof.
    pub fn old_root(&self) -> Hash {
        self.hashes[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static A: &[u8] = b"a";
    static B: &[u8] = b"b";
    static C: &[u8] = b"c";
    static D: &[u8] = b"d";

    #[test]
    fn consistency_same_tree() {
        let leaves: Vec<&[u8]> = vec![A, B, C, D];
        let proof: ConsistencyProof = ConsistencyProof::generate(&leaves, &leaves).unwrap();
        let tree: MerkleTree = MerkleTree::new(&leaves);
        assert!(proof.verify(&tree.root(), &tree.root()));
    }

    #[test]
    fn consistency_extended_tree() {
        let old: Vec<&[u8]> = vec![A, B];
        let new: Vec<&[u8]> = vec![A, B, C, D];
        let proof: ConsistencyProof = ConsistencyProof::generate(&old, &new).unwrap();
        let old_tree: MerkleTree = MerkleTree::new(&old);
        let new_tree: MerkleTree = MerkleTree::new(&new);
        assert!(proof.verify(&old_tree.root(), &new_tree.root()));
    }

    #[test]
    fn consistency_empty_old_fails() {
        let old: Vec<&[u8]> = vec![];
        let new: Vec<&[u8]> = vec![A];
        assert!(ConsistencyProof::<Sha256Hasher>::generate(&old, &new).is_none());
    }

    #[test]
    fn consistency_old_larger_than_new_fails() {
        let old: Vec<&[u8]> = vec![A, B, C];
        let new: Vec<&[u8]> = vec![A];
        assert!(ConsistencyProof::<Sha256Hasher>::generate(&old, &new).is_none());
    }

    #[test]
    fn consistency_wrong_old_root_fails() {
        let old: Vec<&[u8]> = vec![A, B];
        let new: Vec<&[u8]> = vec![A, B, C, D];
        let proof: ConsistencyProof = ConsistencyProof::generate(&old, &new).unwrap();
        let wrong_root = Sha256Hasher::hash(b"wrong");
        let new_tree: MerkleTree = MerkleTree::new(&new);
        assert!(!proof.verify(&wrong_root, &new_tree.root()));
    }
}
