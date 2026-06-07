//! Batch membership proofs for verifying multiple leaves at once.
//!
//! [`BatchProof`] stores proofs for multiple leaves and supports
//! efficient batch verification.

use crate::hash::{Hash, HashStrategy, Sha256Hasher};
use crate::proof::MerkleProof;
use crate::tree::MerkleTree;

/// A batch of Merkle membership proofs sharing the same root.
#[derive(Debug, Clone)]
pub struct BatchProof<H: HashStrategy = Sha256Hasher> {
    pub proofs: Vec<MerkleProof<H>>,
}

impl<H: HashStrategy> BatchProof<H> {
    /// Generate batch proofs for the given leaf indices.
    pub fn generate(tree: &MerkleTree<H>, indices: &[usize]) -> Option<Self> {
        let proofs: Option<Vec<_>> = indices
            .iter()
            .map(|&i| MerkleProof::generate(tree, i))
            .collect();
        proofs.map(|p| BatchProof { proofs: p })
    }

    /// Verify all proofs against the given leaf hashes.
    pub fn verify(&self, leaf_hashes: &[Hash]) -> bool {
        if leaf_hashes.len() != self.proofs.len() {
            return false;
        }
        let root = self.proofs[0].root;
        self.proofs
            .iter()
            .zip(leaf_hashes)
            .all(|(proof, leaf)| proof.root == root && proof.verify(leaf))
    }

    /// Number of proofs in this batch.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static A: &[u8] = b"a";
    static B: &[u8] = b"b";
    static C: &[u8] = b"c";
    static D: &[u8] = b"d";
    static E: &[u8] = b"e";
    static F: &[u8] = b"f";
    static G: &[u8] = b"g";
    static H_: &[u8] = b"h";

    fn build_tree() -> MerkleTree {
        MerkleTree::new(&[A, B, C, D, E, F, G, H_])
    }

    #[test]
    fn batch_verify_all() {
        let tree = build_tree();
        let indices = vec![0, 2, 5, 7];
        let batch = BatchProof::generate(&tree, &indices).unwrap();
        let leaves = [A, B, C, D, E, F, G, H_];
        let hashes: Vec<Hash> = indices.iter().map(|&i| Sha256Hasher::hash(leaves[i])).collect();
        assert!(batch.verify(&hashes));
    }

    #[test]
    fn batch_single_proof() {
        let tree = build_tree();
        let batch = BatchProof::generate(&tree, &[0]).unwrap();
        let hash = Sha256Hasher::hash(A);
        assert!(batch.verify(&[hash]));
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn batch_wrong_count_fails() {
        let tree = build_tree();
        let batch = BatchProof::generate(&tree, &[0, 1]).unwrap();
        assert!(!batch.verify(&[Sha256Hasher::hash(A)]));
    }

    #[test]
    fn batch_with_wrong_leaf_fails() {
        let tree = build_tree();
        let batch = BatchProof::generate(&tree, &[0, 1]).unwrap();
        let hashes = vec![Sha256Hasher::hash(A), Sha256Hasher::hash(b"WRONG")];
        assert!(!batch.verify(&hashes));
    }

    #[test]
    fn batch_out_of_bounds() {
        let tree = build_tree();
        assert!(BatchProof::generate(&tree, &[0, 99]).is_none());
    }
}
