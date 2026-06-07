//! Membership proof generation and verification for binary Merkle trees.
//!
//! A [`MerkleProof`] contains the sibling hashes needed to reconstruct
//! the root from a given leaf.

use crate::hash::{Hash, HashStrategy, Sha256Hasher};
use crate::tree::MerkleTree;

/// Direction of a proof node relative to the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofNode {
    /// Sibling is on the left.
    Left(Hash),
    /// Sibling is on the right.
    Right(Hash),
}

/// A Merkle membership proof.
#[derive(Debug, Clone)]
pub struct MerkleProof<H: HashStrategy = Sha256Hasher> {
    /// Index of the leaf.
    pub leaf_index: usize,
    /// Sibling hashes along the path.
    pub siblings: Vec<ProofNode>,
    /// The expected root hash.
    pub root: Hash,
    _marker: std::marker::PhantomData<H>,
}

impl<H: HashStrategy> MerkleProof<H> {
    /// Generate a membership proof for `leaf_index` in the given binary tree.
    pub fn generate(tree: &MerkleTree<H>, leaf_index: usize) -> Option<Self> {
        if leaf_index >= tree.original_count() {
            return None;
        }

        let num_levels = tree.num_levels();
        // Leaf level is the last level
        let _leaf_level = num_levels - 1;
        let mut pos = leaf_index;
        let mut siblings = Vec::new();

        for level in (1..num_levels).rev() {
            let (level_start, _level_len) = tree.level_info(level);
            let sibling_pos = pos ^ 1; // XOR 1 flips between left/right
            let sibling_idx = level_start + sibling_pos;

            if pos & 1 == 0 {
                // current is left child
                siblings.push(ProofNode::Right(tree.node_at(sibling_idx)));
            } else {
                // current is right child
                siblings.push(ProofNode::Left(tree.node_at(sibling_idx)));
            }

            pos /= 2;
        }

        Some(MerkleProof {
            leaf_index,
            siblings,
            root: tree.root(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Verify the proof against a known leaf hash.
    pub fn verify(&self, leaf_hash: &Hash) -> bool {
        let computed = self.compute_root(leaf_hash);
        computed == self.root
    }

    /// Compute the root from a leaf hash using this proof's siblings.
    pub fn compute_root(&self, leaf_hash: &Hash) -> Hash {
        let mut current = *leaf_hash;
        for sibling in &self.siblings {
            current = match sibling {
                ProofNode::Left(h) => H::hash_pair(h, &current),
                ProofNode::Right(h) => H::hash_pair(&current, h),
            };
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static A: &[u8] = b"a";
    static B: &[u8] = b"b";
    static C: &[u8] = b"c";
    static D: &[u8] = b"d";

    fn build_tree() -> MerkleTree {
        MerkleTree::new(&[A, B, C, D])
    }

    #[test]
    fn valid_proof_verifies() {
        let tree = build_tree();
        let proof = MerkleProof::generate(&tree, 0).unwrap();
        let leaf = Sha256Hasher::hash(A);
        assert!(proof.verify(&leaf));
    }

    #[test]
    fn all_leaves_verify() {
        let tree = build_tree();
        let leaves = [A, B, C, D];
        for (i, leaf_data) in leaves.iter().enumerate() {
            let proof = MerkleProof::generate(&tree, i).unwrap();
            let leaf = Sha256Hasher::hash(leaf_data);
            assert!(proof.verify(&leaf), "proof for leaf {} failed", i);
        }
    }

    #[test]
    fn wrong_leaf_fails() {
        let tree = build_tree();
        let proof = MerkleProof::generate(&tree, 0).unwrap();
        let wrong = Sha256Hasher::hash(b"z");
        assert!(!proof.verify(&wrong));
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let tree = build_tree();
        assert!(MerkleProof::generate(&tree, 99).is_none());
    }

    #[test]
    fn proof_for_padded_tree() {
        static X: &[u8] = b"x";
        static Y: &[u8] = b"y";
        static Z: &[u8] = b"z";
        let tree: MerkleTree = MerkleTree::new(&[X, Y, Z]);
        let proof = MerkleProof::generate(&tree, 2).unwrap();
        let leaf = Sha256Hasher::hash(Z);
        assert!(proof.verify(&leaf));
    }

    #[test]
    fn tampered_root_fails() {
        let tree = build_tree();
        let mut proof = MerkleProof::generate(&tree, 0).unwrap();
        proof.root = [0u8; 32];
        let leaf = Sha256Hasher::hash(A);
        assert!(!proof.verify(&leaf));
    }
}
