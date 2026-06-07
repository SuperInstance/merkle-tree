//! Merkle proof generation and verification.

use crate::hash::hash_pair;

/// Direction of a sibling in a Merkle proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Sibling is on the left (we're on the right).
    Left,
    /// Sibling is on the right (we're on the left).
    Right,
}

/// A Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root.
    siblings: Vec<([u8; 32], Direction)>,
    /// Index of the leaf being proved.
    leaf_index: usize,
}

impl MerkleProof {
    /// Create a new Merkle proof.
    pub fn new(siblings: Vec<([u8; 32], Direction)>, leaf_index: usize) -> Self {
        Self { siblings, leaf_index }
    }

    /// Verify this proof against a known root hash and leaf hash.
    pub fn verify_with_hash(&self, root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
        let mut current = *leaf_hash;

        for (sibling, direction) in &self.siblings {
            current = match direction {
                Direction::Left => hash_pair(sibling, &current),
                Direction::Right => hash_pair(&current, sibling),
            };
        }

        let mut diff = 0u8;
        for (a, b) in current.iter().zip(root.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Verify this proof against a root and leaf data.
    pub fn verify(&self, root: &[u8; 32], leaf_data: &[u8]) -> bool {
        let mut prefixed = vec![0u8];
        prefixed.extend_from_slice(leaf_data);
        let leaf_hash = crate::hash::merkle_hash(&prefixed);
        self.verify_with_hash(root, &leaf_hash)
    }

    /// Get the number of levels in the proof.
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    /// Check if the proof is empty.
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Get the leaf index.
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// Get the siblings.
    pub fn siblings(&self) -> &[([u8; 32], Direction)] {
        &self.siblings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MerkleTree;

    #[test]
    fn test_proof_verification() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(0);
        assert!(proof.verify(&tree.root(), &leaves[0]));
    }

    #[test]
    fn test_proof_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(0);
        assert!(!proof.verify(&tree.root(), b"x"));
    }

    #[test]
    fn test_proof_wrong_root() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(0);
        let bad_root = [0u8; 32];
        assert!(!proof.verify(&bad_root, &leaves[0]));
    }

    #[test]
    fn test_proof_tampering_detected() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let mut proof = tree.proof(1);
        // Tamper with a sibling hash
        if !proof.siblings.is_empty() {
            proof.siblings[0].0[0] ^= 0xFF;
        }
        assert!(!proof.verify(&tree.root(), &leaves[1]));
    }
}
