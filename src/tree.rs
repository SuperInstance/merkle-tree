//! Merkle tree construction and operations.

use crate::hash::hash_pair;
use crate::leaf::Leaf;
use crate::proof::{Direction, MerkleProof};

/// A Merkle tree.
pub struct MerkleTree {
    /// All nodes in the tree stored level by level.
    /// levels[0] = leaf level, levels[last] = root.
    pub levels: Vec<Vec<[u8; 32]>>,
    /// Number of leaves.
    pub leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![[0u8; 32]]],
                leaf_count: 0,
            };
        }

        // Hash leaves
        let leaf_hashes: Vec<[u8; 32]> = leaves
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let leaf = Leaf::new(data, i);
                *leaf.hash()
            })
            .collect();

        // Build tree bottom-up
        let mut levels = vec![leaf_hashes];

        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next_level = Vec::new();

            let mut i = 0;
            while i < current.len() {
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    // Duplicate last node if odd number
                    current[i]
                };
                next_level.push(hash_pair(&left, &right));
                i += 2;
            }

            levels.push(next_level);
        }

        Self {
            levels,
            leaf_count: leaves.len(),
        }
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    /// Get the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Generate a Merkle inclusion proof for the leaf at the given index.
    pub fn proof(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.leaf_count, "Leaf index out of range");

        let mut siblings = Vec::new();
        let mut idx = leaf_index;

        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = if idx.is_multiple_of(2) {
                // We're on the left, sibling is on the right
                if idx + 1 < level.len() {
                    (idx + 1, Direction::Right)
                } else {
                    // No right sibling, use self (will be duplicated)
                    (idx, Direction::Right)
                }
            } else {
                // We're on the right, sibling is on the left
                (idx - 1, Direction::Left)
            };

            siblings.push((level[sibling_idx.0], sibling_idx.1));
            idx /= 2;
        }

        MerkleProof::new(siblings, leaf_index)
    }

    /// Get the hash of a specific leaf.
    pub fn leaf_hash(&self, index: usize) -> Option<&[u8; 32]> {
        self.levels.first().and_then(|l| l.get(index))
    }

    /// Get tree height (number of levels).
    pub fn height(&self) -> usize {
        self.levels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(&[]);
        let _root = tree.root();
        // Just check it doesn't panic
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let leaves: Vec<Vec<u8>> = vec![b"hello".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let proof = tree.proof(0);
        assert!(proof.verify(&tree.root(), &leaves[0]));
    }

    #[test]
    fn test_two_leaves() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::new(&leaves);
        assert!(tree.proof(0).verify(&tree.root(), &leaves[0]));
        assert!(tree.proof(1).verify(&tree.root(), &leaves[1]));
    }

    #[test]
    fn test_four_leaves() {
        let leaves: Vec<Vec<u8>> = vec![
            b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec(),
        ];
        let tree = MerkleTree::new(&leaves);
        for i in 0..4 {
            assert!(tree.proof(i).verify(&tree.root(), &leaves[i]));
        }
    }

    #[test]
    fn test_tree_height() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);
        assert_eq!(tree.height(), 3); // leaf level + 2 internal levels
    }

    #[test]
    fn test_root_deterministic() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let t1 = MerkleTree::new(&leaves);
        let t2 = MerkleTree::new(&leaves);
        assert_eq!(t1.root(), t2.root());
    }
}
