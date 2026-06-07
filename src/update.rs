//! Incremental Merkle tree updates.

use crate::hash::hash_pair;
use crate::tree::MerkleTree;

/// Update a single leaf in the tree and recompute the root.
/// Returns the new root hash without rebuilding the entire tree.
pub fn update_leaf(
    tree: &MerkleTree,
    leaf_index: usize,
    new_data: &[u8],
) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut levels = tree.levels.clone();

    // Update the leaf hash
    let mut prefixed = vec![0u8];
    prefixed.extend_from_slice(new_data);
    let new_hash = crate::hash::merkle_hash(&prefixed);
    levels[0][leaf_index] = new_hash;

    // Recompute up the tree
    let mut idx = leaf_index;
    for level_idx in 0..levels.len() - 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            if idx + 1 < levels[level_idx].len() { idx + 1 } else { idx }
        } else {
            idx - 1
        };

        let left = levels[level_idx][if idx.is_multiple_of(2) { idx } else { sibling_idx }];
        let right = levels[level_idx][if idx.is_multiple_of(2) { sibling_idx } else { idx }];
        let parent = hash_pair(&left, &right);

        idx /= 2;
        if idx < levels[level_idx + 1].len() {
            levels[level_idx + 1][idx] = parent;
        }
    }

    let new_root = levels.last().unwrap()[0];
    (new_root, levels)
}

/// Batch update multiple leaves and recompute the root.
pub fn batch_update(
    tree: &MerkleTree,
    updates: &[(usize, Vec<u8>)],
) -> [u8; 32] {
    let mut levels = tree.levels.clone();

    // Apply all leaf updates
    for &(leaf_index, ref data) in updates {
        let mut prefixed = vec![0u8];
        prefixed.extend_from_slice(data.as_slice());
        levels[0][leaf_index] = crate::hash::merkle_hash(&prefixed);
    }

    // Recompute all levels
    for level_idx in 0..levels.len() - 1 {
        let mut next_level = Vec::new();
        let current = &levels[level_idx];
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() { current[i + 1] } else { current[i] };
            next_level.push(hash_pair(&left, &right));
            i += 2;
        }
        levels[level_idx + 1] = next_level;
    }

    levels.last().unwrap()[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_update() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);
        let old_root = tree.root();

        let (new_root, new_levels) = update_leaf(&tree, 0, b"x");
        assert_ne!(new_root, old_root);

        // Verify proof against new tree
        let new_tree = MerkleTree {
            levels: new_levels,
            leaf_count: tree.leaf_count(),
        };
        let proof = new_tree.proof(0);
        assert!(proof.verify(&new_root, b"x"));
    }

    #[test]
    fn test_batch_update() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::new(&leaves);

        let updates = vec![(0, b"x".to_vec()), (2, b"y".to_vec())];
        let new_root = batch_update(&tree, &updates);

        // Verify by building a fresh tree
        let new_leaves: Vec<Vec<u8>> = vec![b"x".to_vec(), b"b".to_vec(), b"y".to_vec(), b"d".to_vec()];
        let fresh_tree = MerkleTree::new(&new_leaves);
        assert_eq!(new_root, fresh_tree.root());
    }

    #[test]
    fn test_update_all_same() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::new(&leaves);
        // Update with same value - root should not change
        let (new_root, _) = update_leaf(&tree, 0, b"a");
        assert_eq!(new_root, tree.root());
    }
}
