//! Merkle tree construction supporting binary and quad variants.
//!
//! Build a [`MerkleTree`] from leaf data and query the root hash,
//! individual leaf hashes, and tree structure.

use crate::hash::{Hash, HashStrategy, Sha256Hasher};

/// The arity of the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Binary tree (2 children per node).
    Binary,
    /// Quad tree (4 children per node).
    Quad,
}

/// Starting index and size of each level in the flat node array.
#[derive(Debug, Clone, Copy)]
struct LevelInfo {
    start: usize,
    len: usize,
}

/// A Merkle tree parameterized by hash strategy and arity.
#[derive(Debug, Clone)]
pub struct MerkleTree<H: HashStrategy = Sha256Hasher> {
    /// Flat array of hashes: root at index 0, then each level top-to-bottom.
    nodes: Vec<Hash>,
    /// Level metadata: level 0 is root, last level is leaves.
    levels: Vec<LevelInfo>,
    /// Number of leaves (padded to power of arity).
    leaf_count: usize,
    /// Original number of leaves before padding.
    original_count: usize,
    /// Tree arity.
    node_type: NodeType,
    _marker: std::marker::PhantomData<H>,
}

impl<H: HashStrategy> MerkleTree<H> {
    /// Build a binary Merkle tree from leaf data slices.
    pub fn new(leaves: &[&[u8]]) -> Self {
        Self::build(leaves, NodeType::Binary)
    }

    /// Build a quad Merkle tree from leaf data slices.
    pub fn new_quad(leaves: &[&[u8]]) -> Self {
        Self::build(leaves, NodeType::Quad)
    }

    /// General build method.
    fn build(leaves: &[&[u8]], node_type: NodeType) -> Self {
        assert!(!leaves.is_empty(), "need at least one leaf");

        let arity = match node_type {
            NodeType::Binary => 2,
            NodeType::Quad => 4,
        };

        let original_count = leaves.len();
        let leaf_count = next_power(leaves.len(), arity);

        let mut hashes: Vec<Hash> = leaves.iter().map(|l| H::hash(l)).collect();
        let zero_hash = H::hash(&[]);
        while hashes.len() < leaf_count {
            hashes.push(zero_hash);
        }

        // Build bottom-up, collecting levels from leaves to root.
        let mut raw_levels: Vec<Vec<Hash>> = vec![hashes];

        while raw_levels.last().unwrap().len() > 1 {
            let current = raw_levels.last().unwrap();
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                match node_type {
                    NodeType::Binary => {
                        let a = current[i];
                        let b = if i + 1 < current.len() { current[i + 1] } else { zero_hash };
                        next.push(H::hash_pair(&a, &b));
                    }
                    NodeType::Quad => {
                        let a = current[i];
                        let b = if i + 1 < current.len() { current[i + 1] } else { zero_hash };
                        let c = if i + 2 < current.len() { current[i + 2] } else { zero_hash };
                        let d = if i + 3 < current.len() { current[i + 3] } else { zero_hash };
                        next.push(H::hash_quad(&a, &b, &c, &d));
                    }
                }
                i += arity;
            }
            raw_levels.push(next);
        }

        // Reverse so index 0 = root, last = leaves.
        raw_levels.reverse();

        let mut nodes = Vec::new();
        let mut levels = Vec::new();
        for level in &raw_levels {
            let start = nodes.len();
            levels.push(LevelInfo {
                start,
                len: level.len(),
            });
            nodes.extend(level.iter().copied());
        }

        Self {
            nodes,
            levels,
            leaf_count,
            original_count,
            node_type,
            _marker: std::marker::PhantomData,
        }
    }

    /// The Merkle root hash.
    pub fn root(&self) -> Hash {
        self.nodes[0]
    }

    /// Number of leaves (including padding).
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Number of original (non-padded) leaves.
    pub fn original_count(&self) -> usize {
        self.original_count
    }

    /// Get the leaf hash at the given index.
    pub fn leaf_hash(&self, index: usize) -> Option<Hash> {
        if index >= self.original_count {
            return None;
        }
        let leaf_level = self.levels.last().unwrap();
        Some(self.nodes[leaf_level.start + index])
    }

    /// Get the arity of this tree.
    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    /// Total node count.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return a reference to all leaf hashes.
    pub fn leaf_hashes(&self) -> &[Hash] {
        let leaf_level = self.levels.last().unwrap();
        &self.nodes[leaf_level.start..leaf_level.start + leaf_level.len]
    }

    /// Number of levels in the tree.
    pub fn height(&self) -> usize {
        self.levels.len()
    }

    /// Get the node at a flat index.
    pub(crate) fn node_at(&self, index: usize) -> Hash {
        self.nodes[index]
    }

    /// Get the level info for a given level index (0 = root).
    pub(crate) fn level_info(&self, level: usize) -> (usize, usize) {
        let info = &self.levels[level];
        (info.start, info.len)
    }

    /// Number of levels.
    pub(crate) fn num_levels(&self) -> usize {
        self.levels.len()
    }
}

fn next_power(n: usize, base: usize) -> usize {
    if n == 0 {
        return base;
    }
    let mut p = base;
    while p < n {
        p *= base;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake3Hasher;

    static L0: &[u8] = b"leaf0";
    static L1: &[u8] = b"leaf1";
    static L2: &[u8] = b"leaf2";
    static L3: &[u8] = b"leaf3";

    fn sample_leaves() -> Vec<&'static [u8]> {
        vec![L0, L1, L2, L3]
    }

    #[test]
    fn binary_tree_root_consistent() {
        let tree: MerkleTree = MerkleTree::new(&sample_leaves());
        let root = tree.root();
        let tree2: MerkleTree = MerkleTree::new(&sample_leaves());
        assert_eq!(root, tree2.root());
    }

    #[test]
    fn binary_tree_different_data_different_root() {
        static A: &[u8] = b"a";
        static B: &[u8] = b"b";
        static C: &[u8] = b"c";
        static D: &[u8] = b"d";
        let t1: MerkleTree = MerkleTree::new(&sample_leaves());
        let t2: MerkleTree = MerkleTree::new(&[A, B, C, D]);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn binary_tree_pads_to_power_of_two() {
        static A: &[u8] = b"a";
        static B: &[u8] = b"b";
        static C: &[u8] = b"c";
        let tree: MerkleTree = MerkleTree::new(&[A, B, C]);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.original_count(), 3);
    }

    #[test]
    fn quad_tree_builds() {
        let tree: MerkleTree = MerkleTree::new_quad(&sample_leaves());
        assert_eq!(tree.node_type(), NodeType::Quad);
        assert_eq!(tree.leaf_count(), 4);
    }

    #[test]
    fn quad_tree_root_consistent() {
        let t1: MerkleTree = MerkleTree::new_quad(&sample_leaves());
        let t2: MerkleTree = MerkleTree::new_quad(&sample_leaves());
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn blake3_strategy() {
        let tree: MerkleTree<Blake3Hasher> = MerkleTree::new(&sample_leaves());
        let sha_tree: MerkleTree = MerkleTree::new(&sample_leaves());
        assert_ne!(tree.root(), sha_tree.root());
    }

    #[test]
    fn leaf_hash_access() {
        let tree: MerkleTree = MerkleTree::new(&sample_leaves());
        let h0 = tree.leaf_hash(0).unwrap();
        assert_eq!(h0, Sha256Hasher::hash(L0));
        assert!(tree.leaf_hash(99).is_none());
    }

    #[test]
    fn single_leaf() {
        static SOLO: &[u8] = b"solo";
        let tree: MerkleTree = MerkleTree::new(&[SOLO]);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.original_count(), 1);
        let root = tree.root();
        let solo = Sha256Hasher::hash(SOLO);
        let empty = Sha256Hasher::hash(&[]);
        let expected = Sha256Hasher::hash_pair(&solo, &empty);
        assert_eq!(root, expected);
    }
}
