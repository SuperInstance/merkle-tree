//! Merkle tree library.
//!
//! Provides Merkle tree construction, proof generation/verification,
//! leaf management, incremental updates, and a built-in hash function.

pub mod hash;
pub mod leaf;
pub mod proof;
pub mod tree;
pub mod update;

pub use tree::MerkleTree;
pub use proof::MerkleProof;
pub use leaf::Leaf;
