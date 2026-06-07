//! # merkle-tree
//!
//! A comprehensive Merkle tree library supporting binary and quad tree variants,
//! proof generation and verification, batch proofs, and consistency proofs.
//!
//! ## Modules
//!
//! - [`tree`] — Merkle tree construction (binary and quad variants)
//! - [`proof`] — Membership proof generation and verification
//! - [`hash`] — Pluggable hash strategies (SHA-256, BLAKE3)
//! - [`batch`] — Batch membership proofs for multiple leaves
//! - [`consistency`] — Consistency proofs between tree snapshots

pub mod hash;
pub mod tree;
pub mod proof;
pub mod batch;
pub mod consistency;

pub use hash::{HashStrategy, Sha256Hasher, Blake3Hasher};
pub use tree::{MerkleTree, NodeType};
pub use proof::{MerkleProof, ProofNode};
pub use batch::BatchProof;
pub use consistency::ConsistencyProof;
