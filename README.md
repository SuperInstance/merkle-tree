# merkle-tree

A comprehensive Merkle tree library for Rust supporting binary and quad tree variants,
proof generation/verification, batch proofs, and consistency proofs.

## Features

- **Binary and quad Merkle trees** — choose your arity
- **Pluggable hash strategies** — SHA-256 and BLAKE3 built in
- **Membership proofs** — generate and verify Merkle proofs
- **Batch proofs** — verify multiple leaves at once
- **Consistency proofs** — prove tree snapshots are consistent

## Usage

```rust
use merkle_tree::{MerkleTree, MerkleProof, Sha256Hasher};

// Build a tree
let tree = MerkleTree::new(&vec![b"hello", b"world", b"foo", b"bar"]);

// Get the root
let root = tree.root();

// Generate a proof for leaf 0
let proof = MerkleProof::generate(&tree, 0).unwrap();
let leaf_hash = Sha256Hasher::hash(b"hello");

// Verify
assert!(proof.verify(&leaf_hash));
```

## License

MIT OR Apache-2.0
