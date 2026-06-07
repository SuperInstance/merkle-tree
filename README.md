# merkle-tree

A pure-Rust implementation of Merkle trees with no external dependencies.

## Features

- **Tree Construction** — Build Merkle trees from leaf data
- **Proof Generation** — Generate Merkle inclusion proofs
- **Proof Verification** — Verify proofs against a known root hash
- **Hash Function** — Built-in hash for tree nodes
- **Incremental Updates** — Update leaves and recompute root efficiently

## Usage

```rust
use merkle_tree::tree::MerkleTree;

let leaves = vec![b"hello".to_vec(), b"world".to_vec(), b"foo".to_vec(), b"bar".to_vec()];
let tree = MerkleTree::new(&leaves);
let proof = tree.proof(0);
assert!(proof.verify(&tree.root(), &leaves[0]));
```

## Test Coverage

16+ tests covering inclusion proofs, consistency proofs, leaf insertion, root computation, and proof invalidation on tampering.

## License

MIT OR Apache-2.0
