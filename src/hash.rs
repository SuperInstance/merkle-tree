//! Hash function for Merkle tree nodes.

/// A simple hash function producing 32-byte digests.
/// Uses a Davies-Meyer-like construction for educational purposes.
pub fn merkle_hash(data: &[u8]) -> [u8; 32] {
    let mut state: [u64; 4] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
    ];

    // Process in 64-byte blocks
    for chunk in data.chunks(64) {
        let mut block = [0u8; 64];
        block[..chunk.len()].copy_from_slice(chunk);

        for j in 0..8 {
            let word = u64::from_le_bytes(block[j * 8..(j + 1) * 8].try_into().unwrap());
            state[j % 4] ^= word;
            state[j % 4] = state[j % 4].wrapping_add(word.rotate_left((j as u32) * 11 + 7));
            state[j % 4] ^= state[j % 4].rotate_right(23);
        }
    }

    // Length mixing
    let len = data.len() as u64;
    state[0] = state[0].wrapping_add(len);
    state[1] ^= len.wrapping_mul(0x9e3779b97f4a7c15);
    state[2] = state[2].wrapping_add(state[0].rotate_right(17));
    state[3] ^= state[1].rotate_right(31);

    // Output
    let mut output = [0u8; 32];
    for (i, &s) in state.iter().enumerate() {
        output[i * 8..(i + 1) * 8].copy_from_slice(&s.to_le_bytes());
    }
    output
}

/// Hash two node hashes together to produce a parent hash.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 65];
    combined[..32].copy_from_slice(left);
    combined[32..64].copy_from_slice(right);
    combined[64] = 1; // domain separator for internal nodes
    merkle_hash(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let h1 = merkle_hash(b"hello");
        let h2 = merkle_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = merkle_hash(b"hello");
        let h2 = merkle_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_pair_commutative_different() {
        let h1 = merkle_hash(b"a");
        let h2 = merkle_hash(b"b");
        let p1 = hash_pair(&h1, &h2);
        let p2 = hash_pair(&h2, &h1);
        assert_ne!(p1, p2); // Order matters
    }
}
