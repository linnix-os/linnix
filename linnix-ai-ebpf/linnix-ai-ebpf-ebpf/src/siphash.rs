// =============================================================================
// SipHash-2-4: Cryptographic hash for BPF mandate enforcement
// =============================================================================
//
// Inline `#![no_std]` implementation of SipHash-2-4 for eBPF programs.
// Used to hash canonical command arguments for mandate key construction.
//
// Properties:
//   - 128-bit key, 64-bit output
//   - ~3ns per hash on modern CPUs
//   - Collision-resistant against adversarial inputs
//   - Already used internally by the Linux kernel for hash table randomization
//
// Reference: https://cr.yp.to/siphash/siphash-20120918.pdf
//
// The 128-bit key is seeded from /dev/urandom at eBPF load time and stored
// in BPF .rodata (read-only after load).

/// SipHash-2-4 state.
#[derive(Clone)]
pub struct SipHasher {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: u64,
    count: usize,
}

#[inline(always)]
fn rotl(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

impl SipHasher {
    /// Create a new SipHash-2-4 hasher from a 128-bit key.
    /// `k0` and `k1` are the two 64-bit halves of the key.
    #[inline(always)]
    pub fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            buf: 0,
            count: 0,
        }
    }

    /// Write a single byte into the hasher.
    #[inline(always)]
    pub fn write_byte(&mut self, byte: u8) {
        let shift = (self.count % 8) * 8;
        self.buf |= (byte as u64) << shift;
        self.count += 1;

        if self.count % 8 == 0 {
            self.compress();
        }
    }

    /// Write a slice of bytes into the hasher.
    ///
    /// Note: In BPF context, the caller must ensure the slice length
    /// is bounded (BPF verifier requires bounded loops).
    #[inline(always)]
    pub fn write(&mut self, data: &[u8]) {
        for &b in data {
            self.write_byte(b);
        }
    }

    /// Write a u32 value (little-endian).
    #[inline(always)]
    pub fn write_u32(&mut self, val: u32) {
        let bytes = val.to_le_bytes();
        self.write_byte(bytes[0]);
        self.write_byte(bytes[1]);
        self.write_byte(bytes[2]);
        self.write_byte(bytes[3]);
    }

    /// Write a u64 value (little-endian).
    #[inline(always)]
    #[allow(dead_code)] // Used in Phase 1+ for hashing structured args
    pub fn write_u64(&mut self, val: u64) {
        let bytes = val.to_le_bytes();
        self.write_byte(bytes[0]);
        self.write_byte(bytes[1]);
        self.write_byte(bytes[2]);
        self.write_byte(bytes[3]);
        self.write_byte(bytes[4]);
        self.write_byte(bytes[5]);
        self.write_byte(bytes[6]);
        self.write_byte(bytes[7]);
    }

    /// Compress the current 8-byte buffer block (SipHash-2 rounds).
    #[inline(always)]
    fn compress(&mut self) {
        self.v3 ^= self.buf;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= self.buf;
        self.buf = 0;
    }

    /// Finalize and return the 64-bit hash.
    #[inline(always)]
    pub fn finish(mut self) -> u64 {
        // Pad the final block with the total byte count in the high byte
        let b = (self.count as u64) << 56;
        self.buf |= b;

        // Process final block
        self.v3 ^= self.buf;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= self.buf;

        // Finalization (SipHash-4 rounds)
        self.v2 ^= 0xff;
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);

        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Compute SipHash-2-4 of a byte slice with the given 128-bit key.
///
/// This is the primary entry point for BPF programs hashing command arguments.
/// The key should come from the SIPHASH_KEY BPF .rodata global.
#[inline(always)]
#[allow(dead_code)] // Convenience wrapper used by tests and Phase 1+
pub fn siphash_2_4(key: [u64; 2], data: &[u8]) -> u64 {
    let mut hasher = SipHasher::new(key[0], key[1]);
    hasher.write(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        // SipHash-2-4 of empty input with zero key should produce a deterministic value.
        let hash = siphash_2_4([0, 0], &[]);
        assert_ne!(hash, 0, "empty input should not hash to zero");
    }

    #[test]
    fn test_reference_vector() {
        // Test vector from the SipHash paper (Appendix A).
        // Key: 00 01 02 ... 0f
        // Input: 00 01 02 ... 0e (15 bytes)
        let k0 = u64::from_le_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let k1 = u64::from_le_bytes([0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);

        let input: Vec<u8> = (0..15u8).collect();
        let hash = siphash_2_4([k0, k1], &input);

        // Expected: a129ca6149be45e5 (from reference implementation)
        assert_eq!(
            hash, 0xa129ca6149be45e5,
            "SipHash-2-4 reference vector mismatch"
        );
    }

    #[test]
    fn test_deterministic() {
        let key = [0xdeadbeef_u64, 0xcafebabe_u64];
        let data = b"curl https://example.com";
        let h1 = siphash_2_4(key, data);
        let h2 = siphash_2_4(key, data);
        assert_eq!(h1, h2, "same input must produce same hash");
    }

    #[test]
    fn test_different_inputs() {
        let key = [0xdeadbeef_u64, 0xcafebabe_u64];
        let h1 = siphash_2_4(key, b"curl https://example.com");
        let h2 = siphash_2_4(key, b"wget https://example.com");
        assert_ne!(h1, h2, "different inputs should produce different hashes");
    }

    #[test]
    fn test_different_keys() {
        let data = b"curl https://example.com";
        let h1 = siphash_2_4([1, 2], data);
        let h2 = siphash_2_4([3, 4], data);
        assert_ne!(h1, h2, "different keys should produce different hashes");
    }
}
