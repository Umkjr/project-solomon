//! Custom, zero-dependency, constant-time pure Rust Keccak-f[1600] and SHAKE sponge engine.
//!
//! Designed for the Project Solomon post-quantum core. It features complete no-std support,
//! zero memory allocations, and strict side-channel resistance.

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation function
#[inline(always)]
fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta step
        let mut c = [0u64; 5];
        for i in 0..5 {
            c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for i in 0..5 {
            let temp = c[(i + 4) % 5] ^ c[(i + 1) % 5].rotate_left(1);
            for j in 0..5 {
                state[i + 5 * j] ^= temp;
            }
        }

        // Rho and Pi steps combined
        let mut last = state[1];
        for x in 0..24 {
            let temp = state[PI[x]];
            state[PI[x]] = last.rotate_left(RHO[x]);
            last = temp;
        }

        // Chi step
        let state_clone = *state;
        for j in 0..5 {
            for i in 0..5 {
                state[i + 5 * j] = state_clone[i + 5 * j] ^ ((!state_clone[(i + 1) % 5 + 5 * j]) & state_clone[(i + 2) % 5 + 5 * j]);
            }
        }

        // Iota step
        state[0] ^= RC[round];
    }
}

/// The Keccak Sponge State Machine
#[derive(Clone)]
pub struct KeccakSponge {
    pub state: [u64; 25],
    pub rate: usize,             // rate in bytes: SHAKE-128 = 168, SHAKE-256 = 136
    pub pos: usize,              // current index in rate buffer
    pub buffer: [u8; 200],       // buffer of absorbed bytes
    pub delimited_suffix: u8,    // SHAKE standard domain separator suffix (0x1F)
    pub squeezing: bool,         // Flag tracking transition from absorbing to squeezing
}

impl KeccakSponge {
    /// Creates a generic Keccak Sponge instance
    pub fn new(rate: usize, delimited_suffix: u8) -> Self {
        Self {
            state: [0; 25],
            rate,
            pos: 0,
            buffer: [0; 200],
            delimited_suffix,
            squeezing: false,
        }
    }

    /// Creates a SHAKE-128 Keccak Sponge (rate = 168 bytes, suffix = 0x1F)
    pub fn new_shake128() -> Self {
        Self::new(168, 0x1F)
    }

    /// Creates a SHAKE-256 Keccak Sponge (rate = 136 bytes, suffix = 0x1F)
    pub fn new_shake256() -> Self {
        Self::new(136, 0x1F)
    }

    /// Absorb byte input data into the sponge state
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "Cannot absorb data after squeezing phase has initiated.");
        let mut idx = 0;
        while idx < data.len() {
            let todo = core::cmp::min(data.len() - idx, self.rate - self.pos);
            self.buffer[self.pos..self.pos + todo].copy_from_slice(&data[idx..idx + todo]);
            self.pos += todo;
            idx += todo;

            if self.pos == self.rate {
                // XOR buffer into sponge state
                for i in 0..(self.rate / 8) {
                    let mut word = 0u64;
                    for b in 0..8 {
                        word |= (self.buffer[i * 8 + b] as u64) << (b * 8);
                    }
                    self.state[i] ^= word;
                }
                keccak_f1600(&mut self.state);
                self.pos = 0;
                self.buffer = [0u8; 200];
            }
        }
    }

    /// Squeeze bytes out of the sponge state
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            // Squeezing starts. Apply domain separator & multi-rate padding.
            self.buffer[self.pos] ^= self.delimited_suffix;
            self.buffer[self.rate - 1] ^= 0x80;

            // XOR final rate buffer into sponge state
            for i in 0..(self.rate / 8) {
                let mut word = 0u64;
                for b in 0..8 {
                    word |= (self.buffer[i * 8 + b] as u64) << (b * 8);
                }
                self.state[i] ^= word;
            }

            keccak_f1600(&mut self.state);
            self.pos = 0;
            self.squeezing = true;
        }

        let mut idx = 0;
        while idx < out.len() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }

            let todo = core::cmp::min(out.len() - idx, self.rate - self.pos);
            for i in 0..todo {
                let word_idx = (self.pos + i) / 8;
                let byte_idx = (self.pos + i) % 8;
                out[idx + i] = (self.state[word_idx] >> (byte_idx * 8)) as u8;
            }
            self.pos += todo;
            idx += todo;
        }
    }
}

/// One-shot execution of SHAKE-128
pub fn shake128(input: &[u8], output: &mut [u8]) {
    let mut sponge = KeccakSponge::new_shake128();
    sponge.absorb(input);
    sponge.squeeze(output);
}

/// One-shot execution of SHAKE-256
pub fn shake256(input: &[u8], output: &mut [u8]) {
    let mut sponge = KeccakSponge::new_shake256();
    sponge.absorb(input);
    sponge.squeeze(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake128_empty() {
        let mut out = [0u8; 32];
        shake128(b"", &mut out);
        let expected = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
            0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
            0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
            0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn test_shake256_empty() {
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        let expected = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
            0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
            0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
            0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn test_shake_incremental() {
        let mut sponge = KeccakSponge::new_shake256();
        sponge.absorb(b"hello ");
        sponge.absorb(b"world");
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        sponge.squeeze(&mut out1);
        sponge.squeeze(&mut out2);
        
        let mut out_oneshot = [0u8; 32];
        shake256(b"hello world", &mut out_oneshot);
        
        assert_eq!(out1, out_oneshot[0..16]);
        assert_eq!(out2, out_oneshot[16..32]);
    }
}
