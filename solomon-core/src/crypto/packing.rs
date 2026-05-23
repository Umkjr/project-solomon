//! Precise bit-packing and serialization/deserialization for ML-DSA-65.
//!
//! This module implements precise, zero-dependency serializers and deserializers for
//! public keys, private keys, and signatures as defined in the FIPS 204 specification.
//!
//! Specifically:
//! - Public Key (1952 bytes): rho (32 bytes) + t1 (1920 bytes: 6 polys * 320 bytes, 10-bit packed)
//! - Private Key (4032 bytes): rho (32 bytes) + K (32 bytes) + tr (64 bytes) + s1 (640 bytes: 5 polys * 128 bytes, 4-bit packed) + s2 (768 bytes: 6 polys * 128 bytes, 4-bit packed) + t0 (2496 bytes: 6 polys * 416 bytes, 13-bit packed)
//! - Signature (3309 bytes): c_tilde (48 bytes) + z (3200 bytes: 5 polys * 640 bytes, 20-bit packed) + h (61 bytes, packed indices)

use crate::crypto::poly::Polynomial;
use crate::crypto::matrix::PolyVector;
use crate::crypto::scalar::Q;
use crate::error::MlDsaError;

const GAMMA1: i32 = 524288; // 2^19

// --- Helper Functions for Signed Representative Mapping ---

#[inline(always)]
fn to_signed(coeff: i32) -> i32 {
    let limit = (Q - 1) / 2;
    let diff = limit - coeff;
    let mask = diff >> 31; // -1 if coeff > limit, 0 otherwise
    (coeff & !mask) | ((coeff - Q) & mask)
}

#[inline(always)]
fn to_canonical(val: i32) -> i32 {
    let mask = val >> 31; // -1 if val < 0, 0 otherwise
    val + (Q & mask)
}

// --- 10-bit packing/unpacking for t1 ---

fn pack_t1_poly(poly: &Polynomial, buf: &mut [u8]) {
    // 256 coefficients -> packed into 320 bytes (10 bits per coefficient)
    // 4 coefficients take 40 bits = 5 bytes
    for i in 0..64 {
        let c0 = to_signed(poly.coeffs[4 * i]) as u32 & 0x3FF;
        let c1 = to_signed(poly.coeffs[4 * i + 1]) as u32 & 0x3FF;
        let c2 = to_signed(poly.coeffs[4 * i + 2]) as u32 & 0x3FF;
        let c3 = to_signed(poly.coeffs[4 * i + 3]) as u32 & 0x3FF;

        buf[5 * i] = (c0 & 0xFF) as u8;
        buf[5 * i + 1] = (((c0 >> 8) & 0x03) | ((c1 & 0x3F) << 2)) as u8;
        buf[5 * i + 2] = (((c1 >> 6) & 0x0F) | ((c2 & 0x0F) << 4)) as u8;
        buf[5 * i + 3] = (((c2 >> 4) & 0x3F) | ((c3 & 0x03) << 6)) as u8;
        buf[5 * i + 4] = ((c3 >> 2) & 0xFF) as u8;
    }
}

fn unpack_t1_poly(buf: &[u8]) -> Polynomial {
    let mut poly = Polynomial::new();
    for i in 0..64 {
        let b0 = buf[5 * i] as u32;
        let b1 = buf[5 * i + 1] as u32;
        let b2 = buf[5 * i + 2] as u32;
        let b3 = buf[5 * i + 3] as u32;
        let b4 = buf[5 * i + 4] as u32;

        let c0 = b0 | ((b1 & 0x03) << 8);
        let c1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
        let c2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
        let c3 = (b3 >> 6) | (b4 << 2);

        poly.coeffs[4 * i] = to_canonical(c0 as i32);
        poly.coeffs[4 * i + 1] = to_canonical(c1 as i32);
        poly.coeffs[4 * i + 2] = to_canonical(c2 as i32);
        poly.coeffs[4 * i + 3] = to_canonical(c3 as i32);
    }
    poly
}

// --- 4-bit packing/unpacking for small coefficients s1, s2 (eta = 4) ---

fn pack_small_poly(poly: &Polynomial, buf: &mut [u8]) {
    // 256 coefficients -> packed into 128 bytes (4 bits per coefficient)
    // Map coefficient c in [-4, 4] to 4 - c in [0, 8]
    for i in 0..128 {
        let c0 = to_signed(poly.coeffs[2 * i]);
        let c1 = to_signed(poly.coeffs[2 * i + 1]);

        let y0 = (4 - c0) as u8 & 0x0F;
        let y1 = (4 - c1) as u8 & 0x0F;

        buf[i] = y0 | (y1 << 4);
    }
}

fn unpack_small_poly(buf: &[u8]) -> Polynomial {
    let mut poly = Polynomial::new();
    for i in 0..128 {
        let b = buf[i];
        let y0 = (b & 0x0F) as i32;
        let y1 = (b >> 4) as i32;

        let c0 = 4 - y0;
        let c1 = 4 - y1;

        poly.coeffs[2 * i] = to_canonical(c0);
        poly.coeffs[2 * i + 1] = to_canonical(c1);
    }
    poly
}

// --- 13-bit packing/unpacking for t0 ---

fn pack_t0_poly(poly: &Polynomial, buf: &mut [u8]) {
    // 256 coefficients -> packed into 416 bytes (13 bits per coefficient)
    // 8 coefficients take 13 bytes = 104 bits
    // Map coefficient c in [-4095, 4096] to 2^12 - c in [0, 8191]
    for i in 0..32 {
        let c0 = (4096 - to_signed(poly.coeffs[8 * i])) as u32 & 0x1FFF;
        let c1 = (4096 - to_signed(poly.coeffs[8 * i + 1])) as u32 & 0x1FFF;
        let c2 = (4096 - to_signed(poly.coeffs[8 * i + 2])) as u32 & 0x1FFF;
        let c3 = (4096 - to_signed(poly.coeffs[8 * i + 3])) as u32 & 0x1FFF;
        let c4 = (4096 - to_signed(poly.coeffs[8 * i + 4])) as u32 & 0x1FFF;
        let c5 = (4096 - to_signed(poly.coeffs[8 * i + 5])) as u32 & 0x1FFF;
        let c6 = (4096 - to_signed(poly.coeffs[8 * i + 6])) as u32 & 0x1FFF;
        let c7 = (4096 - to_signed(poly.coeffs[8 * i + 7])) as u32 & 0x1FFF;

        let base = 13 * i;
        buf[base] = (c0 & 0xFF) as u8;
        buf[base + 1] = (((c0 >> 8) & 0x1F) | ((c1 & 0x07) << 5)) as u8;
        buf[base + 2] = ((c1 >> 3) & 0xFF) as u8;
        buf[base + 3] = (((c1 >> 11) & 0x03) | ((c2 & 0x3F) << 2)) as u8;
        buf[base + 4] = (((c2 >> 6) & 0x7F) | ((c3 & 0x01) << 7)) as u8;
        buf[base + 5] = ((c3 >> 1) & 0xFF) as u8;
        buf[base + 6] = (((c3 >> 9) & 0x0F) | ((c4 & 0x0F) << 4)) as u8;
        buf[base + 7] = ((c4 >> 4) & 0xFF) as u8;
        buf[base + 8] = (((c4 >> 12) & 0x01) | ((c5 & 0x7F) << 1)) as u8;
        buf[base + 9] = (((c5 >> 7) & 0x3F) | ((c6 & 0x03) << 6)) as u8;
        buf[base + 10] = ((c6 >> 2) & 0xFF) as u8;
        buf[base + 11] = (((c6 >> 10) & 0x07) | ((c7 & 0x1F) << 3)) as u8;
        buf[base + 12] = ((c7 >> 5) & 0xFF) as u8;
    }
}

fn unpack_t0_poly(buf: &[u8]) -> Polynomial {
    let mut poly = Polynomial::new();
    for i in 0..32 {
        let base = 13 * i;
        let b0 = buf[base] as u32;
        let b1 = buf[base + 1] as u32;
        let b2 = buf[base + 2] as u32;
        let b3 = buf[base + 3] as u32;
        let b4 = buf[base + 4] as u32;
        let b5 = buf[base + 5] as u32;
        let b6 = buf[base + 6] as u32;
        let b7 = buf[base + 7] as u32;
        let b8 = buf[base + 8] as u32;
        let b9 = buf[base + 9] as u32;
        let b10 = buf[base + 10] as u32;
        let b11 = buf[base + 11] as u32;
        let b12 = buf[base + 12] as u32;

        let c0 = b0 | ((b1 & 0x1F) << 8);
        let c1 = (b1 >> 5) | (b2 << 3) | ((b3 & 0x03) << 11);
        let c2 = (b3 >> 2) | ((b4 & 0x7F) << 6);
        let c3 = (b4 >> 7) | (b5 << 1) | ((b6 & 0x0F) << 9);
        let c4 = (b6 >> 4) | (b7 << 4) | ((b8 & 0x01) << 12);
        let c5 = (b8 >> 1) | ((b9 & 0x3F) << 7);
        let c6 = (b9 >> 6) | (b10 << 2) | ((b11 & 0x07) << 10);
        let c7 = (b11 >> 3) | (b12 << 5);

        poly.coeffs[8 * i] = to_canonical(4096 - c0 as i32);
        poly.coeffs[8 * i + 1] = to_canonical(4096 - c1 as i32);
        poly.coeffs[8 * i + 2] = to_canonical(4096 - c2 as i32);
        poly.coeffs[8 * i + 3] = to_canonical(4096 - c3 as i32);
        poly.coeffs[8 * i + 4] = to_canonical(4096 - c4 as i32);
        poly.coeffs[8 * i + 5] = to_canonical(4096 - c5 as i32);
        poly.coeffs[8 * i + 6] = to_canonical(4096 - c6 as i32);
        poly.coeffs[8 * i + 7] = to_canonical(4096 - c7 as i32);
    }
    poly
}

// --- 20-bit packing/unpacking for z ---

fn pack_z_poly(poly: &Polynomial, buf: &mut [u8]) {
    // 256 coefficients -> packed into 640 bytes (20 bits per coefficient)
    // 2 coefficients take 40 bits = 5 bytes
    // Map coefficient c in [-GAMMA1, GAMMA1] to GAMMA1 - c in [0, 2*GAMMA1 - 1]
    for i in 0..128 {
        let c0 = (GAMMA1 - to_signed(poly.coeffs[2 * i])) as u32 & 0xFFFFF;
        let c1 = (GAMMA1 - to_signed(poly.coeffs[2 * i + 1])) as u32 & 0xFFFFF;

        buf[5 * i] = (c0 & 0xFF) as u8;
        buf[5 * i + 1] = ((c0 >> 8) & 0xFF) as u8;
        buf[5 * i + 2] = (((c0 >> 16) & 0x0F) | ((c1 & 0x0F) << 4)) as u8;
        buf[5 * i + 3] = ((c1 >> 4) & 0xFF) as u8;
        buf[5 * i + 4] = ((c1 >> 12) & 0xFF) as u8;
    }
}

fn unpack_z_poly(buf: &[u8]) -> Polynomial {
    let mut poly = Polynomial::new();
    for i in 0..128 {
        let b0 = buf[5 * i] as u32;
        let b1 = buf[5 * i + 1] as u32;
        let b2 = buf[5 * i + 2] as u32;
        let b3 = buf[5 * i + 3] as u32;
        let b4 = buf[5 * i + 4] as u32;

        let c0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
        let c1 = (b2 >> 4) | (b3 << 4) | (b4 << 12);

        poly.coeffs[2 * i] = to_canonical(GAMMA1 - c0 as i32);
        poly.coeffs[2 * i + 1] = to_canonical(GAMMA1 - c1 as i32);
    }
    poly
}

// --- Hint Vector Packing/Unpacking with CVE-2026-24850 protection ---

fn pack_hint(h: &PolyVector<6>, buf: &mut [u8; 61]) {
    // Pack hint vector of dimension k=6 into 61 bytes.
    // First 55 bytes contain indices of non-zero coefficients.
    // Last 6 bytes contain cumulative counts.
    buf.fill(0);
    let mut index = 0;
    for i in 0..6 {
        for j in 0..256 {
            if to_signed(h.polys[i].coeffs[j]) != 0 {
                if index < 55 {
                    buf[index] = j as u8;
                    index += 1;
                }
            }
        }
        buf[55 + i] = index as u8;
    }
}

fn unpack_hint(buf: &[u8; 61]) -> Result<PolyVector<6>, MlDsaError> {
    let mut h = PolyVector::<6>::new();
    let mut last_count = 0;

    for i in 0..6 {
        let count = buf[55 + i] as usize;
        if count < last_count || count > 55 {
            return Err(MlDsaError::InvalidSignature);
        }

        // Strict monotonicity check for decoded hint indices (CVE-2026-24850 Protection)
        let mut last_idx = -1;
        for idx in last_count..count {
            let val = buf[idx] as usize;
            if val <= last_idx as usize && idx > last_count {
                return Err(MlDsaError::InvalidSignature);
            }
            h.polys[i].coeffs[val] = 1;
            last_idx = val as i32;
        }
        last_count = count;
    }

    // Verify padding bytes in remaining space of indices are zero
    for idx in last_count..55 {
        if buf[idx] != 0 {
            return Err(MlDsaError::InvalidSignature);
        }
    }

    Ok(h)
}

// --- Public Key serialization routines ---

/// Pack public key into 1952 bytes: rho (32 bytes) + t1 (6 polynomials * 320 bytes = 1920 bytes)
pub fn pack_pk(rho: &[u8; 32], t1: &PolyVector<6>) -> [u8; 1952] {
    let mut pk = [0u8; 1952];
    pk[0..32].copy_from_slice(rho);
    for i in 0..6 {
        pack_t1_poly(&t1.polys[i], &mut pk[32 + i * 320 .. 32 + (i + 1) * 320]);
    }
    pk
}

/// Unpack public key from 1952 bytes
pub fn unpack_pk(pk: &[u8; 1952]) -> ([u8; 32], PolyVector<6>) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[0..32]);
    let mut t1 = PolyVector::<6>::new();
    for i in 0..6 {
        t1.polys[i] = unpack_t1_poly(&pk[32 + i * 320 .. 32 + (i + 1) * 320]);
    }
    (rho, t1)
}

// --- Private Key serialization routines ---

/// Pack private key into 4032 bytes:
/// rho (32) + K (32) + tr (64) + s1 (640) + s2 (768) + t0 (2496)
pub fn pack_sk(
    rho: &[u8; 32],
    k: &[u8; 32],
    tr: &[u8; 64],
    s1: &PolyVector<5>,
    s2: &PolyVector<6>,
    t0: &PolyVector<6>,
) -> [u8; 4032] {
    let mut sk = [0u8; 4032];
    sk[0..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(k);
    sk[64..128].copy_from_slice(tr);

    let mut offset = 128;
    for i in 0..5 {
        pack_small_poly(&s1.polys[i], &mut sk[offset .. offset + 128]);
        offset += 128;
    }
    for i in 0..6 {
        pack_small_poly(&s2.polys[i], &mut sk[offset .. offset + 128]);
        offset += 128;
    }
    for i in 0..6 {
        pack_t0_poly(&t0.polys[i], &mut sk[offset .. offset + 416]);
        offset += 416;
    }
    sk
}

/// Unpack private key from 4032 bytes
pub fn unpack_sk(
    sk: &[u8; 4032],
) -> (
    [u8; 32],
    [u8; 32],
    [u8; 64],
    PolyVector<5>,
    PolyVector<6>,
    PolyVector<6>,
) {
    let mut rho = [0u8; 32];
    let mut k = [0u8; 32];
    let mut tr = [0u8; 64];

    rho.copy_from_slice(&sk[0..32]);
    k.copy_from_slice(&sk[32..64]);
    tr.copy_from_slice(&sk[64..128]);

    let mut s1 = PolyVector::<5>::new();
    let mut s2 = PolyVector::<6>::new();
    let mut t0 = PolyVector::<6>::new();

    let mut offset = 128;
    for i in 0..5 {
        s1.polys[i] = unpack_small_poly(&sk[offset .. offset + 128]);
        offset += 128;
    }
    for i in 0..6 {
        s2.polys[i] = unpack_small_poly(&sk[offset .. offset + 128]);
        offset += 128;
    }
    for i in 0..6 {
        t0.polys[i] = unpack_t0_poly(&sk[offset .. offset + 416]);
        offset += 416;
    }

    (rho, k, tr, s1, s2, t0)
}

// --- Signature serialization routines ---

/// Pack signature into 3309 bytes: c_tilde (48 bytes) + z (3200 bytes) + h (61 bytes)
pub fn pack_sig(c_tilde: &[u8; 48], z: &PolyVector<5>, h: &PolyVector<6>) -> [u8; 3309] {
    let mut sig = [0u8; 3309];
    sig[0..48].copy_from_slice(c_tilde);
    for i in 0..5 {
        pack_z_poly(&z.polys[i], &mut sig[48 + i * 640 .. 48 + (i + 1) * 640]);
    }
    let mut h_bytes = [0u8; 61];
    pack_hint(h, &mut h_bytes);
    sig[3248..3309].copy_from_slice(&h_bytes);
    sig
}

/// Unpack signature from 3309 bytes
pub fn unpack_sig(sig: &[u8; 3309]) -> Result<([u8; 48], PolyVector<5>, PolyVector<6>), MlDsaError> {
    let mut c_tilde = [0u8; 48];
    c_tilde.copy_from_slice(&sig[0..48]);

    let mut z = PolyVector::<5>::new();
    for i in 0..5 {
        z.polys[i] = unpack_z_poly(&sig[48 + i * 640 .. 48 + (i + 1) * 640]);
    }

    let mut h_bytes = [0u8; 61];
    h_bytes.copy_from_slice(&sig[3248..3309]);
    let h = unpack_hint(&h_bytes)?;

    Ok((c_tilde, z, h))
}