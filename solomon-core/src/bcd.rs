//! Native BCD (Binary Coded Decimal) Packing & Unpacking Engine.
//!
//! Provides high-performance, constant-time BCD conversion routines for AS2805,
//! ISO 8583:1987 binary fields, and BCD variable length prefixes (LLVAR / LLLVAR).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcdError {
    InvalidDigit(char),
    InvalidNibble(u8),
    LengthOverflow(usize),
    BufferTooShort { expected: usize, actual: usize },
    InvalidBcdLengthHeader { byte: u8 },
}

impl fmt::Display for BcdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BcdError::InvalidDigit(c) => write!(f, "Invalid BCD digit character: '{}' (must be '0'..='9')", c),
            BcdError::InvalidNibble(n) => write!(f, "Invalid BCD nibble: 0x{:X} (must be 0..=9)", n),
            BcdError::LengthOverflow(len) => write!(f, "BCD length overflow: {}", len),
            BcdError::BufferTooShort { expected, actual } => {
                write!(f, "BCD buffer too short: expected {} bytes, got {}", expected, actual)
            }
            BcdError::InvalidBcdLengthHeader { byte } => {
                write!(f, "Invalid BCD length header byte: 0x{:02X}", byte)
            }
        }
    }
}

impl std::error::Error for BcdError {}

/// Packs an even or odd length numeric string into BCD bytes (left-padded with '0' if odd).
///
/// Example: `"1234"` -> `[0x12, 0x34]`, `"123"` -> `[0x01, 0x23]`
pub fn pack_bcd_left_padded(digits: &str) -> Result<Vec<u8>, BcdError> {
    let digits = digits.trim();
    let is_odd = digits.len() % 2 != 0;
    let total_len = (digits.len() + 1) / 2;
    let mut out = Vec::with_capacity(total_len);

    let mut chars = digits.chars();
    if is_odd {
        let first = chars.next().unwrap();
        let val = digit_to_val(first)?;
        out.push(val); // high nibble is 0
    }

    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let n1 = digit_to_val(c1)?;
        let n2 = digit_to_val(c2)?;
        out.push((n1 << 4) | n2);
    }

    Ok(out)
}

/// Packs a numeric string into BCD bytes (right-padded with `pad_nibble` if odd, typically `0x00` or `0x0F`).
///
/// Example with pad 0x0F: `"123"` -> `[0x12, 0x3F]`
pub fn pack_bcd_right_padded(digits: &str, pad_nibble: u8) -> Result<Vec<u8>, BcdError> {
    let digits = digits.trim();
    let total_len = (digits.len() + 1) / 2;
    let mut out = Vec::with_capacity(total_len);

    let mut chars = digits.chars().peekable();
    while let Some(c1) = chars.next() {
        let n1 = digit_to_val(c1)?;
        let n2 = if let Some(c2) = chars.next() {
            digit_to_val(c2)?
        } else {
            pad_nibble & 0x0F
        };
        out.push((n1 << 4) | n2);
    }

    Ok(out)
}

/// Unpacks BCD bytes into an ASCII numeric string of length `num_digits`.
///
/// Example: `[0x12, 0x34]` with `num_digits = 4` -> `"1234"`
/// Example: `[0x01, 0x23]` with `num_digits = 3` (left-padded) -> `"123"`
pub fn unpack_bcd(bytes: &[u8], num_digits: usize, left_padded_odd: bool) -> Result<String, BcdError> {
    let expected_bytes = (num_digits + 1) / 2;
    if bytes.len() < expected_bytes {
        return Err(BcdError::BufferTooShort {
            expected: expected_bytes,
            actual: bytes.len(),
        });
    }

    let mut out = String::with_capacity(num_digits);
    let is_odd = num_digits % 2 != 0;

    let mut start_idx = 0;
    if is_odd && left_padded_odd {
        // First byte only contains one lower nibble
        let low = bytes[0] & 0x0F;
        if low > 9 {
            return Err(BcdError::InvalidNibble(low));
        }
        out.push((b'0' + low) as char);
        start_idx = 1;
    }

    for &b in &bytes[start_idx..expected_bytes] {
        if out.len() == num_digits {
            break;
        }
        let high = (b >> 4) & 0x0F;
        if high > 9 {
            return Err(BcdError::InvalidNibble(high));
        }
        out.push((b'0' + high) as char);

        if out.len() < num_digits {
            let low = b & 0x0F;
            if low > 9 {
                // If trailing nibble is F (padding) and we reached limit, stop
                if low == 0x0F && !left_padded_odd {
                    break;
                }
                return Err(BcdError::InvalidNibble(low));
            }
            out.push((b'0' + low) as char);
        }
    }

    Ok(out)
}

/// Packs an LLVAR length (0..=99) into a single BCD byte.
///
/// Example: `19` -> `0x19`, `5` -> `0x05`
pub fn pack_llvar_len_bcd(len: usize) -> Result<u8, BcdError> {
    if len > 99 {
        return Err(BcdError::LengthOverflow(len));
    }
    let tens = (len / 10) as u8;
    let units = (len % 10) as u8;
    Ok((tens << 4) | units)
}

/// Unpacks an LLVAR single BCD byte into usize (0..=99).
///
/// Example: `0x19` -> `19`, `0x05` -> `5`
pub fn unpack_llvar_len_bcd(byte: u8) -> Result<usize, BcdError> {
    let tens = (byte >> 4) & 0x0F;
    let units = byte & 0x0F;
    if tens > 9 || units > 9 {
        return Err(BcdError::InvalidBcdLengthHeader { byte });
    }
    Ok((tens as usize) * 10 + (units as usize))
}

/// Packs an LLLVAR length (0..=999) into 2 BCD bytes (left padded with 0).
///
/// Example: `123` -> `[0x01, 0x23]`, `45` -> `[0x00, 0x45]`
pub fn pack_lllvar_len_bcd(len: usize) -> Result<[u8; 2], BcdError> {
    if len > 999 {
        return Err(BcdError::LengthOverflow(len));
    }
    let hundreds = (len / 100) as u8;
    let remainder = len % 100;
    let tens = (remainder / 10) as u8;
    let units = (remainder % 10) as u8;

    Ok([hundreds, (tens << 4) | units])
}

/// Unpacks an LLLVAR 2-byte BCD buffer into usize (0..=999).
///
/// Example: `[0x01, 0x23]` -> `123`, `[0x00, 0x45]` -> `45`
pub fn unpack_lllvar_len_bcd(bytes: [u8; 2]) -> Result<usize, BcdError> {
    let hundreds = bytes[0] & 0x0F;
    let tens = (bytes[1] >> 4) & 0x0F;
    let units = bytes[1] & 0x0F;
    if hundreds > 9 || tens > 9 || units > 9 {
        return Err(BcdError::InvalidBcdLengthHeader { byte: bytes[1] });
    }
    Ok((hundreds as usize) * 100 + (tens as usize) * 10 + (units as usize))
}

/// Packs an LLLLVAR length (0..=9999) into 2 BCD bytes (4 BCD nibbles).
///
/// Example: `3437` -> `[0x34, 0x37]`, `123` -> `[0x01, 0x23]`
pub fn pack_llllvar_len_bcd(len: usize) -> Result<[u8; 2], BcdError> {
    if len > 9999 {
        return Err(BcdError::LengthOverflow(len));
    }
    let high = (len / 100) as u8;
    let low = (len % 100) as u8;
    let thousands = high / 10;
    let hundreds = high % 10;
    let tens = low / 10;
    let units = low % 10;

    Ok([
        (thousands << 4) | hundreds,
        (tens << 4) | units,
    ])
}

/// Unpacks an LLLLVAR 2-byte BCD buffer into usize (0..=9999).
///
/// Example: `[0x34, 0x37]` -> `3437`, `[0x01, 0x23]` -> `123`
pub fn unpack_llllvar_len_bcd(bytes: [u8; 2]) -> Result<usize, BcdError> {
    let thousands = (bytes[0] >> 4) & 0x0F;
    let hundreds = bytes[0] & 0x0F;
    let tens = (bytes[1] >> 4) & 0x0F;
    let units = bytes[1] & 0x0F;
    if thousands > 9 || hundreds > 9 || tens > 9 || units > 9 {
        return Err(BcdError::InvalidBcdLengthHeader { byte: bytes[0] });
    }
    Ok((thousands as usize) * 1000 + (hundreds as usize) * 100 + (tens as usize) * 10 + (units as usize))
}

#[inline(always)]
fn digit_to_val(c: char) -> Result<u8, BcdError> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        _ => Err(BcdError::InvalidDigit(c)),
    }
}
