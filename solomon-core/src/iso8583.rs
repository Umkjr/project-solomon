//! Production-Grade ISO 8583 (1987/1993/2003) Binary Framing, Bitmap Parsing,
//! Data Element Serialization, and Post-Quantum / ZK Field Injection Engine.
//!
//! Provides zero-copy parsing, primary/secondary 128-bit bitmap operations,
//! variable-length field handling (Fixed, LLVAR, LLLVAR), and 2-byte big-endian
//! TCP stream framing matching BASE24, AS2805, and core banking switches.

extern crate alloc;
use alloc::collections::BTreeMap;
use core::fmt;
use alloc::vec::Vec;
use alloc::string::{String, ToString};

/// ISO 8583 Field Data Element Definition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Fixed length data element (e.g., Processing Code is 6 chars, Amount is 12 chars)
    Fixed(usize),
    /// Variable length data element with 2-digit length prefix (0..99)
    LLVAR(usize),
    /// Variable length data element with 3-digit length prefix (0..999)
    LLLVAR(usize),
    /// Variable length data element with 4-digit length prefix (0..9999) for PQC/ZK payloads
    LLLLVAR(usize),
}

/// Errors occurring during ISO 8583 packet framing, parsing, or serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Iso8583Error {
    BufferTooShort { expected: usize, actual: usize },
    InvalidMtiLength(usize),
    InvalidMtiFormat,
    InvalidBitmap,
    FieldOutOfBounds(u8),
    FieldLengthExceeded { field: u8, max: usize, actual: usize },
    InvalidVarLengthHeader { field: u8, header: String },
    TcpFramingError(&'static str),
    SerializationError(&'static str),
    BcdError(crate::bcd::BcdError),
}

/// Supported ISO 8583 wire encoding formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingFormat {
    /// ASCII MTI (4 bytes) + Hex-ASCII Bitmap (16/32 bytes) + ASCII length prefixes
    AsciiHexBitmap,
    /// ASCII MTI (4 bytes) + Binary Bitmap (8/16 bytes) + ASCII length prefixes
    AsciiBinaryBitmap,
    /// BCD MTI (2 bytes) + Binary Bitmap (8/16 bytes) + BCD length prefixes (AS2805 / pure binary switches)
    BinaryBcd,
}

impl fmt::Display for Iso8583Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Iso8583Error::BufferTooShort { expected, actual } => {
                write!(f, "ISO 8583 buffer too short: expected at least {} bytes, got {}", expected, actual)
            }
            Iso8583Error::InvalidMtiLength(len) => {
                write!(f, "Invalid MTI length: {} bytes (must be 4 bytes)", len)
            }
            Iso8583Error::InvalidMtiFormat => {
                write!(f, "Invalid MTI format (must be 4 numeric characters)")
            }
            Iso8583Error::InvalidBitmap => {
                write!(f, "Invalid ISO 8583 bitmap")
            }
            Iso8583Error::FieldOutOfBounds(field) => {
                write!(f, "Field number {} is out of bounds (1..=128)", field)
            }
            Iso8583Error::FieldLengthExceeded { field, max, actual } => {
                write!(f, "Field {} length exceeded: max {}, got {}", field, max, actual)
            }
            Iso8583Error::InvalidVarLengthHeader { field, header } => {
                write!(f, "Field {} has invalid variable length header: '{}'", field, header)
            }
            Iso8583Error::TcpFramingError(msg) => write!(f, "TCP Framing error: {}", msg),
            Iso8583Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Iso8583Error::BcdError(err) => write!(f, "BCD error: {}", err),
        }
    }
}

impl From<crate::bcd::BcdError> for Iso8583Error {
    fn from(err: crate::bcd::BcdError) -> Self {
        Iso8583Error::BcdError(err)
    }
}

impl std::error::Error for Iso8583Error {}

/// Standard ISO 8583 Data Element Schema lookup table
pub fn get_field_type(field: u8) -> FieldType {
    match field {
        1 => FieldType::Fixed(8),       // Secondary Bitmap (Binary 8 bytes)
        2 => FieldType::LLVAR(19),      // Primary Account Number (PAN)
        3 => FieldType::Fixed(6),       // Processing Code
        4 => FieldType::Fixed(12),      // Amount, Transaction
        5 => FieldType::Fixed(12),      // Amount, Settlement
        6 => FieldType::Fixed(12),      // Amount, Cardholder Billing
        7 => FieldType::Fixed(10),      // Transmission Date & Time (MMDDhhmmss)
        8 => FieldType::Fixed(8),       // Amount, Cardholder Billing Fee
        9 => FieldType::Fixed(8),       // Conversion Rate, Settlement
        10 => FieldType::Fixed(8),      // Conversion Rate, Cardholder Billing
        11 => FieldType::Fixed(6),      // Systems Trace Audit Number (STAN)
        12 => FieldType::Fixed(6),      // Time, Local Transaction (hhmmss)
        13 => FieldType::Fixed(4),      // Date, Local Transaction (MMDD)
        14 => FieldType::Fixed(4),      // Date, Expiration
        15 => FieldType::Fixed(4),      // Date, Settlement
        16 => FieldType::Fixed(4),      // Date, Conversion
        17 => FieldType::Fixed(4),      // Date, Capture
        18 => FieldType::Fixed(4),      // Merchant Type
        19 => FieldType::Fixed(3),      // Acquiring Institution Country Code
        22 => FieldType::Fixed(3),      // POS Entry Mode
        23 => FieldType::Fixed(3),      // Card Sequence Number
        24 => FieldType::Fixed(3),      // Network International ID
        25 => FieldType::Fixed(2),      // POS Condition Code
        26 => FieldType::Fixed(2),      // POS PIN Capture Code
        28 => FieldType::Fixed(9),      // Amount, Transaction Fee
        32 => FieldType::LLVAR(11),     // Acquiring Institution ID Code
        33 => FieldType::LLVAR(11),     // Forwarding Institution ID Code
        35 => FieldType::LLVAR(37),     // Track 2 Data
        37 => FieldType::Fixed(12),     // Retrieval Reference Number (RRN)
        38 => FieldType::Fixed(6),      // Authorization Identification Response
        39 => FieldType::Fixed(2),      // Response Code (e.g. "00" Approved)
        41 => FieldType::Fixed(8),      // Card Acceptor Terminal ID
        42 => FieldType::Fixed(15),     // Card Acceptor ID Code
        43 => FieldType::Fixed(40),     // Card Acceptor Name/Location
        44 => FieldType::LLVAR(25),     // Additional Response Data
        45 => FieldType::LLVAR(76),     // Track 1 Data
        48 => FieldType::LLLVAR(999),   // Additional Data - Private
        49 => FieldType::Fixed(3),      // Currency Code, Transaction
        50 => FieldType::Fixed(3),      // Currency Code, Settlement
        51 => FieldType::Fixed(3),      // Currency Code, Cardholder Billing
        52 => FieldType::Fixed(8),      // PIN Data (Binary 8 bytes)
        53 => FieldType::Fixed(16),     // Security Related Control Information
        54 => FieldType::LLLVAR(120),   // Additional Amounts
        55 => FieldType::LLLVAR(255),   // ICC / EMV Data
        60 => FieldType::LLLVAR(999),   // Private / National Data
        61 => FieldType::LLLVAR(999),   // Private / Point of Service Data
        62 => FieldType::LLLVAR(999),   // Private Use Data
        63 => FieldType::LLLVAR(999),   // Private / SMS Data
        64 => FieldType::Fixed(8),      // Message Authentication Code (MAC)
        70 => FieldType::Fixed(3),      // Network Management Information Code
        90 => FieldType::Fixed(42),     // Original Data Elements
        100 => FieldType::LLVAR(11),    // Receiving Institution ID Code
        102 => FieldType::LLVAR(28),    // Account Identification 1
        103 => FieldType::LLVAR(28),    // Account Identification 2
        112 => FieldType::LLLLVAR(9999), // National Data / PQC Extension Slot (TCS BaNCS)
        123 => FieldType::LLLLVAR(9999), // Reserved for Private Use / PQC Extension Slot (Finacle)
        127 => FieldType::LLLLVAR(9999), // Private Post-Quantum & ZK Container Slot
        128 => FieldType::Fixed(8),     // Secondary MAC
        _ => FieldType::LLLVAR(999),    // Default for arbitrary private/national fields
    }
}

/// Represents an ISO 8583 message structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iso8583Message {
    /// 4-character Message Type Identifier (e.g. "0100", "0200", "0800")
    pub mti: [u8; 4],
    /// Key-value map of 1-based data element numbers to their byte payloads
    pub fields: BTreeMap<u8, Vec<u8>>,
}

impl Iso8583Message {
    /// Creates a new, empty ISO 8583 message with the specified MTI.
    pub fn new(mti: [u8; 4]) -> Self {
        Self {
            mti,
            fields: BTreeMap::new(),
        }
    }

    /// Sets a field in the ISO 8583 message.
    pub fn set_field(&mut self, field_num: u8, data: Vec<u8>) {
        if field_num >= 1 && field_num <= 128 {
            self.fields.insert(field_num, data);
        }
    }

    /// Gets a reference to a field's byte payload.
    pub fn get_field(&self, field_num: u8) -> Option<&[u8]> {
        self.fields.get(&field_num).map(|v| v.as_slice())
    }

    /// Gets a field as a UTF-8 string slice if valid ASCII/UTF-8.
    pub fn get_field_str(&self, field_num: u8) -> Option<&str> {
        self.get_field(field_num).and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Removes a field from the message.
    pub fn remove_field(&mut self, field_num: u8) -> Option<Vec<u8>> {
        self.fields.remove(&field_num)
    }

    /// Checks if a field is present in the message.
    pub fn has_field(&self, field_num: u8) -> bool {
        self.fields.contains_key(&field_num)
    }

    /// Injects a Post-Quantum Signature / ZK Proof payload into a specified private/national field.
    pub fn inject_pqc_field(&mut self, field_num: u8, data: &[u8]) {
        self.set_field(field_num, data.to_vec());
    }

    /// Strips the Post-Quantum field and returns the extracted payload (for verify-and-strip proxy architectures).
    pub fn strip_pqc_field(&mut self, field_num: u8) -> Option<Vec<u8>> {
        self.remove_field(field_num)
    }

    /// Parses an ISO 8583 message from raw payload bytes (excluding the 2-byte TCP length prefix).
    pub fn parse(buf: &[u8]) -> Result<Self, Iso8583Error> {
        if buf.len() < 12 {
            return Err(Iso8583Error::BufferTooShort {
                expected: 12,
                actual: buf.len(),
            });
        }

        // 1. Parse MTI (first 4 bytes)
        let mut mti = [0u8; 4];
        mti.copy_from_slice(&buf[0..4]);
        for &b in &mti {
            if b < b'0' || b > b'9' {
                return Err(Iso8583Error::InvalidMtiFormat);
            }
        }

        // 2. Parse Bitmap (starts at byte index 4)
        // Can be Binary (8 bytes / 16 bytes) or Hex-ASCII (16 bytes / 32 bytes)
        let mut offset = 4;
        let mut bitmap = [0u8; 16]; // 128 bits
        let mut is_secondary_present = false;

        // Check if bitmap is Hex-ASCII (e.g. starts with ASCII hex digits '0'-'9', 'A'-'F')
        let is_hex_ascii_bitmap = buf.len() >= 20 && buf[4..20].iter().all(|&b| {
            (b >= b'0' && b <= b'9') || (b >= b'A' && b <= b'F') || (b >= b'a' && b <= b'f')
        });

        if is_hex_ascii_bitmap {
            // Hex-ASCII Primary Bitmap (16 hex chars = 8 bytes)
            if buf.len() < offset + 16 {
                return Err(Iso8583Error::BufferTooShort {
                    expected: offset + 16,
                    actual: buf.len(),
                });
            }
            for i in 0..8 {
                let byte_str = std::str::from_utf8(&buf[offset + 2 * i..offset + 2 * i + 2])
                    .map_err(|_| Iso8583Error::InvalidBitmap)?;
                bitmap[i] = u8::from_str_radix(byte_str, 16)
                    .map_err(|_| Iso8583Error::InvalidBitmap)?;
            }
            offset += 16;

            // Check bit 1 (Secondary Bitmap flag)
            if (bitmap[0] & 0x80) != 0 {
                is_secondary_present = true;
                if buf.len() < offset + 16 {
                    return Err(Iso8583Error::BufferTooShort {
                        expected: offset + 16,
                        actual: buf.len(),
                    });
                }
                for i in 0..8 {
                    let byte_str = std::str::from_utf8(&buf[offset + 2 * i..offset + 2 * i + 2])
                        .map_err(|_| Iso8583Error::InvalidBitmap)?;
                    bitmap[8 + i] = u8::from_str_radix(byte_str, 16)
                        .map_err(|_| Iso8583Error::InvalidBitmap)?;
                }
                offset += 16;
            }
        } else {
            // Binary Primary Bitmap (8 bytes)
            if buf.len() < offset + 8 {
                return Err(Iso8583Error::BufferTooShort {
                    expected: offset + 8,
                    actual: buf.len(),
                });
            }
            bitmap[0..8].copy_from_slice(&buf[offset..offset + 8]);
            offset += 8;

            if (bitmap[0] & 0x80) != 0 {
                is_secondary_present = true;
                if buf.len() < offset + 8 {
                    return Err(Iso8583Error::BufferTooShort {
                        expected: offset + 8,
                        actual: buf.len(),
                    });
                }
                bitmap[8..16].copy_from_slice(&buf[offset..offset + 8]);
                offset += 8;
            }
        }

        // 3. Parse Fields enabled in the bitmap
        let mut fields = BTreeMap::new();
        let max_fields = if is_secondary_present { 128 } else { 64 };

        for field_num in 2..=max_fields {
            let byte_idx = ((field_num - 1) / 8) as usize;
            let bit_idx = 7 - ((field_num - 1) % 8);
            let is_set = (bitmap[byte_idx] & (1 << bit_idx)) != 0;

            if !is_set {
                continue;
            }

            let field_type = get_field_type(field_num);
            match field_type {
                FieldType::Fixed(len) => {
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLVAR(max_len) => {
                    if buf.len() < offset + 2 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 2,
                            actual: buf.len(),
                        });
                    }
                    let len_str = std::str::from_utf8(&buf[offset..offset + 2])
                        .map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                            field: field_num,
                            header: String::from_utf8_lossy(&buf[offset..offset + 2]).to_string(),
                        })?;
                    let len: usize = len_str.parse().map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                        field: field_num,
                        header: len_str.to_string(),
                    })?;
                    offset += 2;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLLVAR(max_len) => {
                    if buf.len() < offset + 3 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 3,
                            actual: buf.len(),
                        });
                    }
                    let len_str = std::str::from_utf8(&buf[offset..offset + 3])
                        .map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                            field: field_num,
                            header: String::from_utf8_lossy(&buf[offset..offset + 3]).to_string(),
                        })?;
                    let len: usize = len_str.parse().map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                        field: field_num,
                        header: len_str.to_string(),
                    })?;
                    offset += 3;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLLLVAR(max_len) => {
                    if buf.len() < offset + 4 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 4,
                            actual: buf.len(),
                        });
                    }
                    let len_str = std::str::from_utf8(&buf[offset..offset + 4])
                        .map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                            field: field_num,
                            header: String::from_utf8_lossy(&buf[offset..offset + 4]).to_string(),
                        })?;
                    let len: usize = len_str.parse().map_err(|_| Iso8583Error::InvalidVarLengthHeader {
                        field: field_num,
                        header: len_str.to_string(),
                    })?;
                    offset += 4;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
            }
        }

        Ok(Self { mti, fields })
    }

    /// Parses an ISO 8583 message using the specified encoding format.
    pub fn parse_with_encoding(buf: &[u8], encoding: EncodingFormat) -> Result<Self, Iso8583Error> {
        match encoding {
            EncodingFormat::AsciiHexBitmap | EncodingFormat::AsciiBinaryBitmap => Self::parse(buf),
            EncodingFormat::BinaryBcd => Self::parse_as2805_bcd(buf),
        }
    }

    /// Parses an AS2805 / pure binary BCD encoded ISO 8583 message.
    ///
    /// Layout:
    /// - 2 bytes BCD MTI (e.g. 0x02, 0x00 for "0200")
    /// - 8 or 16 bytes Binary Bitmap
    /// - Data elements (LLVAR has 1-byte BCD length, LLLVAR has 2-byte BCD length)
    pub fn parse_as2805_bcd(buf: &[u8]) -> Result<Self, Iso8583Error> {
        if buf.len() < 10 {
            return Err(Iso8583Error::BufferTooShort {
                expected: 10,
                actual: buf.len(),
            });
        }

        // 1. Unpack 2-byte BCD MTI into 4 ASCII bytes
        let mti_str = crate::bcd::unpack_bcd(&buf[0..2], 4, false)?;
        let mut mti = [0u8; 4];
        mti.copy_from_slice(mti_str.as_bytes());

        // 2. Parse Binary Bitmap (8 bytes primary, optional 8 bytes secondary)
        let mut offset = 2;
        let mut bitmap = [0u8; 16];
        let mut is_secondary_present = false;

        if buf.len() < offset + 8 {
            return Err(Iso8583Error::BufferTooShort {
                expected: offset + 8,
                actual: buf.len(),
            });
        }
        bitmap[0..8].copy_from_slice(&buf[offset..offset + 8]);
        offset += 8;

        if (bitmap[0] & 0x80) != 0 {
            is_secondary_present = true;
            if buf.len() < offset + 8 {
                return Err(Iso8583Error::BufferTooShort {
                    expected: offset + 8,
                    actual: buf.len(),
                });
            }
            bitmap[8..16].copy_from_slice(&buf[offset..offset + 8]);
            offset += 8;
        }

        // 3. Parse Data Elements using BCD length headers
        let mut fields = BTreeMap::new();
        let max_fields = if is_secondary_present { 128 } else { 64 };

        for field_num in 2..=max_fields {
            let byte_idx = ((field_num - 1) / 8) as usize;
            let bit_idx = 7 - ((field_num - 1) % 8);
            let is_set = (bitmap[byte_idx] & (1 << bit_idx)) != 0;

            if !is_set {
                continue;
            }

            let field_type = get_field_type(field_num);
            match field_type {
                FieldType::Fixed(len) => {
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLVAR(max_len) => {
                    if buf.len() < offset + 1 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 1,
                            actual: buf.len(),
                        });
                    }
                    let len = crate::bcd::unpack_llvar_len_bcd(buf[offset])?;
                    offset += 1;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLLVAR(max_len) => {
                    if buf.len() < offset + 2 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 2,
                            actual: buf.len(),
                        });
                    }
                    let len = crate::bcd::unpack_lllvar_len_bcd([buf[offset], buf[offset + 1]])?;
                    offset += 2;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }
                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
                FieldType::LLLLVAR(max_len) => {
                    if buf.len() < offset + 2 {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + 2,
                            actual: buf.len(),
                        });
                    }
                    let len = crate::bcd::unpack_llllvar_len_bcd([buf[offset], buf[offset + 1]])?;
                    offset += 2;

                    if len > max_len {
                        return Err(Iso8583Error::FieldLengthExceeded {
                            field: field_num,
                            max: max_len,
                            actual: len,
                        });
                    }

                    if buf.len() < offset + len {
                        return Err(Iso8583Error::BufferTooShort {
                            expected: offset + len,
                            actual: buf.len(),
                        });
                    }
                    let field_bytes = buf[offset..offset + len].to_vec();
                    offset += len;
                    fields.insert(field_num, field_bytes);
                }
            }
        }

        Ok(Self { mti, fields })
    }

    /// Serializes the ISO 8583 message into its binary wire representation with Binary Bitmap.
    pub fn serialize_binary_bitmap(&self) -> Vec<u8> {
        self.serialize_internal(false)
    }

    /// Serializes the ISO 8583 message with Hex-ASCII Bitmap.
    pub fn serialize_hex_bitmap(&self) -> Vec<u8> {
        self.serialize_internal(true)
    }

    /// Serializes using the specified wire encoding format.
    pub fn serialize_with_encoding(&self, encoding: EncodingFormat) -> Result<Vec<u8>, Iso8583Error> {
        match encoding {
            EncodingFormat::AsciiHexBitmap => Ok(self.serialize_hex_bitmap()),
            EncodingFormat::AsciiBinaryBitmap => Ok(self.serialize_binary_bitmap()),
            EncodingFormat::BinaryBcd => self.serialize_as2805_bcd(),
        }
    }

    /// Serializes in AS2805 / pure binary BCD format (2-byte BCD MTI, Binary Bitmap, BCD length prefixes).
    pub fn serialize_as2805_bcd(&self) -> Result<Vec<u8>, Iso8583Error> {
        let mut out = Vec::with_capacity(512);

        // 1. Pack 4 ASCII characters MTI into 2 bytes BCD
        let mti_str = std::str::from_utf8(&self.mti).map_err(|_| Iso8583Error::InvalidMtiFormat)?;
        let mti_bcd = crate::bcd::pack_bcd_left_padded(mti_str)?;
        out.extend_from_slice(&mti_bcd);

        // 2. Compute 128-bit bitmap
        let mut bitmap = [0u8; 16];
        let has_secondary = self.fields.keys().any(|&k| k > 64);
        if has_secondary {
            bitmap[0] |= 0x80;
        }

        for &field_num in self.fields.keys() {
            if field_num >= 2 && field_num <= 128 {
                let byte_idx = ((field_num - 1) / 8) as usize;
                let bit_idx = 7 - ((field_num - 1) % 8);
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        // 3. Write Binary Bitmap
        let bitmap_len = if has_secondary { 16 } else { 8 };
        out.extend_from_slice(&bitmap[..bitmap_len]);

        // 4. Write Data Elements in ascending order with BCD length prefixes
        for (&field_num, data) in &self.fields {
            if field_num == 1 {
                continue;
            }
            let field_type = get_field_type(field_num);
            match field_type {
                FieldType::Fixed(len) => {
                    if data.len() == len {
                        out.extend_from_slice(data);
                    } else if data.len() < len {
                        out.extend_from_slice(data);
                        out.resize(out.len() + (len - data.len()), b' ');
                    } else {
                        out.extend_from_slice(&data[..len]);
                    }
                }
                FieldType::LLVAR(max_len) => {
                    let write_len = data.len().min(max_len);
                    let len_byte = crate::bcd::pack_llvar_len_bcd(write_len)?;
                    out.push(len_byte);
                    out.extend_from_slice(&data[..write_len]);
                }
                FieldType::LLLVAR(max_len) => {
                    let write_len = data.len().min(max_len);
                    let len_bytes = crate::bcd::pack_lllvar_len_bcd(write_len)?;
                    out.extend_from_slice(&len_bytes);
                    out.extend_from_slice(&data[..write_len]);
                }
                FieldType::LLLLVAR(max_len) => {
                    let write_len = data.len().min(max_len);
                    let len_bytes = crate::bcd::pack_llllvar_len_bcd(write_len)?;
                    out.extend_from_slice(&len_bytes);
                    out.extend_from_slice(&data[..write_len]);
                }
            }
        }

        Ok(out)
    }

    /// Standard serializer (Hex-ASCII Bitmap for broad banking switch compatibility).
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_hex_bitmap()
    }

    /// Serializes with a 2-byte Big-Endian TCP length header prepended.
    pub fn serialize_tcp_framed(&self) -> Result<Vec<u8>, Iso8583Error> {
        self.serialize_tcp_framed_with_encoding(EncodingFormat::AsciiHexBitmap)
    }

    /// Serializes with a 2-byte Big-Endian TCP length header prepended using the specified encoding format.
    pub fn serialize_tcp_framed_with_encoding(&self, encoding: EncodingFormat) -> Result<Vec<u8>, Iso8583Error> {
        let payload = self.serialize_with_encoding(encoding)?;
        let frame_len = u16::try_from(payload.len())
            .map_err(|_| Iso8583Error::SerializationError("ISO 8583 serialized payload exceeds 65535-byte TCP frame limit"))?;
        let mut framed = Vec::with_capacity(2 + payload.len());
        framed.push((frame_len >> 8) as u8);
        framed.push((frame_len & 0xFF) as u8);
        framed.extend_from_slice(&payload);
        Ok(framed)
    }

    fn serialize_internal(&self, hex_bitmap: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);

        // 1. Write MTI
        out.extend_from_slice(&self.mti);

        // 2. Compute 128-bit bitmap
        let mut bitmap = [0u8; 16];
        let has_secondary = self.fields.keys().any(|&k| k > 64);
        if has_secondary {
            bitmap[0] |= 0x80; // Set Field 1 indicator
        }

        for &field_num in self.fields.keys() {
            if field_num >= 2 && field_num <= 128 {
                let byte_idx = ((field_num - 1) / 8) as usize;
                let bit_idx = 7 - ((field_num - 1) % 8);
                bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        // 3. Write Bitmap (8 or 16 bytes binary, or 16 or 32 bytes hex)
        let bitmap_len = if has_secondary { 16 } else { 8 };
        if hex_bitmap {
            for i in 0..bitmap_len {
                out.extend_from_slice(format!("{:02X}", bitmap[i]).as_bytes());
            }
        } else {
            out.extend_from_slice(&bitmap[..bitmap_len]);
        }

        // 4. Write Data Elements in ascending order
        for (&field_num, data) in &self.fields {
            if field_num == 1 {
                continue; // Bitmap already written
            }
            let field_type = get_field_type(field_num);
            match field_type {
                FieldType::Fixed(len) => {
                    if data.len() == len {
                        out.extend_from_slice(data);
                    } else if data.len() < len {
                        out.extend_from_slice(data);
                        out.resize(out.len() + (len - data.len()), b' '); // Space pad
                    } else {
                        out.extend_from_slice(&data[..len]); // Truncate
                    }
                }
                FieldType::LLVAR(max_len) => {
                    let write_len = data.len().min(max_len).min(99);
                    let len_header = format!("{:02}", write_len);
                    out.extend_from_slice(len_header.as_bytes());
                    out.extend_from_slice(&data[..write_len]);
                }
                FieldType::LLLVAR(max_len) => {
                    let write_len = data.len().min(max_len).min(999);
                    let len_header = format!("{:03}", write_len);
                    out.extend_from_slice(len_header.as_bytes());
                    out.extend_from_slice(&data[..write_len]);
                }
                FieldType::LLLLVAR(max_len) => {
                    let write_len = data.len().min(max_len).min(9999);
                    let len_header = format!("{:04}", write_len);
                    out.extend_from_slice(len_header.as_bytes());
                    out.extend_from_slice(&data[..write_len]);
                }
            }
        }

        out
    }
}

/// Gregorian date conversion helper: days since 1970-01-01 -> (year, month, day)
pub fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Gregorian date conversion helper: (year, month, day) -> days since 1970-01-01
pub fn ymd_to_days(year: u64, month: u64, day: u64) -> u64 {
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y % 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Validates Field 7 (Transmission Date & Time: MMDDhhmmss) against current system UTC time.
/// Returns true if within the allowed clock-skew tolerance (default 120s).
/// Rejects stale, manipulated, or future-drifted transactions.
pub fn is_field7_fresh(f7_str: &str, current_utc_secs: u64, tolerance_secs: i64) -> bool {
    if f7_str.len() != 10 {
        return false;
    }
    let bytes = f7_str.as_bytes();
    for &b in bytes {
        if !b.is_ascii_digit() {
            return false;
        }
    }

    let month: u64 = match f7_str[0..2].parse() { Ok(v) if (1..=12).contains(&v) => v, _ => return false };
    let day: u64 = match f7_str[2..4].parse() { Ok(v) if (1..=31).contains(&v) => v, _ => return false };
    let hh: u64 = match f7_str[4..6].parse() { Ok(v) if v < 24 => v, _ => return false };
    let mm: u64 = match f7_str[6..8].parse() { Ok(v) if v < 60 => v, _ => return false };
    let ss: u64 = match f7_str[8..10].parse() { Ok(v) if v < 60 => v, _ => return false };

    let current_days = current_utc_secs / 86400;
    let (curr_year, curr_month, _curr_day) = days_to_ymd(current_days);

    // Resolve Year Boundary (December -> January rollover)
    let year = if month == 12 && curr_month == 1 {
        curr_year.saturating_sub(1)
    } else if month == 1 && curr_month == 12 {
        curr_year + 1
    } else {
        curr_year
    };

    let tx_days = ymd_to_days(year, month, day);
    let tx_secs = tx_days * 86400 + hh * 3600 + mm * 60 + ss;

    let diff = (current_utc_secs as i64) - (tx_secs as i64);
    diff.abs() <= tolerance_secs
}
