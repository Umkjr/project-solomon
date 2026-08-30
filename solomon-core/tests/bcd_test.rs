//! Tests for BCD (Binary Coded Decimal) packing/unpacking and AS2805 ISO 8583 binary parsing.

use solomon_core::bcd::{
    pack_bcd_left_padded, pack_bcd_right_padded, unpack_bcd,
    pack_llvar_len_bcd, unpack_llvar_len_bcd,
    pack_lllvar_len_bcd, unpack_lllvar_len_bcd,
};
use solomon_core::iso8583::{Iso8583Message, EncodingFormat};

#[test]
fn test_bcd_basic_pack_unpack() {
    // Even length
    let packed = pack_bcd_left_padded("1234").unwrap();
    assert_eq!(packed, vec![0x12, 0x34]);
    let unpacked = unpack_bcd(&packed, 4, false).unwrap();
    assert_eq!(unpacked, "1234");

    // Odd length with left padding
    let packed_odd = pack_bcd_left_padded("123").unwrap();
    assert_eq!(packed_odd, vec![0x01, 0x23]);
    let unpacked_odd = unpack_bcd(&packed_odd, 3, true).unwrap();
    assert_eq!(unpacked_odd, "123");

    // Odd length with right padding
    let packed_right = pack_bcd_right_padded("123", 0x0F).unwrap();
    assert_eq!(packed_right, vec![0x12, 0x3F]);
}

#[test]
fn test_bcd_variable_length_headers() {
    // LLVAR (0..=99)
    let llvar = pack_llvar_len_bcd(19).unwrap();
    assert_eq!(llvar, 0x19);
    let len = unpack_llvar_len_bcd(llvar).unwrap();
    assert_eq!(len, 19);

    let llvar_zero = pack_llvar_len_bcd(0).unwrap();
    assert_eq!(llvar_zero, 0x00);
    assert_eq!(unpack_llvar_len_bcd(llvar_zero).unwrap(), 0);

    let llvar_max = pack_llvar_len_bcd(99).unwrap();
    assert_eq!(llvar_max, 0x99);
    assert_eq!(unpack_llvar_len_bcd(llvar_max).unwrap(), 99);

    assert!(pack_llvar_len_bcd(100).is_err());

    // LLLVAR (0..=999)
    let lllvar = pack_lllvar_len_bcd(123).unwrap();
    assert_eq!(lllvar, [0x01, 0x23]);
    let len3 = unpack_lllvar_len_bcd(lllvar).unwrap();
    assert_eq!(len3, 123);

    let lllvar_small = pack_lllvar_len_bcd(45).unwrap();
    assert_eq!(lllvar_small, [0x00, 0x45]);
    assert_eq!(unpack_lllvar_len_bcd(lllvar_small).unwrap(), 45);

    let lllvar_max = pack_lllvar_len_bcd(999).unwrap();
    assert_eq!(lllvar_max, [0x09, 0x99]);
    assert_eq!(unpack_lllvar_len_bcd(lllvar_max).unwrap(), 999);

    assert!(pack_lllvar_len_bcd(1000).is_err());
}

#[test]
fn test_as2805_bcd_iso8583_roundtrip() {
    let mut msg = Iso8583Message::new(*b"0200");
    msg.set_field(2, b"4111111111111111".to_vec()); // PAN (LLVAR)
    msg.set_field(3, b"000000".to_vec());           // Processing Code
    msg.set_field(4, b"000000015000".to_vec());     // Amount $150.00
    msg.set_field(11, b"654321".to_vec());          // STAN
    msg.set_field(41, b"ATM00001".to_vec());        // Terminal ID

    // Inject simulated PQC data in Field 112 (LLLVAR)
    let pqc_data = vec![0xEE; 64];
    msg.inject_pqc_field(112, &pqc_data);

    // Serialize using AS2805 BCD format
    let serialized_bcd = msg.serialize_as2805_bcd().expect("Failed to serialize AS2805 BCD");
    
    // First 2 bytes must be 0x02, 0x00 (BCD MTI)
    assert_eq!(serialized_bcd[0], 0x02);
    assert_eq!(serialized_bcd[1], 0x00);

    // Parse back using parse_as2805_bcd
    let parsed = Iso8583Message::parse_as2805_bcd(&serialized_bcd).expect("Failed to parse AS2805 BCD");
    assert_eq!(parsed.mti, *b"0200");
    assert_eq!(parsed.get_field_str(2), Some("4111111111111111"));
    assert_eq!(parsed.get_field_str(3), Some("000000"));
    assert_eq!(parsed.get_field_str(4), Some("000000015000"));
    assert_eq!(parsed.get_field_str(11), Some("654321"));
    assert_eq!(parsed.get_field_str(41), Some("ATM00001"));
    assert_eq!(parsed.get_field(112), Some(pqc_data.as_slice()));

    // Test TCP framing with BCD encoding
    let framed = msg.serialize_tcp_framed_with_encoding(EncodingFormat::BinaryBcd).expect("Failed to frame");
    let tcp_len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    assert_eq!(tcp_len, framed.len() - 2);

    let parsed_from_frame = Iso8583Message::parse_with_encoding(&framed[2..], EncodingFormat::BinaryBcd).expect("Failed to parse from frame");
    assert_eq!(parsed_from_frame.mti, *b"0200");
    assert_eq!(parsed_from_frame.get_field_str(2), Some("4111111111111111"));
}
