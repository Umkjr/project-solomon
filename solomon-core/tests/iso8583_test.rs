//! Automated Tests for ISO 8583 (1987/1993/2003) Binary Framing, Bitmap Parsing,
//! Field Encoding/Decoding, and Post-Quantum Field Injection/Stripping.

use solomon_core::iso8583::{Iso8583Message, Iso8583Error};

#[test]
fn test_iso8583_basic_financial_transaction() {
    // Construct 0200 Financial Request
    let mut msg = Iso8583Message::new(*b"0200");
    msg.set_field(2, b"4111111111111111".to_vec());      // PAN (LLVAR)
    msg.set_field(3, b"000000".to_vec());                // Processing Code (Fixed 6)
    msg.set_field(4, b"000000050000".to_vec());          // Amount $500.00 (Fixed 12)
    msg.set_field(7, b"0824120000".to_vec());            // Transmission Date/Time (Fixed 10)
    msg.set_field(11, b"123456".to_vec());               // STAN (Fixed 6)
    msg.set_field(41, b"TERM0001".to_vec());             // Terminal ID (Fixed 8)
    msg.set_field(49, b"840".to_vec());                  // Currency USD (Fixed 3)

    // Serialize
    let serialized = msg.serialize();
    assert!(serialized.starts_with(b"0200"));

    // Parse back
    let parsed = Iso8583Message::parse(&serialized).expect("Failed to parse serialized ISO 8583 message");
    assert_eq!(parsed.mti, *b"0200");
    assert_eq!(parsed.get_field_str(2), Some("4111111111111111"));
    assert_eq!(parsed.get_field_str(3), Some("000000"));
    assert_eq!(parsed.get_field_str(4), Some("000000050000"));
    assert_eq!(parsed.get_field_str(7), Some("0824120000"));
    assert_eq!(parsed.get_field_str(11), Some("123456"));
    assert_eq!(parsed.get_field_str(41), Some("TERM0001"));
    assert_eq!(parsed.get_field_str(49), Some("840"));
}

#[test]
fn test_iso8583_secondary_bitmap_and_pqc_injection() {
    let mut msg = Iso8583Message::new(*b"0100"); // Auth Request
    msg.set_field(3, b"000000".to_vec());
    msg.set_field(4, b"000000010000".to_vec());

    // Inject simulated 128-byte ZK Authorization Proof into Field 112 (National Data / BaNCS)
    let fake_zk_proof = vec![0xAB; 128];
    msg.inject_pqc_field(112, &fake_zk_proof);

    // Inject simulated PQC Signature slice into Field 123 (Reserved Private / Finacle)
    let fake_pqc_sig = vec![0xCD; 200];
    msg.inject_pqc_field(123, &fake_pqc_sig);

    assert!(msg.has_field(112));
    assert!(msg.has_field(123));

    // Serialize with secondary bitmap enabled
    let wire_bytes = msg.serialize();

    // Parse back
    let mut parsed = Iso8583Message::parse(&wire_bytes).expect("Failed to parse message with secondary bitmap");
    assert_eq!(parsed.mti, *b"0100");
    assert_eq!(parsed.get_field(112), Some(fake_zk_proof.as_slice()));
    assert_eq!(parsed.get_field(123), Some(fake_pqc_sig.as_slice()));

    // Test verify-and-strip logic
    let stripped_zk = parsed.strip_pqc_field(112).expect("Field 112 should be present for stripping");
    assert_eq!(stripped_zk, fake_zk_proof);
    assert!(!parsed.has_field(112));

    let stripped_sig = parsed.strip_pqc_field(123).expect("Field 123 should be present for stripping");
    assert_eq!(stripped_sig, fake_pqc_sig);
    assert!(!parsed.has_field(123));

    // Re-serialize clean legacy message
    let clean_wire_bytes = parsed.serialize();
    let clean_parsed = Iso8583Message::parse(&clean_wire_bytes).expect("Failed to parse clean message");
    assert!(!clean_parsed.has_field(112));
    assert!(!clean_parsed.has_field(123));
    assert_eq!(clean_parsed.get_field_str(3), Some("000000"));
}

#[test]
fn test_iso8583_tcp_framing_roundtrip() {
    let mut msg = Iso8583Message::new(*b"0800"); // Network Management Request
    msg.set_field(7, b"0824120000".to_vec());
    msg.set_field(11, b"999999".to_vec());
    msg.set_field(70, b"301".to_vec()); // Echo test

    let framed = msg.serialize_tcp_framed().expect("Failed to create TCP framed message");
    assert!(framed.len() > 2);

    // Extract length header
    let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    assert_eq!(len, framed.len() - 2);

    let parsed = Iso8583Message::parse(&framed[2..]).expect("Failed to parse payload");
    assert_eq!(parsed.mti, *b"0800");
    assert_eq!(parsed.get_field_str(70), Some("301"));
}

#[test]
fn test_iso8583_error_handling() {
    // Buffer too short
    let short_buf = b"020012";
    assert!(matches!(Iso8583Message::parse(short_buf), Err(Iso8583Error::BufferTooShort { .. })));

    // Invalid MTI (non-numeric)
    let invalid_mti = b"02AA0000000000000000";
    assert!(matches!(Iso8583Message::parse(invalid_mti), Err(Iso8583Error::InvalidMtiFormat)));
}

#[test]
fn test_iso8583_llllvar_bcd_and_buffer_boundary_safety() {
    use solomon_core::bcd::{pack_llllvar_len_bcd, unpack_llllvar_len_bcd};

    // 1. Verify LLLLVAR 4-digit BCD packing
    let packed = pack_llllvar_len_bcd(3437).unwrap();
    assert_eq!(packed, [0x34, 0x37]);
    let unpacked = unpack_llllvar_len_bcd(packed).unwrap();
    assert_eq!(unpacked, 3437);

    // Edge lengths
    assert_eq!(pack_llllvar_len_bcd(0).unwrap(), [0x00, 0x00]);
    assert_eq!(unpack_llllvar_len_bcd([0x00, 0x00]).unwrap(), 0);
    assert_eq!(pack_llllvar_len_bcd(9999).unwrap(), [0x99, 0x99]);
    assert_eq!(unpack_llllvar_len_bcd([0x99, 0x99]).unwrap(), 9999);
    assert!(pack_llllvar_len_bcd(10000).is_err());

    // 2. Variable field serialization clamping and formatting safety
    let mut msg = Iso8583Message::new(*b"0200");
    // LLVAR field 2 (PAN max 19) with oversized input
    msg.set_field(2, vec![b'9'; 50]);
    let wire = msg.serialize();
    let parsed = Iso8583Message::parse(&wire).unwrap();
    assert_eq!(parsed.get_field(2).unwrap().len(), 19);

    // 3. AS2805 BCD serialization with Field 112 (LLLLVAR)
    let mut bcd_msg = Iso8583Message::new(*b"0200");
    let test_pqc = vec![0xEE; 1500];
    bcd_msg.set_field(112, test_pqc.clone());
    let bcd_wire = bcd_msg.serialize_as2805_bcd().unwrap();
    let bcd_parsed = Iso8583Message::parse_as2805_bcd(&bcd_wire).unwrap();
    assert_eq!(bcd_parsed.get_field(112).unwrap(), test_pqc.as_slice());
}

