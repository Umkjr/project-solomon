#![cfg(feature = "proxy")]
//! Tests for Hybrid Post-Quantum TLS 1.3 / ML-KEM-768 + X25519 Tunnel Engine.

use solomon_core::tls_tunnel::{
    HybridPqKeyExchange, apply_pq_stream_cipher,
};

#[test]
fn test_hybrid_pq_key_exchange_roundtrip() {
    // 1. Server generates Hybrid Keypair (X25519 + ML-KEM-768)
    let (server_sk, server_pk) = HybridPqKeyExchange::generate_keypair();
    assert_eq!(server_pk.x25519_pk.len(), 32);
    assert_eq!(server_pk.ml_kem_pk_bytes.len(), 1184); // ML-KEM-768 Encapsulation Key length

    // 2. Client encapsulates against Server Public Key
    let (client_ct, client_session_key) = HybridPqKeyExchange::client_encapsulate(&server_pk)
        .expect("Client encapsulation failed");
    assert_eq!(client_ct.x25519_ephemeral_pk.len(), 32);
    assert_eq!(client_ct.ml_kem_ct_bytes.len(), 1088); // ML-KEM-768 Ciphertext length
    assert_eq!(client_session_key.len(), 32);

    // 3. Server decapsulates Client Ciphertext using Server Secret Key
    let server_session_key = HybridPqKeyExchange::server_decapsulate(&server_sk, &client_ct)
        .expect("Server decapsulation failed");
    assert_eq!(server_session_key.len(), 32);

    // 4. Shared 256-bit symmetric session keys MUST match identically!
    assert_eq!(client_session_key, server_session_key);
}

#[test]
fn test_hybrid_pq_tamper_resistance() {
    let (server_sk, server_pk) = HybridPqKeyExchange::generate_keypair();
    let (mut client_ct, _client_key) = HybridPqKeyExchange::client_encapsulate(&server_pk).unwrap();

    // Tamper with classical X25519 ephemeral PK
    let mut tampered_x25519 = client_ct.clone();
    tampered_x25519.x25519_ephemeral_pk[0] ^= 0xFF;
    let tampered_x25519_key = HybridPqKeyExchange::server_decapsulate(&server_sk, &tampered_x25519).unwrap();
    assert_ne!(_client_key, tampered_x25519_key); // Must produce different / non-matching key

    // Tamper with ML-KEM-768 ciphertext
    client_ct.ml_kem_ct_bytes[10] ^= 0xFF;
    let result = HybridPqKeyExchange::server_decapsulate(&server_sk, &client_ct);
    // In ML-KEM (Fujisaki-Okamoto transform), decapsulation of an invalid ciphertext yields an implicit random failure key
    if let Ok(tampered_kem_key) = result {
        assert_ne!(_client_key, tampered_kem_key);
    }
}

#[test]
fn test_pq_stream_cipher_encryption_decryption() {
    let session_key = [0x5Au8; 32];
    let original_payload = b"02004111111111111111000000000000050000";
    
    let mut encrypted = original_payload.to_vec();
    apply_pq_stream_cipher(&mut encrypted, &session_key, 1);
    assert_ne!(&encrypted, original_payload);

    let mut decrypted = encrypted.clone();
    apply_pq_stream_cipher(&mut decrypted, &session_key, 1);
    assert_eq!(&decrypted, original_payload);

    // Different sequence number should fail to decrypt properly
    let mut bad_seq_decrypted = encrypted.clone();
    apply_pq_stream_cipher(&mut bad_seq_decrypted, &session_key, 2);
    assert_ne!(&bad_seq_decrypted, original_payload);
}

#[test]
fn test_aead_authenticated_framing_and_bitflip_rejection() {
    use solomon_core::tls_tunnel::{encrypt_pq_frame, decrypt_pq_frame};

    let session_key = [0x7Cu8; 32];
    let original_payload = b"ISO8583_PAYMENT_TX_AUTH_INR_99999";
    let seq = 42u64;

    // 1. Encrypt frame with AES-256-GCM AEAD
    let ciphertext = encrypt_pq_frame(original_payload, &session_key, seq)
        .expect("AEAD encryption should succeed");
    assert_ne!(&ciphertext, original_payload);

    // 2. Decrypt valid frame
    let decrypted = decrypt_pq_frame(&ciphertext, &session_key, seq)
        .expect("AEAD decryption should succeed");
    assert_eq!(&decrypted, original_payload);

    // 3. Bit-flip attack: tamper with single byte in ciphertext
    let mut tampered = ciphertext.clone();
    tampered[5] ^= 0x01;
    let result = decrypt_pq_frame(&tampered, &session_key, seq);
    assert!(result.is_err(), "Tampered ciphertext must fail AEAD authentication");

    // 4. Replay / Out-of-order sequence attack
    let wrong_seq = seq + 1;
    let seq_result = decrypt_pq_frame(&ciphertext, &session_key, wrong_seq);
    assert!(seq_result.is_err(), "Mismatched sequence counter must fail AEAD authentication");
}
