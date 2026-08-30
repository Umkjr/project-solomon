#![no_main]
use libfuzzer_sys::fuzz_target;
use solomon_core::crypto::hybrid::{
    construct_composite_message_with_ctx, HybridPublicKey, HybridSignature,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE,
};

fuzz_target!(|data: &[u8]| {
    // 1. Target memory boundary parsing for Hybrid Public Keys
    if data.len() >= HYBRID_PUBLIC_KEY_SIZE {
        let pk_slice = &data[..HYBRID_PUBLIC_KEY_SIZE];
        let _ = HybridPublicKey::from_slice(pk_slice);
    }

    // 2. Target memory boundary parsing for Hybrid Signatures
    if data.len() >= HYBRID_SIGNATURE_SIZE {
        let sig_slice = &data[..HYBRID_SIGNATURE_SIZE];
        let _ = HybridSignature::from_slice(sig_slice);
    }

    // 3. Target delimiter collision & variable-length context reconstruction
    if data.len() >= 32 + 1952 + 4 {
        let ed_pk = match <&[u8; 32]>::try_from(&data[0..32]) {
            Ok(p) => p,
            Err(_) => return,
        };
        let pq_pk = match <&[u8; 1952]>::try_from(&data[32..32 + 1952]) {
            Ok(p) => p,
            Err(_) => return,
        };
        
        let ctx_len = ((data[1984] as usize) << 8) | (data[1985] as usize);
        let rem = &data[1986..];
        
        if rem.len() >= ctx_len {
            let ctx = &rem[..ctx_len];
            let msg = &rem[ctx_len..];
            // Must format without panicking or triggering out-of-bounds index shifts
            let _ = construct_composite_message_with_ctx(ed_pk, pq_pk, msg, ctx);
        }
    }
});
