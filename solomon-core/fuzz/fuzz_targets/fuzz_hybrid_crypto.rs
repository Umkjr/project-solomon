#![no_main]
use libfuzzer_sys::fuzz_target;
use solomon_core::crypto::hybrid::{
    hybrid_verify, HybridPublicKey, HybridSignature,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SIGNATURE_SIZE,
};

fuzz_target!(|data: &[u8]| {
    // Total min length for pk + sig + min message
    if data.len() < HYBRID_PUBLIC_KEY_SIZE + HYBRID_SIGNATURE_SIZE {
        return;
    }

    let pk_bytes = &data[0..HYBRID_PUBLIC_KEY_SIZE];
    let sig_bytes = &data[HYBRID_PUBLIC_KEY_SIZE..HYBRID_PUBLIC_KEY_SIZE + HYBRID_SIGNATURE_SIZE];
    let msg = &data[HYBRID_PUBLIC_KEY_SIZE + HYBRID_SIGNATURE_SIZE..];

    // Constrain message length to prevent unbounded execution timeouts in fuzzing engine
    if msg.len() > 1024 {
        return;
    }

    if let (Some(pk), Some(sig)) = (
        HybridPublicKey::from_slice(pk_bytes),
        HybridSignature::from_slice(sig_bytes),
    ) {
        // Must fail-closed (return false) on mutated inputs rather than panic
        let _ = hybrid_verify(&pk, msg, &sig);
    }
});
