fn main() {
    solomon_core::crypto::heartbeat::set_daily_salt([0x5Au8; 32]);
    use solomon_core::crypto::nist_api::{keygen, sign, verify};

    let seed = [0x5Au8; 32];
    let msg = b"Project Solomon cryptographic heartbeat payload";

    // Warmup
    for _ in 0..3 {
        let (sk, pk) = keygen(&seed);
        let sig = sign(&sk, msg);
        let _ = verify(&pk, msg, &sig);
    }

    // Timed run
    let n = 50u64;
    let start = std::time::Instant::now();
    for _ in 0..n {
        let (sk, pk) = keygen(&seed);
        let sig = sign(&sk, msg);
        let _ = verify(&pk, msg, &sig);
    }
    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / n as u128;
    let avg_ms = elapsed.as_millis() as f64 / n as f64;
    eprintln!("keygen+sign+verify avg over {} runs: {:.3}ms ({} us)", n, avg_ms, avg_us);
    eprintln!("Total elapsed: {:?}", elapsed);
    eprintln!("Sign-only timing: running sign 200 times...");
    let (sk, pk) = keygen(&seed);
    let n2 = 200u64;
    let start2 = std::time::Instant::now();
    for _ in 0..n2 {
        let sig = sign(&sk, msg);
        let _ = verify(&pk, msg, &sig);
    }
    let elapsed2 = start2.elapsed();
    let avg_ms2 = elapsed2.as_millis() as f64 / n2 as f64;
    eprintln!("sign+verify only avg over {} runs: {:.3}ms ({} us)", n2, elapsed2.as_micros() / n2 as u128, elapsed2.as_micros() / n2 as u128);
}
