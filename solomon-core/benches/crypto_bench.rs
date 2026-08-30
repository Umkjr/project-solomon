use criterion::{black_box, criterion_group, criterion_main, Criterion};
use solomon_core::crypto::nist_api::{keygen, sign, sign_hedged, verify};

fn bench_ml_dsa_65(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65");

    let seed = [0x5au8; 32];
    let (sk, pk) = keygen(&seed);
    let msg = b"ISO8583_FINANCIAL_TRANSACTION_PAYLOAD_FOR_BENCHMARKING_ENTERPRISE_PQC";
    let rnd = [0x42u8; 32];
    let sig = sign(&sk, msg);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let (sk, pk) = keygen(black_box(&seed));
            black_box((sk, pk))
        });
    });

    group.bench_function("sign_deterministic", |b| {
        b.iter(|| {
            let sig = sign(&sk, black_box(msg));
            black_box(sig)
        });
    });

    group.bench_function("sign_hedged", |b| {
        b.iter(|| {
            let sig = sign_hedged(&sk, black_box(msg), black_box(&rnd), black_box(b""));
            black_box(sig)
        });
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = verify(&pk, black_box(msg), black_box(&sig));
            black_box(valid)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_ml_dsa_65);
criterion_main!(benches);
