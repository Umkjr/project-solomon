use criterion::{black_box, criterion_group, criterion_main, Criterion};
use solomon_core::ai::feature::extract_features;
use solomon_core::ai::model::EdgeAutoencoder;
use solomon_core::zk::batch::{BatchAccumulator, TransactionRecord};

fn bench_ai_and_zk(c: &mut Criterion) {
    let mut group = c.benchmark_group("AI-and-ZK-Engine");

    let payload = b"02003238040000000000000000000001500008241935000481236011840";
    let timestamp = 1756040100i64;

    group.bench_function("8d_feature_extraction", |b| {
        b.iter(|| {
            let features = extract_features(black_box(payload), black_box(timestamp));
            black_box(features)
        });
    });

    let mut rng = rand::thread_rng();
    let mut model = EdgeAutoencoder::new(&mut rng);
    let features = extract_features(payload, timestamp);

    group.bench_function("ai_forward_inference", |b| {
        b.iter(|| {
            let (x_hat, h) = model.forward(black_box(&features));
            black_box((x_hat, h))
        });
    });

    let (x_hat, h) = model.forward(&features);
    group.bench_function("ai_backward_dp_pass", |b| {
        b.iter(|| {
            model.backward(black_box(&features), black_box(&x_hat), black_box(&h));
        });
    });

    // ZK Batch Merkle Tree Benchmarks
    let dummy_tx = TransactionRecord {
        payload: payload.to_vec(),
        public_key: [0x55u8; 1952],
        signature: [0x77u8; 3309],
    };
    let unpadded_batch = vec![dummy_tx.clone(); 7];
    let padded_batch = BatchAccumulator::pad_batch(unpadded_batch);

    group.bench_function("zk_batch_merkle_tree_16_leaves", |b| {
        b.iter(|| {
            let (root, proofs) = BatchAccumulator::build_merkle_tree(black_box(&padded_batch));
            black_box((root, proofs))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_ai_and_zk);
criterion_main!(benches);
