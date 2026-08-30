use criterion::{black_box, criterion_group, criterion_main, Criterion};
use solomon_core::iso8583::Iso8583Message;
use solomon_core::bcd::{pack_bcd_left_padded, unpack_bcd};

fn bench_iso8583_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("ISO-8583-Engine");

    let mut msg = Iso8583Message::new(*b"0200");
    msg.set_field(3, b"000000".to_vec());
    msg.set_field(4, b"000000015000".to_vec());
    msg.set_field(7, b"0824193500".to_vec());
    msg.set_field(11, b"048123".to_vec());
    msg.set_field(18, b"6011".to_vec());
    msg.set_field(49, b"840".to_vec());

    let raw_bytes = msg.serialize_binary_bitmap();
    let pqc_sig = [0x7au8; 3309];

    group.bench_function("message_pack_binary_bitmap", |b| {
        b.iter(|| {
            let bytes = black_box(&msg).serialize_binary_bitmap();
            black_box(bytes)
        });
    });

    group.bench_function("message_pack_hex_bitmap", |b| {
        b.iter(|| {
            let bytes = black_box(&msg).serialize_hex_bitmap();
            black_box(bytes)
        });
    });

    group.bench_function("message_parse", |b| {
        b.iter(|| {
            let parsed = Iso8583Message::parse(black_box(&raw_bytes)).expect("Parse failed");
            black_box(parsed)
        });
    });

    group.bench_function("pqc_field_112_injection", |b| {
        b.iter(|| {
            let mut clone_msg = msg.clone();
            clone_msg.inject_pqc_field(112, black_box(&pqc_sig));
            black_box(clone_msg)
        });
    });

    let mut injected_msg = msg.clone();
    injected_msg.inject_pqc_field(112, &pqc_sig);

    group.bench_function("pqc_field_112_stripping", |b| {
        b.iter(|| {
            let mut clone_msg = injected_msg.clone();
            let stripped = clone_msg.strip_pqc_field(112);
            black_box((clone_msg, stripped))
        });
    });

    let digits_16 = "1234567890123456";
    group.bench_function("bcd_encoding_16_digits", |b| {
        b.iter(|| {
            let encoded = pack_bcd_left_padded(black_box(digits_16)).expect("BCD encode failed");
            black_box(encoded)
        });
    });

    let bcd_bytes = pack_bcd_left_padded(digits_16).unwrap();
    group.bench_function("bcd_decoding_16_digits", |b| {
        b.iter(|| {
            let decoded = unpack_bcd(black_box(&bcd_bytes), 16, true).expect("BCD decode failed");
            black_box(decoded)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_iso8583_pipeline);
criterion_main!(benches);
