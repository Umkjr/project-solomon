use solomon_zk::trace::{generate_keccak_rows, TraceBuilder};
use solomon_zk::quotient::QuotientEvaluator;
use solomon_zk::air::{ShakeMatrixExpansionAir, MlDsaFullAir, AirBuilder};
use solomon_zk::field::GoldilocksField;
use solomon_zk::prover::generate_stark_proof;
use solomon_zk::verifier::verify_stark_proof;

struct MockAirBuilder {
    local_row: Vec<GoldilocksField>,
    next_row: Vec<GoldilocksField>,
    eq_assert_count: usize,
    zero_assert_count: usize,
    lookup_count: usize,
}

impl MockAirBuilder {
    fn new(local: Vec<GoldilocksField>, next: Vec<GoldilocksField>) -> Self {
        Self {
            local_row: local,
            next_row: next,
            eq_assert_count: 0,
            zero_assert_count: 0,
            lookup_count: 0,
        }
    }
}

impl AirBuilder for MockAirBuilder {
    type F = GoldilocksField;
    type Var = GoldilocksField;

    fn assert_eq(&mut self, _x: Self::Var, _y: Self::Var) {
        self.eq_assert_count += 1;
    }

    fn assert_zero(&mut self, _x: Self::Var) {
        self.zero_assert_count += 1;
    }

    fn assert_lookup(&mut self, _limb: Self::Var, _table_id: u32) {
        self.lookup_count += 1;
    }

    fn add(&self, x: Self::Var, y: Self::Var) -> Self::Var {
        use solomon_zk::field::Field;
        x.add(y)
    }

    fn local(&self) -> &[Self::Var] {
        &self.local_row
    }

    fn next(&self) -> &[Self::Var] {
        &self.next_row
    }
}

#[test]
fn test_keccak_rows_structure_and_memory_budget() {
    let seed = [0x42u8; 32];
    let rows = generate_keccak_rows(&seed);

    assert_eq!(rows.len(), 24, "Must generate exactly 24 Keccak round rows");
    for (r_idx, row) in rows.iter().enumerate() {
        assert_eq!(row.len(), 400, "Row {} must be 400 columns wide", r_idx);
        for &val in row.iter() {
            assert!(val.0 < 16, "Each nibble cell must be in [0, 15]");
        }
    }

    let total_bytes = rows.len() * 400 * std::mem::size_of::<GoldilocksField>();
    println!("\n[Keccak AIR] 24-round trace memory footprint: {} bytes ({:.2} KB)", total_bytes, total_bytes as f64 / 1024.0);
    assert_eq!(total_bytes, 76_800, "Peak memory for 24-round Keccak rows must be exactly 75 KB");
}

#[test]
fn test_keccak_air_builder_theta_transition() {
    let seed = [0x55u8; 32];
    let rows = generate_keccak_rows(&seed);

    let shake_air: ShakeMatrixExpansionAir<GoldilocksField> = ShakeMatrixExpansionAir::new();
    let mut builder = MockAirBuilder::new(rows[0].to_vec(), rows[1].to_vec());
    shake_air.eval(&mut builder);

    assert_eq!(builder.eq_assert_count, 5, "Shake AIR must enforce 5 column consistency assertions");

    let full_air: MlDsaFullAir<GoldilocksField> = MlDsaFullAir::new();
    let mut full_builder = MockAirBuilder::new(rows[0].to_vec(), rows[1].to_vec());
    full_air.eval(&mut full_builder);
    assert!(full_builder.eq_assert_count >= 5, "Full AIR must include Shake constraints");
}

#[test]
fn test_keccak_constraint_evaluator_active() {
    let mut trace_builder = TraceBuilder::new();
    let mut dummy_sig = vec![0u8; 3309];
    dummy_sig[0] = 0xAA;
    trace_builder.ingest_signature(&dummy_sig);

    let alphas = vec![
        GoldilocksField::from_u64(10),
        GoldilocksField::from_u64(20),
        GoldilocksField::from_u64(30),
        GoldilocksField::from_u64(40),
    ];
    let zeta = GoldilocksField::from_u64(999);
    let evaluator = QuotientEvaluator::new(alphas, zeta);

    let seed1 = [0x11u8; 32];
    let keccak_rows1 = generate_keccak_rows(&seed1);
    let quotient_with_keccak = evaluator.evaluate_with_keccak_rows(&trace_builder.matrix, &keccak_rows1);

    let quotient_without_keccak = evaluator.evaluate_with_keccak_rows(&trace_builder.matrix, &[]);

    assert_ne!(
        quotient_with_keccak, quotient_without_keccak,
        "Quotient evaluation with Keccak rows must differ from evaluation without Keccak rows"
    );
}

#[test]
fn test_keccak_seed_tamper_alters_stark_proof() {
    let mut sig = vec![0u8; 3309];
    for i in 0..sig.len() {
        sig[i] = ((i * 7 + 1) % 256) as u8;
    }
    let mut pk1 = vec![0u8; 1952];
    for i in 0..pk1.len() {
        pk1[i] = ((i * 13 + 3) % 256) as u8;
    }
    let mut pk2 = pk1.clone();
    pk2[0] ^= 0xFF; // Tamper Keccak seed byte 0

    let msg = b"Transaction INR 100,000".to_vec();

    let proof1 = generate_stark_proof(&sig, &pk1, &msg);
    let proof2 = generate_stark_proof(&sig, &pk2, &msg);

    assert_ne!(proof1, proof2, "Proofs with different public key seeds must differ");

    let res1 = verify_stark_proof(&proof1, &pk1, &msg);
    assert_eq!(res1, Ok(true), "Proof 1 must verify with pk1");

    let res2 = verify_stark_proof(&proof2, &pk2, &msg);
    assert_eq!(res2, Ok(true), "Proof 2 must verify with pk2");
}
