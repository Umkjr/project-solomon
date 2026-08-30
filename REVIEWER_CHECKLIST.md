# Reviewer Checklist 

You're being asked to sanity-check Project Solomon: a **post-quantum signature scheme
(NIST FIPS 204 / ML-DSA-65)** plus a **zero-knowledge proof** that compresses the signatures,
wrapped in a **transparent reverse proxy** for ISO 8583 payment traffic. The seller needs it
reviewed **cold** — you have no stake, you're not from India, and you should try to break it.

Do **not** trust the README. Run these yourself. Everything below is reproducible from a clean
checkout of this repository.

---

## 0. Env

```bash
rustup default stable        # 1.80+ / 1.96+
cargo build --release --workspace
```

## 1. Build is clean

```bash
cargo build --workspace --release
```

- No errors, no warnings you'd flag in review.

## 2. Tests passed? 

```bash
cargo test --workspace --all-features --release
```

- Look at the **actual counts**: how many tests ran, how many failed.
- `--all-features` matters — the proxy path is feature-gated.

## 3. Is the ML-DSA actually correct? 

The signature scheme is only credible if it hits **official NIST test vectors**.

- **`solomon-core/tests/acvp_test.rs`** — reads real NIST **ACVP JSON vectors**
  (`data/acvp_mldsa65_siggen.json`) and asserts **byte-for-byte deterministic** output. If this
  passes against genuine NIST vectors, the scheme is real, not a hand-wavy approximation.
- **`solomon-core/tests/kat_sig_test.rs`** — NIST-style known-answer tests.

Open the files. Do they load real vectors and assert exact bytes? Ask for the vector source.
A scheme that can't reproduce the spec's own test vectors is not FIPS 204.

## 4. THE sharp test — is the zero-knowledge proof actually *verified*?

Open **`solomon-core/tests/compression_1000_to_1_test.rs`**.

- Does it **generate** a proof **and then call the verifier** on it?
- Does it `assert!(verified)` — i.e., prove the proof it made passes verification?
- **If it only checks size / compression ratio and never verifies, that is a red flag** —
  it means the "compression" claim is unproven. Call that out loudly.

(The current state: it uses `solomon_zk::verify_stark_proof` and asserts the roundtrip
`PROVE->VERIFY ROUNDTRIP: true`. Verify that's still true when *you* read it.)

## 5. Latency claim is reproducible

```bash
cargo bench        # or: cargo run --release --bin timing_bench_main
```

- Is the claimed overhead actually sub-millisecond-ish on *your* machine?
- A single run means nothing — run it a few times, take the median.

## 6. End-to-end transplant — does a PQC payload really get injected?

```bash
python run_tech_demo.py
```

- Does an ML-DSA signature (and proof) actually get **injected into an ISO 8583 message
  (Field 112/123)** and **verifiably stripped** at the receiving end — **without any
  application code changes**?
- This is the whole product pitch. If this doesn't demonstrably work end-to-end, nothing else
  matters. One-command pilot + report:

```bash
python pilot/run_pilot.py
```

- Produces a forwardable report with latency + acceptance + proof-size + crypto-evidence.

## 7. Be brutal on honesty

- **"Does this look like real engineering, or vaporware-shadowed-by-buzzwords?"**
- Check the docs ([`PILOT.md`](PILOT.md)) for what they **refuse** to claim — a real project
  states its limitations (e.g. "not TLS 1.3", "the 1,000:1 ratio is a Merkle root, not the
  proof"). If they're *only* hyping, that's a tell.
- What would make you **not** trust it? Say that too — it's the cheapest insurance before a
  bank sees it.

---

## Suggested verdict format

> **Build:** clean / not
> **Tests:** N passed, M failed
> **ML-DSA against NIST vectors:** pass / fail / unverifiable
> **ZK proof actually verified:** yes / NO ← this is the one that matters
> **Latency on my machine:** X ms
> **End-to-end injection works:** yes / no
> **Honesty check:** they claimed [X]; I could not verify [X] because...
> **Bottom line:** would you point a bank at this? why / why not.
