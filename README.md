# Project Solomon

So basically this is a post-quantum cryptography layer I built that sits transparently in front of a bank's payment switch. The idea is that current encryption will eventually break under quantum computing — this protects against that by signing every transaction with ML-DSA-65, which is a brand new NIST standard (FIPS 204) specifically built for the post-quantum era.

The key thing is **zero rewrites** on the bank's side. It just proxies their existing ISO 8583 traffic, signs it, compresses the signatures via a ZK proof, and packs everything into spare fields the standard already has (Field 112/123). They don't touch a line of their own code.

There's also a **shadow/monitor mode** — the proxy runs alongside live traffic without touching it, so a bank can trial it for a week with zero risk before flipping it on.

---

## How it works — what happens to a transaction

```
 ATM / POS terminal
        │
        │  ISO 8583 TCP frame (plaintext)
        ▼
┌───────────────────────────────────────┐
│           Solomon Proxy               │
│                                       │
│  1. Parse ISO 8583 frame              │
│     (2-byte BE length + body)         │
│                                       │
│  2. ML-DSA-65 Sign  ◄── private key  │
│     (NIST FIPS 204, constant-time,    │
│      no data-dependent branches)      │
│                                       │
│  3. VBR Gate                          │
│     (verify the sig we just made      │
│      before releasing — catches       │
│      hardware bit-flip faults)        │
│                                       │
│  4. ZK Proof (STARK)                  │
│     generate_stark_proof()            │
│     verify_stark_proof()  ← asserted  │
│     (self-contained, no SP1/zkVM)     │
│                                       │
│  5. Pack into ISO 8583 Field 112/123  │
│     (spare "national data" field —    │
│      the bank's switch ignores it)    │
│                                       │
│  6. Forward enriched frame upstream   │
└───────────────────────────────────────┘
        │
        │  Same ISO 8583 frame + PQC payload in Field 112
        ▼
 Bank's core banking system
 (untouched)
        │
        ▼
┌───────────────────────────────────────┐
│        Solomon Proxy (Receiving)      │
│                                       │
│  1. Extract Field 112 payload         │
│  2. Verify ML-DSA-65 signature        │
│  3. Verify ZK proof                   │
│  4. Strip PQC field                   │
│  5. Pass clean original frame to host │
└───────────────────────────────────────┘
```

**In monitor/shadow mode** steps 2–5 run off to the side, the original frame is forwarded untouched, and nothing is ever rejected. You just get a log of what would have happened.

---

## Repo structure

```
project-solomon/
│
├── solomon-core/               # main crypto engine + proxy
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── scalar.rs       # constant-time field arithmetic
│   │   │   ├── sign.rs         # ML-DSA-65 signing (Fiat-Shamir, VBR gate)
│   │   │   ├── nist_api.rs     # keygen / sign / verify (FIPS 204 API)
│   │   │   ├── shake.rs        # pure Keccak / SHAKE-128 / SHAKE-256
│   │   │   └── heartbeat.rs    # fail-closed daily token gate
│   │   └── proxy.rs            # ISO 8583 TCP proxy + Field 112 repacker
│   └── tests/
│       ├── acvp_test.rs        # NIST ACVP vectors — byte-for-byte check
│       ├── kat_sig_test.rs     # NIST known-answer tests
│       └── compression_1000_to_1_test.rs  # prove → verify roundtrip
│
├── solomon-zk/                 # self-contained STARK prover/verifier
│   └── src/
│       ├── field.rs            # Goldilocks field (2^64 - 2^32 + 1)
│       ├── air.rs              # algebraic intermediate representation
│       ├── fri.rs / merkle.rs  # FRI + Merkle commitments
│       ├── ntt.rs / intt.rs    # NTT/iNTT + SIMD (AVX-512/NEON)
│       ├── prover.rs           # generate_stark_proof()
│       └── verifier.rs         # verify_stark_proof()
│
├── pilot/
│   └── run_pilot.py            # one command — boots everything, emits HTML report
│
├── PILOT.md                    # what this is + honest caveats
└── README.md                   # you are here
```

---

## What I'm asking you to look at

I'm not asking you to run anything (though you can if you want to verify). Mainly I just want to know: **does this pass as a product that can or will be adopted by small banks and payment aggregators(just need your opinion)**

**1. Does the structure make sense?**
Does the layout above look like someone who knows what they're doing, or does something feel off?

**2. Is the crypto actually real, or hand-wavy?**
- `solomon-core/tests/acvp_test.rs` — does it load real NIST JSON vectors (`data/acvp_mldsa65_siggen.json`) and assert byte-for-byte output? If yes, the signature scheme is legitimate.
- `solomon-core/tests/compression_1000_to_1_test.rs` — does it actually call `verify_stark_proof` and assert it passes? If it only checks size and never verifies, the ZK claim is unproven — call that out.

**3. Does the honesty check out?**
Check `PILOT.md` — we say it's not TLS 1.3, and the "1000:1" number is a Merkle root accumulator not the proof itself. Does this read as honest or oversold?

**4. Bottom line — would you show this to a vendor?**
If you were me and wanted to pitch this to a fintech or a bank, does this look passable professionally? What would make you not trust it?

---

## If you want to actually run it

```bash
# needs Rust stable 1.80+ and Python 3.11+
cargo build --workspace --release
cargo test --workspace --all-features --release

# one-command pilot — boots everything, drives traffic, spits out an HTML report
python pilot/run_pilot.py
```
