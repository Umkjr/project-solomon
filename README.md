# Project Solomon

So basically this is a post-quantum cryptography layer I built that sits transparently in front of a bank's payment switch. The idea is that current encryption will eventually break under quantum computing — this protects against that by signing every transaction with ML-DSA-65, which is a brand new NIST standard (FIPS 204) specifically built for the post-quantum era.

The key thing is **zero rewrites** on the bank's side. It just proxies their existing ISO 8583 traffic, signs it, compresses the signatures via a ZK proof, and packs everything into spare fields the standard already has (Field 112/123). They don't touch a line of their own code.

There's also a **shadow/monitor mode** — the proxy runs alongside live traffic without touching it, so a bank can trial it for a week with zero risk before flipping it on.

---

## What I'm asking you to look at

I'm not asking you to run anything (though you can if you want to verify). Mainly I just want to know: **does this look like real engineering, or does it look like buzzword soup?**

Specifically:

**1. Does the structure make sense?**
- `solomon-core/` — the Rust crypto engine (ML-DSA-65, constant-time, `#![no_std]`)
- `solomon-zk/` — self-contained STARK prover/verifier (AIR, FRI, Merkle, NTT over a Goldilocks field — no external zkVM)
- `solomon-core/src/proxy.rs` — the actual transparent proxy + ISO 8583 repacker
- `pilot/run_pilot.py` — one command boots the whole thing and spits out a report

**2. Is the crypto actually real, or is it hand-wavy?**
- `solomon-core/tests/acvp_test.rs` — open this and check if it loads real NIST JSON vectors (`data/acvp_mldsa65_siggen.json`) and asserts byte-for-byte output. If yes, the signature scheme is legitimate.
- `solomon-core/tests/compression_1000_to_1_test.rs` — check if it actually calls `verify_stark_proof` and asserts it passes. If it only checks size and never verifies, the ZK claim is unproven — call that out.

**3. Does the honesty check out?**
- Check `PILOT.md` — a project that states its own limitations (we say it's not TLS 1.3, we say the 1000:1 ratio is a Merkle root not the proof itself) is more credible than one that only hypes. Does this read as honest or oversold?

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
