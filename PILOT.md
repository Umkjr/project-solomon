# Project Solomon — Easy-Pilot Brief

> **Zero-rewrite post-quantum hardening for your payment switch — that also hands your
> auditor a tamper-proof, RBI-aligned evidence trail.**

One page for a small NBFC / fintech. If you run a legacy ISO 8583 switch and a product team
that says "no rewrites, no slowdown", this is the shape of the pilot.

---

## What it does for you

| You have today | Solomon drops in and adds |
| :--- | :--- |
| An ISO 8583 payment switch (TCS BaNCS, iMobil, in-house, etc.) | A **transparent proxy** in front of it — **no application code changes** |
| Plaintext transactions that today's cryptography will not protect against a quantum harvest ("Store Now, Decrypt Later") | Post-quantum **ML-DSA-65 (NIST FIPS 204)** signs every message, time-stamped and tamper-evident |
| A stack your auditor keeps asking about | A **hash-chained, segment-sealed evidence log** aligned to RBI cyber-resilience expectations |

## Why it's low-risk to try

- **Run it in shadow for a week.** The proxy starts in **monitor mode**: it watches **every**
  transaction, runs the crypto path **off to the side**, and **forwards your traffic untouched**.
  Nothing is rejected, nothing is modified, nothing can break you. You read the report. Only
  when you're comfortable do you flip it to enforcement.
- **Sub-millisecond class overhead** on the enforced path (numbers in the pilot report).
- **No procurement horror-show.** No off-site signing ceremony, no secret-sharing rituals to
  start. You nominate an email address, we agree a daily rolling token, done.

## What the pilot hands you

A single forwardable **pilot report** (HTML) containing:

1. **Zero-rewrite transplant proof** — transactions driven through the real proxy path.
2. **Latency** — p50 / p95 / p99 over the enforced path.
3. **Crypto is real** — automated evidence: ML-DSA-65 matches **NIST ACVP official vectors
   byte-for-byte**, and the zero-knowledge proof the demo generates is **independently verified**
   (generated *and* verified, not just sized).
4. **RBI-aligned evidence trail** — the audit log you can hand your SSA / CISA.

## The honest caveat

We don't promise to "pass an RBI audit". RBI doesn't certify software — your own SSA / CISA /
internal auditor does. What we hand you is **evidence**: tamper-evident logs, NIST-vector-tested
crypto, and verifiable proof generation. Your auditor judges it. That's the honest frame and
it's the frame that survives scrutiny.

## What we do NOT claim

- **~~TLS 1.3~~** — the project ships a custom post-quantum tunnel for encrypted channels; it is
  **not** a TLS 1.3 terminator. We won't overstate it.
- **~~1,000:1 proof compression~~** — that ratio is the **Merkle batch accumulator** (1,000 signatures
  → one 32-byte root). The STARK-style proof itself is ~3:1 and is *verified*, not just sized.
  Ask us about the numbers in the report; we'll give you the real ones.

## How to pilot

```bash
python pilot/run_pilot.py              # boots the topology, drives load, emits the report
```

The report lands in `pilot/reports/pilot_report_<timestamp>.html`.

---

For the hands-on verification steps a technical reviewer should run themselves, see
[`REVIEWER_CHECKLIST.md`](REVIEWER_CHECKLIST.md).