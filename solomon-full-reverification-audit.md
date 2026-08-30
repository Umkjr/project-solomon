# Project Solomon — Full Re-Verification Audit (Post-STARK-Build)
## Purpose
Multiple benchmark numbers have been cited across different sessions (0.460ms, 0.5ms, 0.8ms, 1.1ms, 1.3ms) and used to build financial projections (revenue models, GPU cost calculations, TPS capacity). Before any of these numbers are used in outreach, pitches, or planning, they need to be independently re-derived from the actual current codebase — not from any prior summary, walkthrough, or self-report.

**Ground rule: every number in your answer must come from something you actually ran and can show output for. If you cannot verify a number, say so explicitly rather than repeating a previously-claimed figure.**

---

## Part 1: List the files first

Before running anything, list out and briefly describe every file relevant to:
1. The ML-DSA-65 signing/verification core (`solomon-core/src/crypto/`)
2. The current STARK prover pipeline (`solomon-zk/src/` — trace, challenger, quotient, fri, lde, intt, merkle, prover, air)
3. Any benchmark files (`solomon-core/benches/`, any `tests/*bench*.rs`, `run_production_barrage.py`, `benchmark_full_pipeline.rs`)
4. The proxy's actual HTTP header injection code (`proxy.rs`, wherever `X-Solomon-STARK-Root` / `X-Solomon-FRI-Commitment` is set)

Report this list back to me first as a plain file inventory (path + one-line description each) before doing any deeper verification, so I know what actually exists versus what was only described in prior chat sessions.

---

## Part 2: Re-verify the core ML-DSA-65 timing (ground truth baseline)

- Run the existing timing benchmark for keygen+sign+verify (the one that previously measured 2.4–3.4ms) fresh, right now, and paste the real output.
- If that specific benchmark file no longer exists or was modified, say so, and run whatever the current equivalent is — but be explicit that it may not be the same test as before.

---

## Part 3: Re-verify the STARK prover timing — the number the whole financial model depends on

- Locate the actual benchmark that produced the "0.8ms" and later "1.1ms" STARK proving numbers.
- Read the benchmark code itself and answer plainly: does this benchmark call the FULL current pipeline (trace generation → iNTT → LDE → quotient evaluation → FRI folding → final proof bytes), or does it only time a subset of these steps?
- Run it fresh and paste the real, current output.
- Explicitly check: does the benchmark include the Keccak/challenger overhead, or is that timed separately/not at all?
- Cross-check against the "Zero-Mock" verdict from the prior session: at that time, the honest answer was "the LDE domain was partially synthesized, not derived from real trace interpolation in all cases." Has that been fully resolved, or does it still apply? Quote the relevant code if uncertain.

---

## Part 4: Test for correctness under adversarial input — not just happy-path timing

This has never been tested in any prior session. It matters more than speed:

- Take a valid signed transaction, generate a valid STARK proof for it.
- Now corrupt ONE byte of the signature (or the trace, or the proof itself — pick one and be explicit which).
- Run the verifier against the corrupted input.
- Report plainly: does verification correctly REJECT the tampered input, or does it incorrectly ACCEPT it?
- Do this for at least 3 different corruption points (signature byte, trace matrix entry, final proof bytes) and report each result separately.

**This is the single most important test in this entire document. A fast proof system that doesn't reject invalid inputs is not a security system — it's a fast way to generate meaningless bytes.**

---

## Part 5: Re-derive the financial/capacity numbers from Part 2 and 3's REAL results

Using the actual verified timing numbers from Parts 2 and 3 (not the previously-claimed 0.5ms/0.8ms/1.3ms):

- Recalculate: how many transactions per second can one CPU core actually sustain (1000ms / real total ms per transaction)?
- Recalculate: how many cores are needed for 5,000 TPS peak load, using the real number?
- State plainly whether this materially changes the GPU/server cost estimate from the earlier financial model, and by roughly how much.

---

## Part 6: Check the specific "Zero Data Bloat" and "1000:1 compression" claim against what's actually being compressed

- Confirm: does the current `ZkAuthorizationProof` / Merkle commitment / STARK proof output actually replace the need to store the raw 3.3KB ML-DSA signature anywhere in the pipeline, or does the raw signature still need to be stored/transmitted somewhere for the system to function (e.g., for the async/deferred verification step)?
- If the raw signature is still needed somewhere, state clearly that the "1000:1 storage reduction" claim only applies to a specific part of the data (e.g., hot-path logs) and not the full picture — quantify what is and isn't actually reduced.

---

## Reporting format
Answer Part 1 first and wait for confirmation before proceeding, OR complete all parts in one pass if instructed to — but every single numeric claim (timing, TPS, byte sizes) must be traceable to an actual command you ran in this session, with the real output pasted, not a number carried over from a previous conversation's summary.
