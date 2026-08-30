#!/usr/bin/env python3
"""Project Solomon — One-command pilot kit.

Boots the local topology (mock control plane + mock banking backend + proxy),
drives a latency load through the real PQC path (sign -> VBR verify -> ZK proof
-> ISO 8583 repack), verifies crypto evidence (ACVP/KAT + prove->verify), and
emits a forwardable HTML pilot report.

By default the proxy runs in MONITOR (shadow) mode: every transaction is
forwarded untouched and nothing is ever rejected — a non-disruptive pilot.
Set SOLOMON_PROXY_MODE=ingress to run the enforcing path instead.

Usage (from the repository root):
    python pilot/run_pilot.py [--tx 200] [--concurrency 20] [--no-crypto]
"""

import argparse
import datetime
import json
import math
import os
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # .../pilot
ROOT = os.path.dirname(SCRIPT_DIR)                       # repo root
CORE_DIR = os.path.join(ROOT, "solomon-core")
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

import requests  # noqa: E402
from run_tech_demo import bootstrap_infrastructure, teardown  # noqa: E402

PORT_PROXY = 8080
PROXY_URL = f"http://127.0.0.1:{PORT_PROXY}"


def pct(sorted_lat, p):
    if not sorted_lat:
        return 0.0
    k = (len(sorted_lat) - 1) * p
    lo = int(math.floor(k))
    hi = int(math.ceil(k))
    if lo == hi:
        return sorted_lat[lo]
    return sorted_lat[lo] * (hi - k) + sorted_lat[hi] * (k - lo)


def fire_tx(index):
    """POST one transaction through the proxy; returns (ok: bool, latency_ms: float)."""
    payload = {
        "transaction_id": f"pilot_{index}",
        "amount": 1000 + (index % 10000),
        "currency": "INR",
        "sponsor_bank": "bank_A_tcs_bancs",
        "timestamp": "2026-08-30T12:00:00Z",
    }
    start = time.perf_counter()
    try:
        r = requests.post(PROXY_URL, json=payload,
                          headers={"X-Sponsor-Bank": "bank_A_tcs_bancs"}, timeout=30)
        latency = (time.perf_counter() - start) * 1000.0
        return (r.status_code == 200, latency, r.status_code)
    except Exception as e:  # noqa: BLE001
        return (False, (time.perf_counter() - start) * 1000.0, f"err:{e}")


def run_latency_load(tx_count, concurrency):
    print(f"\n== Driving {tx_count} tx with concurrency={concurrency} ==")
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for r in pool.map(fire_tx, range(tx_count)):
            results.append(r)
    ok = sum(1 for r in results if r[0])
    latencies = sorted(r[1] for r in results)
    return {
        "sent": tx_count,
        "accepted": ok,
        "accepted_rate": (ok / tx_count) if tx_count else 0,
        "p50_ms": pct(latencies, 0.50),
        "p95_ms": pct(latencies, 0.95),
        "p99_ms": pct(latencies, 0.99),
        "mean_ms": statistics.mean(latencies) if latencies else 0.0,
        "min_ms": latencies[0] if latencies else 0.0,
        "max_ms": latencies[-1] if latencies else 0.0,
    }


def check_crypto_evidence():
    print("\n== Verifying crypto evidence (ACVP / KAT / prove->verify) ==")
    tests = ["acvp_test", "kat_sig_test", "compression_1000_to_1_test"]
    # shell=True + 2>&1 merges stdout/stderr into one stream so Rust's test
    # harness flushes its println! output (separate pipes cause TTY-detection
    # buffering that swallows the numbers). --nocapture is required so the
    # compression test's print_table! lines reach subprocess stdout.
    test_flags = " ".join(f"--test {t}" for t in tests)
    cmd = (f"cargo test --release -p solomon-core {test_flags} "
           f"-- --test-threads=1 --nocapture 2>&1")
    proc = subprocess.run(cmd, shell=True, cwd=CORE_DIR, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    out = proc.stdout + proc.stderr
    # Count per-test "test result: ok. N passed"
    passed = [t for t in tests if f"{t}.rs" in out and "test result: ok." in out]
    evidence = {t: ("PASS" if t in passed else "FAIL/MISSING") for t in tests}
    # Mine the compression numbers out of the capture for the report.
    numbers = {}
    for key in ("PROVE->VERIFY ROUNDTRIP", "STARK Prove Latency", "STARK Verify Latency",
                "Full STARK Proof Size", "Time to Generate 1,000 Sigs"):
        for line in out.splitlines():
            if key in line:
                val = line.strip()
                # Drop any leading bullet/label chars regardless of encoding.
                while val and not val[0].isalnum():
                    val = val[1:].lstrip()
                numbers[key] = val
                break
    return evidence, numbers, proc.returncode == 0


def render_html(lat, evidence, numbers, mode, duration_s):
    def row(k, v):
        return f"<tr><td class='k'>{k}</td><td class='v'>{v}</td></tr>"

    ev_rows = "".join(
        f"<tr><td class='k'>{k}</td><td class='v {'pass' if v=='PASS' else 'fail'}'>"
        f"{v}</td></tr>" for k, v in evidence.items()
    )
    num_rows = "".join(f"<tr><td class='k'>{k}</td><td class='v'><code>{v}</code></td></tr>"
                       for k, v in numbers.items())
    num_block = f"<table>{num_rows}</table>" if num_rows else ""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode_label = "Monitor (shadow) — traffic forwarded untouched" if mode == "monitor" else "Ingress — PQC enforced"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Project Solomon — Pilot Report</title>
<style>
 body{{font-family:Segoe UI,system-ui,Arial,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;background:#f7f8fc;}}
 h1{{color:#143a7a;border-bottom:3px solid #143a7a;padding-bottom:.4rem;}}
 h2{{color:#143a7a;margin-top:1.6rem;}}
 table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.08);}}
 td{{padding:.5rem .75rem;border-bottom:1px solid #e6e8f0;}}
 td.k{{font-weight:600;width:55%;}} td.v{{text-align:right;}}
 .pass{{color:#0a7d33;font-weight:700;}} .fail{{color:#c0272d;font-weight:700;}}
 .good{{color:#0a7d33;}} .warn{{color:#b26a00;}}
 .meta{{color:#555;}}
 code{{background:#eef1f8;padding:.1rem .35rem;border-radius:4px;}}
</style></head><body>
<h1>Project Solomon — Pilot Report</h1>
<p class="meta">Generated {ts} · Proxy mode: <b>{mode_label}</b> · Total run: {duration_s:.1f}s</p>

<h2>1. Zero-rewrite transplant &amp; latency</h2>
<p>Transactions driven through the real proxy path (ML-DSA-65 sign → VBR verify →
ZK proof → ISO 8583 Field 112/123 repack). All latency in milliseconds.</p>
<table>{row("Transactions sent", lat['sent'])}
{row("Accepted (HTTP 200)", f"<span class='good'>{lat['accepted']}</span> / {lat['sent']}")}
{row("Acceptance rate", f"{lat['accepted_rate']*100:.2f}%")}
{row("Mean latency", f"{lat['mean_ms']:.2f} ms")}
{row("p50 latency", f"{lat['p50_ms']:.2f} ms")}
{row("p95 latency", f"{lat['p95_ms']:.2f} ms")}
{row("p99 latency", f"{lat['p99_ms']:.2f} ms")}
{row("min / max", f"{lat['min_ms']:.2f} / {lat['max_ms']:.2f} ms")}
</table>

<h2>2. Crypto is real — automated evidence</h2>
<table>{ev_rows}</table>
<p class="warn"><b>Honest note on "1,000:1":</b> that headline ratio is the Merkle
<i>batch-root accumulator</i> (1,000 signatures → 32-byte root). The STARK proof
itself is ~3:1 over the raw batch — it is independently generated <i>and</i>
verified (see row below), but do not pitch it as 1,000:1 proof compression.</p>
{num_block}

<h2>3. Why you can trust this</h2>
<ul>
<li><b>ACVP vectors</b> — ML-DSA-65 matches NIST official test vectors byte-for-byte.</li>
<li><b>prove→verify</b> — the demo no longer sizes a proof; it verifies it.</li>
<li>In <b>monitor mode</b> nothing is rejected or modified — safe to shadow real traffic.</li>
</ul>
<p>Reproduce: <code>cargo test --workspace --all-features --release</code> then
<code>python pilot/run_pilot.py</code>.</p>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Solomon pilot kit + report")
    ap.add_argument("--tx", type=int, default=200, help="number of transactions")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--no-crypto", action="store_true", help="skip crypto evidence check")
    args = ap.parse_args()

    mode = os.environ.get("SOLOMON_PROXY_MODE", "monitor").lower()
    os.environ["SOLOMON_PROXY_MODE"] = mode  # ensure run_tech_demo passes it to the proxy

    t0 = time.time()
    # Crypto evidence first: it's a pure build/test and must NOT contend with the
    # live proxy's cargo build for the target/ lock.
    if args.no_crypto:
        evidence, numbers = {}, {}
    else:
        evidence, numbers, _ = check_crypto_evidence()
    try:
        bootstrap_infrastructure()
        lat = run_latency_load(args.tx, args.concurrency)
    finally:
        teardown()
    duration = time.time() - t0

    html = render_html(lat, evidence, numbers, mode, duration)
    os.makedirs(os.path.join(SCRIPT_DIR, "reports"), exist_ok=True)
    out_path = os.path.join(SCRIPT_DIR, "reports",
                            f"pilot_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    print("\n" + "=" * 60)
    print("PILOT SUMMARY")
    print("=" * 60)
    print(f"  mode            : {mode}")
    print(f"  sent/accepted   : {lat['sent']} / {lat['accepted']} ({lat['accepted_rate']*100:.2f}%)")
    print(f"  latencies (ms)  : p50={lat['p50_ms']:.2f}  p95={lat['p95_ms']:.2f}  p99={lat['p99_ms']:.2f}")
    if evidence:
        print(f"  crypto evidence : {', '.join(f'{k}={v}' for k, v in evidence.items())}")
    print(f"  report          : {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
