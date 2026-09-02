# Project Solomon — System Architecture & FinTech Integration

**Version:** 2.0.0 (Enterprise Compliance Release)  
**Security Standards:** NIST FIPS 204 (ML-DSA-65), NIST FIPS 203 (ML-KEM-768), PCI-DSS 3.5, RBI Cybersecurity Framework  
**Engine:** Pure Safe Rust (`--release`), Dual-Engine (RustCrypto Audited Default + Zero-Copy SIMD), Native STARK AIR  

---

## 1. High-Level Architecture Overview

Project Solomon operates as a high-throughput Post-Quantum Cryptographic Gateway, Zero-Knowledge Audit Compression Engine, and Edge AI Telemetry Shield designed for financial payment rails, API switches, and interbank networks (NPCI/UPI, TCS BaNCS, Finacle, Base24).

```
                                INCOMING FINTECH / UPI / ATM TRAFFIC
                                                │
                                                ▼
                        ┌──────────────────────────────────────────────┐
                        │          SOLOMON HIGH-SPEED GATEWAY          │
                        │     (Pure Rust / Axum / Zero-Copy SIMD)      │
                        └───────────────────────┬──────────────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
    ┌─────────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────────┐
    │   TRACK 1: FAST-PATH    │   │    TRACK 2: ZK BATCHING   │   │    TRACK 3: FEDERATED AI  │
    │  (Real-Time Clearing)   │   │   (Audit Log Compression) │   │   (Edge Anomaly Defense)  │
    ├─────────────────────────┤   ├───────────────────────────┤   ├───────────────────────────┤
    │ • FIPS 204 (ML-DSA-65)  │   │ • 640-Row Native AIR      │   │ • 8D Telemetry Autoencoder│
    │ • Hybrid Mode (Ed25519) │   │ • 1,000:1 Compression     │   │ • Sub-5 µs Non-blocking   │
    │ • Latency: < 0.50 ms    │   │ • Prover: ~ 1.10 ms       │   │ • Lock-free SGD Training  │
    │ • Throughput: 30k+ TPS  │   │ • Verifier: 13 µs         │   │ • Byzantine-Robust FedAvg │
    │ • 100% RBI / NIST / PCI │   │ • 99.996% Archival Savings│   │ • Zero PII Exposure       │
    └─────────────────────────┘   └───────────────────────────┘   └───────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Dual-Engine Cryptography (`solomon-core/src/crypto/`)
* **Audited FIPS 204 Default (`audited_mldsa.rs`):** Wraps RustCrypto's `ml-dsa v0.1.1` in pure Rust, constant-time arithmetic without data-dependent branching, satisfying strict enterprise procurement audits.
* **SIMD Hardware Engine (`sign.rs` / `solomon-zk/src/simd/`):** Gated behind the `fast-simd` cargo flag, offering AVX-512 and ARM NEON vectorized polynomial arithmetic for high-frequency benchmarking.
* **Differential KAT Validation (`differential_kat_test.rs`):** Guarantees byte-for-byte key equivalence and signature interoperability between the audited engine and the custom SIMD implementation across all test vectors.
* **Verify-Before-Release (VBR):** Hardware fault-injection (Rowhammer) gate validates signatures before memory release, zeroizing lattice memory upon verification failure.

### 2.2 Enterprise Keystore & Memory Protection (`solomon-core/src/hsm.rs`)
* **OS Memory Locking:** Uses Windows `VirtualLock` and POSIX `mlock` to pin cryptographic private keys in physical RAM, preventing keys from ever being swapped to disk (PCI-DSS 3.5).
* **Encrypted File Backend:** AES-256-GCM authenticated encryption with PBKDF2/SHA-256 (10,000 iterations) key derivation to persist node keys across reboots.
* **Multi-Tenant Key Registry:** Provides strict cryptographic isolation and dynamic rotation (`rotate_tenant_key`) across multiple acquiring banks without service downtime.
* **KMS Envelope Root-of-Trust:** Pluggable envelope encryption for AWS KMS, Azure Key Vault, and HashiCorp Vault.

### 2.3 Transparent ISO 8583 & Mainframe EBCDIC Engine (`solomon-core/src/ebcdic.rs` & `proxy.rs`)
* **Field 112 / Field 123 Injection:** Transparently packages ML-DSA-65 post-quantum signatures and ZK receipts into standard spare national data fields that existing switches ignore.
* **IBM CP037 EBCDIC Translation:** Complete bidirectional 256-byte translation tables for seamless interoperability with mainframe switches (e.g. TCS BaNCS, AS/400).
* **Shadow / Monitor Mode:** Transparently taps live network traffic to generate telemetry and signature verification logs without altering or dropping live transactions.

### 2.4 Authenticated AEAD Tunneling (`solomon-core/src/tls_tunnel.rs`)
* **AES-256-GCM AEAD Framing:** Replaces unauthenticated stream ciphers with authenticated encryption, using monotonic sequence counter nonce derivation to prevent on-wire bit-flipping and replay attacks.
* **Grace Period Fail-Closed Logic:** Replaces hardcoded process termination (`std::process::exit`) with a resilient 72-hour grace period upon licensing verification failures.

### 2.5 Tamper-Evident Continuous Audit Ledger (`solomon-core/src/audit/`)
* **Unbroken SHA-256 Hash Chaining:** $H_n = \text{SHA256}(H_{n-1} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{Details})$.
* **Reboot Recovery:** Automatically extracts the latest block hash on startup to preserve audit continuity across service restarts and daily midnight segment rotations.
* **RBI Data Localization:** Validates Indian cloud host endpoints (AWS `ap-south-1`, Azure `centralindia`, GCP `asia-south1`) and rejects non-Indian routes.

### 2.6 Edge AI Telemetry & Byzantine-Robust Federated Learning (`solomon-core/src/ai/`)
* **Normalized 8D Feature Vector:** Extracts transaction amount, processing code risk, STAN interval, MCC risk, foreign currency indicator, PAN entropy, POS entry mode, and cyclical hour of day.
* **Microsecond Edge Scoring:** Forward pass takes $< 5\,\mu\text{s}$ to calculate reconstructive anomaly score $S(x) = \frac{1}{8}\sum (x_i - \hat{x}_i)^2 / 0.1$.
* **Decoupled Training Queue:** Features are dispatched to a lock-free background channel, running asynchronous SGD without blocking incoming transaction threads.
* **Differential Privacy & Byzantine Aggregator:** Edge nodes apply L2 norm clipping and Gaussian noise before uploading weights. Solomon Cloud aggregates updates via coordinate-wise trimmed mean ($\beta = 0.20$), rejecting poisoned client updates.

### 2.7 Native STARK Prover & Verifier (`solomon-zk/`)
* **Prover (`generate_stark_proof`):** Maps transaction audit batches to a 640-row trace over Goldilocks field $\mathbb{Z}_p$ ($p = 2^{64} - 2^{32} + 1$), applying 4-step cache-oblivious NTT, $4\times$ LDE, and recursive FRI folding.
* **Verifier (`verify_stark_proof`):** Standalone zero-knowledge verifier checking Merkle trace commitments, Fiat-Shamir challenges, and FRI colinearity across fold layers.

### 2.8 Solomon Cloud Control Plane (`solomon-cloud/`)
* **REST Fleet Management APIs:** Endpoints for fleet health (`/api/dashboard/fleet`), remote node suspension (`/api/dashboard/toggle`), configuration synchronization (`/api/dashboard/sync`), and node enrollment (`/api/dashboard/register`).
* **Interactive Dashboard:** Real-time web UI serving live edge telemetry, throughput metrics, and cryptographic status.

---

## 3. Proxy Network Header Specification

When running in HTTP / REST gateway mode, Project Solomon injects and validates the following headers:

| Header Name | Type | Description |
| :--- | :--- | :--- |
| `X-Solomon-Hybrid-Sig` | Base64 String | 3,373-byte composite signature ($64\text{ B Ed25519} \parallel 3309\text{ B ML-DSA-65}$). |
| `X-Solomon-ZK-Receipt` | Hex String | 128-byte cryptographic STARK receipt proving batch audit integrity. |
| `X-Solomon-Tenant-ID` | UTF-8 String | Identifier of the tenant bank key used for cryptographic signing. |
| `X-Solomon-Anomaly-Score` | Float (`0.0` - `1.0`) | Reconstructive anomaly score generated by the edge autoencoder. |
| `X-Solomon-Audit-Hash` | Hex String | 32-byte SHA-256 hash linking transaction to the continuous audit chain. |
