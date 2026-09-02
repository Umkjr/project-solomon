# Project Solomon — Enterprise Post-Quantum Cryptography & AI Payment Shield

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![NIST Compliance](https://img.shields.io/badge/NIST-FIPS%20204%20(ML--DSA--65)-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![PCI-DSS](https://img.shields.io/badge/PCI--DSS-3.5%20Memory%20Locking-blueviolet.svg)](https://www.pcisecuritystandards.org/)
[![RBI Compliance](https://img.shields.io/badge/RBI-Cybersecurity%20Framework-emerald.svg)](https://www.rbi.org.in/)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B%20Stable-orange.svg)](https://www.rust-lang.org/)

**Project Solomon** is an enterprise-grade, transparent Post-Quantum Cryptographic (PQC) Gateway, Zero-Knowledge Audit Compression Engine, and Edge AI Telemetry Shield designed for financial payment switches, interbank networks, and payment aggregators (NPCI/UPI, TCS BaNCS, Finacle, Base24).

It protects banking transactions against future "Harvest Now, Decrypt Later" (HNDL) quantum threats by securing traffic with **FIPS 204 ML-DSA-65** post-quantum signatures with **zero code changes** required on existing core banking hosts.

---

## Key Capabilities

1. **Dual-Engine Post-Quantum Signatures (NIST FIPS 204 ML-DSA-65)**
   - **Audited Default**: Ships by default with audited RustCrypto `ml-dsa v0.1.1` (pure Rust, constant-time, zero unproven custom math).
   - **High-Performance SIMD**: Preserves ultra-fast AVX-512 and ARM NEON hardware acceleration behind the opt-in `fast-simd` cargo feature flag for benchmarking.
   - **100% KAT Validated**: Passes 60/60 NIST ACVP test vectors and cross-engine differential KAT vectors with bit-for-bit key and signature equivalence.

2. **Zero Core Banking Changes (Transparent Field 112/123 Repacker & EBCDIC)**
   - Intercepts standard ISO 8583 TCP frames and REST payment payloads.
   - Automatically signs transaction data and injects PQC signatures into spare National Data fields (Field 112 / Field 123) that existing switches safely ignore.
   - Native bidirectional **IBM CP037 EBCDIC** translation engine for legacy mainframe switches (TCS BaNCS, AS/400).
   - Receiving-mode proxy validates signatures upstream, strips the PQC field, and passes clean native frames to the core banking ledger.

3. **Enterprise Key Management & PCI-DSS 3.5 Memory Protection**
   - **Persistent Encrypted Keystore**: AES-256-GCM AEAD envelope encryption with PBKDF2/SHA-256 (10,000 rounds) key derivation.
   - **OS Memory Locking**: Prevents secret keys from ever swapping to disk via Windows `VirtualLock` and Unix `mlock` APIs.
   - **Multi-Tenant Registry**: Dynamic isolation and zero-downtime key rotation across multiple sponsor banks (HDFC, ICICI, Axis).
   - **KMS Root-of-Trust**: Pluggable KMS envelope backend for AWS KMS, Azure Key Vault, and HashiCorp Vault.

4. **Authenticated Hybrid TLS / AEAD Tunnel (No XOR Ciphers)**
   - Hardened inter-proxy tunnels use authenticated **AES-256-GCM** framing with sequence-counter nonce derivation to defeat on-wire bit-flipping and packet replay.
   - Fail-closed 72-hour grace period eliminates hardcoded killswitches (`process::exit(1)`) while preserving operational resilience.

5. **Tamper-Evident RBI & PCI-DSS Continuous Audit Hash Ledger**
   - Cryptographic SHA-256 hash chains ($H_n = \text{SHA256}(H_{n-1} \parallel \text{Record})$) recording all transaction and administrative actions.
   - **Unbroken Across Reboots**: Automatic head-hash recovery preserves unbroken blockchain continuity across server restarts and daily segment rotations.
   - Strict Indian Cloud Data Localization validation (AWS `ap-south-1`, Azure `centralindia`, GCP `asia-south1`) with automatic rejection of foreign hops.

6. **Edge AI Anomaly Detection & Byzantine-Robust Federated Learning**
   - Microsecond non-blocking forward pass ($< 5\,\mu\text{s}$) evaluates an 8-dimensional telemetry vector (amount log scale, PAN entropy, velocity, inter-arrival time, MCC risk, POS entry mode).
   - Asynchronous local training decoupled from the live transaction path.
   - Byzantine-robust Federated Averaging (`FedAvg` with coordinate-wise trimmed mean) aggregates edge gateway weights in Solomon Cloud without exposing plaintext customer PII.

7. **Centralized Cloud Control Plane & Fleet Management Dashboard**
   - Unified web control plane (`solomon-cloud`) with live fleet health, node suspension toggles, configuration hot-reloading, and real-time network telemetry.

---

## Transaction Lifecycle Flow

```
 ATM / POS / Fintech Client
            │
            │  Standard ISO 8583 / JSON Payment Frame
            ▼
┌────────────────────────────────────────────────────────┐
│               Solomon Ingress Proxy                    │
│                                                        │
│  1. Extract Telemetry Features (8D Normalized Vector)  │
│  2. Microsecond AI Anomaly Scoring (< 5 µs)            │
│  3. Async Dispatch to SGD Background Training Queue   │
│  4. ML-DSA-65 Sign (NIST FIPS 204 Audited Engine)     │
│  5. Verify-Before-Release (VBR) Hardware Fault Check   │
│  6. Pack PQC Signature into Field 112 / 123           │
│     (Automatic IBM CP037 EBCDIC conversion if needed)  │
│  7. Append to Tamper-Evident RBI Audit Hash Chain      │
│  8. Forward Enriched Frame Upstream                   │
└────────────────────────────────────────────────────────┘
            │
            │  Standard Frame + Transparent Field 112 PQC Payload
            ▼
 Core Banking Switch (TCS BaNCS, Finacle, Base24)
 (Operates unchanged — ignores national data field)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│               Solomon Egress Proxy                     │
│                                                        │
│  1. Extract & Validate Field 112 PQC Signature         │
│  2. Verify ZK Proof / Audit Record Integrity           │
│  3. Strip PQC Field and restore clean native frame     │
│  4. Deliver verified transaction to core account ledger│
└────────────────────────────────────────────────────────┘
```

---

## Workspace Structure

```
project-solomon/
├── solomon-core/               # Core PQC Gateway, Keystore & Audit Engine
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── audited_mldsa.rs # FIPS 204 RustCrypto ML-DSA-65 drop-in engine
│   │   │   ├── hybrid.rs       # Dual classical (Ed25519) + PQC (ML-DSA) scheme
│   │   │   ├── nist_api.rs     # FIPS 204 standard KeyGen, Sign, Verify API
│   │   │   └── heartbeat.rs    # Tamper-resistant daily license token gate
│   │   ├── audit/              # RBI & PCI-DSS unbroken hash chain & SAR engine
│   │   ├── ai/                 # Edge Autoencoder, feature extraction & DP SGD
│   │   ├── hsm.rs              # AES-256-GCM keystore, KMS & OS memory locking
│   │   ├── ebcdic.rs           # IBM CP037 EBCDIC bidirectional translation
│   │   ├── tls_tunnel.rs       # AES-256-GCM authenticated frame transport
│   │   └── proxy.rs            # High-throughput async TCP & HTTP payment proxy
│   └── tests/                  # ACVP KATs, Differential tests, Barrage tests
│
├── solomon-zk/                 # Standalone STARK & FRI Zero-Knowledge Engine
│   ├── src/
│   │   ├── field.rs            # Goldilocks field (p = 2^64 - 2^32 + 1)
│   │   ├── air.rs              # Algebraic Intermediate Representation (AIR)
│   │   ├── fri.rs / merkle.rs  # FRI folding commitment protocol & Merkle proofs
│   │   ├── ntt.rs / intt.rs    # 4-step cache-oblivious NTT & SIMD acceleration
│   │   ├── prover.rs           # STARK proof generation
│   │   └── verifier.rs         # Standalone STARK proof verifier
│   └── tests/                  # AIR constraints, FRI folding & verifier tests
│
├── solomon-cloud/              # Centralized Control Plane & Fleet Dashboard
│   ├── src/
│   │   ├── api.rs              # REST APIs for fleet management & telemetry
│   │   ├── db.rs               # SQLite fleet state & node registry
│   │   ├── ai_aggregator.rs    # Byzantine-robust FedAvg weight aggregator
│   │   └── main.rs             # Axum server with CORS & static dashboard
│   ├── dashboard/              # Interactive Glassmorphic Control Plane UI
│   └── tests/                  # Database, PKI & Dashboard API integration tests
│
├── docs/                       # Architecture, cryptographic whitepaper & security
├── ARCHITECTURE.md             # System architecture & integration specifications
├── CRYPTO.md                   # Formal cryptographic parameters & AIR equations
└── Cargo.toml                  # Workspace root manifest
```

---

## Building and Testing

### Prerequisites
- Rust stable `1.80+`
- Cargo workspace tools

### Compile Workspace
```bash
# Standard audited release build
cargo build --workspace --release

# High-performance SIMD build (AVX-512 / NEON)
cargo build --workspace --release --features solomon-core/fast-simd
```

### Run Comprehensive Verification
```bash
# Run all workspace unit, integration, and compliance tests
cargo test --workspace --release

# Run with proxy network features enabled
cargo test -p solomon-core --features proxy --release
```

---

## Production Security & Compliance Checklist

- [x] **FIPS 204 Standard Compliant**: Default crypto uses audited `ml-dsa v0.1.1` from RustCrypto.
- [x] **PCI-DSS 3.5 Memory Protection**: Keystores use OS page-locking (`VirtualLock` / `mlock`) and AES-256-GCM persistence.
- [x] **Zero Plaintext XOR Tunnels**: Network payloads protected with authenticated AES-256-GCM AEAD framing.
- [x] **RBI Cybersecurity Framework Compliant**: Tamper-evident SHA-256 audit ledger with unbroken reboot continuity and Indian cloud region enforcement.
- [x] **No Production Panics**: Background batch provers auto-recover on transient errors; all panic backdoors gated strictly to debug builds.
- [x] **No PII in AI Training**: Edge autoencoder trains solely on normalized network telemetry without inspecting cardholder names or card PAN numbers.
