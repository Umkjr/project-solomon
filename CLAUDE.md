# CLAUDE.md — Project Solomon

> **Post-Quantum Cryptographic (PQC) Core, Batch Commitment Gateway & Reverse Proxy Engine**  
> Clean-room, zero-dependency, constant-time Rust implementation of **NIST FIPS 204 (ML-DSA-65)** with lightweight **Merkle/Keccak Cryptographic Commitments** and transparent **ISO 8583** legacy financial rail repacking.

---

## 1. Project Overview

**Project Solomon** is a lightweight post-quantum cryptographic prototype designed to secure legacy financial switches and payment networks against quantum decryption threats ("Store Now, Decrypt Later") with zero application code rewrites.

### Core Architectural Pillars
1. **Math & Post-Quantum Signing Core (`solomon-core`):** A strictly `#![no_std]`, zero-dependency, constant-time implementation of the NIST FIPS 204 (ML-DSA-65) digital signature algorithm in pure Rust.
2. **Cryptographic Batch Commitments (`solomon-core/src/zk/batch.rs`):** Generates 128-byte hash-based authenticity commitments over verified ML-DSA-65 signatures, aggregating them via a Merkle tree micro-batch accumulator to optimize throughput.
3. **Transparent Financial Reverse Proxy (`solomon-core/src/proxy.rs`):** An asynchronous Axum-based reverse proxy that intercepts plaintext transaction streams on local loopback, signs/attests them, and dynamically repacks the 128-byte commitments into underutilized fields of legacy financial standards (e.g., ISO 8583 Field 112 / Field 123).
4. **Licensing & Heartbeat Control Plane (`solomon-cloud`):** A centralized management hub providing rolling daily epoch tokens (`Daily_Salt`) and ingesting anonymized performance telemetry.
5. **Quantum Cryptography Verification Suite (`tests/test_quantum_crypto.py`):** Comprehensive empirical simulation and formal verification engine for Quantum Key Distribution (QKD), Quantum Bit Error Rate (QBER), Cascade error correction, and entropy monitoring.

---

## 2. Cryptographic Parameters & Algebraic Specifications

All mathematical transformations execute strictly within the quotient ring:
$$R_q = \mathbb{Z}_q[x] / (x^{256} + 1)$$

### Strict System Parameter Bounds (ML-DSA-65)

| Parameter | Mathematical Value | Description |
| :--- | :--- | :--- |
| **Field Modulus ($q$)** | `8,380,417` | Prime modulus ($q = 2^{23} - 2^{13} + 1$) |
| **Matrix Dimension ($k$)** | `6` | Vector dimension for output polynomial matrices |
| **Matrix Dimension ($l$)** | `5` | Vector dimension for secret polynomial matrices |
| **Noise Bound ($\eta$)** | `4` | Uniform bound for secret noise vector sampling $[-\eta, \eta]$ |
| **Masking Bound ($\gamma_1$)** | $2^{19} = 524,288$ | Masking coefficient boundary condition |
| **Rounding Factor ($\gamma_2$)** | $(q-1)/32 = 261,888$ | Low-bit scaling and rounding parameter |
| **Challenge Beta ($\beta$)** | `196` | Norm acceptance bound ($\|z\|_\infty < \gamma_1 - \beta$) |
| **Montgomery Radix ($R$)** | $2^{32}$ | Montgomery reduction multiplier radix |
| **Montgomery Constant ($Q^{-1}$)**| `58,728,449` | $q^{-1} \pmod{2^{32}}$ for subtraction-based reduction |
| **Primitive Root ($\omega$)** | `1753` | Primitive 512th root of unity modulo $q$ ($\omega^{512} \equiv 1 \pmod q$) |
| **NTT Inverse Factor** | `8,347,681` | $256^{-1} \pmod q$ (`16,382` in Montgomery form) |
| **Challenge Hamming Weight ($\tau$)** | `49` | Number of $\pm 1$ coefficients in challenge polynomial $c$ |
| **Hint Weight Limit ($\omega$)** | `55` | Maximum number of 1-bits allowed in signature hint vector $h$ |

---

## 3. Security Architecture & Production Hardening

- **Zero-Branch Constant-Time Arithmetic:** Absolutely no data-dependent branching (`if`, `else`, `match`) or runtime CPU division (`/`, `%`) in inner loops. Boundary corrections use bitwise arithmetic shifts and masking:
  ```rust
  let diff = t - Q;
  let mask = diff >> 31; // -1 if t < Q, 0 if t >= Q
  t = diff + (Q & mask);
  ```
- **Hardware Speculative Execution Barriers (`barriers.rs`):** Emits hardware serialization instructions (`_mm_lfence()` on x86_64) prior to secret-dependent masking loops to prevent speculative cache-timing side-channels (Spectre-style leakage).
- **Arithmetic Secret Sharing (`sign.rs`):** Secret keys ($s_1, s_2$) never reside in raw form in a single memory register; they are split into independent random shares ($s_x = \text{share}_A + \text{share}_B \pmod q$) to neutralize electromagnetic (EM) profiling.
- **Verify-Before-Release (VBR) Gate:** The signing engine internally self-verifies candidate signatures against the public key before emitting bytes to trap physical DRAM bit-flips (Rowhammer fault injection).
- **Volatile Pointer Zeroization (`zeroize.rs`):** Implements explicit volatile memory scrubbing (`core::ptr::write_volatile`) and compiler memory fences (`Ordering::SeqCst`) on `Drop` to ensure private key material is erased immediately when leaving scope.
- **Strict Hint-Index Monotonicity (CVE-2026-24850 Protection):** Verification deserializers enforce strictly increasing hint indices ($x_1 < x_2$) to eliminate signature malleability.
- **Fail-Closed Licensing Architecture (`heartbeat.rs`):** Edge instances fail-closed and self-abort if the rolling cryptographic heartbeat `Daily_Salt` is uninitialized or tampered with.

---

## 4. Repository Structure

```text
project-solomon/
├── Cargo.toml                       # Master workspace definition
├── solomon-core/                    # Post-Quantum Cryptographic Engine & Proxy
│   ├── Cargo.toml                   # Core library dependencies & build features
│   ├── src/
│   │   ├── crypto/
│   │   │   ├── scalar.rs            # Constant-time field arithmetic (Z_q, Montgomery reduction)
│   │   │   ├── poly.rs              # Cooley-Tukey NTT, iNTT, DL-SCA coordinate shuffling
│   │   │   ├── matrix.rs            # PolyVector<K>, PolyMatrix<K,L>, ExpandA, ExpandS
│   │   │   ├── shake.rs             # Pure Keccak-p[1600,24], SHAKE-128, SHAKE-256
│   │   │   ├── packing.rs           # Poly/vector bit-packing, High/Low bit decomposition
│   │   │   ├── sign.rs              # Fiat-Shamir with aborts, VBR gate, arithmetic shares
│   │   │   ├── zeroize.rs           # Volatile pointer memory scrubber (Zeroize trait)
│   │   │   ├── barriers.rs          # Hardware execution serialization (LFENCE / ISB)
│   │   │   ├── str_enc.rs           # Compile-time string literal XOR encryption macro
│   │   │   ├── heartbeat.rs         # Fail-closed Daily Salt licensing verification
│   │   │   ├── batch.rs             # Merkle/Keccak hash commitment layer
│   │   │   ├── nist_api.rs          # Standard FIPS 204 keygen, sign, verify exports
│   │   │   └── mod.rs               # Crypto module root
│   │   ├── proxy.rs                 # Transparent Axum reverse proxy & ISO 8583 repacker
│   │   ├── error.rs                 # Domain error types
│   │   ├── lib.rs                   # Library crate entrypoint (#![no_std])
│   │   └── main.rs                  # Standalone edge daemon binary
│   └── tests/
│       └── integration_test.rs      # Comprehensive Rust integration test suite (13 tests)
├── solomon-cloud/                   # Central SaaS Fleet Control Plane
│   ├── dashboard/                   # High-throughput monitoring UI
│   │   └── index.html               # Real-time canvas telemetry charts & node fleet
│   ├── src/
│   │   ├── api.rs                   # Licensing handshake & daily epoch generator
│   │   ├── crypto.rs                # Ed25519 token signing
│   │   └── db.rs                    # Fleet state storage
├── tests/
│   └── test_quantum_crypto.py       # Formal verification suite (QKD, QBER, Cascade, QRNG)
├── run_barrage_simulation.py        # High-throughput load test script
├── run_tech_demo.py                 # Multi-service local tech demo launcher
└── tech_demo_chaos.py               # 3-scenario cyber-defense chaos simulation
```

---

## 5. Development & Testing Commands

### 5.1 Prerequisites
- **Rust Toolchain:** `1.80+` / `1.96+` (stable)
- **Python:** `3.11+` / `3.12+` with `pytest`

### 5.2 Running the Cryptographic Verification Suites

#### 1. Post-Quantum Rust Core Tests (Unit & Integration)
```bash
# Run all 31 cryptographic tests in solomon-core
cd project-solomon/solomon-core
cargo test -- --test-threads=1
```
*Note: `--test-threads=1` ensures deterministic isolation for the global `Daily_Salt` fail-closed tests.*

#### 2. Quantum Cryptography Formal Verification Suite (Python)
```bash
# Run standalone formal audit runner (formatted table output)
python tests/test_quantum_crypto.py

# Run via PyTest
pytest -v tests/test_quantum_crypto.py
```

### 5.3 Running the Local End-to-End Environment

```bash
# 1. Start the Mock Control Plane (Port 9000)
python project-solomon/solomon-core/mock_control_plane.py

# 2. Start the Mock Banking Backend (Port 8081)
python project-solomon/solomon-core/mock_banking_backend.py

# 3. Launch the Solomon PQ-Proxy (Port 8080)
cd project-solomon/solomon-core
cargo run --release --features proxy

# 4. Execute an end-to-end financial transaction
python project-solomon/solomon-core/test_e2e.py
```

### 5.4 Running Chaos & Security Simulations

```bash
# Run the 3-Scenario Cyber Defense Chaos Simulation (Fail-Closed, Rowhammer, DudeCT)
python project-solomon/tech_demo_chaos.py

# Run high-concurrency transaction barrage simulation
python project-solomon/run_barrage_simulation.py
```

---

## 6. Implementation Invariants & Coding Guidelines

1. **`#![no_std]` Strictness:** All core cryptographic modules under `solomon-core/src/crypto/` must remain strictly `#![no_std]` compatible, relying exclusively on `core`.
2. **Side-Channel Invariant:** Never introduce variable-time code constructs (`/`, `%`, or value-based conditional branches) in arithmetic routines. Always use constant-time Montgomery reduction and bitwise masking.
3. **Deterministic Memory Scrubbing:** Any heap or stack structure containing private lattice components ($s_1, s_2, k, \mu$) must implement explicit volatile pointer zeroing on `Drop`.
4. **Release Profile Security:** Production binaries must be built with aggressive symbol stripping and abort-on-panic to prevent binary decompilation:
   ```toml
   [profile.release]
   opt-level = "s"
   lto = true
   codegen-units = 1
   panic = "abort"
   strip = true
   ```
5. **Hint Deserialization Order:** The hint unpacker must strictly validate monotonic order ($x_1 < x_2$) across non-zero hint indices to prevent signature malleability.
