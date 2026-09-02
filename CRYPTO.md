# Project Solomon — Cryptographic Specification

**Standard Compliance:** NIST FIPS 204 (ML-DSA-65), NIST FIPS 203 (ML-KEM-768), RFC 8439 / FIPS 197 (AES-256-GCM)  
**Security Level:** NIST Level 3 (Equivalent to AES-192 Classical / 128-bit Quantum Security)  
**STARK Field:** Goldilocks Field $\mathbb{Z}_p$, where $p = 2^{64} - 2^{32} + 1 = \text{0xFFFF\_FFFF\_0000\_0001}$  
**ML-DSA Lattice Ring:** $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$, where $q = 8,380,417 = 2^{23} - 2^{13} + 1$  

---

## 1. Mathematical Parameters & Sizes

| Parameter | Symbol | Value | Description |
| :--- | :--- | :--- | :--- |
| **ML-DSA Modulus** | $q$ | $8,380,417$ | Prime modulus for polynomial ring $R_q$. |
| **Ring Degree** | $n$ | $256$ | Dimension of polynomial ring. |
| **Lattice Dimensions** | $(k, l)$ | $(6, 5)$ | Matrix dimensions for ML-DSA-65. |
| **Infinity Norm Bound** | $\gamma_1$ | $2^{19} = 524,288$ | Masking vector coefficient bound. |
| **Rejection Bound** | $\beta$ | $55$ | Rejection sampling threshold. |
| **Max Hint Weight** | $\omega$ | $55$ | Maximum number of $1$'s in the hint polynomial. |
| **Public Key Size** | $|pk|$ | $1,952\text{ bytes}$ | Raw public key size ($\rho \parallel \mathbf{t}_1$). |
| **Secret Key Size** | $|sk|$ | $4,032\text{ bytes}$ | Expanded secret key ($\rho \parallel K \parallel \text{tr} \parallel \mathbf{s}_1 \parallel \mathbf{s}_2 \parallel \mathbf{t}_0$). |
| **Signature Size** | $|\sigma|$ | $3,309\text{ bytes}$ | Standard FIPS 204 ML-DSA-65 signature ($\tilde{c} \parallel \mathbf{z} \parallel \mathbf{h}$). |
| **Hybrid Signature Size**| $|\sigma_{hyb}|$| $3,373\text{ bytes}$ | Composite signature ($64\text{ B Ed25519} \parallel 3309\text{ B ML-DSA-65}$). |
| **Goldilocks Prime** | $p$ | $2^{64} - 2^{32} + 1$ | 64-bit prime field for high-speed STARK proving. |

---

## 2. Dual-Engine Cryptographic Architecture

To reconcile enterprise compliance requirements with high-performance throughput demands, Project Solomon implements a **Dual-Engine Architecture**:

```
                                  ML-DSA-65 INVOCATION
                                           │
                                           ▼
                       ┌───────────────────────────────────────┐
                       │       CARGO FEATURE CONFIGURATION     │
                       └───────────────────┬───────────────────┘
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 │ default (audited-crypto)                          │ --features fast-simd
                 ▼                                                   ▼
┌──────────────────────────────────┐               ┌──────────────────────────────────┐
│        AuditedMlDsa65            │               │      Vectorized SIMD Engine      │
│  (RustCrypto ml-dsa v0.1.1)      │               │   (AVX-512 / ARM NEON Assembly)  │
├──────────────────────────────────┤               ├──────────────────────────────────┤
│ • Pure safe Rust                 │               │ • Vector register packing        │
│ • Zero unproven math             │               │ • In-register modular reduction  │
│ • FIPS 204 compliant             │               │ • Sub-400 µs signing latency     │
│ • Enterprise Procurement Ready   │               │ • High-Frequency Benchmarking    │
└──────────────────────────────────┘               └──────────────────────────────────┘
```

Both engines are continuously validated for mutual interoperability and byte-for-byte key equivalence in `solomon-core/tests/differential_kat_test.rs`.

---

## 3. Storage & Transport Cryptography

### 3.1 Encrypted Keystore Specification
* **Key Derivation:** PBKDF2 with HMAC-SHA256, 10,000 iterations, and a 32-byte cryptographically secure random salt.
* **Cipher:** AES-256-GCM authenticated encryption (NIST SP 800-38D).
* **Payload Format:** `[12-byte Nonce] || [Ciphertext] || [16-byte GCM Tag]`.
* **RAM Protection:** Secret keys are pinned in physical memory via OS kernel page locking (`VirtualLock` on Windows, `mlock` on POSIX) and wiped with zeroize on drop.

### 3.2 Authenticated Transport Framing (AEAD Tunnel)
* **Cipher:** AES-256-GCM.
* **Nonce Generation:** Derived deterministically from a 64-bit monotonic packet sequence counter to defeat replay attacks:
  $$\text{Nonce} = \text{Counter}_{64} \parallel \mathbf{0}_{32}$$
* **Authentication:** Payloads failing GCM tag verification are instantly dropped before parsing.

---

## 4. STARK Algebraic Intermediate Representation (AIR) Constraints

The zero-knowledge compression engine operates over the Goldilocks field and enforces three constraint groups:

### 4.1 NTT Butterfly Transition Constraints
For trace row inputs $a, b$, twiddle factor $\omega$, and next row outputs $u, v$:
$$u_{next} - (a_{local} + b_{local} \cdot \omega_{local}) \equiv 0 \pmod p$$
$$v_{next} - (a_{local} - b_{local} \cdot \omega_{local}) \equiv 0 \pmod p$$

### 4.2 Infinity Norm Boundary Constraints
Verifies that all coefficients of the witness vector $\mathbf{z}$ satisfy:
$$\|\mathbf{z}\|_\infty < \gamma_1 - \beta$$
Enforced via base-decomposition range-check polynomial constraints over discrete sub-fields.

### 4.3 Vanishing Polynomial & Quotient Division
For execution trace evaluation domain $H$ of size $N = 640$:
$$Z_H(X) = X^N - 1$$
$$Q(X) = \frac{C(X)}{Z_H(X)}$$
Computed out-of-domain at random Fiat-Shamir point $\zeta \in \mathbb{Z}_p$ using Fermat's Little Theorem modular inversion:
$$\zeta^{-1} \equiv \zeta^{p-2} \pmod p$$
