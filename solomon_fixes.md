# Project Solomon: Cryptographic & Architectural Remediation Plan

This document outlines the strict technical substitutions required to resolve the critical vulnerabilities identified in the `solomon-zk` and `solomon-core` workspaces.

---

## 1. Field Subgroup & Domain Resolution (`solomon-zk/src/verifier.rs`, `solomon-zk/src/quotient.rs`)

### Vulnerability Mechanism
The current implementation attempts to evaluate a vanishing polynomial $Z_H(X) = X^{640} - 1$ over the Dilithium prime field $q = 8,380,417$. The domain size $640$ does not divide the multiplicative group order $q - 1 = 8,380,416$. Therefore, no primitive 640-th root of unity exists, rendering STARK polynomial interpolation impossible.

### Strict Remediation
**Switch the Proving Field:**
The Dilithium base field lacks sufficient 2-adicity to support execution traces larger than $128$ ($2^7$).
*   **Action:** Transition the STARK proving engine to operate over the **Goldilocks field** ($q = 2^{64} - 2^{32} + 1$).
*   **Mathematical Justification:** The Goldilocks field supports a 2-adicity of $32$, allowing execution trace domains up to $2^{32}$, which is strictly necessary to encode the Keccak permutations and NTT operations required for ML-DSA verification.

---

## 2. AIR Constraint Implementation (`solomon-zk/src/air.rs`)

### Vulnerability Mechanism
The current `MlDsaFullAir` contains unconstrained `eval()` methods. The prover executes zero assertions, effectively proving $0 = 0$.

### Strict Remediation
**Implement Full FIPS 204 Constraints:**
*   **Action:** Define explicit algebraic transitions for every variable in the execution trace.
*   **Requirements:**
    1.  **Keccak-f[1600]:** Encode the boolean and Chi-stage constraints for the SHAKE-128 matrix expansion $\mathbf{A} \in R_q^{6 \times 5}$. This will require $pprox 150,000$ to $400,000$ rows.
    2.  **NTT Operations:** Constrain the Cooley-Tukey butterfly operations in the frequency domain.
    3.  **Infinity Norm:** Assert $\|\mathbf{z}\|_\infty < \gamma_1 - eta$.

---

## 3. Cryptographic Proof Structural Integrity (`solomon-zk/src/prover.rs`, `solomon-zk/src/fri.rs`)

### Vulnerability Mechanism
The prover truncates the STARK payload to 128 bytes by completely stripping the Merkle authentication paths for the FRI queries, effectively falsifying the zero-knowledge property.

### Strict Remediation
**Restore FRI Decommitments:**
*   **Action:** Re-enable Merkle tree commitments for all intermediate FRI folding layers.
*   **Requirements:**
    1.  Sample $N_{queries} \ge 40$ random coset points.
    2.  Include the full Merkle authentication paths for these queries in the final proof payload.
    3.  **Note on Proof Size:** Acknowledge that the valid STARK proof will scale to $pprox 20	ext{ KB} - 150	ext{ KB}$.
*   **Alternative Compression:** If a 128-byte artifact is a hard network requirement, implement a STARK-to-SNARK recursion layer (e.g., wrap the STARK verifier in a Groth16 circuit over BN254).

---

## 4. Hybrid Signature Cross-Binding (`solomon-core/src/crypto/hybrid.rs`)

### Vulnerability Mechanism
The Ed25519 signature isolates the message context from the ML-DSA signature, allowing an active adversary to execute a stripping/downgrade attack by dropping the `X-Solomon-PQ-Sig` header.

### Strict Remediation
**Implement Non-Separable Binding (RFC 9591):**
*   **Action:** Force the classical signature to explicitly commit to the post-quantum keys and context.
*   **Code Implementation:**
    Modify the signing payload in `hybrid_sign`:
    `\sigma_{Ed} = 	ext{Sign}_{sk_{Ed}}(H(	ext{message} \parallel \mathbf{pk}_{Ed} \parallel \mathbf{pk}_{PQ} \parallel 	ext{Context}))`
*   **Validation:** In `hybrid_verify`, ensure the Ed25519 verification strictly asserts the presence and integrity of the appended post-quantum material.

---

## 5. Batching Concurrency Optimization (`solomon-core/src/zk/batch.rs`)

### Vulnerability Mechanism
Synchronous double-mutex locking on 5.3 KB data structures causes severe thread contention. Synchronous inline Merkle tree generation creates massive tail-latency spikes. Unhandled `.unwrap()` lock acquisitions guarantee a total proxy server crash upon any thread panic.

### Strict Remediation
**Asynchronous Lock-Free Architecture:**
*   **Action 1 (Ingestion):** Replace the double `std::sync::Mutex` array with a lock-free concurrent queue (e.g., `crossbeam` channels) for transaction ingestion.
*   **Action 2 (Processing):** Offload batch padding and Merkle tree generation to a dedicated, asynchronous background worker thread.
*   **Action 3 (Resilience):** Eliminate all `.unwrap()` calls on lock acquisition and implement explicit panic isolation mechanisms.
