# Project Solomon — Cryptographic Specification

**Standard Compliance:** NIST FIPS 204 (ML-DSA-65) & NIST FIPS 203 (ML-KEM-768)  
**Security Level:** NIST Level 3 (Equivalent to AES-192 Classical / Quantum Collision Resistance)  
**STARK Field:** $\mathbb{Z}_q$, where $q = 8,380,417 = 2^{23} - 2^{13} + 1$  

---

## 1. Mathematical Parameters

| Parameter | Symbol | Value |
| :--- | :--- | :--- |
| **Prime Modulus** | $q$ | $8,380,417$ |
| **Ring Degree** | $n$ | $256$ |
| **Matrix Dimensions** | $(k, l)$ | $(6, 5)$ |
| **Infinity Norm Bound** | $\gamma_1$ | $2^{19} = 524,288$ |
| **Rejection Bound** | $\beta$ | $55$ |
| **Max Hint Weight** | $\omega$ | $55$ |
| **Public Key Size** | $|pk|$ | $1,952\text{ bytes}$ |
| **Secret Key Size** | $|sk|$ | $4,032\text{ bytes}$ |
| **Signature Size** | $|\sigma|$ | $3,309\text{ bytes}$ |
| **Hybrid Signature Size** | $|\sigma_{hyb}|$ | $3,373\text{ bytes}$ ($64\text{ Ed} + 3309\text{ PQC}$) |

---

## 2. Algebraic Intermediate Representation (AIR) Constraints

The STARK prover maps ML-DSA-65 verification into three constraint domains:

### 2.1 NTT Butterfly Transition Constraints
For trace row inputs $a, b$, twiddle factor $\omega$, and next row outputs $u, v$:
$$u_{next} - (a_{local} + b_{local} \cdot \omega_{local}) \equiv 0 \pmod q$$
$$v_{next} - (a_{local} - b_{local} \cdot \omega_{local}) \equiv 0 \pmod q$$

### 2.2 Infinity Norm Boundary Constraints
Verifies that all coefficients of the witness vector $\mathbf{z}$ satisfy:
$$\|\mathbf{z}\|_\infty < \gamma_1 - \beta$$
Enforced via base-decomposition range-check polynomial constraints over discrete sub-fields.

### 2.3 Vanishing Polynomial & Quotient Division
For execution trace evaluation domain $H$ of size $N = 640$:
$$Z_H(X) = X^N - 1$$
$$Q(X) = \frac{C(X)}{Z_H(X)}$$
Computed out-of-domain at random Fiat-Shamir point $\zeta \in \mathbb{Z}_q$ using modular inversion:
$$\zeta^{-1} \equiv \zeta^{q-2} \pmod q$$

---

## 3. STARK Proof Byte Layout (128 Bytes)

| Byte Range | Field Element | Description |
| :--- | :--- | :--- |
| `[0..32]` | Trace Merkle Root | 32-byte Keccak-256 root over the 640-row trace. |
| `[32..44]` | Mixing Scalars ($\alpha_0, \alpha_1, \alpha_2$) | 3 random 4-byte mixing coefficients sampled from challenger. |
| `[44..48]` | Evaluation Point ($\zeta$) | 4-byte out-of-domain challenge point. |
| `[48..52]` | Quotient Evaluation ($q_0$) | 4-byte evaluation of $Q(\zeta)$. |
| `[52..56]` | FRI Folding Constant ($C_{FRI}$) | 4-byte folded constant commitment. |
| `[56..128]` | Context Padding | Reserved for multi-batch Merkle inclusion paths. |
