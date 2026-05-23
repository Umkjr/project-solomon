\# Project Solomon Quantum-Safe Cryptographic Core Specification



\## 1. Executive Mission \& Context

Project Solomon is a clean-room, zero-dependency, constant-time implementation of the NIST FIPS 204 (ML-DSA-65) Digital Signature Algorithm engineered in pure Rust. 



\### Core Architectural Paradigm

The system is built as an On-Premises Tethered Transparent Reverse Proxy. 

&#x20;The Math \& Signing Core Operates strictly on-premises within the client's secure Virtual Private Cloud (VPC), communicating with legacy services over local loopback (`127.0.0.1`). This guarantees that unencrypted sensitive financial or personal transaction payloads never leave the host network, fulfilling strict data sovereignty mandates.

&#x20;The Cloud Tether Control Plane The local engine requires a daily cryptographic handshake (heartbeat) with our centralized control plane to receive a rolling `Daily\_Salt`. Without this live telemetry stream, the mathematical initialization of the key matrices fails-closed, preventing software piracy or unauthorized binary reverse engineering.

&#x20;Identity-Centric ZK Proofs Rather than proving the full ML-DSA lattice math in a Zero-Knowledge circuit, the local proxy verifies the ML-DSA signature and then generates a lightweight ZK proof asserting its authorized identity and verification state to the network, eliminating severe prover latency.



\---



\## 2. Hard Cryptographic \& Algebraic Parameters



All mathematical operations, vectors, and polynomials must be computed strictly within the following static parameter bounds for the ML-DSA-65 security tier.



\### The Polynomial Ring

All polynomial additions, subtractions, and multiplications occur natively in the quotient ring

$$R\_q = mathbb{Z}\_q\[x]  (x^{256} + 1)$$



\### Strict Structural Constraints

&#x20;Parameter  Mathematical Value  Description  Operational Bounds 

&#x20;---  ---  --- 

&#x20;$q$  $8,380,417$  The primary post-quantum scalar field modulus. 

&#x20;$k$  $6$  Vector dimension for output polynomial matrices. 

&#x20;$l$  $5$  Vector dimension for secret polynomial matrices. 

&#x20;$eta$  $4$  Uniform bound for secret noise vector distribution sampling. 

&#x20;$gamma\_1$  $2^{19} = 524,288$  Masking coefficient boundary condition. 

&#x20;$gamma\_2$  $(q-1)32 = 261,888$  Low-bit scaling and rounding factor parameter. 

&#x20;$beta$  $196$  The strict boundary condition beta for challenge proofs. 

&#x20;$R$  $2^{32}$  Montgomery reduction radix constraint. 

&#x20;$q'$  $4,206,593$  Montgomery constant precomputed as $-q^{-1} pmod R$. 



\---



\## 3. Core Algorithmic Engineering Phases



The Antigravity orchestration loop must build and evaluate the codebase through five distinct, isolated cryptographic layers.



\### Phase 1 Constant-Time Scalar Arithmetic

Implement basic modular addition, subtraction, and multiplication over the prime field $mathbb{Z}\_q$.

&#x20;Montgomery Reduction Raw 64-bit products (`i64`) must be reduced to canonical 32-bit fields (`i32`) in the range $\[0, q-1]$ using the Montgomery multiplier architecture to completely eliminate standard CPU division (``) overhead.

&#x20;Side-Channel Protection Rule Data-dependent branching (`ifelse` checks based on integer signs or values) is completely prohibited. All operations must evaluate using static bitwise shifts and conditional selection arithmetic masks to protect against timing observation attacks.



\### Phase 2 Number Theoretic Transform (NTT) Engine

Optimize polynomial multiplication from $O(n^2)$ down to $O(n log n)$ inside the ring $R\_q$.

&#x20;Forward Transform Implement an in-place Radix-2 Cooley-Tukey butterfly transform utilizing the primitive $512text{-th}$ root of unity $omega = 1753$. Input is processed in standard array ordering, and output is emitted in bit-reversed frequency space.

&#x20;Inverse Transform (iNTT) Implement an in-place Gentleman-Sande butterfly transform accepting bit-reversed inputs and returning spatial arrays scaled natively by the precomputed modular inverse factor

$$256^{-1} equiv 8,347,681 pmod q$$

&#x20;DL-SCA Execution Shuffling To disrupt Deep Learning-Assisted Side-Channel Attacks (DL-SCA) tracking power and electromagnetic emissions, the independent butterfly nodes inside the NTT and iNTT loops must be processed in a cryptographically randomized sequence rather than strict deterministic index order.



\### Phase 3 Module Linear Algebra \& SHAKE Samplers

Handle operations across multi-dimensional grids of polynomials.

&#x20;Matrix Layout Construct abstract type structures for `PolyVectorconst N usize` and `PolyMatrixconst K usize, const L usize` to map to the $6 times 5$ dimension arrays.

&#x20;Deterministic Sampling Integrate standard `SHAKE-128` and `SHAKE-256` sponge functions to implement `ExpandA` (expanding a public seed $rho$ into the master public matrix $mathbf{A}$) and `SampleBounded` (generating the secret noise components $mathbf{s}\_1, mathbf{s}\_2$).



\### Phase 4 Fiat-Shamir with Aborts Protocol Loop

Build the state machine for Key Generation, Signing, and Verification.

&#x20;Hardware-Level Speculative Execution Barriers To prevent modern out-of-order (OoO) CPUs from speculatively executing secret-dependent lattice loops and leaking timing data to the cache, agents must insert serialization instructions (`LFENCE` on x86, `ISB` on ARM) immediately before the masking loops begin.

&#x20;Arithmetic Secret Masking Secret keys ($mathbf{s}\_1, mathbf{s}\_2$) must never reside as raw coordinates within a single memory register during processing loops. The signing engine must divide the values into independent arithmetic random shares ($mathbf{s}\_x equiv mathbf{Share}\_A + mathbf{Share}\_B pmod q$). Matrix equations must execute over these separate shares to neutralize AI-driven EM pattern profiling.

&#x20;The Signing Rejection Gate Implement a continuous deterministic verification loop. For every signature iteration, the infinity norm of the candidate vector $mathbf{z}$ must be checked. If it breaks the boundary

$$mathbf{z}\_infty ge gamma\_1 - beta$$

the execution thread must immediately execute a memory clearing sequence, increment the internal sequence nonce, abort the execution branch, and loop back to compute a fresh masking vector.

&#x20;Fault-Attack Guardrail (Verify-Before-Release) Before releasing the generated signature vector to the proxy layer, the signing engine must internally call the standard ML-DSA `verify()` function on its own output using the associated public key. If verification fails (e.g., due to a Rowhammer hardware bit-flip), the execution must instantly abort and zeroize memory to prevent leaking the master key.

&#x20;Decomposition \& HighLow Packing Implement the spatial partitioning loops (`HighBits`, `LowBits`, `MakeHint`, `UseHint`).

&#x20;Strict Hint-Index Monotonicity (CVE-2026-24850 Protection) To prevent double-spend signature malleability, the verification deserializer must strictly enforce that decoded hint indices are strictly increasing ($x\_1  x\_2$). Agents are strictly prohibited from using `=` in this boundary check.



\### Phase 5 Cryptographic Handshake \& Hardening

Protect the compiled system when shipped to untrusted on-premises enterprise networks.

&#x20;Safe Memory Destruction Manually implement the `Drop` trait on all memory blocks housing secret keys ($mathbf{s}\_1, mathbf{s}\_2$). Use explicit memory fences (`stdptrwrite\_volatile`) to ensure RAM registers are scrubbed and zeroed out the moment variables fall out of execution scope.

&#x20;The Heartbeat Module Establish a secure network loopback layer that intercepts system boots. It must parse an encrypted `Epoch Token` fetched from our licensing endpoint, extract the rolling validation parameters, and pass them down as the underlying initialization sequence vectors for the matrix components.



\---



\## 4. Reverse-Engineering Defense Matrix



Because the compiled Rust binary will reside on client-controlled hardware, the compilation profile must enforce aggressive code-hardening strategies to prevent decompilation via tools like Ghidra or IDA Pro



1\. Symbol Stripping The project's release configuration must explicitly enforce `strip = true` and `panic = abort` to erase all function labels, structural maps, and backtrace print strings.

2\. String Encryption All internal string literals—specifically backend URL endpoints, validation telemetry tags, and diagnostic statements—must be encrypted at compile-time via procedural code macros, decrypting in-memory only during transient clock cycles.

3\. Control Flow Obfuscation The final build pipeline must utilize LLVM flattening optimizations to break transparent mathematical logic loops into deeply nested state-machine webs, rendering the decompiled assembly layout mathematically indistinguishable from random digital signal processing code.



\---



\## 5. Verification \& Testing Toolchain

Antigravity agents are authorized to use local environment tools to continuously validate compliance targets across the codebase layout



&#x20;Syntax and Check Engine `cargo check`

&#x20;Cryptographic Unit Isolation Testing `cargo test`

&#x20;Pipeline Integration Simulation `cargo test --test integration\_test`

&#x20;Performance Analysis `cargo bench`

&#x20;Statistical Constant-Time Auditing (DudeCT) Logical constant-time design is insufficient, as the Rust LLVM compiler may silently reintroduce variable-time branches. Agents must implement the `dudect-bencher` crate to perform Welch's t-tests on the CPU clock cycles of the `ml\_dsa\_sign` core loops. If the absolute t-value exceeds `5.0` across 1,000,000+ measurements, the loop is leaking timing data, and the CICD pipeline must fail the build.

