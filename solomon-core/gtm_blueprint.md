# Project Solomon: Complete Enterprise Architecture & GTM Blueprint

This document defines the complete architectural blueprint and Go-To-Market (GTM) strategy for Project Solomon. It bridges the deep-tech cryptographic performance optimizations with our production deployment model and commercial roadmap.

---

## 1. Executive Summary & Year 1 GTM Wedge

Project Solomon delivers a drop-in, post-quantum cryptographic (PQC) reverse proxy engineered to secure legacy enterprise financial networks against future quantum decryption threats without sacrificing transaction processing speed. 

While our ultimate long-term goal is protecting the multi-trillion-dollar core infrastructures of Tier-1 legacy banks, our Year 1 Go-To-Market strategy targets high-frequency enterprise **Payment Gateways** (such as Razorpay and Cashfree). Gateways operate on identical transaction payload architectures as banks and face immediate, upcoming regulatory post-quantum mandates, but possess significantly shorter engineering sales cycles. 

### Commercial Metrics (Year 1)
*   **Target ARR:** $150,000 to $200,000
*   **Customer Acquisition Model:** 3 to 4 paid annual pilot contracts with mid-market payment gateways needing immediate, low-latency compliance.

---

## 2. System Topology: The Shield vs. The Control Panel

The system utilizes a secure hub-and-spoke topology to separate heavy local compute from central fleet orchestration while maintaining absolute data privacy compliance.

### A. The Shield (The Local Edge Container)
*   **Deployment:** Delivered as a lightweight, containerized package (Docker/Podman) that drops directly into the payment gateway’s existing cloud perimeter.
*   **Zero-Leak Privacy:** Runs entirely within the client's infrastructure. Sensitive transaction payloads or Personally Identifiable Information (PII) never leave their network, bypassing strict financial compliance barriers.
*   **The Engine:** Houses the high-performance Rust execution proxy core and the SP1 zkVM circuits.
*   **Edge Inference:** Executes lightweight AI models locally on client hardware to handle predictive load balancing without slowing down processing loops.

### B. The Control Panel (Our Central Brain)
*   **Hosting:** Hosted centrally on Project Solomon's cloud infrastructure as a multi-tenant SaaS management hub.
*   **Fleet Management:** Authenticates client licenses, updates cryptographic rules, and pushes configuration updates instantly to all deployed Shield containers without requiring downtime.
*   **Telemetry Aggregation:** Ingests completely anonymized structural network metadata (packet arrival intervals, byte size distributions, and memory queue lengths) streamed from the edge.
*   **The Training Ground:** Aggregates this clean metadata centrally to train and refine proprietary security AI models, establishing a robust data moat.

---

## 3. Core Technical Stack

*   **Proxy Infrastructure:** Written in **Rust** (compiled in `--release` mode) for maximum execution speed, deterministic memory safety, and high-performance polynomial math.
*   **Web Framework:** Built using the **Axum** framework for lightning-fast asynchronous HTTP routing and non-blocking payload interception.
*   **Zero-Knowledge Compute:** Utilizes Succinct’s **SP1 zkVM** to execute the verification trace of lattice-based **ML-DSA-65** digital signatures.
*   **Simulation & Testing:** System testing, stress testing, and network chaos simulations are engineered in **Python**.
*   **AI Inference Layer:** Built as lightweight, tabular time-series networks using **ONNX Runtime** native Rust bindings to run efficiently on edge client hardware (such as an RTX 3070 Ti).
*   **AI Development Tools:** The development pipeline is heavily AI-native, utilizing **DeepSeek-R1** and **Qwen** via **Ollama**, alongside official Anthropic **Claude Code** to rapidly execute designed architectures.

---

## 4. Deep-Tech Optimization & Precompiles

To eliminate the compute latency of general-purpose RISC-V compilation inside a zkVM, Solomon abandons software-based finite-field arithmetic. Instead, we offload bottleneck operations to custom hardware acceleration using **SP1 Precompiles** and **Plonky3 AIR Constraints**.

### Phase 1: Patching the Hashing Overhead
Standard SHAKE256 hashing calls are stripped from the main CPU guest trace and routed directly to SP1's pre-optimized hash circuits.

```toml
# Cargo.toml (Data Plane)
[dependencies]
sha3 = { version = "0.10.8", default-features = false }

[patch.crates-io]
# Forces standard crypto hashes to use SP1's zkVM precompiles automatically
sha3 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", tag = "patch-sha3-0.10.8-sp1-6.0.0" }
```

### Phase 2: The Rust Execution Hook

When the ML-DSA algorithm needs to multiply polynomials, a custom system call (`ecall`) pauses the zkVM guest program and passes the matrix pointer directly to the host machine to execute at native hardware speeds.

```rust
// src/syscalls/ntt_hook.rs (Guest Program)
#[no_mangle]
pub extern "C" fn syscall_mldsa_ntt(poly_ptr: *mut [u32; 256]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") crate::syscalls::MLDSA_NTT_ID, // Custom unique system call ID
            in("a0") poly_ptr,                      // Pointer to the polynomial matrix
            in("a1") 0
        );
    }
    
    #[cfg(not(target_os = "zkvm"))]
    unreachable!("NTT hook should only run inside the zkVM");
}
```

### Phase 3: The SP1 Executor Event

The host machine intercepts the `ecall`, executes the Number Theoretic Transform (NTT) calculation instantly on the host GPU using SP1's CUDA features, writes the result back to zkVM memory, and logs an event for the prover.

```rust
// src/executor/ntt_executor.rs (Host Environment)
use sp1_core::executor::{Syscall, SyscallContext, SyscallCode};

pub(crate) struct MldsaNttSyscall;

impl Syscall for MldsaNttSyscall {
    fn execute(&self, rt: &mut SyscallContext, syscall_code: SyscallCode, arg1: u32, arg2: u32) -> Option<u32> {
        let poly_ptr = arg1;
        
        // 1. Read the polynomial from the zkVM memory space
        // 2. Compute the NTT calculation instantly on the host GPU
        // 3. Write the computed result back into the zkVM memory space
        
        // 4. Log the execution event for the Plonky3 Prover
        let lookup_id = rt.syscall_lookup_id;
        let event = PrecompileEvent::MldsaNtt(NttEvent {
            lookup_id,
            shard: rt.current_shard(),
            clk: rt.clk,
            ptr: poly_ptr,
        });
        
        let syscall_event = rt.rt.syscall_event(rt.clk, syscall_code.syscall_id(), arg1, arg2, lookup_id);
        rt.add_precompile_event(syscall_code, syscall_event, event);
        
        None
    }
}
```

### Phase 4: Plonky3 AIR Constraints (The Custom Chip)

To ensure soundness, we write custom Algebraic Intermediate Representation (AIR) constraints that mathematically prove the host executor did not lie about the NTT calculation modulo $q = 8380417$.

```rust
// src/machine/ntt_chip.rs (Host Environment)
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::Matrix;

pub struct MldsaNttChip;

impl<AB: AirBuilder> Air<AB> for MldsaNttChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0); // Current polynomial state
        let next = main.row_slice(1);  // Polynomial state after butterfly operation
        
        let q = AB::Expr::from_canonical_u32(8380417);
        
        // Enforce butterfly constraints for elements i and j with twiddle factor omega
        // Example logic matrix check: (a_i + a_j * omega) - a'_i == 0 mod q
        builder.assert_zero(
            (local[0] + local[1] * local[2]) - next[0] - (q.clone() * next[3]) 
        );
    }
}
```

---

## 5. The Legacy ISO 8583 Routing Matrix

Financial infrastructure switches and bank mainframes reject arbitrary JSON metadata wrappers. While the zkVM handles the mathematical compression, the Solomon proxy references a configuration ledger to pack the resulting 128-byte SNARK proof directly into existing, underutilized slots in the standard financial messaging format.

```json
{
  "sponsor_banks": {
    "bank_A_tcs_bancs": {
      "iso_version": "1987",
      "pqc_snark_field": "Field 112 (Additional Data - National)",
      "max_buffer_size": 256,
      "encoding": "EBCDIC",
      "strip_headers": ["X-PQC-Metadata", "Fintech-Telemetry"]
    },
    "bank_B_finacle": {
      "iso_version": "1993",
      "pqc_snark_field": "Field 123 (Reserved for Private Use)",
      "max_buffer_size": 150,
      "encoding": "ASCII",
      "strip_headers": ["X-Signature-Raw"]
    }
  }
}
```

This ensures that the quantum-safe payload routes flawlessly through legacy core banking applications and clearing networks without requiring the underlying banking architecture to be rewritten.
