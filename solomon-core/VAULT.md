# Project Solomon: Enterprise Vault & Containerization Specification

## 1. Executive Summary & Mission
The Enterprise Vault is the final deployment artifact for the Solomon Post-Quantum Proxy. Tier-1 financial institutions mandate absolute execution isolation, zero-state persistence, and strict network confinement. 

This document defines the multi-stage Docker compilation and orchestration parameters required to package the Rust binary into an immutable, crash-only artifact that is completely immune to container-escape vulnerabilities.

---

## 2. Multi-Stage Build Architecture

To minimize the attack surface and eliminate supply-chain vulnerabilities, the Rust compiler and source code must never exist in the final production container.

### Stage 1: The Builder Enclave
* **Base Image:** `rust:alpine`
* **Dependencies:** `musl-dev`, `pkgconfig`, `openssl-dev`
* **Execution:** Copy the source tree and compile the project using `cargo build --release`. 

### Stage 2: The Production Runtime
* **Base Image:** `alpine:latest`
* **Distroless Philosophy:** The final image must contain absolutely nothing except the compiled `solomon-core` binary and the standard CA certificates required for the `reqwest` HTTPS heartbeat to the Control Plane.

---

## 3. Operational Security (OpSec) Constraints

The Dockerfile and orchestration layer must strictly enforce the following security guardrails:

### 3.1 Non-Root Execution (Privilege Drop)
If an attacker manages to execute arbitrary code inside the container, they must not have administrative rights.
* The Dockerfile must explicitly create a restricted, unprivileged user and group (e.g., `solomon`).
* The `USER solomon` directive must be invoked before the `CMD` execution point.

### 3.2 Linux Kernel Capability Stripping
Standard Docker containers retain several default Linux kernel capabilities. These must be aggressively stripped to prevent lateral movement.
* **Orchestration Rule:** The `docker-compose.yml` must explicitly drop all kernel privileges using the `cap_drop: - ALL` directive. This removes dangerous capabilities like `CAP_NET_ADMIN` (network manipulation) and `CAP_SYS_ADMIN` (host system control).
* **Escalation Block:** The compose file must include `security_opt: - no-new-privileges:true` to guarantee the process can never elevate itself via `sudo` or `setuid`.

### 3.3 Zero-State Disk Confinement
The container relies on the Rust proxy's internal volatile memory scrubbing (`std::ptr::write_volatile`). To prevent key leakage:
* No transaction payloads or Daily Salts may ever be written to disk or stdout/stderr logs.
* No volumes or persistent data mounts are permitted.

---

## 4. The Loopback Network Mandate

The Solomon Proxy acts as an invisible shield for a legacy backend running on the same machine. It must never be reachable from the external internet or the internal VPC.

* **Orchestration Rule:** The container must deploy using `network_mode: "host"`.
* **Why:** This forces the Docker container to share the host machine's network stack, allowing the proxy's `127.0.0.1:8080` bind to act strictly as a local loopback. Any inbound traffic attempting to reach the proxy from an external IP will hit a closed port.

---

## 5. Orchestrated Crash-Only Recovery

As established in `PROXY.md`, the Solomon binary is designed to "fail-closed." If it detects a Rowhammer bit-flip, an invalid Epoch Token, or a hardware clone attempt, it executes an immediate system panic.

* **No Internal Recovery:** The proxy does not attempt to restart threads or connections.
* **Orchestration Rule:** The `docker-compose.yml` must intercept exit code `1` and utilize `restart: on-failure`. This ensures the Docker daemon instantly destroys the compromised container state and spins up a brand-new, clean, zero-state instance from scratch.