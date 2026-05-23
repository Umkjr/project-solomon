# Project Solomon: Execution & Containerization Pipeline

## 1. Executive Summary
This document defines the operational transition from a compiled Rust codebase to a live, network-isolated proxy. It outlines the three final phases of the deployment lifecycle:
1. **The Mock Control Plane:** Establishing a local telemetry lifeline to authorize the proxy's boot sequence.
2. **End-to-End Live Testing:** Simulating banking traffic and verifying the CVE-2026-24850 cryptographic guardrails.
3. **Enterprise Containerization:** Wrapping the proxy in a minimal, crash-only Docker container designed for deployment in secure financial enclaves.

---

## Phase 1: The Mock Control Plane (The Lifeline)
The Solomon proxy is engineered to "fail-closed." If it cannot fetch an `Epoch Token` and `Daily_Salt` upon boot, it terminates. To run the proxy locally, we must simulate the Solomon Cloud infrastructure.

### 1.1 Local Server Implementation
We use a lightweight Python FastAPI server to act as the Control Plane. It authenticates the proxy request and returns a signed 80-byte `Epoch Token` encrypting our 32-byte daily salt using SHAKE-256. It signs the token using the master Ed25519 private key corresponding to the public key hardcoded in the Rust proxy.

Create a file named `mock_control_plane.py` in the root directory:

```python
# mock_control_plane.py
import base64
import hashlib
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519

app = FastAPI(title="Solomon Mock Control Plane")

MASTER_LICENSE_KEY = b"SOLOMON_KEY_2026_SECURE_LICENSE_"
ED25519_PRIVATE_KEY_SEED = b"\x01" * 32
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_PRIVATE_KEY_SEED)

class LicensingRequest(BaseModel):
    license_id: str
    hardware_fingerprint: str

def shake256_hash(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)

@app.post("/licensing")
async def verify_licensing(req: LicensingRequest):
    print(f"☁️ Received licensing request for ID: {req.license_id}")
    if req.license_id != "ENT-5821":
        raise HTTPException(status_code=401, detail="Unauthorized License")
    
    # Generate 32-byte secure IV
    iv = os.urandom(32)
    # Expected Daily Salt (32 bytes)
    expected_salt = b"LOCAL_DEV_SALT_32_BYTES_LONG_000"
    
    # keystream = SHAKE-256(Master Key || IV)
    keystream = shake256_hash(MASTER_LICENSE_KEY + iv, 32)
    # ciphertext = salt ^ keystream
    ciphertext = bytes(s ^ k for s, k in zip(expected_salt, keystream))
    # MAC = SHAKE-256(Master Key || IV || Ciphertext)[0..16]
    mac = shake256_hash(MASTER_LICENSE_KEY + iv + ciphertext, 16)
    
    # 80-byte token
    token_bytes = iv + ciphertext + mac
    # Ed25519 signature
    sig_bytes = private_key.sign(token_bytes)
    
    return {
        "token": token_bytes.hex(),
        "signature": sig_bytes.hex()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000)
```

---

## Phase 2: End-to-End Live Testing

To test the transparent proxy pipeline, we simulate banking transaction traffic by passing it through our post-quantum reverse proxy and forwarding it to a mock legacy banking backend.

### 2.1 The Mock Banking Backend
The backend simulates a financial transaction clearing receiver. It listens on port `8081` and enforces that any incoming payload carries the required post-quantum headers (`X-Solomon-PQ-Sig` and `X-Solomon-ZK-Auth`) injected by the proxy.

Create a file named `mock_banking_backend.py` in the root directory:

```python
# mock_banking_backend.py
from fastapi import FastAPI, Header, Request, HTTPException
import json

app = FastAPI(title="Solomon Mock Banking Backend")

@app.post("/api/submit")
async def submit_transaction(
    request: Request,
    x_solomon_pq_sig: str = Header(None, alias="X-Solomon-PQ-Sig"),
    x_solomon_zk_auth: str = Header(None, alias="X-Solomon-ZK-Auth")
):
    if not x_solomon_pq_sig:
        raise HTTPException(status_code=400, detail="Missing post-quantum signature X-Solomon-PQ-Sig")
    if not x_solomon_zk_auth:
        raise HTTPException(status_code=400, detail="Missing ZK authorization proof X-Solomon-ZK-Auth")
        
    body = await request.body()
    payload = json.loads(body)
    
    print(f"\n🏦 Received transaction: {payload}")
    print(f"🔒 ML-DSA-65 Signature (len {len(x_solomon_pq_sig)} hex chars): {x_solomon_pq_sig[:60]}...")
    print(f"🛡️ Identity ZK-Proof: {x_solomon_zk_auth}")
    
    return {
        "status": "APPROVED",
        "post_quantum_verified": True,
        "transaction_id": payload.get("transaction_id")
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8081)
```

### 2.2 E2E Client Simulation
A client simulation script issues a standard JSON credit transfer payload to the Solomon Proxy.

Create a file named `test_e2e.py` in the root directory:

```python
# test_e2e.py
import requests
import time

PROXY_URL = "http://127.0.0.1:8080/api/submit"

def run_e2e_test():
    payload = {
        "transaction_id": "TXN-90218318",
        "sender_iban": "DE89370400440532013000",
        "receiver_iban": "FR7630006000010245678901234",
        "amount_usd": 15000.00,
        "currency": "USD",
        "description": "Enterprise secure clearing payload"
    }
    
    print("📡 Sending transaction to Solomon Proxy...")
    start = time.time()
    try:
        response = requests.post(PROXY_URL, json=payload)
        print(f"⏱️ Roundtrip: {time.time() - start:.4f} seconds")
        print(f"📶 Response Code: {response.status_code}")
        print(f"🏦 Response JSON: {response.json()}")
    except Exception as e:
        print(f"❌ Error connecting to proxy: {e}")

if __name__ == "__main__":
    run_e2e_test()
```

---

## Phase 3: Enterprise Containerization

For deployment in secure banking enclaves, Solomon utilizes a hardened multi-stage Docker setup. It operates strictly disk-silent and stateless, executing as a non-privileged system user.

### 3.1 Dockerfile
The multi-stage `Dockerfile` compiles the binary with static linking and aggressive symbol stripping.

```dockerfile
# Dockerfile
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /usr/src/solomon
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release --features proxy
RUN rm -rf src
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --features proxy

FROM alpine:latest AS runtime
RUN apk add --no-cache ca-certificates \
    && addgroup -S solomon \
    && adduser -S solomon -G solomon
WORKDIR /home/solomon
USER solomon
COPY --from=builder /usr/src/solomon/target/release/ml-dsa-65 /usr/local/bin/solomon-proxy
EXPOSE 8080
ENV PROXY_LISTEN_ADDR=127.0.0.1:8080
ENV BACKEND_URL=http://127.0.0.1:8081
ENV CONTROL_PLANE_URL=http://127.0.0.1:9000
ENV LICENSE_ID=ENT-5821
CMD ["/usr/local/bin/solomon-proxy"]
```

### 3.2 Docker Compose Manifest
To orchestrate the complete topology locally for enterprise simulation, we use the following `docker-compose.yml`:

```yaml
# docker-compose.yml
version: '3.8'
services:
  solomon-vault:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: solomon-vault
    network_mode: "host"       # Loopback Mandate: Enforce host networking
    cap_drop:
      - ALL                    # Drop all kernel capabilities
    environment:
      - PROXY_LISTEN_ADDR=127.0.0.1:8080
      - BACKEND_URL=http://127.0.0.1:8081
      - CONTROL_PLANE_URL=http://127.0.0.1:9000
      - LICENSE_ID=ENT-5821
    restart: on-failure
```

---

## 4. Execution Procedures

### 4.1 Automated Verification
Verify the cryptographic core and the proxy pipeline via Cargo:
```bash
cargo test --features proxy --target-dir target_test_unique -- --test-threads=1
```

### 4.2 Manual E2E Execution
1. **Launch the Orchestrated Topology:**
   ```bash
   docker-compose up --build
   ```
2. **Execute E2E Client Simulation:**
   ```bash
   python test_e2e.py
   ```
3. **Verify Security Invariants:** Inspect terminal logs for `mock-banking-backend` to verify the presence of `X-Solomon-PQ-Sig` (6618 characters of hex-encoded ML-DSA-65 signature) and `X-Solomon-ZK-Auth` (128-byte JSON ZK-attestation containing committing fields).