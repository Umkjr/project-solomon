# Project Solomon: Cloud Control Plane Specification

## 1. Executive Summary & Mission
The Solomon Cloud Control Plane is the centralized licensing, telemetry, and administrative backbone of the Project Solomon infrastructure. 

While the on-premises proxies handle the heavy post-quantum lattice mathematics (ML-DSA-65), they are mathematically "locked" until authorized by this Control Plane. This server acts as the Master Cryptographic Issuer, delivering the daily operational parameters (`Epoch Tokens`) required to initialize the proxies' local network shields.

**Primary Objectives:**
1. Enforce SaaS billing by dynamically authorizing or revoking proxy nodes.
2. Prevent container cloning via Hardware Fingerprint tracking.
3. Establish the root of trust via Ed25519 signature issuance.

---

## 2. Technical Stack (MVP Phase)
To guarantee rapid deployment while maintaining high performance and memory safety, the MVP Control Plane utilizes the following stack:
* **Language:** Rust (Stable)
* **Web Framework:** Axum / Tokio
* **Database:** SQLite (via SQLx) for portable, zero-configuration state management.
* **Cryptography:** `ed25519-dalek` for issuing deterministic hardware signatures.

---

## 3. Database Schema & State Management

The Control Plane must maintain a strict ledger of all authorized enterprise clients. On initial boot, the application must use SQLx to verify or create the following SQLite schema:

### Table: `clients`
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `license_id` | TEXT | PRIMARY KEY | The unique identifier issued to the enterprise client upon subscription (e.g., `ENT-5821`). |
| `hardware_fingerprint` | TEXT | NULLABLE | The hashed CPU/VPC identifier of the client's host server. |
| `is_active` | BOOLEAN | NOT NULL (Default: TRUE) | The SaaS Kill-Switch. If false, the heartbeat fails and the remote proxy self-terminates. |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record of issuance. |

*Note on Fingerprinting:* The system utilizes a **Trust-On-First-Use (TOFU)** mechanism. When a new `license_id` is generated, the `hardware_fingerprint` is left NULL. The very first time the client proxy connects, its hardware fingerprint is permanently locked into this column.

---

## 4. Cryptographic Master State

The Control Plane represents the absolute Root of Trust for the Solomon ecosystem. 

### 4.1 Master Key Generation
Upon its first execution, the Control Plane must generate an Ed25519 Master Keypair. 
* For the MVP, this keypair can be serialized to a local `.pem` or `.key` file within the container.
* *Enterprise V2 Upgrade Path:* This key will eventually be migrated to an AWS KMS or HashiCorp Vault instance.

### 4.2 The Epoch Token Signature
The daily salt is not just a random string; it must be cryptographically bound to the Solomon Master Identity.
* **Input:** A cryptographically secure random 32-byte array (`Daily_Salt`).
* **Operation:** Compute the Ed25519 signature of the `Daily_Salt`.
* **Output:** The raw signature bytes, converted to Base64 for JSON transport.

---

## 5. API Endpoint Specifications

The Control Plane exposes a single, highly resilient public endpoint for proxy telemetry.

### `POST /v1/epoch`
**Purpose:** Verifies remote proxy identity and issues the daily mathematical salt.

**Request Payload (JSON):**
```json
{
  "license_id": "ENT-5821",
  "hardware_fingerprint": "0x8F9A2B...CPU_UUID",
  "timestamp": 1716335181
}