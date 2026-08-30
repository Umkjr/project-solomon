# Security Analysis: Merkle/Keccak Cryptographic Commitment Layer

## 1. Overview
Project Solomon utilizes a 128-byte lightweight cryptographic commitment mechanism (`ZkAuthorizationProof`) alongside a micro-batch Merkle Accumulator to bind and authenticate ML-DSA-65 signatures, hardware attestation fingerprints, and node identities into standard ISO 8583 payment fields.

**Important Designation:** This construct is **not** a Zero-Knowledge Proof (ZKP). It does not provide knowledge-soundness, zero-knowledge, or computational extractability (e.g., SNARK/STARK). Instead, it acts as an **integrity and authenticity commitment**, relying on the collision-resistance and pre-image resistance of the underlying cryptographic hash function (Keccak-256).

## 2. Structure of the Commitment

The `ZkAuthorizationProof` is a fixed-size 128-byte data structure injected into Field 112 (National Data) or Field 123 (Private Use). It consists of:

1. `identity_commitment`: A 32-byte hash of the authorized Solomon Proxy Node's identity.
2. `attestation_hash`: A 32-byte hash representing the un-tampered hardware environment fingerprint.
3. `state_commitment`: A 32-byte hash of the transaction data and its valid ML-DSA-65 signature.
4. `proof_elements`: A 32-byte Keccak-256 sponge commitment over the preceding three elements: `Keccak(identity || fingerprint || state)`.

## 3. Cryptographic Guarantees

This architecture leverages the standard properties of the Keccak-256 hash function to achieve the following:

### 3.1. Collision Resistance
It is computationally infeasible for an adversary to find two different sets of inputs `(identity_1, fingerprint_1, state_1)` and `(identity_2, fingerprint_2, state_2)` that map to the same 32-byte `proof_elements` commitment.
If any bit in the underlying transaction payload or the ML-DSA-65 signature is modified in transit (a "bit-flip" attack), the `state_commitment` changes entirely. The Receiving Proxy re-computes `Keccak(identity || fingerprint || state)` and verifies it against `proof_elements`. A mismatch immediately flags the payload as tampered.

### 3.2. Pre-Image Resistance
An attacker intercepting the 128-byte commitment payload from the network cannot reverse-engineer the original hardware fingerprint or node identity from the hashes.

### 3.3. Binding Authenticity
Because the proxy node performs the ML-DSA-65 signature validation locally and binds the result into the `state_commitment`, the receiving system is guaranteed that the proxy verified the transaction at the network edge. Trust is placed in the proxy's hardware attestation (represented by the `attestation_hash`).

## 4. Merkle Batch Accumulator

To optimize throughput, Solomon aggregates commitments using a Merkle tree (`BatchAccumulator`):
- **Mechanism:** Up to 16 transaction commitments are hashed together into a single Merkle Root. Dummy/padding transactions are deterministically added to incomplete batches to prevent timing or size side-channels.
- **Guarantee:** The Merkle Root cryptographically binds the exact sequence and state of the 16 transactions. Modification, reordering, or dropping of any transaction within the batch invalidates the root.

## 5. Security Limitations

Because this is a hash-based commitment rather than a recursive SNARK:
- **No Succinct Verification of Computation:** The Receiving Proxy verifies the *commitment* of the Edge Proxy's validation, but it cannot mathematically prove that the Edge Proxy executed the ML-DSA-65 verification algorithm flawlessly (a SNARK would prove the execution trace itself).
- **Trusted Edge Model:** The security of the network relies on the assumption that if the `attestation_hash` matches an authorized hardware enclave, the proxy faithfully executed its validation logic before generating the commitment.
