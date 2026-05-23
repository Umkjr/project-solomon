# mock_control_plane.py
import base64
import hashlib
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519

app = FastAPI(title="Solomon Mock Control Plane")

# Cryptographic parameters matching tests and QUANTUM.md
MASTER_LICENSE_KEY = b"SOLOMON_KEY_2026_SECURE_LICENSE_"
ED25519_PRIVATE_KEY_SEED = b"\x01" * 32
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_PRIVATE_KEY_SEED)

class LicensingRequest(BaseModel):
    license_id: str
    hardware_fingerprint: str

class HandshakeRequest(BaseModel):
    license_id: str
    hardware_fingerprint: str
    timestamp: int

def shake256_hash(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)

@app.post("/licensing")
async def verify_licensing(req: LicensingRequest):
    """
    Main licensing endpoint hit by the transparent reverse proxy.
    Validates license and generates a signed 80-byte Epoch Token.
    """

    
    # Enforce strict licensing simulation
    if req.license_id != "ENT-5821":
        raise HTTPException(status_code=401, detail="Unauthorized License")
    
    # 1. Generate 32-byte cryptographically secure IV
    iv = os.urandom(32)
    
    # 2. Expected 32-byte Daily Salt for ML-DSA-65 initialization
    expected_salt = b"LOCAL_DEV_SALT_32_BYTES_LONG_000"
    
    # 3. Keystream = SHAKE-256(Master Key || IV)
    keystream = shake256_hash(MASTER_LICENSE_KEY + iv, 32)
    
    # 4. Ciphertext = expected_salt ^ keystream
    ciphertext = bytes(s ^ k for s, k in zip(expected_salt, keystream))
    
    # 5. MAC = SHAKE-256(Master Key || IV || Ciphertext)[0..16]
    mac = shake256_hash(MASTER_LICENSE_KEY + iv + ciphertext, 16)
    
    # 6. Construct Epoch Token (80 bytes total)
    token_bytes = iv + ciphertext + mac
    
    # 7. Generate Ed25519 signature of the Epoch Token using the master private key
    sig_bytes = private_key.sign(token_bytes)
    
    response_payload = {
        "token": token_bytes.hex(),
        "signature": sig_bytes.hex()
    }
    
    print("[Control Plane] Authenticated & issued Epoch Token and signature.")
    return response_payload

@app.post("/v1/epoch")
async def verify_handshake(req: HandshakeRequest):
    """
    Backward-compatible endpoint for legacy control plane simulator.
    """
    if req.license_id != "ENT-5821":
        raise HTTPException(status_code=401, detail="Unauthorized License")
    
    dummy_salt = base64.b64encode(b"LOCAL_DEV_SALT_32_BYTES_LONG_000").decode('utf-8')
    
    return {
        "daily_salt": dummy_salt,
        "signature": "mock_ed25519_signature_string"
    }

if __name__ == "__main__":
    import uvicorn
    print("[Control Plane] Solomon Mock Control Plane active on port 9000")
    uvicorn.run(app, host="127.0.0.1", port=9000)
