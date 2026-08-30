# mock_control_plane.py
import base64
import hashlib
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import List

app = FastAPI(title="Solomon Mock Control Plane")

# Enable CORS for live dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cryptographic parameters matching tests and QUANTUM.md
MASTER_LICENSE_KEY = b"SOLOMON_KEY_2026_SECURE_LICENSE_"
ED25519_PRIVATE_KEY_SEED = b"\x01" * 32
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ED25519_PRIVATE_KEY_SEED)

# Global state for dynamic control plane orchestration
STATE = {
    "fleet": {
        "ENT-5821": {"name": "Razorpay Edge Shield", "status": "Online", "fp": "8f9a2b7c4d5e8f9a2b...b5c7d8e9", "lastSeen": "Just now"},
        "ENT-9022": {"name": "Cashfree India Edge", "status": "Online", "fp": "5a4e3c2b1a0f9e8d7c...f1d2e3d4", "lastSeen": "12s ago"},
        "ENT-1109": {"name": "Paytm Secure Route", "status": "Suspended", "fp": "7d6c5b4a3f2e1d0c9b...9a8f7e6d", "lastSeen": "48h ago"}
    },
    "ai_weights": [],
    "ai_training": {
        "is_training": False,
        "epoch": 48,
        "loss": 0.0042,
        "progress": 0
    }
}

class LicensingRequest(BaseModel):
    license_id: str
    hardware_fingerprint: str

class HandshakeRequest(BaseModel):
    license_id: str
    hardware_fingerprint: str
    timestamp: int

class AiSyncRequest(BaseModel):
    license_id: str
    weights: List[float]
    loss: float
    epoch: int

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
    node = STATE["fleet"].get(req.license_id)
    if not node or node["status"] != "Online":
        print(f"[Control Plane] Rejecting license request for revoked/unauthorized ID: {req.license_id}")
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
    
    node["lastSeen"] = "Just now"
    print(f"[Control Plane] Authenticated & issued Epoch Token to {req.license_id}.")
    return response_payload

@app.post("/v1/epoch")
async def verify_handshake(req: HandshakeRequest):
    """
    Backward-compatible endpoint for legacy control plane simulator.
    """
    node = STATE["fleet"].get(req.license_id)
    if not node or node["status"] != "Online":
        raise HTTPException(status_code=401, detail="Unauthorized License")
    
    dummy_salt = base64.b64encode(b"LOCAL_DEV_SALT_32_BYTES_LONG_000").decode('utf-8')
    
    return {
        "daily_salt": dummy_salt,
        "signature": "mock_ed25519_signature_string"
    }

@app.post("/v1/ai/sync-weights")
async def sync_weights(req: AiSyncRequest):
    """
    Receives Federated learning weights/gradients from edge proxy nodes.
    """
    node = STATE["fleet"].get(req.license_id)
    if node:
        node["lastSeen"] = "Just now"
    
    STATE["ai_weights"].append({
        "license_id": req.license_id,
        "weights": req.weights,
        "loss": req.loss,
        "epoch": req.epoch
    })
    
    # Update current AI training parameters based on incoming fit
    STATE["ai_training"]["epoch"] = req.epoch
    STATE["ai_training"]["loss"] = round(req.loss, 4)
    
    print(f"[Control Plane] Received weights from node {req.license_id}. Epoch: {req.epoch}, Loss: {req.loss:.4f}")
    return {"status": "success"}

@app.get("/v1/ai/global-model")
async def get_global_model():
    """
    Returns latest aggregated global model parameters back to edge nodes.
    """
    return {
        "global_epoch": STATE["ai_training"]["epoch"],
        "global_loss": STATE["ai_training"]["loss"],
        "parameters": [0.15, -0.23, 0.42, 0.88, -0.05, 0.61, -0.72, 0.33]
    }

@app.get("/api/dashboard/fleet")
async def get_fleet():
    """
    Returns fleet state for dashboard consumption.
    """
    fleet_list = []
    for lic_id, info in STATE["fleet"].items():
        fleet_list.append({
            "name": info["name"],
            "license": lic_id,
            "fp": info["fp"],
            "status": info["status"],
            "lastSeen": info["lastSeen"]
        })
    return {"fleet": fleet_list}

@app.post("/api/dashboard/toggle")
async def toggle_node(license_id: str):
    """
    Toggles node status between Online and Suspended.
    """
    node = STATE["fleet"].get(license_id)
    if not node:
        raise HTTPException(status_code=404, detail="License ID not found")
    node["status"] = "Suspended" if node["status"] == "Online" else "Online"
    return {"license_id": license_id, "status": node["status"]}

@app.post("/api/dashboard/sync")
async def sync_node(license_id: str):
    """
    Simulates syncing latest configuration to node.
    """
    node = STATE["fleet"].get(license_id)
    if not node:
        raise HTTPException(status_code=404, detail="License ID not found")
    return {"status": "synced"}

@app.post("/api/dashboard/register")
async def register_node():
    """
    Dynamically registers a new Shield edge node.
    """
    rand_id = f"ENT-{hashlib.md5(os.urandom(8)).hexdigest()[:4].upper()}"
    new_node = {
        "name": "Proxy Shield Enclave",
        "status": "Online",
        "fp": hashlib.sha256(os.urandom(8)).hexdigest()[:16] + "...",
        "lastSeen": "Just now"
    }
    STATE["fleet"][rand_id] = new_node
    return {"license_id": rand_id, "node": new_node}

@app.get("/api/dashboard/telemetry")
async def get_telemetry():
    """
    Aggregates live metrics from the running proxy or falls back to simulation parameters.
    """
    import urllib.request
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/metrics")
        with urllib.request.urlopen(req, timeout=0.5) as response:
            content = response.read().decode('utf-8')
            active = 0
            total = 0
            last_bytes = 0
            last_interval = 0
            for line in content.split("\n"):
                if line.startswith("solomon_active_requests"):
                    active = int(line.split()[1])
                elif line.startswith("solomon_processed_requests_total"):
                    total = int(line.split()[1])
                elif line.startswith("solomon_last_request_bytes"):
                    last_bytes = int(line.split()[1])
                elif line.startswith("solomon_last_packet_interval_ms"):
                    last_interval = int(line.split()[1])
            return {
                "active_requests": active,
                "total_processed": total,
                "last_bytes": last_bytes,
                "last_interval": last_interval,
                "live": True
            }
    except Exception:
        # Fallback to simulated dashboard data
        import random
        return {
            "active_requests": random.randint(0, 2),
            "total_processed": len(STATE["ai_weights"]) + 10,
            "last_bytes": 210 + random.randint(0, 50),
            "last_interval": 290 + random.randint(0, 80),
            "live": False
        }

if __name__ == "__main__":
    import uvicorn
    print("[Control Plane] Solomon Mock Control Plane active on port 9000")
    uvicorn.run(app, host="127.0.0.1", port=9000)
