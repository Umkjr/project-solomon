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
    """
    Mock transaction receiver endpoint.
    Verifies that the transparent reverse proxy correctly intercepts transaction payloads,
    injects the ML-DSA-65 post-quantum signature and the identity-attested ZK authorization proof.
    """
    if not x_solomon_pq_sig:
        raise HTTPException(
            status_code=400, 
            detail="Security violation: Missing post-quantum signature header X-Solomon-PQ-Sig"
        )
    if not x_solomon_zk_auth:
        raise HTTPException(
            status_code=400, 
            detail="Security violation: Missing Zero-Knowledge authorization proof header X-Solomon-ZK-Auth"
        )
    
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = body.decode('utf-8')
        
    print(f"\n[Mock Banking Backend] Transaction Received!")
    print(f"[Backend] Payload: {payload}")
    print(f"[Backend] ML-DSA-65 PQ-Signature (len {len(x_solomon_pq_sig)} hex chars):")
    print(f"   {x_solomon_pq_sig[:70]}...")
    print(f"[Backend] ZK-SNARK Identity Authorization Proof:")
    
    try:
        zk_proof = json.loads(x_solomon_zk_auth)
        print(json.dumps(zk_proof, indent=4))
    except Exception:
        print(f"   {x_solomon_zk_auth}")
        
    return {
        "status": "APPROVED",
        "post_quantum_verified": True,
        "transaction_id": payload.get("transaction_id") if isinstance(payload, dict) else "unknown"
    }

if __name__ == "__main__":
    import uvicorn
    print("[Mock Banking Backend] Solomon Mock Banking Backend active on port 8081")
    uvicorn.run(app, host="127.0.0.1", port=8081)
