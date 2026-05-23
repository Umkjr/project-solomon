# test_e2e.py
import requests
import json
import time

PROXY_URL = "http://127.0.0.1:8080/api/submit"

def run_e2e_test():
    print("[E2E Test Client] Initializing simulated transaction...")
    
    # Financial transaction payload simulating a credit transfer
    transaction_payload = {
        "transaction_id": "TXN-90218318",
        "sender_iban": "DE89370400440532013000",
        "receiver_iban": "FR7630006000010245678901234",
        "amount_usd": 15000.00,
        "currency": "USD",
        "description": "Enterprise secure clearing payload"
    }
    
    print(f"[E2E] Payload size: {len(json.dumps(transaction_payload))} bytes")
    print(f"[E2E] Sending POST request to Solomon PQ-Proxy at: {PROXY_URL}")
    
    start_time = time.time()
    try:
        response = requests.post(
            PROXY_URL,
            json=transaction_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        duration = time.time() - start_time
        
        print(f"[E2E] Roundtrip duration: {duration:.4f} seconds")
        print(f"[E2E] Response HTTP status code: {response.status_code}")
        
        if response.status_code == 200:
            print("[E2E] E2E Transaction completed successfully!")
            print(f"[E2E] Backend Response: {response.json()}")
        else:
            print(f"[E2E] Transaction failed. Status code: {response.status_code}")
            print(f"[E2E] Response Content: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("\n[E2E] Connection Error: Could not connect to the Solomon Proxy.")
        print("   Make sure the following services are running:")
        print("   1. Mock Control Plane (port 9000)")
        print("   2. Mock Banking Backend (port 8081)")
        print("   3. Solomon Proxy Server (port 8080)")
    except Exception as e:
        print(f"[E2E] Unexpected error occurred: {e}")

if __name__ == "__main__":
    run_e2e_test()
