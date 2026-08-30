import asyncio
import aiohttp
import time

TARGET_URL = "http://localhost:8080"

async def fire_payload(session, tx_id):
    payload = {
        "transaction_id": f"tx_{tx_id}",
        "amount": 250000,
        "currency": "INR",
        "timestamp": "2026-05-27T12:44:00Z"
    }
    
    start_time = time.perf_counter()
    try:
        async with session.post(TARGET_URL, json=payload, timeout=2) as response:
            latency = (time.perf_counter() - start_time) * 1000
            print(f"[SUCCESS] Tx {tx_id} | Latency: {latency:.2f}ms")
    except Exception as e:
        print(f"[FAIL-CLOSED] Connection dropped: {type(e).__name__}")

async def main():
    async with aiohttp.ClientSession() as session:
        # Firing 100 concurrent requests to stress the ZK Prover
        tasks = [fire_payload(session, i) for i in range(100)]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
