import asyncio
import json
from pathlib import Path

import httpx
import websockets


async def main():
    base_url = "http://localhost:8000/api/v1"

    # Login
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{base_url}/auth/login", json={"email": "admin@maljan.com", "password": "password123"}
        )
        if res.status_code != 200:
            print(f"Login failed: {res.text}")
            return
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload a dummy sample
        dummy_file = Path("dummy.exe")
        dummy_file.write_bytes(b"MZ" + b"\x00" * 1024)

        with open("dummy.exe", "rb") as f:
            res = await client.post(
                f"{base_url}/samples/upload", files={"file": f}, headers=headers
            )
        if res.status_code not in (200, 201):
            print(f"Upload failed: {res.text}")
            return
        sample_id = res.json()["id"]
        print(f"Sample uploaded: {sample_id}")

        # Create job
        job_data = {"sample_id": sample_id, "config": {"max_iterations": 1, "llm_provider": "mock"}}
        res = await client.post(f"{base_url}/jobs", json=job_data, headers=headers)
        if res.status_code != 201:
            print(f"Job creation failed: {res.text}")
            return
        job_id = res.json()["id"]
        print(f"Job created: {job_id}")

    # Connect to WebSocket
    uri = f"ws://localhost:8000/api/v1/ws/analysis/{job_id}"
    print(f"Connecting to {uri}")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Listening for events...")
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    data = json.loads(message)
                    print(f"Event received: {data.get('type')}")
                    if data.get("type") in ("completed", "error", "cancelled"):
                        print("Analysis finished.")
                        print(data)
                        break
                except TimeoutError:
                    print("Timeout waiting for event. Still listening...")
    except Exception as e:
        print(f"WebSocket error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
