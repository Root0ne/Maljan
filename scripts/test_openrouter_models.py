import requests

TOKEN = "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"
URL = "https://openrouter.ai/api/v1/models"

try:
    r = requests.get(URL, headers={"Authorization": "Bearer " + TOKEN}, timeout=15)
    print(f"HTTP {r.status_code}")
    data = r.json()
    free_models = [m["id"] for m in data.get("data", []) if ":free" in m["id"].lower()]
    print(f"\nFound {len(free_models)} free models:")
    for m in free_models[:20]:
        print(f"  {m}")
except Exception as e:
    print(f"ERROR: {e}")
