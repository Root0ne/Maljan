import requests

TOKEN = "sk-kimi-vzaXsocP9zCEden9B89EKD0lilTg1aMOcZAxcGG1GdwSEC5F1Fz1scQ9aqaFuRqc"
URL = "https://api.kimi.com/coding/v1/chat/completions"

payload = {
    "model": "kimi-k2.6",
    "messages": [{"role": "user", "content": "Say hello"}],
    "max_tokens": 10,
}

try:
    r = requests.post(URL, headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"}, json=payload, timeout=15)
    print(f"HTTP {r.status_code}")
    print(r.text[:500])
except Exception as e:
    print(f"ERROR: {e}")
