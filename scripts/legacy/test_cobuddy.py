import requests

TOKEN = "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"
URL = "https://openrouter.ai/api/v1/chat/completions"

payload = {
    "model": "baidu/cobuddy:free",
    "messages": [{"role": "user", "content": "Say hello briefly"}],
    "max_tokens": 20,
}

print("Sending request to baidu/cobuddy:free...")
try:
    r = requests.post(
        URL,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://maljan.local",
            "X-Title": "Maljan",
        },
        json=payload,
        timeout=60,
    )
    print(f"HTTP {r.status_code}")
    print(r.text[:800])
except Exception as e:
    print(f"ERROR: {e}")
