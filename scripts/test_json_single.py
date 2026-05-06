import requests
import json
import sys

TOKEN = "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"
URL = "https://openrouter.ai/api/v1/chat/completions"

model = sys.argv[1] if len(sys.argv) > 1 else "google/gemma-4-26b-a4b-it:free"

payload = {
    "model": model,
    "messages": [
        {"role": "system", "content": "You are a JSON generator. Always respond with valid JSON only. No markdown, no explanation."},
        {"role": "user", "content": 'Return this JSON: {"verdict": "malware", "confidence": 0.95}'}
    ],
    "max_tokens": 50,
}

headers = {
    "Authorization": "Bearer " + TOKEN,
    "Content-Type": "application/json",
    "HTTP-Referer": "https://maljan.local",
    "X-Title": "Maljan",
}

try:
    r = requests.post(URL, headers=headers, json=payload, timeout=15)
    content = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    try:
        data = json.loads(content)
        print(f"JSON OK: {data}")
    except:
        print(f"JSON FAIL: {content[:100]}")
except Exception as e:
    print(f"ERROR: {e}")
