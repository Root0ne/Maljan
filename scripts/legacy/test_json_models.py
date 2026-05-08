import requests
import json

TOKEN = "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"
URL = "https://openrouter.ai/api/v1/chat/completions"

models = [
    "google/gemma-4-26b-a4b-it:free",
    "inclusionai/ling-2.6-1t:free",
    "openai/gpt-oss-20b:free",
    "minimax/minimax-m2.5:free",
]

payload = {
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

for model in models:
    p = {**payload, "model": model}
    try:
        r = requests.post(URL, headers=headers, json=p, timeout=15)
        content = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        # Try parse JSON
        try:
            data = json.loads(content)
            status = "JSON OK"
        except:
            status = "JSON FAIL"
        print(f"{model:<45} {status} -> {content[:60]}")
    except Exception as e:
        print(f"{model:<45} ERROR -> {str(e)[:50]}")
