import requests
import time

TOKEN = "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"
URL = "https://openrouter.ai/api/v1/chat/completions"

models = [
    "baidu/cobuddy:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "poolside/laguna-xs.2:free",
    "poolside/laguna-m.1:free",
    "inclusionai/ling-2.6-1t:free",
    "tencent/hy3-preview:free",
    "baidu/qianfan-ocr-fast:free",
    "google/gemma-4-26b-a4b-it:free",
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "minimax/minimax-m2.5:free",
    "liquid/lfm-2.5-1.2b-thinking:free",
    "liquid/lfm-2.5-1.2b-instruct:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "nvidia/nemotron-nano-12b-v2-vl:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "openai/gpt-oss-120b:free",
    "openai/gpt-oss-20b:free",
    "z-ai/glm-4.5-air:free",
]

payload_template = {
    "messages": [{"role": "user", "content": "Say hello briefly"}],
    "max_tokens": 10,
}

headers = {
    "Authorization": "Bearer " + TOKEN,
    "Content-Type": "application/json",
    "HTTP-Referer": "https://maljan.local",
    "X-Title": "Maljan",
}

results = []

for model in models:
    payload = {**payload_template, "model": model}
    start = time.time()
    try:
        r = requests.post(URL, headers=headers, json=payload, timeout=30)
        elapsed = time.time() - start
        if r.status_code == 200:
            data = r.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            results.append((model, elapsed, 200, content[:30]))
        else:
            results.append((model, elapsed, r.status_code, r.text[:50]))
    except Exception as e:
        elapsed = time.time() - start
        results.append((model, elapsed, "ERR", str(e)[:50]))

# Sort by elapsed time (fastest first)
results.sort(key=lambda x: x[1] if isinstance(x[1], float) else 999)

print("\n" + "=" * 80)
print(f"{'Model':<50} {'Time':>8} {'Status':>8} {'Response':<20}")
print("=" * 80)
for model, elapsed, status, content in results:
    print(f"{model:<50} {elapsed:>7.2f}s {str(status):>8} {content:<20}")
