import requests

TOKEN = "sk-kimi-vzaXsocP9zCEden9B89EKD0lilTg1aMOcZAxcGG1GdwSEC5F1Fz1scQ9aqaFuRqc"
endpoints = [
    "https://api.kimi.com/coding/v1/models",
    "https://api.moonshot.ai/v1/models",
    "https://api.moonshot.cn/v1/models",
]
for url in endpoints:
    try:
        r = requests.get(url, headers={"Authorization": "Bearer " + TOKEN}, timeout=10)
        print(f"{url}: HTTP {r.status_code}")
        if r.status_code != 200:
            print(f"  Body: {r.text[:200]}")
    except Exception as e:
        print(f"{url}: ERROR {e}")
