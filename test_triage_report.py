"""Fetch Triage sample report."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from maljan.core.config import settings
import httpx

token = settings.sandbox.triage_api_token
headers = {"Authorization": f"Bearer {token}"}

sample_id = "260506-yjnq2adw9q"

# Fetch report
r = httpx.get(f"https://api.tria.ge/v0/samples/{sample_id}/reports/static", headers=headers, timeout=30)
print(f"Static report: {r.status_code}")
if r.status_code == 200:
    data = r.json()
    print(f"Score: {data.get('analysis', {}).get('score', 'N/A')}")
    print(f"Family: {data.get('analysis', {}).get('family', 'N/A')}")
    print(f"Tags: {data.get('analysis', {}).get('tags', [])}")
else:
    print(r.text)

# Fetch behavioral summary
r2 = httpx.get(f"https://api.tria.ge/v0/samples/{sample_id}/summary", headers=headers, timeout=30)
print(f"\nSummary: {r2.status_code}")
if r2.status_code == 200:
    print(r2.text[:2000])
