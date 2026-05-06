"""Check Triage sample status."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from maljan.core.config import settings
import httpx

token = settings.sandbox.triage_api_token
headers = {"Authorization": f"Bearer {token}"}

sample_id = "260506-yjnq2adw9q"

# Check sample status
r = httpx.get(f"https://api.tria.ge/v0/samples/{sample_id}", headers=headers, timeout=30)
print(f"Sample status: {r.status_code}")
print(r.text)
