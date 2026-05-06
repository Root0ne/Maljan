"""Quick test for Triage sandbox submission."""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from maljan.loaders.cape2_client import CAPEv2Client
from maljan.core.config import settings

print(f"Sandbox backend: {settings.sandbox.backend}")
print(f"Triage base URL: {settings.sandbox.triage_base_url}")

if settings.sandbox.backend != "triage":
    print("ERROR: Backend is not set to 'triage'. Check .env file.")
    sys.exit(1)

# Submit dummy_malware.exe
try:
    # Note: TriageClient doesn't exist in the codebase, we need to use Triage API directly
    # Let's use httpx directly for a quick test
    import httpx

    token = settings.sandbox.triage_api_token
    if not token:
        print("ERROR: TRIAGE_API_TOKEN is not set.")
        sys.exit(1)

    headers = {"Authorization": f"Bearer {token}"}

    # First, check if token is valid
    r = httpx.get("https://api.tria.ge/v0/me", headers=headers, timeout=30)
    print(f"Token check: {r.status_code} - {r.text}")

    # Submit sample
    sample_path = Path(__file__).parent / "dummy_malware.exe"
    if not sample_path.exists():
        print(f"ERROR: {sample_path} not found.")
        sys.exit(1)

    print(f"Submitting {sample_path} to Triage...")
    with open(sample_path, "rb") as f:
        files = {"file": (sample_path.name, f)}
        r = httpx.post(
            "https://api.tria.ge/v0/samples",
            headers=headers,
            files=files,
            timeout=120,
        )
    print(f"Submit response: {r.status_code}")
    print(r.text)

except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
