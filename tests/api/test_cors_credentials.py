import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.config import settings  # noqa: E402


def test_cors_allows_credentials_and_never_wildcards_origins():
    # Cookies (Set-Cookie / credentialed fetches) require an explicit origin
    # allowlist — a browser refuses to honour "*" together with
    # allow_credentials=True, and if it didn't, this would let any origin
    # read the HttpOnly refresh cookie's responses.
    assert "*" not in settings.cors_origins
    assert settings.cors_origins, "an empty allowlist would be a silent lock-out, not a control"
