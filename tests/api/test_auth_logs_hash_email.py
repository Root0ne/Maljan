import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.auth import _email_tag  # noqa: E402


def test_email_tag_is_a_stable_short_hash_without_the_address():
    tag = _email_tag("Someone@Example.org")
    assert tag == _email_tag("someone@example.org")
    assert len(tag) == 12 and "@" not in tag and "example" not in tag
