import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.config import APISettings  # noqa: E402


def test_trusted_proxy_entries_must_be_addresses_or_networks(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)
    ok = APISettings(trusted_proxy_ips=["10.0.0.0/8", "192.168.1.5", "fd00::/8"])
    assert ok.trusted_proxy_ips == ["10.0.0.0/8", "192.168.1.5", "fd00::/8"]
    for bad in (["proxy"], ["10.0.0.0/33"], ["10.0.0.256"]):
        with pytest.raises(ValidationError):
            APISettings(trusted_proxy_ips=bad)
