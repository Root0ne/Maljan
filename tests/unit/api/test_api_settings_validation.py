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


# B4 (dev audit 2026-09-06): a negative ``login_lockout_seconds`` was accepted
# and applied. It reaches Redis as an expiry, and a negative expiry deletes the
# key instead of setting it -- an operator who typed "-300" silently turned the
# brute-force lockout off. Every numeric API leaf an admin can PATCH is bounded
# so the value never gets past validation.
_BOUNDED = {
    "login_lockout_seconds": (1, 0),
    "login_max_attempts": (1, 0),
    "rate_limit_requests": (1, 0),
    "rate_limit_window_seconds": (1, 0),
    "enrichment_max_lookups": (1, 0),
    "upload_max_bytes": (1024, 0),
    "jwt_access_token_expire_minutes": (1, 0),
    "jwt_refresh_token_expire_days": (1, 0),
    "db_pool_size": (1, 0),
    "db_max_overflow": (0, -1),
    "db_pool_recycle_seconds": (1, 0),
}


@pytest.mark.parametrize(("name", "bounds"), sorted(_BOUNDED.items()))
def test_a_numeric_api_leaf_refuses_a_value_below_its_floor(name, bounds):
    lowest, below = bounds
    assert getattr(APISettings(**{name: lowest}), name) == lowest
    for bad in (below, -300):
        with pytest.raises(ValidationError):
            APISettings(**{name: bad})


@pytest.mark.parametrize("name", sorted(_BOUNDED))
def test_the_settings_service_reports_an_out_of_range_leaf_under_its_own_key(name):
    from app.services.settings_service import SettingsService, SettingsValidationError

    service = SettingsService.__new__(SettingsService)
    with pytest.raises(SettingsValidationError) as exc:
        service.validate({}, {name: -300})
    assert f"api.{name}" in exc.value.errors
