import pytest
from pydantic import ValidationError

from app.config import APISettings
from app.services.settings_catalog_api import catalog_index
from app.services.settings_service import SettingsService, SettingsValidationError


def test_trusted_proxy_entries_must_be_addresses_or_networks():
    service = SettingsService.__new__(SettingsService)
    service.validate({}, {"trusted_proxy_ips": ["10.0.0.0/8", "192.168.1.5", "fd00::/8"]})
    for bad in (["proxy"], ["10.0.0.0/33"], ["10.0.0.256"]):
        with pytest.raises(SettingsValidationError) as exc:
            service.validate({}, {"trusted_proxy_ips": bad})
        assert "api.trusted_proxy_ips" in exc.value.errors


@pytest.mark.parametrize(
    ("name", "bad_value"),
    [
        ("upload_allowed_mime_types", [1]),
        ("rate_limit_whitelist", [None]),
        ("trusted_proxy_ips", [3.5]),
    ],
)
def test_a_list_settings_leaf_rejects_a_non_string_item(name, bad_value):
    # Fix round 1, minor 1: the old ``list[str]`` field on APISettings would
    # have rejected/coerced a non-string item; the catalog-driven validator
    # must reject it the same way now that the field is gone.
    service = SettingsService.__new__(SettingsService)
    with pytest.raises(SettingsValidationError) as exc:
        service.validate({}, {name: bad_value})
    assert f"api.{name}" in exc.value.errors


# B4 (dev audit 2026-09-06): a negative ``login_lockout_seconds`` was accepted
# and applied. It reaches Redis as an expiry, and a negative expiry deletes the
# key instead of setting it -- an operator who typed "-300" silently turned the
# brute-force lockout off. Every numeric API leaf an admin can PATCH is bounded
# so the value never gets past validation.
#
# Task 2 moved every one of these except the ``db_*`` pool settings off
# APISettings and into the settings-store catalog (``API_EDITABLE`` /
# ``API_DEFAULTS`` in ``settings_catalog_api``); their floor is still
# enforced, just no longer by pydantic's ``Field(ge=...)``.
_CATALOG_BOUNDED = {
    "login_lockout_seconds": (1, 0),
    "login_max_attempts": (1, 0),
    "rate_limit_requests": (1, 0),
    "rate_limit_window_seconds": (1, 0),
    "enrichment_max_lookups": (1, 0),
    "upload_max_bytes": (1024, 0),
    "jwt_access_token_expire_minutes": (1, 0),
    "jwt_refresh_token_expire_days": (1, 0),
}

# These stayed on APISettings (deployment-shaped, not moved to the store) and
# keep their pydantic ``Field(ge=...)`` bound.
_MODEL_BOUNDED = {
    "db_pool_size": (1, 0),
    "db_max_overflow": (0, -1),
    "db_pool_recycle_seconds": (1, 0),
}


@pytest.mark.parametrize(("name", "bounds"), sorted(_MODEL_BOUNDED.items()))
def test_a_numeric_api_leaf_refuses_a_value_below_its_floor(name, bounds):
    lowest, below = bounds
    assert getattr(APISettings(**{name: lowest}), name) == lowest
    for bad in (below, -300):
        with pytest.raises(ValidationError):
            APISettings(**{name: bad})


@pytest.mark.parametrize(("name", "bounds"), sorted(_CATALOG_BOUNDED.items()))
def test_a_catalog_editable_leaf_refuses_a_value_below_its_floor(name, bounds):
    lowest, below = bounds
    entry = catalog_index()[f"api.{name}"]
    assert entry.minimum == lowest
    service = SettingsService.__new__(SettingsService)
    service.validate({}, {name: lowest})
    for bad in (below, -300):
        with pytest.raises(SettingsValidationError) as exc:
            service.validate({}, {name: bad})
        assert f"api.{name}" in exc.value.errors


# Only the catalog-editable leaves: a ``db_*`` name is not a catalog key, so
# ``save`` rejects it in ``check_keys`` and it can never reach ``validate`` in
# the first place (final review M1, which removed the dead
# ``APISettings(**nest(merged_api))`` call that used to answer for it). Their
# floor is tested directly against the model above.
@pytest.mark.parametrize("name", sorted(_CATALOG_BOUNDED))
def test_the_settings_service_reports_an_out_of_range_leaf_under_its_own_key(name):
    service = SettingsService.__new__(SettingsService)
    with pytest.raises(SettingsValidationError) as exc:
        service.validate({}, {name: -300})
    assert f"api.{name}" in exc.value.errors
