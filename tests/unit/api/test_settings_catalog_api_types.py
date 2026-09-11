from app.config import APISettings
from app.services.settings_catalog_api import (
    API_DEFAULTS,
    api_catalog,
    catalog_index,
    full_catalog,
)

_KNOWN_WIDGET_TYPES = {"bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"}

# Task 2: every one of these left APISettings/the environment and now lives
# in the settings store, falling back to API_DEFAULTS. Bootstrap-contract
# fields (debug, auth_disabled, cors_origins, database_url, redis_url,
# minio_endpoint, cookie_secure, samples_dir, upload_temp_dir) are the only
# ones that stay read-only.
_MOVED_TO_STORE = {
    "mock_mode_allowed",
    "enrichment_enabled",
    "enrichment_max_lookups",
    "virustotal_api_key",
    "abuseipdb_api_key",
    "rate_limit_enabled",
    "rate_limit_requests",
    "rate_limit_window_seconds",
    "rate_limit_whitelist",
    "login_max_attempts",
    "login_lockout_seconds",
    "upload_max_bytes",
    "upload_allowed_mime_types",
    "trusted_proxy_ips",
    "qdrant_url",
    "qdrant_collection",
    "qdrant_api_key",
    "jwt_access_token_expire_minutes",
    "jwt_refresh_token_expire_days",
}

_READONLY_CONTRACT = {
    "debug",
    "auth_disabled",
    "cors_origins",
    "database_url",
    "redis_url",
    "minio_endpoint",
    "cookie_secure",
    "samples_dir",
    "upload_temp_dir",
}


def test_apisettings_has_no_moved_application_field():
    assert not _MOVED_TO_STORE & set(APISettings.model_fields)


def test_every_moved_field_is_an_api_default_and_a_live_catalog_entry():
    by_path = {e.path: e for e in api_catalog()}
    for name in _MOVED_TO_STORE:
        assert name in API_DEFAULTS, name
        entry = by_path[name]
        assert entry.applies == "live"
        assert entry.editable is True


def test_readonly_group_is_exactly_the_bootstrap_contract():
    by_path = {e.path: e for e in api_catalog() if not e.editable}
    assert set(by_path) == _READONLY_CONTRACT
    for entry in by_path.values():
        assert entry.applies == "restart"
        assert entry.group == "system"


def test_cookie_secure_types_as_bool_not_str():
    # cookie_secure is declared "bool | None = None" so a model_validator can
    # fill in "not debug" after construction; the catalog must still type it
    # as a bool so the settings UI renders a disabled toggle, not a text box
    # showing the literal word "true"/"false".
    by_path = {e.path: e for e in api_catalog()}
    assert by_path["cookie_secure"].type == "bool"


def test_every_api_catalog_entry_has_a_known_widget_type():
    for entry in api_catalog():
        assert entry.type in _KNOWN_WIDGET_TYPES, (entry.path, entry.type)


def test_qdrant_api_key_types_as_secret():
    by_path = {e.path: e for e in api_catalog()}
    assert by_path["qdrant_api_key"].type == "secret"
    assert by_path["qdrant_api_key"].secret


def test_api_entries_carry_the_two_new_fields_with_neutral_defaults():
    from app.services.settings_catalog_api import api_catalog

    for e in api_catalog():
        assert e.applies_when is None
        assert e.order == 0


def test_full_catalog_leads_provider_groups_with_the_selector():
    # GET /api/v1/settings/schema is served from full_catalog(), not
    # core_catalog() directly — the provider selector must sort first in its
    # group on this path too, or the UI never sees it lead.
    entries = full_catalog()
    static = [e for e in entries if e.group == "static"]
    sandbox = [e for e in entries if e.group == "sandbox"]
    assert static[0].key == "core.static.provider"
    assert sandbox[0].key == "core.sandbox.provider"


def test_schema_dto_carries_subgroup_advanced_and_group_description() -> None:
    from app.schemas.settings import CatalogEntryDTO, GroupDTO

    assert CatalogEntryDTO.model_fields["subgroup"].default is None
    assert CatalogEntryDTO.model_fields["advanced"].default is False
    assert GroupDTO.model_fields["description"].default == ""


def test_no_catalog_text_points_an_operator_at_a_dotenv_file() -> None:
    """The ``.env`` layer is gone, and the catalog is what the UI reads aloud.

    The read-only ``reason`` is wire-visible beyond the UI too: it is the 422
    message ``POST /settings/import`` and ``check_keys`` return for a
    read-only key.
    """
    offenders = [
        (e.key, text)
        for e in full_catalog()
        for text in (e.description or "", e.reason or "")
        if ".env" in text
    ]
    assert offenders == []


def test_the_read_only_group_names_the_deployment_environment() -> None:
    entry = catalog_index()["api.debug"]
    assert entry.editable is False
    assert entry.reason == "set in the deployment environment; restart required"
    assert "Set in the deployment environment." in entry.description


def test_the_frontier_arms_description_drops_the_environment_variable_hint() -> None:
    """W5: there is no environment form of this setting to hint at any more."""
    assert "LLM__FRONTIER__ARMS" not in catalog_index()["core.llm.frontier.arms"].description
