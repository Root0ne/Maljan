import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.settings_catalog_api import api_catalog, full_catalog  # noqa: E402

_KNOWN_WIDGET_TYPES = {"bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"}


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
