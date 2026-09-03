import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.settings_catalog_api import api_catalog  # noqa: E402

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
