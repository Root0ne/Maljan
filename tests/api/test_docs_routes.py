import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))


def test_docs_routes_exist_only_in_debug(monkeypatch):
    from app import config as api_config
    from app.main import create_app

    for debug, expected in ((True, {"/docs", "/redoc", "/openapi.json"}), (False, set())):
        api_config._settings = None
        monkeypatch.setenv("DEBUG", "true" if debug else "false")
        app = create_app()
        paths = {getattr(r, "path", "") for r in app.routes}
        assert paths & {"/docs", "/redoc", "/openapi.json"} == expected
    api_config._settings = None
