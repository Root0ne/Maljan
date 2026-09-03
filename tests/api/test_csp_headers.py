"""The default CSP forbids inline scripts; the docs routes keep their own policy.

``SecurityHeadersMiddleware`` used to ship a single Content-Security-Policy
whose ``script-src`` allowed ``'unsafe-inline'`` so Swagger's bundled assets
would run. That widened the whole API's script policy for one debug-only
route. Task 12 splits it: everything gets a strict default with no inline
script, and only ``/docs``, ``/redoc`` and ``/openapi.json`` get the looser
Swagger-compatible policy.
"""

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.middleware.security_headers_middleware import SecurityHeadersMiddleware  # noqa: E402


def _app() -> TestClient:
    app = FastAPI(docs_url="/docs", openapi_url="/openapi.json")
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/plain")
    def plain() -> dict:
        return {"ok": True}

    return TestClient(app)


def test_default_policy_has_no_inline_script() -> None:
    csp = _app().get("/plain").headers["content-security-policy"]
    script = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
    assert "'unsafe-inline'" not in script


def test_docs_get_the_swagger_policy() -> None:
    csp = _app().get("/docs").headers["content-security-policy"]
    assert "'unsafe-inline'" in csp and "cdn.jsdelivr.net" in csp


def test_redoc_gets_the_swagger_policy() -> None:
    csp = _app().get("/redoc").headers["content-security-policy"]
    assert "'unsafe-inline'" in csp and "cdn.jsdelivr.net" in csp


def test_openapi_json_gets_the_swagger_policy() -> None:
    csp = _app().get("/openapi.json").headers["content-security-policy"]
    assert "'unsafe-inline'" in csp and "cdn.jsdelivr.net" in csp
