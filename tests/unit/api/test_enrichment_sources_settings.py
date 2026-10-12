"""The enrichment source map as a setting: validated, its own keys encrypted, its tests declared."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography.fernet import Fernet

from app.services.enrichment_sources import (
    ENRICHMENT_SOURCES_KEY,
    SOURCE_SECRETS,
    credential_for,
    credential_settings,
    source_facts,
)
from app.services.server_map import TOKEN_MASK
from app.services.settings_catalog_api import catalog_index, validate_editable_api_value
from app.services.settings_probes import known_probe, run_probe
from app.services.settings_service import SettingsService, SettingsValidationError
from maljan.core import settings_secrets as box
from maljan.enrichment.declared import effective_sources

HOST = ".".join(["rep", "example", "org"])


def _own_key() -> str:
    """A credential-shaped value built at run time."""
    return "-".join(["own", "k", "1"])


def _invented(**extra: Any) -> dict[str, Any]:
    return {
        "label": "Domain reputation",
        "kinds": ["domain"],
        "requests": {
            "domain": {
                "url": f"https://{HOST}/v1/{{value}}",
                "headers": {"Authorization": "Bearer {credential}"},
            }
        },
        "probe": {"url": f"https://{HOST}/v1/ping", "headers": {"Authorization": "{credential}"}},
        "record": [{"name": "malicious", "path": "/bad", "read": "count"}],
        **extra,
    }


def _problem(value: Any) -> str | None:
    return validate_editable_api_value(catalog_index()[ENRICHMENT_SOURCES_KEY], value)


class _Rows(list):
    def __init__(self, rows: Any = ()) -> None:
        super().__init__(rows)
        self.added: list = []
        self.deleted: list = []

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def delete(self, row: Any) -> None:
        self.deleted.append(row)

    async def commit(self) -> None:
        return None


def _service(rows: Any = ()) -> tuple[SettingsService, _Rows]:
    session = _Rows(rows)
    service = SettingsService(MagicMock())
    service._rows = AsyncMock(return_value=list(session))  # type: ignore[method-assign]
    service.db = session  # type: ignore[assignment]
    return service, session


# ---- validation ------------------------------------------------------


def test_the_map_is_an_editable_setting_of_the_enrichment_group() -> None:
    entry = catalog_index()[ENRICHMENT_SOURCES_KEY]
    assert entry.editable and entry.type == "dict" and entry.group == "enrichment"
    assert entry.default == {}


def test_a_valid_invented_source_is_accepted_and_a_broken_one_refused_in_words() -> None:
    assert _problem({"domainrep": _invented()}) is None
    said = _problem({"domainrep": _invented(kinds=["domain", "ip"])})
    assert said is not None and said.startswith("domainrep:") and "missing ip" in said
    assert _problem(["not", "a", "map"]) == "Input should be a valid object"


def test_a_credential_may_name_only_an_enrichment_secret() -> None:
    assert credential_settings() == {"api.virustotal_api_key", "api.abuseipdb_api_key"}
    said = _problem({"domainrep": _invented(credential="core.llm.anthropic.api_key")})
    assert said is not None and "not an enrichment secret setting" in said
    assert _problem({"domainrep": _invented(credential="api.virustotal_api_key")}) is None


@pytest.mark.asyncio
async def test_a_stored_reference_to_another_secret_reads_as_no_credential() -> None:
    source = effective_sources({"domainrep": _invented(credential="core.llm.anthropic.api_key")})[
        "domainrep"
    ]
    reader = AsyncMock(return_value="must-not-be-read")
    assert await credential_for("domainrep", source, reader) == ""
    reader.assert_not_awaited()


def test_the_schema_tells_the_console_each_source_and_never_a_credential() -> None:
    facts = source_facts({"domainrep": _invented(api_key=_own_key())})
    assert [f["key"] for f in facts] == ["virustotal", "abuseipdb", "domainrep"]
    assert facts[2] == {
        "key": "domainrep",
        "label": "Domain reputation",
        "kinds": ["domain"],
        "enabled": True,
        "credential_key": None,
        "own_credential": True,
        "server": None,
        "server_enabled": None,
        "probe": True,
    }
    assert _own_key() not in str(facts)


def test_a_server_source_says_whether_its_server_is_on() -> None:
    from types import SimpleNamespace

    declared = {
        "intel": {
            "kinds": ["ip"],
            "server": "intelsrv",
            "tool": "lookup",
            "record": [{"name": "score", "path": "/score", "read": "count"}],
        }
    }
    on = source_facts(declared, {"intelsrv": SimpleNamespace(enabled=True)})
    off = source_facts(declared, {"intelsrv": SimpleNamespace(enabled=False)})
    gone = source_facts(declared, {})
    assert [f["server_enabled"] for f in (on[-1], off[-1], gone[-1])] == [True, False, False]


def test_a_source_enrichment_cannot_ask_is_refused_naming_the_reputation_lookup() -> None:
    said = _problem({"hashrep": _invented(kinds=["hash"], requests={})})
    assert said is not None and said.startswith("hashrep:")
    assert "hash reputation is declared as a reputation lookup tool" in said


# ---- a source's own key ---------------------------------------------


def test_the_map_never_carries_a_source_s_own_key() -> None:
    cleaned, secrets = SOURCE_SECRETS.split({"domainrep": _invented(api_key=_own_key())})
    assert "api_key" not in cleaned["domainrep"]
    assert secrets == {"domainrep": _own_key()}
    assert SOURCE_SECRETS.row_key("domainrep") == f"{ENRICHMENT_SOURCES_KEY}.domainrep.api_key"


@pytest.mark.asyncio
async def test_saving_puts_the_key_in_its_own_encrypted_row_and_reading_folds_it_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    declared = {"domainrep": _invented(api_key=_own_key())}
    await service.save({ENRICHMENT_SOURCES_KEY: declared}, user_id=None, ip=None)
    map_row = next(r for r in session.added if r.key == ENRICHMENT_SOURCES_KEY)
    key_row = next(r for r in session.added if r.key == SOURCE_SECRETS.row_key("domainrep"))
    assert _own_key() not in str(map_row.value)
    assert key_row.is_secret is True and box.decrypt(str(key_row.value)) == _own_key()

    # Read back: the effective map carries the key, the console sees the mask.
    reader, _ = _service([map_row, key_row])
    merged = await SettingsService.load_overrides(reader)
    assert merged[ENRICHMENT_SOURCES_KEY]["domainrep"]["api_key"] == _own_key()
    shown = (await reader.values())[ENRICHMENT_SOURCES_KEY].value
    assert shown["domainrep"]["api_key"] == TOKEN_MASK


@pytest.mark.asyncio
async def test_a_refused_map_stores_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    with pytest.raises(SettingsValidationError) as refused:
        await service.save(
            {ENRICHMENT_SOURCES_KEY: {"domainrep": _invented(kinds=["ip"])}}, user_id=None, ip=None
        )
    assert ENRICHMENT_SOURCES_KEY in refused.value.errors
    assert session.added == []


# ---- its test --------------------------------------------------------


@pytest.mark.asyncio
async def test_an_invented_source_is_tested_by_its_declared_request_with_its_own_key() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    real = httpx.AsyncClient

    def client(**kwargs: Any) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(handler), **kwargs)

    stored = {ENRICHMENT_SOURCES_KEY: {"domainrep": _invented(api_key=_own_key())}}
    assert known_probe("domainrep", stored)
    assert not known_probe("domainrep", {})
    with patch("maljan.enrichment.declared.httpx.AsyncClient", client):
        result = await run_probe("domainrep", {}, stored)
        staged = {ENRICHMENT_SOURCES_KEY: {"domainrep": {"api_key": TOKEN_MASK}}}
        masked = await run_probe("domainrep", staged, stored)
    assert result.ok and masked.ok
    assert [str(r.url) for r in seen] == [f"https://{HOST}/v1/ping"] * 2
    assert all(r.headers["Authorization"] == _own_key() for r in seen)
    assert _own_key() not in result.detail
