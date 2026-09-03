# Provider Layer Implementation Plan (sub-project A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the static tool and the sandbox attachable, choosable and configurable — from `.env`, from the settings UI and per job — by introducing `src/maljan/providers/`, a neutral `SandboxReport`, `static.*` / `sandbox.*` settings with legacy aliases, and nine adapters (ghidra, r2, capa_yara, generic_mcp, none; cape2, mock, upload, triage), **without changing a single prompt byte, tool allow-list entry, sandbox report dict or extractor output on the default `ghidra` + `cape2`/`mock` profile**.

**Architecture:** Twenty-four sequential tasks on one branch, one commit each. Task 1 freezes today's behaviour as golden fixtures captured from the unmodified branch; every later task runs them. The provider contracts (`providers/base.py`) and the registry (`providers/registry.py`, a copy of `llm/registry.py`'s decorator pattern) are the only new vocabulary; capability flags decide what the pipeline does, so `if provider == "ghidra"` never appears outside `providers/static/ghidra.py`. The nine raw-CAPE consumers do not move: `providers/cape_view.py::to_cape_shaped_dict` returns `report.raw` **by identity** for CAPE-shaped sources, so byte-identity is structural rather than a property of a normalisation function. `SubmissionResult` and `SandboxClient` stay, wrapped by `providers/sandbox/_legacy.py::as_sandbox_client`, so `src/maljan/app.py` and the existing sandbox tests are untouched.

**Tech Stack:** Python 3.13, pydantic / pydantic-settings, LangChain + LangGraph, MCP (stdio + streamable-http), httpx, FastAPI, SQLAlchemy async + alembic, MinIO, arq; Next.js 16 / React 19 / TypeScript; Playwright; Docker Compose.

**Spec:** docs/specs/2026-09-03-provider-layer-design.md

## Global Constraints

- Branch `feat/provider-layer` (from `dev`), one commit per task, imperative messages in the repository's voice, no AI attribution anywhere.
- Every task: TDD (failing test first), then `uv run ruff check <files>`, `uv run ruff format --check <files>`, `uv run mypy src/ apps/api/` clean; frontend tasks also `cd apps/web && npx tsc --noEmit && npm run lint` (10 pre-existing warnings, none new).
- Run only the test modules the task names (`uv run pytest <paths> -q`), never the whole suite mid-task; Playwright only the single spec a task names, `--project=chromium` only, after `free -g` shows >= 6 GB available and no `next dev` is running.
- Never print or read the real `.env`; never log or return a secret value; test credentials are built at runtime (see `_dsn()` in `tests/unit/api/test_settings_probes.py`), never a literal `scheme://user:pass@host`.
- Every new core setting needs an `ANNOTATIONS` leaf in `src/maljan/core/settings_annotations.py` (`tests/unit/core/test_settings_catalog.py` enforces it); every new `APISettings` field needs an `API_EDITABLE` or `API_READONLY` entry in `apps/api/app/services/settings_catalog_api.py`.
- Local development with an unchanged `.env` keeps working: every legacy environment variable resolves through the alias table to the same effective value.
- The paper's numbers do not move: `tests/evaluation/**` is not modified at all, `make facts` output is byte-identical, `tests/evaluation/test_suite_count.json` is not re-measured.
- The invariant: with `static.provider=ghidra` and `sandbox.provider` in {cape2, mock} no prompt byte, tool allow-list, sandbox report dict or extractor output changes, enforced by the golden tests from Task 1.
- No question sentences in headings, comments or docs.
- Do not run `git checkout`, `git stash` or `git reset`; `git add` explicit paths only.
- Implementers do not spawn subagents.

---

### Task 1: Golden snapshots captured from the unmodified branch

**Files:**
- Create: `scripts/capture_provider_goldens.py` (one-off capture script, committed so a reviewer can re-run it), `tests/fixtures/prompts/static_isr_system_ghidra.txt`, `tests/fixtures/prompts/dynamic_system_cape2.txt`, `tests/fixtures/golden/allowlists.json`, `tests/fixtures/golden/extractors/<name>.json` (one per CAPE-shaped fixture), `tests/agents/test_prompt_byte_identity.py`, `tests/providers/__init__.py`, `tests/providers/test_extractor_golden.py`
- Modify: nothing. This task must not touch `src/`.
- Test: `tests/agents/test_prompt_byte_identity.py`, `tests/providers/test_extractor_golden.py`

**Interfaces:**
- Consumes: `maljan.agents.static_analyst._ISR_SYSTEM`, `maljan.agents.static_analyst.StaticAnalyst._GHIDRA_ALLOWED_TOOLS`, `maljan.agents.ghidra_tool_selector._CORE_TOOLS`, `maljan.agents.dynamic_analyst._ISR_SYSTEM`, `maljan.extractors.dynamic_extractor.build_dynamic_behavior`, `maljan.extractors.network_extractor.build_network_iocs`
- Produces:
  ```python
  # tests/providers/test_extractor_golden.py
  CAPE_GLOBS: tuple[str, ...] = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")
  def cape_reports() -> list[tuple[str, dict]]        # (fixture name, raw report)
  def dump(model: BaseModel | None) -> Any            # model_dump(mode="json") or None
  ```
  Golden files are the single source of truth for tasks 6, 7, 9, 10, 11, 13, 16, 24.

- [ ] **Step 1: Write the capture script**

```python
# scripts/capture_provider_goldens.py
"""Freeze today's prompts, allow-lists and extractor outputs as golden fixtures.

Run once, on `dev`, before the provider refactor begins:

    uv run python scripts/capture_provider_goldens.py

It imports the live module constants and writes them to tests/fixtures/. It is
committed so a reviewer can re-run it on `dev` and diff the result against what
this branch carries — the whole argument for the refactor being behaviour-free
rests on these bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_ISR_SYSTEM
from maljan.agents.ghidra_tool_selector import _CORE_TOOLS
from maljan.agents.static_analyst import _ISR_SYSTEM as STATIC_ISR_SYSTEM
from maljan.agents.static_analyst import StaticAnalyst
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs

ROOT = Path(__file__).resolve().parents[1]
PROMPTS = ROOT / "tests" / "fixtures" / "prompts"
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
CAPE_GLOBS = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")

# The 13 CAPE MCP tool names the dynamic analyst keeps when
# ``mcp.cape.tools`` is empty (dynamic_analyst.py:121-135).
CAPE_ESSENTIALS = [
    "get_cuckoo_status",
    "search_task",
    "extended_search",
    "submit_file",
    "submit_static",
    "get_task_status",
    "get_task_report",
    "get_task_iocs",
    "get_task_config",
    "list_tasks",
    "view_task",
    "get_latest_tasks",
    "verify_auth",
]


def main() -> None:
    PROMPTS.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "extractors").mkdir(parents=True, exist_ok=True)

    (PROMPTS / "static_isr_system_ghidra.txt").write_text(STATIC_ISR_SYSTEM, encoding="utf-8")
    (PROMPTS / "dynamic_system_cape2.txt").write_text(DYNAMIC_ISR_SYSTEM, encoding="utf-8")

    (GOLDEN / "allowlists.json").write_text(
        json.dumps(
            {
                "ghidra_allowed_tools": sorted(StaticAnalyst._GHIDRA_ALLOWED_TOOLS),
                "ghidra_core_tools": sorted(_CORE_TOOLS),
                "cape_essential_tools": sorted(CAPE_ESSENTIALS),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            dyn = build_dynamic_behavior(raw)
            net = build_network_iocs(raw)
            out = {
                "dynamic_behavior": dyn.model_dump(mode="json") if dyn is not None else None,
                "network_iocs": net.model_dump(mode="json") if net is not None else None,
            }
            dest = GOLDEN / "extractors" / f"{path.stem}.json"
            dest.write_text(
                json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    print(f"prompts -> {PROMPTS}")
    print(f"goldens -> {GOLDEN}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the capture script**

Run: `uv run python scripts/capture_provider_goldens.py`
Expected: two prompt files, `allowlists.json` with 20 Ghidra names, 15 core names and 13 CAPE names, and one JSON per CAPE-shaped fixture (98 files: `data/cape_reports/*.json` plus `data/samples/dynamic/sample_1.json`).

Verify the counts before continuing:

```bash
wc -c tests/fixtures/prompts/*.txt
uv run python -c "import json;d=json.load(open('tests/fixtures/golden/allowlists.json'));print({k:len(v) for k,v in d.items()})"
ls tests/fixtures/golden/extractors | wc -l
```
Expected: `{'cape_essential_tools': 13, 'ghidra_allowed_tools': 20, 'ghidra_core_tools': 15}` and 98 extractor goldens.

- [ ] **Step 3: Write the golden tests**

```python
# tests/agents/test_prompt_byte_identity.py
"""The default profile's prompts and allow-lists are frozen.

Captured from `dev` by ``scripts/capture_provider_goldens.py`` before the
provider refactor. Any change to a byte of the static (ghidra) or dynamic
(cape2) system prompt, or to either tool allow-list, is a behaviour change and
fails here — which is the point: sub-project A is a refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PROMPTS = FIXTURES / "prompts"
GOLDEN = FIXTURES / "golden"


def _golden(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def test_static_ghidra_system_prompt_is_byte_identical():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")


def test_dynamic_cape2_system_prompt_is_byte_identical():
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("dynamic_system_cape2.txt")


def test_ghidra_allow_list_and_core_set_are_unchanged():
    from maljan.agents.ghidra_tool_selector import _CORE_TOOLS
    from maljan.agents.static_analyst import StaticAnalyst

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    assert sorted(StaticAnalyst._GHIDRA_ALLOWED_TOOLS) == expected["ghidra_allowed_tools"]
    assert len(expected["ghidra_allowed_tools"]) == 20
    assert sorted(_CORE_TOOLS) == expected["ghidra_core_tools"]


def test_cape_essential_tool_names_are_unchanged():
    """The 13 names the dynamic analyst keeps when ``mcp.cape.tools`` is empty.

    Read out of the module source rather than a constant, because today the set
    is an inline literal inside ``_initialize_mcp_client``. Task 11 turns it
    into ``CAPE_ESSENTIAL_TOOLS`` in the provider and this test then compares
    against that name; until then the literal is what ships.
    """
    import inspect

    from maljan.agents.dynamic_analyst import DynamicAnalyst

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    source = inspect.getsource(DynamicAnalyst._initialize_mcp_client)
    for name in expected["cape_essential_tools"]:
        assert f'"{name}"' in source, name
    assert len(expected["cape_essential_tools"]) == 13
```

```python
# tests/providers/test_extractor_golden.py
"""``build_dynamic_behavior`` and ``build_network_iocs`` over every CAPE fixture.

These two functions are the whole downstream contract of the sandbox report:
the report's dynamic section, its IOC tables and the DGA / LOLBin Layer-0
scanners all read what they produce. Freezing their output over the real
corpus (``data/cape_reports/*.json``, 97 detonations) is what lets the provider
layer be introduced under the raw dicts without anybody having to trust a
normalisation function.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "extractors"
CAPE_GLOBS: tuple[str, ...] = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")


def cape_reports() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                out.append((path.stem, raw))
    return out


def dump(model: Any) -> Any:
    return None if model is None else model.model_dump(mode="json")


_REPORTS = cape_reports()


def test_the_corpus_is_present():
    assert len(_REPORTS) >= 90, "CAPE golden corpus is missing; goldens cannot be trusted"


@pytest.mark.parametrize("name,raw", _REPORTS, ids=[n for n, _ in _REPORTS])
def test_extractor_output_matches_the_golden(name: str, raw: dict[str, Any]):
    expected = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    assert dump(build_dynamic_behavior(raw)) == expected["dynamic_behavior"]
    assert dump(build_network_iocs(raw)) == expected["network_iocs"]
```

- [ ] **Step 4: Run the golden tests on the unmodified branch**

Run: `uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers/test_extractor_golden.py -q`
Expected: PASS, all green, on the branch with no `src/` change. **Task 2 does not start until this is green** — a golden captured from already-modified code proves nothing.

- [ ] **Step 5: Lint and type-check**

Run: `uv run ruff check scripts/capture_provider_goldens.py tests/agents/test_prompt_byte_identity.py tests/providers/test_extractor_golden.py && uv run ruff format --check scripts/capture_provider_goldens.py tests/agents/test_prompt_byte_identity.py tests/providers/test_extractor_golden.py && uv run mypy src/ apps/api/`

- [ ] **Step 6: Commit**

```bash
git add scripts/capture_provider_goldens.py tests/fixtures/prompts tests/fixtures/golden tests/agents/test_prompt_byte_identity.py tests/providers/__init__.py tests/providers/test_extractor_golden.py
git commit -m "test: freeze the default profile's prompts, allow-lists and extractor output as goldens"
```

---

### Task 2: Settings shape — `StaticConfig`, the new `SandboxConfig`, and the legacy alias validator

**Files:**
- Modify: `src/maljan/core/config.py:394-419` (`SandboxConfig` replaced), `:702-741` (`MCPServerConfig` kept, `MCPConfig` documented as the transitional mirror), `:807-833` (`Settings` fields + the alias validator), `tests/unit/test_sandbox_container.py:40-100` (attribute paths only)
- Create: `tests/unit/core/test_settings_aliases.py`
- Test: `tests/unit/core/test_settings_aliases.py`, `tests/unit/test_sandbox_container.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/config.py
  class StaticR2Config(MCPServerConfig):
      binary_path: str = "r2mcp"
      mirror_dir: str = "data/samples/.work"

  class StaticCapaConfig(BaseModel):
      rules_dir: str = "data/capa-rules"
      signatures_dir: str = "data/capa-signatures"
      timeout_seconds: Annotated[int, Field(ge=1)] = 300
      backend: Literal["auto", "vivisect", "pefile", "binja"] = "auto"

  class StaticYaraConfig(BaseModel):
      rules_dir: str = "data/yara_rules"
      timeout_seconds: Annotated[int, Field(ge=1)] = 60

  class StaticConfig(BaseModel):
      provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] = "ghidra"
      ghidra: MCPServerConfig
      r2: StaticR2Config
      capa: StaticCapaConfig
      yara: StaticYaraConfig
      generic: MCPServerConfig

  class SandboxCape2Config(BaseModel):
      base_url: str = "http://localhost:8000"
      api_token: SecretStr = SecretStr("")
      timeout_seconds: Annotated[int, Field(ge=1)] = 300
      poll_interval_seconds: Annotated[int, Field(ge=1)] = 10
      mcp: MCPServerConfig

  class SandboxTriageConfig(BaseModel):
      base_url: str = "https://tria.ge/api/v0"
      api_token: SecretStr = SecretStr("")
      profile: str = ""
      timeout_seconds: Annotated[int, Field(ge=1)] = 900
      poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
      fetch_pcap: bool = True

  class SandboxUploadConfig(BaseModel):
      max_report_bytes: Annotated[int, Field(ge=1)] = 67_108_864
      allowed_formats: list[str] = ["cape2", "cuckoo", "triage"]

  class SandboxConfig(BaseModel):
      provider: Literal["mock", "cape2", "upload", "triage"] = "mock"
      cape2: SandboxCape2Config
      triage: SandboxTriageConfig
      upload: SandboxUploadConfig

  SETTINGS_ALIASES: tuple[tuple[str, str], ...]     # (legacy dotted path, new dotted path)
  def apply_settings_aliases(data: dict[str, Any]) -> dict[str, Any]
  ```
  `Settings.static: StaticConfig` is added; `Settings.mcp: MCPConfig` **stays** through Task 12 as a mirror of `static.ghidra` / `sandbox.cape2.mcp` so the modules that still read it keep working; Task 12 removes `MCPConfig.ghidra` and Task 23 removes `MCPConfig` itself.

- [ ] **Step 1: Write the alias-validator probe test first**

The one thing that has to be proven before any of this design is committed to: what shape `model_validator(mode="before")` receives when the values come from environment variables rather than init kwargs.

```python
# tests/unit/core/test_settings_aliases.py
"""Legacy environment variables must keep producing the same effective values.

The first test is a probe, not a feature test: it pins the shape the
``mode="before"`` validator sees when pydantic-settings has assembled the
env/dotenv sources. If it ever fails, the fallback is the
``settings_customise_sources`` pre-pass documented in the plan — same alias
table, applied one source at a time.
"""

from __future__ import annotations

import pytest

from maljan.core.config import SETTINGS_ALIASES, Settings, apply_settings_aliases


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "MCP__GHIDRA__URL",
        "MCP__GHIDRA__ENABLED",
        "MCP__GHIDRA__TRANSPORT",
        "MCP__GHIDRA__AUTH_TOKEN",
        "MCP__GHIDRA__TOOL_SELECTION",
        "MCP__CAPE__ENABLED",
        "MCP__CAPE__URL",
        "SANDBOX__BACKEND",
        "SANDBOX__PROVIDER",
        "SANDBOX__CAPE2_BASE_URL",
        "SANDBOX__CAPE2_API_TOKEN",
        "SANDBOX__CAPE2_TIMEOUT_SECONDS",
        "SANDBOX__CAPE2_POLL_INTERVAL_SECONDS",
        "SANDBOX__CAPE2__BASE_URL",
        "STATIC__PROVIDER",
        "STATIC__GHIDRA__URL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_the_validator_sees_the_env_derived_nested_dict(monkeypatch):
    """PROBE: env vars reach ``mode='before'`` as a nested dict, not as strings."""
    seen: list[dict] = []
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://ghidra.example:8089")
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")

    original = Settings._alias_legacy_keys.__func__  # type: ignore[attr-defined]

    def spy(cls, data):
        if isinstance(data, dict):
            seen.append(dict(data))
        return original(cls, data)

    monkeypatch.setattr(Settings, "_alias_legacy_keys", classmethod(spy))
    Settings(_env_file=None)

    assert seen, "the before-validator never ran"
    payload = seen[0]
    assert isinstance(payload.get("mcp"), dict), payload.get("mcp")
    assert payload["mcp"]["ghidra"]["url"] == "http://ghidra.example:8089"
    assert payload["sandbox"]["backend"] == "cape2"


def test_legacy_ghidra_env_lands_on_static_ghidra(monkeypatch):
    monkeypatch.setenv("MCP__GHIDRA__ENABLED", "true")
    monkeypatch.setenv("MCP__GHIDRA__TRANSPORT", "http")
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://ghidra.example:8089")
    monkeypatch.setenv("MCP__GHIDRA__TOOL_SELECTION", "curated")
    s = Settings(_env_file=None)
    assert s.static.ghidra.enabled is True
    assert s.static.ghidra.transport == "http"
    assert s.static.ghidra.url == "http://ghidra.example:8089"
    assert s.static.ghidra.tool_selection == "curated"
    # The transitional mirror carries the same values for the modules that
    # still read ``mcp.ghidra`` until Task 12.
    assert s.mcp.ghidra.url == s.static.ghidra.url


def test_legacy_sandbox_env_lands_on_the_nested_cape2_block(monkeypatch):
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    monkeypatch.setenv("SANDBOX__CAPE2_BASE_URL", "http://cape.example:8000")
    monkeypatch.setenv("SANDBOX__CAPE2_API_TOKEN", "not-a-real-token")
    monkeypatch.setenv("SANDBOX__CAPE2_TIMEOUT_SECONDS", "1200")
    monkeypatch.setenv("SANDBOX__CAPE2_POLL_INTERVAL_SECONDS", "15")
    s = Settings(_env_file=None)
    assert s.sandbox.provider == "cape2"
    assert s.sandbox.cape2.base_url == "http://cape.example:8000"
    assert s.sandbox.cape2.api_token.get_secret_value() == "not-a-real-token"
    assert s.sandbox.cape2.timeout_seconds == 1200
    assert s.sandbox.cape2.poll_interval_seconds == 15


def test_legacy_cape_mcp_env_lands_under_sandbox_cape2_mcp(monkeypatch):
    monkeypatch.setenv("MCP__CAPE__ENABLED", "true")
    monkeypatch.setenv("MCP__CAPE__URL", "http://cape-mcp.example:9004/mcp/")
    s = Settings(_env_file=None)
    assert s.sandbox.cape2.mcp.enabled is True
    assert s.sandbox.cape2.mcp.url == "http://cape-mcp.example:9004/mcp/"


def test_the_new_key_wins_over_the_legacy_one(monkeypatch):
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    monkeypatch.setenv("SANDBOX__PROVIDER", "mock")
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://legacy:8089")
    monkeypatch.setenv("STATIC__GHIDRA__URL", "http://new:8089")
    s = Settings(_env_file=None)
    assert s.sandbox.provider == "mock"
    assert s.static.ghidra.url == "http://new:8089"


def test_aliasing_is_a_pure_function_over_a_plain_dict():
    out = apply_settings_aliases({"sandbox": {"backend": "cape2", "cape2_base_url": "http://x:1"}})
    assert out["sandbox"]["provider"] == "cape2"
    assert out["sandbox"]["cape2"]["base_url"] == "http://x:1"
    assert "backend" not in out["sandbox"]
    assert "cape2_base_url" not in out["sandbox"]


def test_every_alias_names_a_real_new_path():
    flat = {
        "static.ghidra",
        "sandbox.cape2.mcp",
        "sandbox.provider",
        "sandbox.cape2.base_url",
        "sandbox.cape2.api_token",
        "sandbox.cape2.timeout_seconds",
        "sandbox.cape2.poll_interval_seconds",
    }
    assert {new for _old, new in SETTINGS_ALIASES} == flat


def test_defaults_are_todays_defaults():
    s = Settings(_env_file=None)
    assert s.static.provider == "ghidra"
    assert s.sandbox.provider == "mock"
    assert s.sandbox.cape2.base_url == "http://localhost:8000"
    assert s.sandbox.cape2.timeout_seconds == 300
    assert s.sandbox.cape2.poll_interval_seconds == 10
    assert s.sandbox.upload.max_report_bytes == 67_108_864
    assert s.sandbox.triage.base_url == "https://tria.ge/api/v0"


def test_one_deprecation_warning_per_process(monkeypatch, caplog):
    import maljan.core.config as config_module

    monkeypatch.setattr(config_module, "_ALIAS_WARNED", False, raising=False)
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    with caplog.at_level("WARNING"):
        Settings(_env_file=None)
        Settings(_env_file=None)
    hits = [r for r in caplog.records if "legacy setting name" in r.getMessage()]
    assert len(hits) == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_settings_aliases.py -q`
Expected: FAIL — `ImportError: cannot import name 'SETTINGS_ALIASES' from 'maljan.core.config'`.

- [ ] **Step 3: Add the new config models**

Replace `SandboxConfig` (`config.py:394-419`) with the block below, and add the static models next to it. `MCPServerConfig` (`:705-733`) is unchanged and must stay declared **above** these models in the file.

```python
class StaticR2Config(MCPServerConfig):
    """radare2 MCP server, plus where the sample has to be for r2 to read it.

    ``mirror_dir`` is the host directory the worker copies the sample into when
    the provider declares ``needs_sample_mirror``; it defaults to the same
    ``.work`` subdirectory the Ghidra mirror already uses, because a co-located
    r2mcp reads the host path directly.
    """

    binary_path: str = "r2mcp"
    mirror_dir: str = "data/samples/.work"


class StaticCapaConfig(BaseModel):
    """flare-capa rule sources and its execution budget."""

    rules_dir: str = "data/capa-rules"
    signatures_dir: str = "data/capa-signatures"
    timeout_seconds: Annotated[int, Field(ge=1)] = 300
    backend: Literal["auto", "vivisect", "pefile", "binja"] = "auto"


class StaticYaraConfig(BaseModel):
    """Rule directory for the evidence-only YARA pass of the capa_yara provider.

    The deterministic YARA *layer* (``analysis/yara_layer.py``) keeps its own
    vendored corpus; this is the operator's own rule directory, scanned only by
    the capa_yara static provider.
    """

    rules_dir: str = "data/yara_rules"
    timeout_seconds: Annotated[int, Field(ge=1)] = 60


class StaticConfig(BaseModel):
    """Which static-analysis tool the static analyst attaches, and its settings.

    ``provider`` is the single switch; every block below is the configuration of
    one provider and is inert unless that provider is selected. ``ghidra`` is
    the default and is byte-for-byte the configuration that used to live at
    ``mcp.ghidra``.
    """

    provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] = "ghidra"
    ghidra: MCPServerConfig = Field(default_factory=MCPServerConfig)
    r2: StaticR2Config = Field(default_factory=StaticR2Config)
    capa: StaticCapaConfig = Field(default_factory=StaticCapaConfig)
    yara: StaticYaraConfig = Field(default_factory=StaticYaraConfig)
    generic: MCPServerConfig = Field(default_factory=MCPServerConfig)


class SandboxCape2Config(BaseModel):
    """CAPEv2 REST endpoint plus the optional CAPE MCP server beside it."""

    base_url: str = "http://localhost:8000"
    api_token: SecretStr = SecretStr("")
    timeout_seconds: Annotated[int, Field(ge=1)] = 300
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 10
    mcp: MCPServerConfig = Field(default_factory=MCPServerConfig)


class SandboxTriageConfig(BaseModel):
    """Hatching Triage cloud API.

    ``profile`` names a Triage VM profile; empty means the account default.
    ``timeout_seconds`` is generous because a Triage run queues behind other
    tenants' work.
    """

    base_url: str = "https://tria.ge/api/v0"
    api_token: SecretStr = SecretStr("")
    profile: str = ""
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
    fetch_pcap: bool = True


class SandboxUploadConfig(BaseModel):
    """Limits for operator-uploaded sandbox reports (no detonation of our own)."""

    max_report_bytes: Annotated[int, Field(ge=1)] = 67_108_864  # 64 MiB
    allowed_formats: list[str] = Field(default_factory=lambda: ["cape2", "cuckoo", "triage"])


class SandboxConfig(BaseModel):
    """Which sandbox produces the dynamic evidence, and how to reach it.

    provider:
        "mock"   (default) — fixture JSON from the samples directory, no network.
        "cape2"  — a live CAPEv2 instance over its REST API.
        "upload" — no detonation: an operator-uploaded report is attached to the job.
        "triage" — Hatching Triage cloud sandbox.

    The legacy flat names (``SANDBOX__BACKEND``, ``SANDBOX__CAPE2_BASE_URL``, …)
    keep working through the alias table on ``Settings``.
    """

    provider: Literal["mock", "cape2", "upload", "triage"] = "mock"
    cape2: SandboxCape2Config = Field(default_factory=SandboxCape2Config)
    triage: SandboxTriageConfig = Field(default_factory=SandboxTriageConfig)
    upload: SandboxUploadConfig = Field(default_factory=SandboxUploadConfig)

    @model_validator(mode="before")
    @classmethod
    def _alias_flat_keys(cls, data: Any) -> Any:
        """Accept ``SandboxConfig(backend=..., cape2_base_url=...)`` directly.

        The table on ``Settings`` covers values arriving through the environment;
        this covers direct construction, which tests and the container do.
        """
        if not isinstance(data, dict):
            return data
        return _alias_within(data, _SANDBOX_LOCAL_ALIASES)
```

- [ ] **Step 4: Add the alias table and the validator**

Above `Settings` (after `MCPConfig`), add:

```python
# ---------------------------------------------------------------------------
# Legacy key aliases
# ---------------------------------------------------------------------------
#
# The provider layer moved four groups of settings. Every legacy name keeps
# working: the table below is applied to the assembled input before validation,
# and only where the new key is absent, so a `.env` written for the old shape
# and one written for the new shape both produce the same Settings. One warning
# per process names the file to edit; nothing is removed in this release.

SETTINGS_ALIASES: tuple[tuple[str, str], ...] = (
    ("mcp.ghidra", "static.ghidra"),
    ("mcp.cape", "sandbox.cape2.mcp"),
    ("sandbox.backend", "sandbox.provider"),
    ("sandbox.cape2_base_url", "sandbox.cape2.base_url"),
    ("sandbox.cape2_api_token", "sandbox.cape2.api_token"),
    ("sandbox.cape2_timeout_seconds", "sandbox.cape2.timeout_seconds"),
    ("sandbox.cape2_poll_interval_seconds", "sandbox.cape2.poll_interval_seconds"),
)

# The subset that a bare ``SandboxConfig(...)`` can carry (paths relative to it).
_SANDBOX_LOCAL_ALIASES: tuple[tuple[str, str], ...] = (
    ("backend", "provider"),
    ("cape2_base_url", "cape2.base_url"),
    ("cape2_api_token", "cape2.api_token"),
    ("cape2_timeout_seconds", "cape2.timeout_seconds"),
    ("cape2_poll_interval_seconds", "cape2.poll_interval_seconds"),
)

_ALIAS_WARNED = False


def _dig(data: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, str]:
    """Return (owning mapping, last segment) for ``path``, or (None, ...) if absent."""
    cursor: Any = data
    parts = path.split(".")
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return None, parts[-1]
        cursor = cursor[part]
    return (cursor if isinstance(cursor, dict) else None), parts[-1]


def _ensure(data: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    """Return (owning mapping, last segment) for ``path``, creating dicts as needed."""
    cursor = data
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = cursor.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[part] = nxt
        cursor = nxt
    return cursor, parts[-1]


def _alias_within(data: dict[str, Any], table: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    """Move every legacy path in ``table`` onto its new path, new key wins.

    Sub-mappings are merged key by key (``mcp.ghidra`` -> ``static.ghidra``
    keeps a ``static.ghidra.url`` that was set explicitly), scalars are moved
    only when the target is absent. The legacy key is removed either way so the
    model never sees an unknown field.
    """
    out = dict(data)
    used: list[str] = []
    for old, new in table:
        src_owner, src_key = _dig(out, old)
        if src_owner is None or src_key not in src_owner:
            continue
        value = src_owner.pop(src_key)
        used.append(old)
        dst_owner, dst_key = _ensure(out, new)
        if isinstance(value, dict):
            target = dst_owner.get(dst_key)
            merged = dict(value)
            if isinstance(target, dict):
                merged.update(target)  # explicit new keys win
            dst_owner[dst_key] = merged
        elif dst_key not in dst_owner:
            dst_owner[dst_key] = value
    if used:
        _warn_once(used)
    return out


def _warn_once(paths: list[str]) -> None:
    global _ALIAS_WARNED
    if _ALIAS_WARNED:
        return
    _ALIAS_WARNED = True
    from maljan.core.logger import logger

    logger.warning(
        "Reading legacy setting name(s) %s; they now live under static.* / sandbox.* "
        "(MCP__GHIDRA__* -> STATIC__GHIDRA__*, MCP__CAPE__* -> SANDBOX__CAPE2__MCP__*, "
        "SANDBOX__BACKEND -> SANDBOX__PROVIDER, SANDBOX__CAPE2_* -> SANDBOX__CAPE2__*). "
        "The old names keep working; update .env when convenient.",
        ", ".join(sorted(paths)),
    )


def apply_settings_aliases(data: dict[str, Any]) -> dict[str, Any]:
    """Public, pure form of the alias pass — used by the validator and by tests."""
    return _alias_within(data, SETTINGS_ALIASES)
```

On `Settings`, add the field and the validator (`from pydantic import model_validator` goes on the existing pydantic import line):

```python
    static: StaticConfig = Field(default_factory=StaticConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    # Transitional mirror of static.ghidra / sandbox.cape2.mcp. Every reader
    # moves to the provider in tasks 9-12; MCPConfig itself goes in Task 23.
    mcp: MCPConfig = Field(default_factory=MCPConfig)

    @model_validator(mode="before")
    @classmethod
    def _alias_legacy_keys(cls, data: Any) -> Any:
        """Translate the pre-provider setting names, then mirror back for readers.

        pydantic-settings hands this the assembled mapping of init kwargs,
        dotenv and environment (nested by the ``__`` delimiter), which the probe
        test in ``tests/unit/core/test_settings_aliases.py`` pins. If that ever
        stops holding, the fallback is ``settings_customise_sources`` — the same
        table applied to each source; see the plan's Task 2 Step 5.
        """
        if not isinstance(data, dict):
            return data
        out = apply_settings_aliases(data)
        # Keep the deprecated mirror in step with the new home so a module that
        # has not been migrated yet reads the operator's real value.
        static_ghidra = (out.get("static") or {}).get("ghidra") if isinstance(out.get("static"), dict) else None
        if isinstance(static_ghidra, dict):
            mcp = out.setdefault("mcp", {})
            if isinstance(mcp, dict) and not isinstance(mcp.get("ghidra"), dict):
                mcp["ghidra"] = dict(static_ghidra)
        cape_mcp = ((out.get("sandbox") or {}).get("cape2") or {}).get("mcp") if isinstance(out.get("sandbox"), dict) else None
        if isinstance(cape_mcp, dict):
            mcp = out.setdefault("mcp", {})
            if isinstance(mcp, dict) and not isinstance(mcp.get("cape"), dict):
                mcp["cape"] = dict(cape_mcp)
        return out
```

`model_post_init` gains the reverse mirror, so a `Settings` built from *new* keys still answers `settings.mcp.ghidra.url` while tasks 9-12 are in flight:

```python
        # Transitional: the readers that still say ``mcp.ghidra`` (static
        # analyst, pipeline nodes, worker mirror) must see the provider's
        # configuration until Task 12 moves them.
        if self.mcp.ghidra == MCPServerConfig():
            self.mcp.ghidra = self.static.ghidra.model_copy(deep=True)
        if self.mcp.cape == MCPServerConfig():
            self.mcp.cape = self.sandbox.cape2.mcp.model_copy(deep=True)
```

- [ ] **Step 5: Fallback, only if the probe test fails**

If `test_the_validator_sees_the_env_derived_nested_dict` fails (the validator receives raw init kwargs and the env source is merged afterwards), delete the `model_validator` and use a source pre-pass instead — same table, same function:

```python
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Alias legacy names inside each source, before they are merged.

        The merge is a deep dict update, so aliasing per source is equivalent to
        aliasing the merged mapping as long as a source never contributes half
        of an aliased sub-mapping — and a source is one file or one environment,
        so it cannot.
        """

        class _Aliased(PydanticBaseSettingsSource):
            def __init__(self, inner: PydanticBaseSettingsSource) -> None:
                super().__init__(settings_cls)
                self._inner = inner

            def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
                return self._inner.get_field_value(field, field_name)

            def __call__(self) -> dict[str, Any]:
                return apply_settings_aliases(self._inner())

        return (
            _Aliased(init_settings),
            _Aliased(env_settings),
            _Aliased(dotenv_settings),
            _Aliased(file_secret_settings),
        )
```
(imports: `from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict` and `from pydantic.fields import FieldInfo`.)

- [ ] **Step 6: Update the two flat-attribute assertions in the sandbox container test**

`tests/unit/test_sandbox_container.py` keeps every test; only the attribute paths move, since the values did not:

- `test_default_backend_is_mock` → `SandboxConfig().provider == "mock"`
- `test_default_cape2_base_url` → `SandboxConfig().cape2.base_url == "http://localhost:8000"`
- `test_default_api_token_empty` → `SandboxConfig().cape2.api_token.get_secret_value() == ""`
- `test_default_timeout_seconds` → `SandboxConfig().cape2.timeout_seconds == 300`
- `test_default_poll_interval_seconds` → `SandboxConfig().cape2.poll_interval_seconds == 10`
- `test_backend_override` → keep `SandboxConfig(backend="cape2")` and assert `.provider == "cape2"` (this is what `_alias_flat_keys` exists for), then add `assert SandboxConfig(provider="cape2").provider == "cape2"`
- `test_sandbox_defaults_to_mock_backend` → `settings.sandbox.provider == "mock"`
- `test_cape2_backend_raises_without_httpx` and `test_mock_config_selects_mock_client` keep `SandboxConfig(backend=...)` unchanged.

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/unit/core/test_settings_aliases.py tests/unit/test_sandbox_container.py tests/unit/core/test_settings_overrides.py -q`
Expected: PASS. `tests/unit/core/test_settings_catalog.py` is expected to FAIL here (unannotated leaves) — Task 3 fixes it; do not run it in this task.

- [ ] **Step 8: Lint and type-check**

Run: `uv run ruff check src/maljan/core/config.py tests/unit/core/test_settings_aliases.py tests/unit/test_sandbox_container.py && uv run ruff format --check src/maljan/core/config.py tests/unit/core/test_settings_aliases.py tests/unit/test_sandbox_container.py && uv run mypy src/ apps/api/`

- [ ] **Step 9: Commit**

```bash
git add src/maljan/core/config.py tests/unit/core/test_settings_aliases.py tests/unit/test_sandbox_container.py
git commit -m "feat(config): static and sandbox provider settings, with the pre-provider names as aliases"
```

---

### Task 3: Annotations, groups, `order` and `applies_when`

**Files:**
- Modify: `src/maljan/core/settings_annotations.py` (`Annotation` TypedDict, `GROUP_ORDER`, `_PREFIX_GROUPS`, `ANNOTATIONS`), `src/maljan/core/settings_catalog.py:39-58` (`CatalogEntry` gains two fields), `:141-170` (`core_catalog` fills them and sorts by them), `apps/api/app/schemas/settings.py:16-33` (`CatalogEntryDTO`), `apps/api/app/services/settings_catalog_api.py:212-250` (API entries default both fields)
- Test: `tests/unit/core/test_settings_catalog.py` (extended), `tests/unit/api/test_settings_catalog_api_types.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/settings_annotations.py
  class Annotation(TypedDict):
      title: str
      description: str
      applies: NotRequired[Literal["next_job", "live", "restart"]]
      probe: NotRequired[str]
      group: NotRequired[str]
      applies_when: NotRequired[dict[str, list[str]]]   # key -> values that reveal this entry
      order: NotRequired[int]                           # within the group; default 0

  def mcp_server_annotations(prefix: str, label: str, *, probe: str | None = None,
                             applies_when: dict[str, list[str]] | None = None,
                             order: int = 0) -> dict[str, Annotation]
  ```
  ```python
  # src/maljan/core/settings_catalog.py
  @dataclass(frozen=True)
  class CatalogEntry:
      ...                                     # existing fields unchanged, in order
      applies_when: dict[str, list[str]] | None
      order: int
  ```
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/core/test_settings_catalog.py`:

```python
def test_provider_selectors_lead_their_groups_and_have_the_registry_choices():
    by_path = {e.path: e for e in cat.core_catalog()}
    static = by_path["static.provider"]
    sandbox = by_path["sandbox.provider"]
    assert static.type == "enum" and static.order == -1
    assert static.choices == ["ghidra", "r2", "capa_yara", "generic_mcp", "none"]
    assert sandbox.type == "enum" and sandbox.order == -1
    assert sandbox.choices == ["mock", "cape2", "upload", "triage"]
    assert static.applies_when is None and sandbox.applies_when is None


def test_provider_specific_leaves_declare_when_they_apply():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["static.ghidra.url"].applies_when == {"core.static.provider": ["ghidra"]}
    assert by_path["static.r2.binary_path"].applies_when == {"core.static.provider": ["r2"]}
    assert by_path["static.capa.rules_dir"].applies_when == {"core.static.provider": ["capa_yara"]}
    assert by_path["static.yara.rules_dir"].applies_when == {"core.static.provider": ["capa_yara"]}
    assert by_path["static.generic.command"].applies_when == {
        "core.static.provider": ["generic_mcp"]
    }
    assert by_path["sandbox.cape2.base_url"].applies_when == {"core.sandbox.provider": ["cape2"]}
    assert by_path["sandbox.triage.api_token"].applies_when == {"core.sandbox.provider": ["triage"]}
    assert by_path["sandbox.upload.max_report_bytes"].applies_when == {
        "core.sandbox.provider": ["upload"]
    }


def test_every_applies_when_names_a_real_key_and_real_choices():
    entries = cat.core_catalog()
    by_key = {e.key: e for e in entries}
    for e in entries:
        for key, values in (e.applies_when or {}).items():
            assert key in by_key, f"{e.key} depends on unknown {key}"
            assert by_key[key].choices is not None, f"{key} is not an enum"
            unknown = set(values) - set(by_key[key].choices or [])
            assert not unknown, f"{e.key}: {key} has no choices {sorted(unknown)}"


def test_static_group_exists_and_sandbox_group_is_renamed():
    titles = dict(GROUP_ORDER)
    assert titles["static"] == "Static analysis provider"
    assert titles["sandbox"] == "Sandbox provider"
    groups = [g for g, _ in GROUP_ORDER]
    assert groups.index("static") < groups.index("sandbox")


def test_entries_sort_by_order_then_path_within_a_group():
    static = [e for e in cat.core_catalog() if e.group == "static"]
    assert static[0].path == "static.provider"
    assert static == sorted(static, key=lambda e: (e.order, e.path))
```

Append to `tests/unit/api/test_settings_catalog_api_types.py`:

```python
def test_api_entries_carry_the_two_new_fields_with_neutral_defaults():
    from app.services.settings_catalog_api import api_catalog

    for e in api_catalog():
        assert e.applies_when is None
        assert e.order == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/api/test_settings_catalog_api_types.py -q`
Expected: FAIL — `unannotated settings: ['sandbox.cape2.api_token', 'sandbox.cape2.base_url', …, 'static.yara.timeout_seconds']` and `AttributeError: 'CatalogEntry' object has no attribute 'order'`.

- [ ] **Step 3: Extend `CatalogEntry`**

In `settings_catalog.py`, add the two fields at the **end** of the dataclass (so positional construction elsewhere is unaffected) and fill them in `core_catalog`:

```python
@dataclass(frozen=True)
class CatalogEntry:
    # ...every existing field unchanged, in its existing order, ending with:
    probe: str | None
    # Conditional visibility: {settings key: values of that key which reveal this
    # entry}. The UI filters on the staged-or-current value; the API never
    # hides anything, because a hidden setting is still an effective setting.
    applies_when: dict[str, list[str]] | None = None
    # Rank within the group; lower first, ties broken by path. Provider
    # selectors use -1 so the switch sits above the fields it governs.
    order: int = 0
```

In `core_catalog`, pass `applies_when=ann.get("applies_when")`, `order=ann.get("order", 0)` and change the sort to:

```python
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    entries.sort(key=lambda e: (order[e.group], e.order, e.path))
```

`apps/api/app/schemas/settings.py::CatalogEntryDTO` gains `applies_when: dict[str, list[str]] | None = None` and `order: int = 0`; `settings_catalog_api.py` passes `applies_when=None, order=0` in both the `API_EDITABLE` and `API_READONLY` loops.

- [ ] **Step 4: Add the annotations**

In `settings_annotations.py`: extend the `Annotation` TypedDict with the two `NotRequired` keys, add `("static", "Static analysis provider")` to `GROUP_ORDER` immediately before the sandbox entry, rename the sandbox entry to `("sandbox", "Sandbox provider")`, and add `("static", "static")` to `_PREFIX_GROUPS` above the `mcp` row.

Add the generator for the six `MCPServerConfig`-shaped blocks (`static.ghidra`, `static.r2`, `static.generic`, `sandbox.cape2.mcp`) so nine near-identical leaves are described once:

```python
def mcp_server_annotations(
    prefix: str,
    label: str,
    *,
    probe: str | None = None,
    applies_when: dict[str, list[str]] | None = None,
    order: int = 0,
) -> dict[str, Annotation]:
    """The nine leaves of an ``MCPServerConfig`` block, described for ``label``.

    Every MCP server in the settings has the same nine knobs; writing them out
    six times invites drift between blocks that must behave identically. The
    per-field wording is fixed, the server's name is the only variable.
    """
    common: Annotation = {"title": "", "description": ""}
    del common  # documented shape; each entry below is built explicitly

    def ann(title: str, description: str, *, with_probe: bool = False) -> Annotation:
        a: Annotation = {"title": title, "description": description, "order": order}
        if applies_when is not None:
            a["applies_when"] = applies_when
        if with_probe and probe:
            a["probe"] = probe
        return a

    return {
        f"{prefix}.enabled": ann(
            f"{label} enabled",
            f"Turns on the {label} integration. When off the analyst runs on the "
            "evidence it already has and exposes no tools from this server.",
            with_probe=True,
        ),
        f"{prefix}.transport": ann(
            f"{label} transport",
            "How the server is reached: stdio launches a local subprocess "
            "(command/args/env); http, streamable-http and sse connect to a "
            "running server (url/auth_token).",
        ),
        f"{prefix}.command": ann(
            f"{label} command",
            "Executable launched for the stdio transport, e.g. python or r2mcp.",
        ),
        f"{prefix}.args": ann(
            f"{label} args",
            "Command-line arguments for the stdio subprocess. Relative paths are "
            "resolved against the project root.",
        ),
        f"{prefix}.env": ann(
            f"{label} environment",
            "Extra environment variables for the stdio subprocess. The child gets "
            "these plus a fixed base set, and no credentials of its own.",
        ),
        f"{prefix}.url": ann(
            f"{label} URL",
            "Address of the server for the http transports, e.g. "
            "http://localhost:8089.",
            with_probe=True,
        ),
        f"{prefix}.auth_token": ann(
            f"{label} auth token",
            "Bearer token sent to the server over the http transports. Leave "
            "empty when the server does not enforce one.",
            with_probe=True,
        ),
        f"{prefix}.tool_selection": ann(
            f"{label} tool selection",
            "How many of the server's tools the analyst sees per run: curated is "
            "a fixed allow-list (fastest, narrowest); dynamic shows a core triage "
            "set plus the tools relevant to the sample's inferred capabilities; "
            "all exposes every tool, which is measurably slower and noisier.",
        ),
        f"{prefix}.use_all_tools": ann(
            f"{label} force all tools",
            "Back-compat flag: when true, forces tool selection to all regardless "
            "of its own value.",
        ),
    }


_STATIC_GHIDRA = {"core.static.provider": ["ghidra"]}
_STATIC_R2 = {"core.static.provider": ["r2"]}
_STATIC_CAPA_YARA = {"core.static.provider": ["capa_yara"]}
_STATIC_GENERIC = {"core.static.provider": ["generic_mcp"]}
_SANDBOX_CAPE2 = {"core.sandbox.provider": ["cape2"]}
_SANDBOX_TRIAGE = {"core.sandbox.provider": ["triage"]}
_SANDBOX_UPLOAD = {"core.sandbox.provider": ["upload"]}
```

Then, after the literal `ANNOTATIONS` dict, add the provider leaves:

```python
ANNOTATIONS.update(
    {
        "static.provider": {
            "title": "Static analysis provider",
            "description": (
                "Which tool produces the static evidence. ghidra runs the Ghidra MCP "
                "server (today's default and the profile the evaluation was measured "
                "on); r2 runs radare2 over its MCP server; capa_yara runs capa and "
                "YARA with no tool server and hands the analyst evidence rather than "
                "tools; generic_mcp attaches any MCP server you configure; none "
                "leaves the static analyst with no tools at all."
            ),
            "group": "static",
            "order": -1,
        },
        "sandbox.provider": {
            "title": "Sandbox provider",
            "description": (
                "Which sandbox produces the dynamic evidence. mock loads fixture "
                "reports from the samples directory with no network access; cape2 "
                "submits to a live CAPEv2 instance; upload runs no detonation and "
                "uses the report attached to the job; triage submits to the Hatching "
                "Triage cloud sandbox."
            ),
            "order": -1,
        },
        "static.r2.binary_path": {
            "title": "radare2 MCP binary",
            "description": (
                "Executable that serves the radare2 MCP tools, looked up on PATH "
                "when it is a bare name. The provider's connection test reports "
                "clearly when it is missing."
            ),
            "applies_when": _STATIC_R2,
            "probe": "r2",
        },
        "static.r2.mirror_dir": {
            "title": "radare2 sample directory",
            "description": (
                "Host directory the sample is copied into so radare2 can open it by "
                "path. Defaults to the same private .work directory the Ghidra "
                "mirror uses."
            ),
            "applies_when": _STATIC_R2,
        },
        "static.capa.rules_dir": {
            "title": "capa rules directory",
            "description": (
                "Directory of flare-capa rules. Missing or empty lowers the "
                "provider to no evidence with a warning rather than failing a run."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa",
        },
        "static.capa.signatures_dir": {
            "title": "capa signatures directory",
            "description": (
                "Directory of capa's library-identification signatures, used to keep "
                "statically linked library code out of the results."
            ),
            "applies_when": _STATIC_CAPA_YARA,
            "probe": "capa",
        },
        "static.capa.timeout_seconds": {
            "title": "capa timeout (s)",
            "description": (
                "Wall-clock budget for one capa run. A sample that exceeds it "
                "contributes no capa evidence and the run continues."
            ),
            "applies_when": _STATIC_CAPA_YARA,
        },
        "static.capa.backend": {
            "title": "capa backend",
            "description": (
                "Analysis engine capa uses: auto picks per file type, vivisect is "
                "the portable default, pefile is header-only and fast, binja needs a "
                "local Binary Ninja installation."
            ),
            "applies_when": _STATIC_CAPA_YARA,
        },
        "static.yara.rules_dir": {
            "title": "YARA rules directory (static provider)",
            "description": (
                "Your own YARA rules, scanned by the capa_yara static provider. The "
                "deterministic YARA detection layer keeps its own vendored corpus "
                "and is unaffected by this."
            ),
            "applies_when": _STATIC_CAPA_YARA,
        },
        "static.yara.timeout_seconds": {
            "title": "YARA timeout (s)",
            "description": "Wall-clock budget for one YARA scan of the sample.",
            "applies_when": _STATIC_CAPA_YARA,
        },
        "sandbox.cape2.base_url": {
            "title": "CAPEv2 base URL",
            "description": (
                "Base URL of the CAPEv2 REST API. CAPEv2 is not part of this "
                "repository — it runs on its own Linux host with KVM and registered "
                "guest images; point this at that host's apiv2 address."
            ),
            "applies_when": _SANDBOX_CAPE2,
            "probe": "cape2",
        },
        "sandbox.cape2.api_token": {
            "title": "CAPEv2 API token",
            "description": (
                "Bearer token for the CAPEv2 REST API. Can be left empty for an "
                "unauthenticated local instance."
            ),
            "applies_when": _SANDBOX_CAPE2,
            "probe": "cape2",
        },
        "sandbox.cape2.timeout_seconds": {
            "title": "CAPEv2 timeout (s)",
            "description": (
                "Maximum seconds to wait for a CAPEv2 detonation and report before "
                "giving up. Real detonation takes minutes, so the default is set "
                "well above the poll interval."
            ),
            "applies_when": _SANDBOX_CAPE2,
        },
        "sandbox.cape2.poll_interval_seconds": {
            "title": "CAPEv2 poll interval (s)",
            "description": "Seconds between polls of the CAPEv2 API while a task runs.",
            "applies_when": _SANDBOX_CAPE2,
        },
        "sandbox.triage.base_url": {
            "title": "Triage API base URL",
            "description": (
                "Hatching Triage cloud API root. Use https://private.tria.ge/api/v0 "
                "for a private instance."
            ),
            "applies_when": _SANDBOX_TRIAGE,
            "probe": "triage",
        },
        "sandbox.triage.api_token": {
            "title": "Triage API token",
            "description": (
                "Bearer token from your Triage account. Samples leave this host when "
                "this provider is selected."
            ),
            "applies_when": _SANDBOX_TRIAGE,
            "probe": "triage",
        },
        "sandbox.triage.profile": {
            "title": "Triage VM profile",
            "description": (
                "Name of the Triage analysis profile to request. Empty means the "
                "account's default profile."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.timeout_seconds": {
            "title": "Triage timeout (s)",
            "description": (
                "Maximum seconds to wait for a Triage analysis to reach the reported "
                "state, queueing behind other tenants included."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.poll_interval_seconds": {
            "title": "Triage poll interval (s)",
            "description": (
                "Initial seconds between status polls. The provider backs off by "
                "1.5x up to a minute and honours a Retry-After header."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.triage.fetch_pcap": {
            "title": "Fetch the Triage capture",
            "description": (
                "Download each task's PCAP so the network analyst can inspect the "
                "packets rather than only the structured indicators."
            ),
            "applies_when": _SANDBOX_TRIAGE,
        },
        "sandbox.upload.max_report_bytes": {
            "title": "Uploaded report size limit (bytes)",
            "description": (
                "Reports larger than this are rejected while streaming, before "
                "anything is stored. A gzipped upload is checked again after "
                "inflation."
            ),
            "applies_when": _SANDBOX_UPLOAD,
        },
        "sandbox.upload.allowed_formats": {
            "title": "Accepted report formats",
            "description": (
                "Formats the sniffer may accept for an uploaded report: cape2, "
                "cuckoo, triage. A file that sniffs as anything else is refused."
            ),
            "applies_when": _SANDBOX_UPLOAD,
        },
    }
)

ANNOTATIONS.update(
    mcp_server_annotations(
        "static.ghidra", "Ghidra MCP", probe="ghidra", applies_when=_STATIC_GHIDRA
    )
)
ANNOTATIONS.update(
    mcp_server_annotations("static.r2", "radare2 MCP", probe="r2", applies_when=_STATIC_R2)
)
ANNOTATIONS.update(
    mcp_server_annotations("static.generic", "Custom MCP", applies_when=_STATIC_GENERIC)
)
ANNOTATIONS.update(
    mcp_server_annotations("sandbox.cape2.mcp", "CAPE MCP", applies_when=_SANDBOX_CAPE2)
)
```

The existing `mcp.ghidra.*` and `mcp.cape.*` annotations stay until Task 23 removes the mirror; their titles gain the prefix "Deprecated: " and their descriptions a first sentence naming the replacement key, so an operator reading the UI is told where the setting went. The five flat `sandbox.*` annotations (`sandbox.backend`, `sandbox.cape2_*`) are **deleted** here, because those leaves no longer exist and `test_every_leaf_is_annotated_and_no_annotation_is_orphaned` fails on an orphan.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/api/test_settings_catalog_api_types.py tests/unit/core/test_settings_aliases.py -q`
Expected: PASS.

- [ ] **Step 6: Lint and type-check**

Run: `uv run ruff check src/maljan/core/settings_annotations.py src/maljan/core/settings_catalog.py apps/api/app/schemas/settings.py apps/api/app/services/settings_catalog_api.py && uv run ruff format --check src/maljan/core/settings_annotations.py src/maljan/core/settings_catalog.py apps/api/app/schemas/settings.py apps/api/app/services/settings_catalog_api.py && uv run mypy src/ apps/api/`

- [ ] **Step 7: Commit**

```bash
git add src/maljan/core/settings_annotations.py src/maljan/core/settings_catalog.py apps/api/app/schemas/settings.py apps/api/app/services/settings_catalog_api.py tests/unit/core/test_settings_catalog.py tests/unit/api/test_settings_catalog_api_types.py
git commit -m "feat(settings): annotate the provider settings and give the catalog conditional visibility"
```

---

### Task 4: Stored-override migration and the probe rename

**Files:**
- Create: `apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py`
- Modify: `apps/api/app/services/settings_probes.py` (`_INPUTS`, `PROBES`, `probe_cape` renamed to `probe_cape2` with a `cape` alias), `apps/api/app/api/v1/settings.py:113-146` (no code change; verify the export derives the new names)
- Test: `tests/unit/api/test_settings_probes.py` (extended), `tests/unit/api/test_settings_key_migration.py` (new)

**Interfaces:**
- Produces:
  ```python
  # apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py
  revision = "20260903000000"
  down_revision = "20260902000000"
  KEY_RENAMES: dict[str, str]      # old runtime_settings.key -> new key
  ```
  ```python
  # apps/api/app/services/settings_probes.py
  async def probe_cape2(v: dict[str, Any]) -> ProbeResult
  PROBES["cape2"] = probe_cape2
  PROBES["cape"] = probe_cape2      # one release of alias, named in the annotation
  ```
- Consumes: `maljan.core.config.SETTINGS_ALIASES` (the migration derives its table from it, so the two cannot drift).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_settings_key_migration.py
"""Stored UI overrides survive the provider rename.

The alembic revision renames ``runtime_settings.key`` in place. It is derived
from the same alias table the config uses, is idempotent (running it twice is a
no-op), and never overwrites a row that already carries the new key.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

_REV = _API / "alembic" / "versions" / "20260903000000_rename_provider_setting_keys.py"


def _load():
    spec = importlib.util.spec_from_file_location("rename_provider_setting_keys", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_rename_table_covers_every_moved_key():
    from maljan.core.config import SETTINGS_ALIASES

    mod = _load()
    for old, new in SETTINGS_ALIASES:
        if old in ("mcp.ghidra", "mcp.cape"):
            # Sub-tree aliases: the stored keys are leaves under them.
            assert any(k.startswith(f"core.{old}.") for k in mod.KEY_RENAMES), old
        else:
            assert mod.KEY_RENAMES[f"core.{old}"] == f"core.{new}"


def test_every_renamed_key_is_a_real_catalog_key():
    from app.services.settings_catalog_api import catalog_index

    mod = _load()
    index = catalog_index()
    for old, new in mod.KEY_RENAMES.items():
        assert new in index, f"{old} renames to unknown {new}"


def test_renames_are_one_to_one():
    mod = _load()
    assert len(set(mod.KEY_RENAMES.values())) == len(mod.KEY_RENAMES)
```

Append to `tests/unit/api/test_settings_probes.py`:

```python
def test_the_cape_probe_is_registered_under_both_names():
    assert probes.PROBES["cape2"] is probes.probe_cape2
    assert probes.PROBES["cape"] is probes.probe_cape2


def test_probe_inputs_name_only_existing_settings_keys():
    from app.services.settings_catalog_api import catalog_index

    index = catalog_index()
    for name, inputs in probes._INPUTS.items():
        for key in inputs:
            assert key in index, f"probe {name!r} reads unknown setting {key}"


@pytest.mark.asyncio
async def test_ghidra_probe_reads_the_static_block(monkeypatch):
    seen: dict[str, object] = {}

    async def fake(v):
        seen.update(v)
        return probes.ProbeResult(True, 1, "HTTP 200")

    monkeypatch.setitem(probes.PROBES, "ghidra", fake)
    await probes.run_probe(
        "ghidra", {"core.static.ghidra.url": "http://ghidra.example:8089"}, {}
    )
    assert seen["url"] == "http://ghidra.example:8089"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/api/test_settings_key_migration.py tests/unit/api/test_settings_probes.py -q`
Expected: FAIL — the revision file does not exist; `probes.PROBES` has no `"cape2"`.

- [ ] **Step 3: Write the migration**

```python
# apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py
"""Rename the stored UI overrides the provider layer moved.

``runtime_settings`` is keyed by the dotted setting path, so the provider
rename (``core.mcp.ghidra.*`` -> ``core.static.ghidra.*``,
``core.sandbox.cape2_*`` -> ``core.sandbox.cape2.*``, …) would otherwise strand
every override an operator had set: the key would no longer match a catalog
entry and the value would be ignored in silence. The table is derived from
``maljan.core.config.SETTINGS_ALIASES`` so config and migration cannot drift.

Idempotent by construction: a row already carrying the new key is left alone
and the stale old row is deleted, so re-running the revision changes nothing.

Revision ID: 20260903000000
Revises: 20260902000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from maljan.core.config import SETTINGS_ALIASES

revision = "20260903000000"
down_revision = "20260902000000"
branch_labels = None
depends_on = None

# The nine leaves an MCPServerConfig block stores.
_MCP_LEAVES = (
    "enabled",
    "transport",
    "command",
    "args",
    "env",
    "url",
    "auth_token",
    "tool_selection",
    "use_all_tools",
)


def _build_renames() -> dict[str, str]:
    out: dict[str, str] = {}
    for old, new in SETTINGS_ALIASES:
        if old in ("mcp.ghidra", "mcp.cape"):
            for leaf in _MCP_LEAVES:
                out[f"core.{old}.{leaf}"] = f"core.{new}.{leaf}"
        else:
            out[f"core.{old}"] = f"core.{new}"
    return out


KEY_RENAMES: dict[str, str] = _build_renames()


def _move(mapping: dict[str, str]) -> None:
    conn = op.get_bind()
    for old, new in mapping.items():
        conn.execute(
            sa.text(
                "UPDATE runtime_settings SET key = :new "
                "WHERE key = :old "
                "AND NOT EXISTS (SELECT 1 FROM runtime_settings r2 WHERE r2.key = :new)"
            ),
            {"old": old, "new": new},
        )
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :old"), {"old": old})


def upgrade() -> None:
    _move(KEY_RENAMES)


def downgrade() -> None:
    _move({new: old for old, new in KEY_RENAMES.items()})
```

- [ ] **Step 4: Rename the probe and re-point its inputs**

In `settings_probes.py`: rename `probe_cape` to `probe_cape2` (body unchanged — it still calls `/apiv2/tasks/view/1/`), register it under both `"cape2"` and `"cape"` in `PROBES` with the comment "``cape`` is kept for one release: a stored annotation may still name it", and update `_INPUTS`:

```python
    "ghidra": {
        "core.static.ghidra.url": "url",
        "core.static.ghidra.auth_token": "auth_token",
    },
    "cape2": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
    "cape": {
        "core.sandbox.cape2.base_url": "base_url",
        "core.sandbox.cape2.api_token": "api_token",
    },
```
The `probe` values in `settings_annotations.py` for the CAPE leaves become `"cape2"` (Task 3 already wrote them that way); the deprecated `mcp.ghidra.*` mirror keeps `"ghidra"`.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/api/test_settings_key_migration.py tests/unit/api/test_settings_probes.py tests/unit/core/test_settings_catalog.py -q`
Expected: PASS.

Verify the export emits the new names without a code change:

```bash
uv run python -c "
from app.services.settings_catalog_api import catalog_index
e = catalog_index()['core.sandbox.cape2.base_url']
print(e.path.upper().replace('.', '__'))"
```
(run from `apps/api`) Expected: `SANDBOX__CAPE2__BASE_URL`.

- [ ] **Step 6: Lint and type-check**

Run: `uv run ruff check apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py apps/api/app/services/settings_probes.py tests/unit/api/test_settings_key_migration.py tests/unit/api/test_settings_probes.py && uv run ruff format --check apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py apps/api/app/services/settings_probes.py tests/unit/api/test_settings_key_migration.py tests/unit/api/test_settings_probes.py && uv run mypy src/ apps/api/`

- [ ] **Step 7: Commit**

```bash
git add apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py apps/api/app/services/settings_probes.py src/maljan/core/settings_annotations.py tests/unit/api/test_settings_key_migration.py tests/unit/api/test_settings_probes.py
git commit -m "feat(api): migrate stored setting keys to the provider paths and rename the CAPE probe"
```

---

### Task 5: The provider contracts, the registry and the errors

**Files:**
- Create: `src/maljan/providers/__init__.py`, `src/maljan/providers/base.py`, `src/maljan/providers/registry.py`, `src/maljan/providers/errors.py`, `src/maljan/providers/static/__init__.py`, `src/maljan/providers/sandbox/__init__.py`
- Test: `tests/providers/test_registry.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/base.py
  @dataclass(frozen=True)
  class StaticCapabilities:
      provides_tools: bool = False
      provides_evidence: bool = False
      provides_function_hashes: bool = False
      needs_sample_mirror: bool = False
      supports_tool_curation: bool = False
      degrade_on_failure: bool = False

  @dataclass(frozen=True)
  class SandboxCapabilities:
      can_submit: bool = False
      can_poll: bool = False
      can_fetch_report: bool = True
      can_fetch_pcap: bool = False
      accepts_uploaded_report: bool = False
      provides_tools: bool = False
      report_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "generic"
      degrade_on_failure: bool = True

  @dataclass(frozen=True)
  class MirrorSpec:
      work_subdir: str
      container_prefix: str

  @dataclass(frozen=True)
  class StaticJobContext:
      host_sample_path: str | None = None
      mirror_sample_path: str | None = None      # today's state["static_sample_path"]
      sha256: str = ""
      file_type: str = "unknown"
      platform: str = "unknown"
      capability_categories: frozenset[str] = frozenset()
      output_guardrail: Callable[[str], str] | None = None
      max_output_chars: int = 8000
      truncation_ledger: Any | None = None

  @dataclass(frozen=True)
  class StaticEvidenceBundle:
      api_capabilities: dict[str, int] = field(default_factory=dict)
      technique_hits: list[dict[str, Any]] = field(default_factory=list)
      strings: list[dict[str, Any]] = field(default_factory=list)
      technical_evidence: dict[str, str] = field(default_factory=dict)

  @dataclass(frozen=True)
  class ProviderProbe:
      ok: bool
      detail: str
      latency_ms: int = 0

  class StaticProvider(ABC):        # id, capabilities, from_settings, probe, open, get_tools,
                                    # select_tools, prompt_fragment, collect_evidence,
                                    # function_hashes, mirror_spec, close
  class SandboxProvider(ABC):       # id, capabilities, from_settings, probe, open, submit,
                                    # wait_for_completion, fetch, fetch_pcap, attach_report,
                                    # dynamic_tools, dynamic_prompt_fragment, close
  ```
  ```python
  # src/maljan/providers/registry.py
  def register_static_provider(name: str) -> Callable[[type], type]
  def register_sandbox_provider(name: str) -> Callable[[type], type]
  def discover_providers() -> None
  def static_provider_ids() -> list[str]
  def sandbox_provider_ids() -> list[str]
  def get_static_provider(cfg: Settings) -> StaticProvider
  def get_sandbox_provider(cfg: Settings) -> SandboxProvider
  ```
  ```python
  # src/maljan/providers/errors.py
  class ProviderError(MaljanError)
  class ProviderNotAvailableError(ProviderError, ImportError)
  class ProviderConfigurationError(ProviderError)
  ```
- Consumes: `maljan.core.config.Settings`, `maljan.core.exceptions.MaljanError`, `maljan.loaders.sandbox_client.SubmissionResult`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/test_registry.py
"""The registry ids are the settings vocabulary.

The one invariant worth a test of its own: a provider id exists in exactly two
places — the registry and the settings ``Literal`` — and they must be the same
set, or the UI offers a choice nothing can build.
"""

from __future__ import annotations

from typing import get_args

import pytest

from maljan.core.config import Settings, StaticConfig
from maljan.providers import registry


def test_static_ids_equal_the_settings_choices():
    field = StaticConfig.model_fields["provider"]
    assert sorted(registry.static_provider_ids()) == sorted(get_args(field.annotation))


def test_sandbox_ids_equal_the_settings_choices():
    from maljan.core.config import SandboxConfig

    field = SandboxConfig.model_fields["provider"]
    assert sorted(registry.sandbox_provider_ids()) == sorted(get_args(field.annotation))


def test_default_settings_build_the_ghidra_and_mock_providers():
    cfg = Settings(_env_file=None)
    static = registry.get_static_provider(cfg)
    sandbox = registry.get_sandbox_provider(cfg)
    assert static.id == "ghidra"
    assert sandbox.id == "mock"


def test_an_unknown_id_names_the_available_ones():
    from maljan.providers.errors import ProviderConfigurationError

    cfg = Settings(_env_file=None)
    object.__setattr__(cfg.static, "provider", "nope")
    with pytest.raises(ProviderConfigurationError) as exc:
        registry.get_static_provider(cfg)
    assert "ghidra" in str(exc.value)


def test_capability_defaults_are_conservative():
    from maljan.providers.base import SandboxCapabilities, StaticCapabilities

    s = StaticCapabilities()
    assert not any(
        (s.provides_tools, s.provides_evidence, s.provides_function_hashes,
         s.needs_sample_mirror, s.supports_tool_curation, s.degrade_on_failure)
    )
    b = SandboxCapabilities()
    assert b.can_fetch_report is True and b.degrade_on_failure is True
    assert b.report_format == "generic"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/providers/test_registry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.providers'`.

- [ ] **Step 3: Write `errors.py`**

```python
# src/maljan/providers/errors.py
"""Failures a provider can raise, in the project's existing exception tree."""

from __future__ import annotations

from maljan.core.exceptions import MaljanError


class ProviderError(MaljanError):
    """A provider could not do what it was asked."""


class ProviderNotAvailableError(ProviderError, ImportError):
    """A provider's dependency or tool server is not installed.

    Multi-inherits from ImportError for the same reason
    ``SandboxNotAvailableError`` does: callers that catch ImportError around an
    optional integration keep working.
    """


class ProviderConfigurationError(ProviderError):
    """The settings name a provider that does not exist, or configure it wrongly."""
```

- [ ] **Step 4: Write `base.py`**

The dataclasses exactly as in the Interfaces block above, plus the two abstract classes. Every method has a working default so an adapter only overrides what it does:

```python
class StaticProvider(ABC):
    """One static-analysis tool, as the pipeline sees it.

    Lifecycle: ``from_settings`` (cheap, no I/O) -> ``probe`` (optional, the
    UI's connection test) -> ``open(job)`` (attach, once per sample) -> work ->
    ``close()``. Everything the pipeline branches on is a capability flag, so
    the pipeline never names a provider.
    """

    id: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> StaticProvider: ...

    @property
    @abstractmethod
    def capabilities(self) -> StaticCapabilities: ...

    async def probe(self) -> ProviderProbe:
        return ProviderProbe(ok=True, detail="no connection test for this provider")

    def open(self, job: StaticJobContext) -> None:
        """Attach to the tool for one sample. Idempotent."""
        return None

    def get_tools(self) -> list[BaseTool]:
        return []

    def select_tools(
        self, tools: list[BaseTool], categories: set[str] | None = None
    ) -> list[BaseTool]:
        return list(tools)

    def prompt_fragment(self) -> str:
        """The tool-facing body of the static system prompt for this provider."""
        return ""

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        return None

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        return []

    def mirror_spec(self) -> MirrorSpec | None:
        return None

    def close(self) -> None:
        return None
```

`SandboxProvider` mirrors it: `submit(sample_path) -> str`, `wait_for_completion(task_id, timeout_seconds, poll_interval_seconds) -> str`, `fetch(task_id) -> SandboxRun`, `fetch_pcap(task_id, dest_dir) -> str | None` (default `None`), `attach_report(blob: bytes, *, filename: str) -> SandboxRun` (default raises `ProviderError("this sandbox does not accept uploaded reports")`), `dynamic_tools() -> list[BaseTool]` (default `[]`), `dynamic_prompt_fragment() -> str` (default `""`), `close()`. `SandboxRun` lives in `schemas/sandbox_report.py` (Task 6) and is imported under `TYPE_CHECKING` here to keep the import graph acyclic; the runtime annotation is a string.

- [ ] **Step 5: Write `registry.py`**

A copy of `llm/registry.py`'s shape, with the thread-safety of `agents/registry.py`:

```python
"""Provider registry with auto-discovery via decorator.

Same pattern as ``maljan.llm.registry``: a module-level dict, a decorator, and
one discovery import. The id functions are the project's single provider
vocabulary — the settings ``Literal`` choices, the API enum, the job override
and (in sub-project C) the profile references all read them, and a test refuses
any drift between them.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from maljan.core.config import Settings
    from maljan.providers.base import SandboxProvider, StaticProvider

_STATIC_REGISTRY: dict[str, type] = {}
_SANDBOX_REGISTRY: dict[str, type] = {}
_LOCK = threading.RLock()
_DISCOVERY_DONE = False


def register_static_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _STATIC_REGISTRY:
                logger.debug("Static provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _STATIC_REGISTRY[name] = cls
        return cls

    return decorator


def register_sandbox_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _SANDBOX_REGISTRY:
                logger.debug("Sandbox provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _SANDBOX_REGISTRY[name] = cls
        return cls

    return decorator


def discover_providers() -> None:
    """Import the built-in adapters once to trigger their decorators."""
    global _DISCOVERY_DONE
    if _DISCOVERY_DONE:
        return
    with _LOCK:
        if _DISCOVERY_DONE:
            return
        import maljan.providers.sandbox.cape2  # noqa: F401
        import maljan.providers.sandbox.mock  # noqa: F401
        import maljan.providers.sandbox.triage  # noqa: F401
        import maljan.providers.sandbox.upload  # noqa: F401
        import maljan.providers.static.capa_yara  # noqa: F401
        import maljan.providers.static.generic_mcp  # noqa: F401
        import maljan.providers.static.ghidra  # noqa: F401
        import maljan.providers.static.null  # noqa: F401
        import maljan.providers.static.r2  # noqa: F401

        _DISCOVERY_DONE = True


def static_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_STATIC_REGISTRY)


def sandbox_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_SANDBOX_REGISTRY)


def _build(registry: dict[str, type], name: str, cfg: Any, kind: str) -> Any:
    cls = registry.get(name)
    if cls is None:
        available = ", ".join(sorted(registry)) or "(none)"
        raise ProviderConfigurationError(
            f"Unknown {kind} provider: {name!r}. Available: {available}"
        )
    return cls.from_settings(cfg)


def get_static_provider(cfg: Settings) -> StaticProvider:
    discover_providers()
    return _build(_STATIC_REGISTRY, str(cfg.static.provider), cfg, "static")  # type: ignore[no-any-return]


def get_sandbox_provider(cfg: Settings) -> SandboxProvider:
    discover_providers()
    return _build(_SANDBOX_REGISTRY, str(cfg.sandbox.provider), cfg, "sandbox")  # type: ignore[no-any-return]
```

`providers/__init__.py` re-exports the contracts and the six registry functions so callers write `from maljan.providers import get_static_provider`. Because `discover_providers()` imports all nine adapters, **this task is not green until Task 19**: create the nine adapter modules now as one-line stubs raising `NotImplementedError` in `from_settings`, each already carrying its `@register_*_provider(...)` decorator and its `capabilities` property, and fill them in their own tasks. The stubs are what makes the id-parity test meaningful from here on.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/providers/test_registry.py -q`
Expected: PASS (the ghidra and mock stubs' `from_settings` return an instance; only the unimplemented adapters raise).

- [ ] **Step 7: Lint and type-check**

Run: `uv run ruff check src/maljan/providers tests/providers/test_registry.py && uv run ruff format --check src/maljan/providers tests/providers/test_registry.py && uv run mypy src/ apps/api/`

- [ ] **Step 8: Commit**

```bash
git add src/maljan/providers tests/providers/test_registry.py
git commit -m "feat(providers): contracts, capability flags and the provider registry"
```

---

### Task 6: `SandboxReport`, `to_cape_shaped_dict` and `sniff_format`

**Files:**
- Create: `src/maljan/schemas/sandbox_report.py`, `src/maljan/providers/cape_view.py`, `src/maljan/providers/sandbox/formats.py`
- Test: `tests/providers/test_sandbox_report.py`, `tests/providers/test_cape_normalization_golden.py`, `tests/providers/test_sniff_format.py`

**The keys today's consumers read.** `to_cape_shaped_dict` must reproduce every one of these on the non-short-circuit path, and test (c) below iterates exactly this list:

| CAPE path | Shape read | Read by |
| :-- | :-- | :-- |
| `target.sha256`, `target.md5`, `target.name` | str | `cape2_client.fetch_report`, `container.load_sandbox_data_for_agent("static")` |
| `target.file.type` | str (MIME) | `app.py:126` (`_infer_sample_platform`) |
| `behavior.processes[]` | `{pid, ppid, process_name|name, command_line|cmd, calls[]}` | `dynamic_extractor._build_process_tree` / `_injection_edges`, `sigma_layer._sandbox_events`, `lolbin_layer._iter_command_lines`, `persistence_extractor` |
| `behavior.calls[]` | `{api, arguments: [{name, value}]}` | `dynamic_extractor._extract_registry_mods` / `_extract_file_operations` / `_extract_notable_apis`, `sigma_layer._sandbox_events` |
| `behavior.apistats` | `{pid: {api: count}}` | `dynamic_extractor._extract_notable_apis`, `dynamic_parser` |
| `behavior.generic[]` | `{category, description}` | `dynamic_parser` |
| `behavior.summary.{files,write_files,modified_files,wrote_files}` | `list[str]` | `persistence_extractor` (Linux path rules) |
| `behavior.notable_apis[]` / `dynamic.notable_apis[]` | `{api, category, process, arguments}` | `persistence_extractor` (LD_PRELOAD) |
| `file_writes[]`, `files_written[]` (top level) | `list[str]` | `persistence_extractor` |
| `signatures[]` | `{name, description, severity|score, marks[], ttp_tags|attck_id}` | `dynamic_extractor._extract_signatures`, `persistence_extractor._scan_signatures`, `attribution`, `dynamic_parser` |
| `network.dns[]` | `{request|hostname|name, answers:[{data|ip}], pid}` | `network_extractor._extract_domains`, `network_parser`, `dynamic_parser` |
| `network.http[]` | `{host|hostname, uri|path, method, status, port, encrypted, ssl, user_agent|ua}` | `network_extractor._extract_urls` / `_extract_user_agents`, `network_parser`, `dynamic_parser` |
| `network.tcp[]`, `network.udp[]` | `{dst|dst_ip|ip|address, dport|dst_port|port}` | `network_extractor._extract_ips`, `network_parser`, `dynamic_parser` |
| `network.hosts[]` | `{ip|address, asn, asn_name, country_name, hostname, ports[]}` | `network_extractor._host_metadata`, `network_parser`, `dynamic_parser` |
| `network.domains[]` | `str` or `{domain}` | `network_extractor._extract_domains`, `network_parser`, `dynamic_parser` |
| `network.tls[]` | `{ja3|ja3_hash, ja3s|ja3s_hash}` | `network_extractor._extract_ja3` / `_extract_ja3s` |
| `network.pcap_local_path` | str | `network_parser` (written by `app._submit_to_sandbox`) |
| `cti.family[]` | `list[str]` | `attribution._extract_sandbox_family`, `attribution._family_is_grounded` |
| `ttp_tags[]` | list | `app._submit_to_sandbox` (log line only) |

**Interfaces:**
- Produces:
  ```python
  # src/maljan/schemas/sandbox_report.py
  class SandboxTarget(BaseModel):     sha256, md5, name, file_type, mime_type, size
  class SandboxProcess(BaseModel):    pid, ppid, name, command_line, first_seen, calls: list[dict]
  class SandboxSignatureRow(BaseModel): name, description, severity, marks: list, ttp_tags: list[str]
  class SandboxNetwork(BaseModel):    dns, http, tcp, udp, hosts, domains, tls: list[dict]; pcap_local_path: str | None
  class SandboxReport(BaseModel):
      provider: str
      source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"]
      task_id: str = ""
      target: SandboxTarget
      processes: list[SandboxProcess]
      apistats: dict[str, dict[str, int]]
      generic_events: list[dict[str, Any]]
      signatures: list[SandboxSignatureRow]
      network: SandboxNetwork
      dropped_files: list[dict[str, Any]]
      registry: list[dict[str, Any]]
      screenshots: list[dict[str, Any]]
      cti: dict[str, Any]
      unavailable: list[str]
      raw: dict[str, Any]
  class SandboxRun(BaseModel):
      task_id: str; sample_sha256: str = ""; sample_name: str = ""; status: str = "reported"
      report: SandboxReport; raw: dict[str, Any]; error: str = ""
  def cape_report_to_sandbox_report(raw, *, provider, source_format="cape2", task_id="") -> SandboxReport
  ```
  ```python
  # src/maljan/providers/cape_view.py
  def to_cape_shaped_dict(report: SandboxReport) -> dict[str, Any]
  ```
  ```python
  # src/maljan/providers/sandbox/formats.py
  Format = Literal["cape2", "cuckoo", "triage", "unknown"]
  def sniff_format(payload: dict[str, Any]) -> Format
  ```
- Consumes: nothing outside `pydantic` and the golden fixtures.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/test_cape_normalization_golden.py
"""The CAPE round trip is an identity, and the render is complete without it.

Three properties, one file:
  (a) a CAPE-sourced report renders to *the same object* it came from, so no
      consumer can observe the provider layer at all;
  (b) the extractors agree on the rendered dict and on the raw one;
  (c) with ``raw`` emptied — the path a non-CAPE provider takes — the render
      still carries every key the nine consumers read.
"""

from __future__ import annotations

import json

import pytest

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

from tests.providers.test_extractor_golden import cape_reports, dump

_REPORTS = cape_reports()
_IDS = [n for n, _ in _REPORTS]

# Every path the table in the plan's Task 6 names, as (path, kind).
CONSUMER_KEYS: tuple[tuple[str, str], ...] = (
    ("target.sha256", "scalar"),
    ("target.md5", "scalar"),
    ("target.name", "scalar"),
    ("behavior.processes", "list"),
    ("behavior.calls", "list"),
    ("behavior.apistats", "dict"),
    ("behavior.generic", "list"),
    ("behavior.summary", "dict"),
    ("signatures", "list"),
    ("network.dns", "list"),
    ("network.http", "list"),
    ("network.tcp", "list"),
    ("network.udp", "list"),
    ("network.hosts", "list"),
    ("network.domains", "list"),
    ("network.tls", "list"),
    ("cti", "dict"),
)


def _at(d, path):
    cursor = d
    for part in path.split("."):
        assert isinstance(cursor, dict), path
        assert part in cursor, f"missing {path}"
        cursor = cursor[part]
    return cursor


@pytest.mark.parametrize("name,raw", _REPORTS, ids=_IDS)
def test_cape_render_is_the_same_object(name, raw):
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert to_cape_shaped_dict(report) is raw


@pytest.mark.parametrize("name,raw", _REPORTS, ids=_IDS)
def test_extractors_agree_on_rendered_and_raw(name, raw):
    rendered = to_cape_shaped_dict(cape_report_to_sandbox_report(raw, provider="cape2"))
    assert dump(build_dynamic_behavior(rendered)) == dump(build_dynamic_behavior(raw))
    assert dump(build_network_iocs(rendered)) == dump(build_network_iocs(raw))


@pytest.mark.parametrize("name,raw", _REPORTS[:5], ids=_IDS[:5])
def test_the_render_reproduces_every_consumer_key_without_the_short_circuit(name, raw):
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    assert rendered is not raw
    for path, kind in CONSUMER_KEYS:
        value = _at(rendered, path)
        assert isinstance(value, {"list": list, "dict": dict}.get(kind, (str, int, float, type(None))))


@pytest.mark.parametrize("name,raw", _REPORTS[:5], ids=_IDS[:5])
def test_the_rendered_extractors_still_find_what_the_raw_ones_found(name, raw):
    """The rendered dict is not merely shaped right; it carries the same evidence."""
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    raw_dyn, new_dyn = build_dynamic_behavior(raw), build_dynamic_behavior(rendered)
    if raw_dyn is None:
        assert new_dyn is None
    else:
        assert new_dyn is not None
        assert len(new_dyn.process_tree) == len(raw_dyn.process_tree)
        assert [s.name for s in new_dyn.sandbox_signatures] == [
            s.name for s in raw_dyn.sandbox_signatures
        ]
    raw_net, new_net = build_network_iocs(raw), build_network_iocs(rendered)
    if raw_net is None:
        assert new_net is None
    else:
        assert new_net is not None
        assert {d.fqdn for d in new_net.domains} == {d.fqdn for d in raw_net.domains}
        assert {i.address for i in new_net.ips} == {i.address for i in raw_net.ips}


def test_pcap_path_and_unavailable_survive_the_render():
    report = cape_report_to_sandbox_report(
        {"target": {"sha256": "a" * 64}, "network": {"pcap_local_path": "/tmp/x.pcap"}},
        provider="triage",
        source_format="triage",
    ).model_copy(update={"unavailable": ["apistats", "calls"]})
    rendered = to_cape_shaped_dict(report)
    assert rendered["network"]["pcap_local_path"] == "/tmp/x.pcap"
    assert rendered["unavailable"] == ["apistats", "calls"]
```

```python
# tests/providers/test_sniff_format.py
"""Format sniffing, most specific first.

A Triage overview carries ``analysis.score`` and ``tasks``; a CAPE report
carries ``info.version`` with "CAPE" in it or the CAPE-only top-level ``CAPE``
key; Cuckoo is the fallback for a report that has ``behavior`` and ``info`` but
neither marker. Order matters: a Triage report has a ``signatures`` list too.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.providers.sandbox.formats import sniff_format

ROOT = Path(__file__).resolve().parents[2]


def test_a_real_cape_report_sniffs_as_cape2():
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    assert sniff_format(json.loads(path.read_text(encoding="utf-8"))) == "cape2"


def test_a_triage_overview_sniffs_as_triage():
    payload = {
        "version": "0.3.0",
        "sample": {"id": "260903-abcdef", "target": "x.exe", "sha256": "a" * 64},
        "tasks": [{"name": "behavioral1", "kind": "behavioral"}],
        "analysis": {"score": 10, "family": ["qakbot"]},
        "signatures": [{"name": "s", "score": 10}],
    }
    assert sniff_format(payload) == "triage"


def test_a_cuckoo_report_sniffs_as_cuckoo():
    payload = {
        "info": {"version": "2.0.7", "id": 12},
        "behavior": {"processes": [], "generic": []},
        "signatures": [],
    }
    assert sniff_format(payload) == "cuckoo"


def test_anything_else_is_unknown():
    assert sniff_format({"hello": "world"}) == "unknown"
    assert sniff_format({}) == "unknown"
```

`tests/providers/test_sandbox_report.py` covers the model itself: defaults are empty rather than `None`, `unavailable` round-trips, `SandboxRun.report` is required, and `cape_report_to_sandbox_report` keeps `raw is raw`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/providers/test_sandbox_report.py tests/providers/test_cape_normalization_golden.py tests/providers/test_sniff_format.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.schemas.sandbox_report'`.

- [ ] **Step 3: Write `schemas/sandbox_report.py`**

Plain pydantic models with the fields listed above, `model_config = ConfigDict(extra="ignore")`, every collection defaulting to empty. Then the CAPE reader, which copies rather than interprets:

```python
def cape_report_to_sandbox_report(
    raw: dict[str, Any],
    *,
    provider: str,
    source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "cape2",
    task_id: str = "",
) -> SandboxReport:
    """Read a CAPE/Cuckoo-shaped report into the neutral model, keeping ``raw``.

    Deliberately lossless in one direction only: everything the neutral model
    names is copied out, and the original dict is carried whole in ``raw`` so
    ``to_cape_shaped_dict`` can hand today's consumers the very object they
    would have received before the provider layer existed.
    """
    behavior = raw.get("behavior") if isinstance(raw.get("behavior"), dict) else {}
    net = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    file_block = target.get("file") if isinstance(target.get("file"), dict) else {}

    processes = [
        SandboxProcess(
            pid=_int(p.get("pid")),
            ppid=_int(p.get("ppid")),
            name=str(p.get("process_name") or p.get("name") or ""),
            command_line=str(p.get("command_line") or p.get("cmd") or ""),
            first_seen=str(p.get("first_seen") or ""),
            calls=[c for c in (p.get("calls") or []) if isinstance(c, dict)],
        )
        for p in (behavior.get("processes") or [])
        if isinstance(p, dict)
    ]
    signatures = [
        SandboxSignatureRow(
            name=str(s.get("name") or ""),
            description=str(s.get("description") or s.get("name") or ""),
            severity=_int(s.get("severity") or s.get("score")),
            marks=list(s.get("marks") or []),
            ttp_tags=_as_str_list(s.get("ttp_tags") or s.get("attck_id")),
        )
        for s in (raw.get("signatures") or [])
        if isinstance(s, dict)
    ]
    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or (raw.get("info") or {}).get("id") or ""),
        target=SandboxTarget(
            sha256=str(target.get("sha256") or ""),
            md5=str(target.get("md5") or ""),
            name=str(target.get("name") or ""),
            file_type=str(file_block.get("type") or ""),
            mime_type=str(file_block.get("type") or ""),
            size=_int(file_block.get("size")),
        ),
        processes=processes,
        apistats={
            str(pid): {str(api): _int(n) for api, n in (stats or {}).items()}
            for pid, stats in (behavior.get("apistats") or {}).items()
            if isinstance(stats, dict)
        },
        generic_events=[g for g in (behavior.get("generic") or []) if isinstance(g, dict)],
        signatures=signatures,
        network=SandboxNetwork(
            dns=_rows(net.get("dns")),
            http=_rows(net.get("http")),
            tcp=_rows(net.get("tcp")),
            udp=_rows(net.get("udp")),
            hosts=_rows(net.get("hosts")),
            domains=list(net.get("domains") or []),
            tls=_rows(net.get("tls")),
            pcap_local_path=net.get("pcap_local_path") or None,
        ),
        dropped_files=_rows(raw.get("dropped")),
        registry=_rows((behavior.get("summary") or {}).get("keys")),
        screenshots=_rows(raw.get("screenshots")),
        cti=raw.get("cti") if isinstance(raw.get("cti"), dict) else {},
        unavailable=[],
        raw=raw,
    )
```
(`_int`, `_rows`, `_as_str_list` are three four-line module helpers; `calls` at `behavior.calls` — the flat list some CAPE builds emit — is carried through `raw` and re-emitted by the renderer from `behavior.get("calls")`, so the model keeps only the per-process lists.)

- [ ] **Step 4: Write `providers/cape_view.py`**

```python
"""Render a ``SandboxReport`` into the dict today's nine consumers read.

The short circuit is the design, not an optimisation. A CAPE or mock report
already *is* the dict every extractor, parser and analysis layer was written
against, so returning ``report.raw`` — the same object, ``rendered is raw`` —
makes byte-identity structural: no normalisation function has to be complete
for the default profile to behave exactly as it did. Providers that never saw a
CAPE report (triage, a report uploaded in another shape) take the real render
below, and the golden test proves that render carries every key the consumers
touch.
"""

from __future__ import annotations

from typing import Any

from maljan.schemas.sandbox_report import SandboxReport

_CAPE_SHAPED = {"cape2", "mock"}


def to_cape_shaped_dict(report: SandboxReport) -> dict[str, Any]:
    if report.source_format in _CAPE_SHAPED and report.raw:
        return report.raw

    behavior: dict[str, Any] = {
        "processes": [
            {
                "pid": p.pid,
                "ppid": p.ppid,
                "process_name": p.name,
                "command_line": p.command_line,
                "first_seen": p.first_seen,
                "calls": list(p.calls),
            }
            for p in report.processes
        ],
        "apistats": {pid: dict(stats) for pid, stats in report.apistats.items()},
        "generic": list(report.generic_events),
        "calls": [c for p in report.processes for c in p.calls],
        "summary": {"keys": list(report.registry)},
    }
    rendered: dict[str, Any] = {
        "target": {
            "sha256": report.target.sha256,
            "md5": report.target.md5,
            "name": report.target.name,
            "file": {"type": report.target.mime_type, "size": report.target.size},
        },
        "behavior": behavior,
        "signatures": [
            {
                "name": s.name,
                "description": s.description,
                "severity": s.severity,
                "marks": list(s.marks),
                "ttp_tags": list(s.ttp_tags),
            }
            for s in report.signatures
        ],
        "network": {
            "dns": list(report.network.dns),
            "http": list(report.network.http),
            "tcp": list(report.network.tcp),
            "udp": list(report.network.udp),
            "hosts": list(report.network.hosts),
            "domains": list(report.network.domains),
            "tls": list(report.network.tls),
        },
        "dropped": list(report.dropped_files),
        "screenshots": list(report.screenshots),
        "cti": dict(report.cti),
        "ttp_tags": sorted({t for s in report.signatures for t in s.ttp_tags}),
        # Named here because an empty section from a sandbox that cannot produce
        # it reads exactly like a clean sample; the report renderers say so.
        "unavailable": list(report.unavailable),
    }
    if report.network.pcap_local_path:
        rendered["network"]["pcap_local_path"] = report.network.pcap_local_path
    return rendered
```

- [ ] **Step 5: Write `providers/sandbox/formats.py`**

```python
def sniff_format(payload: dict[str, Any]) -> Format:
    """Name the sandbox that produced ``payload``, most specific first.

    Triage first: its overview carries ``analysis`` plus ``tasks``, which no
    CAPE report has. CAPE next: ``CAPE`` as a top-level key, or a version string
    naming it. Cuckoo last, as the generic ``info`` + ``behavior`` shape CAPE
    inherited from it — so it can only be reached once CAPE has been ruled out.
    """
    if not isinstance(payload, dict) or not payload:
        return "unknown"
    analysis = payload.get("analysis")
    if isinstance(analysis, dict) and isinstance(payload.get("tasks"), list):
        return "triage"
    if isinstance(payload.get("CAPE"), (dict, list)):
        return "cape2"
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    version = str(info.get("version") or "")
    if "cape" in version.lower():
        return "cape2"
    if isinstance(payload.get("behavior"), dict) and info:
        return "cuckoo"
    return "unknown"
```

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/providers/test_sandbox_report.py tests/providers/test_cape_normalization_golden.py tests/providers/test_sniff_format.py tests/providers/test_extractor_golden.py -q`
Expected: PASS (≈ 300 parametrised cases).

- [ ] **Step 7: Lint and type-check**

Run: `uv run ruff check src/maljan/schemas/sandbox_report.py src/maljan/providers/cape_view.py src/maljan/providers/sandbox/formats.py tests/providers && uv run ruff format --check src/maljan/schemas/sandbox_report.py src/maljan/providers/cape_view.py src/maljan/providers/sandbox/formats.py tests/providers && uv run mypy src/ apps/api/`

- [ ] **Step 8: Commit**

```bash
git add src/maljan/schemas/sandbox_report.py src/maljan/providers/cape_view.py src/maljan/providers/sandbox/formats.py tests/providers/test_sandbox_report.py tests/providers/test_cape_normalization_golden.py tests/providers/test_sniff_format.py
git commit -m "feat(providers): neutral sandbox report, the CAPE-shaped view and format sniffing"
```

---

### Task 7: The CAPEv2 and mock sandbox providers, and the legacy wrapper

**Files:**
- Create: `src/maljan/providers/sandbox/cape2.py`, `src/maljan/providers/sandbox/mock.py`, `src/maljan/providers/sandbox/_legacy.py`
- Modify: `src/maljan/loaders/sandbox_client.py:36-64` (`SubmissionResult` gains `normalized`)
- Test: `tests/providers/sandbox/__init__.py`, `tests/providers/sandbox/test_cape2_provider.py`, `tests/providers/sandbox/test_legacy_wrapper.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/sandbox/cape2.py
  @register_sandbox_provider("cape2")
  class CAPE2SandboxProvider(SandboxProvider):
      CAPE_ESSENTIAL_TOOLS: ClassVar[tuple[str, ...]]     # the 13 names, from the golden
      CAPE_PROMPT_FRAGMENT: ClassVar[str]                 # moved from dynamic_analyst (Task 11)
  # src/maljan/providers/sandbox/mock.py
  @register_sandbox_provider("mock")
  class MockSandboxProvider(SandboxProvider)
  # src/maljan/providers/sandbox/_legacy.py
  def as_sandbox_client(provider: SandboxProvider) -> SandboxClient
  ```
  ```python
  # src/maljan/loaders/sandbox_client.py
  @dataclass
  class SubmissionResult:
      ...                                       # existing fields unchanged
      normalized: SandboxReport | None = None   # the provider's neutral view, when it has one
  ```
- Consumes: `maljan.loaders.cape2_client.CAPEv2Client`, `maljan.loaders.mock_sandbox_client.MockSandboxClient`, `cape_report_to_sandbox_report`, `to_cape_shaped_dict`.

Both providers **delegate to the existing clients** rather than re-implementing them: the CAPE REST quirks (the three submit response shapes, transient-poll tolerance, the 24-byte PCAP floor) are hard-won and stay exactly where they are.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/sandbox/test_cape2_provider.py
"""The CAPE provider is the existing client behind the provider contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

ROOT = Path(__file__).resolve().parents[3]


class _FakeClient:
    def __init__(self, report):
        self.report = report
        self.submitted: list[str] = []
        self.waited: list[tuple[str, int, int]] = []

    def submit(self, sample_path):
        self.submitted.append(str(sample_path))
        return "42"

    def wait_for_completion(self, task_id, timeout_seconds=300, poll_interval_seconds=10):
        self.waited.append((task_id, timeout_seconds, poll_interval_seconds))
        return "reported"

    def fetch_report(self, task_id):
        from maljan.loaders.sandbox_client import SubmissionResult

        target = self.report.get("target", {})
        return SubmissionResult(
            task_id=task_id,
            sample_sha256=target.get("sha256", ""),
            sample_name=target.get("name", ""),
            status="reported",
            report=self.report,
        )

    def fetch_pcap(self, task_id, dest_dir):
        return None


@pytest.fixture
def raw_report():
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    return json.loads(path.read_text(encoding="utf-8"))


def test_capabilities(raw_report):
    caps = CAPE2SandboxProvider.from_settings(Settings(_env_file=None)).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report and caps.can_fetch_pcap
    assert caps.provides_tools and caps.report_format == "cape2"
    assert caps.degrade_on_failure is True
    assert caps.accepts_uploaded_report is False


def test_fetch_keeps_the_raw_report_by_identity(raw_report):
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw_report)
    run = provider.fetch("42")
    assert run.raw is raw_report
    assert to_cape_shaped_dict(run.report) is raw_report
    assert run.report.source_format == "cape2"
    assert run.sample_sha256 == raw_report["target"]["sha256"]


def test_the_configured_timeout_and_interval_reach_the_client(raw_report):
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.timeout_seconds = 1200
    cfg.sandbox.cape2.poll_interval_seconds = 15
    provider = CAPE2SandboxProvider.from_settings(cfg)
    client = _FakeClient(raw_report)
    provider._client = client
    provider.wait_for_completion("42")
    assert client.waited == [("42", 1200, 15)]


def test_the_essential_tool_names_match_the_golden():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS) == golden["cape_essential_tools"]
```

```python
# tests/providers/sandbox/test_legacy_wrapper.py
"""``as_sandbox_client`` keeps ``SandboxClient``'s contract, including fetch_pcap."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.loaders.sandbox_client import SandboxClient
from maljan.providers.registry import get_sandbox_provider
from maljan.providers.sandbox._legacy import as_sandbox_client

ROOT = Path(__file__).resolve().parents[3]


def test_the_wrapper_satisfies_the_protocol():
    client = as_sandbox_client(get_sandbox_provider(Settings(_env_file=None)))
    assert isinstance(client, SandboxClient)


def test_the_mock_provider_round_trips_a_fixture(tmp_path):
    raw = json.loads(
        (ROOT / "data" / "samples" / "dynamic" / "sample_1.json").read_text(encoding="utf-8")
    )
    (tmp_path / "dynamic").mkdir()
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"payload")
    import hashlib

    sha = hashlib.sha256(b"payload").hexdigest()
    (tmp_path / "dynamic" / f"{sha}.json").write_text(json.dumps(raw), encoding="utf-8")

    cfg = Settings(_env_file=None)
    provider = get_sandbox_provider(cfg)
    provider.fixtures_dir = str(tmp_path)  # the mock provider's only knob
    client = as_sandbox_client(provider)
    task_id = client.submit(sample)
    assert client.wait_for_completion(task_id) == "reported"
    result = client.fetch_report(task_id)
    assert result.report == raw
    assert result.normalized is not None and result.normalized.source_format == "mock"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/providers/sandbox -q`
Expected: FAIL — `NotImplementedError` from the Task 5 stubs.

- [ ] **Step 3: Write the two providers**

`cape2.py` holds the client lazily (constructing `CAPEv2Client` imports httpx and opens a pool, which a settings probe or a registry listing must not do):

```python
@register_sandbox_provider("cape2")
class CAPE2SandboxProvider(SandboxProvider):
    """CAPEv2 behind the provider contract.

    A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
    response shapes, transient polls that are a busy sandbox rather than a
    failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
    re-implemented here.
    """

    CAPE_ESSENTIAL_TOOLS: ClassVar[tuple[str, ...]] = (
        "get_cuckoo_status", "search_task", "extended_search", "submit_file",
        "submit_static", "get_task_status", "get_task_report", "get_task_iocs",
        "get_task_config", "list_tasks", "view_task", "get_latest_tasks", "verify_auth",
    )
    CAPE_PROMPT_FRAGMENT: ClassVar[str] = ""   # filled by Task 11's verbatim move

    def __init__(self, cfg: SandboxCape2Config) -> None:
        self._cfg = cfg
        self._client: Any = None
        self._toolkit: Any = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> CAPE2SandboxProvider:
        return cls(cfg.sandbox.cape2)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True, can_poll=True, can_fetch_report=True, can_fetch_pcap=True,
            provides_tools=bool(self._cfg.mcp.enabled), report_format="cape2",
            degrade_on_failure=True,
        )

    def _get_client(self) -> Any:
        if self._client is None:
            from maljan.loaders.cape2_client import CAPEv2Client

            self._client = CAPEv2Client(
                base_url=self._cfg.base_url, api_token=self._cfg.api_token
            )
        return self._client

    def submit(self, sample_path: str | Path) -> str:
        return str(self._get_client().submit(sample_path))

    def wait_for_completion(
        self, task_id: str, timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        return str(self._get_client().wait_for_completion(
            task_id,
            timeout_seconds=timeout_seconds or self._cfg.timeout_seconds,
            poll_interval_seconds=poll_interval_seconds or self._cfg.poll_interval_seconds,
        ))

    def fetch(self, task_id: str) -> SandboxRun:
        result = self._get_client().fetch_report(task_id)
        report = cape_report_to_sandbox_report(
            result.report, provider="cape2", source_format="cape2", task_id=str(task_id)
        )
        return SandboxRun(
            task_id=str(task_id), sample_sha256=result.sample_sha256,
            sample_name=result.sample_name, status=result.status, report=report,
            raw=result.report, error=result.error,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        return self._get_client().fetch_pcap(task_id, dest_dir)

    async def probe(self) -> ProviderProbe:
        """Ask CAPE about task 1: the cheapest call that exercises URL and token."""
        import time

        import httpx

        t0 = time.perf_counter()
        token = self._cfg.api_token.get_secret_value()
        headers = {"Authorization": f"Token {token}"} if token else {}
        url = f"{self._cfg.base_url.rstrip('/')}/apiv2/tasks/view/1/"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False, detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400, detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the REST pool, if one was ever built. Never raises."""
        client, self._client = self._client, None
        if client is not None:
            with suppress(Exception):
                client.close()
        toolkit, self._toolkit = self._toolkit, None
        if toolkit is not None:
            with suppress(Exception):
                _run_coro_blocking(toolkit.cleanup(), hard_timeout=20.0, label="cape-mcp-close")
```
`dynamic_tools()` and `dynamic_prompt_fragment()` stay empty here and are filled by Task 11 (the CAPE MCP toolkit and the moved prompt fragment), so this task's diff is only the sandbox half.

`mock.py` wraps `MockSandboxClient` the same way with `capabilities = SandboxCapabilities(can_submit=True, can_poll=True, can_fetch_report=True, report_format="mock")` and a `fixtures_dir` attribute defaulting to `data/samples` through `resolve_data`.

- [ ] **Step 4: Write `_legacy.py`**

```python
def as_sandbox_client(provider: SandboxProvider) -> SandboxClient:
    """Present a provider as the ``SandboxClient`` the pipeline already speaks.

    ``src/maljan/app.py`` and every existing sandbox test drive submit / wait /
    fetch_report and sniff for an optional ``fetch_pcap``. Adapting the provider
    to them — rather than rewriting them onto the provider — is what keeps
    sub-project A a refactor: ``app.py`` is untouched, and the neutral report
    rides along in the new ``SubmissionResult.normalized`` field for whoever
    wants it next.
    """

    class _ProviderBackedClient:
        def __init__(self) -> None:
            self._provider = provider

        def submit(self, sample_path: str | Path) -> str:
            return self._provider.submit(sample_path)

        def wait_for_completion(
            self, task_id: str, timeout_seconds: int = 300, poll_interval_seconds: int = 10
        ) -> str:
            return self._provider.wait_for_completion(
                task_id, timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )

        def fetch_report(self, task_id: str) -> SubmissionResult:
            run = self._provider.fetch(task_id)
            return SubmissionResult(
                task_id=run.task_id, sample_sha256=run.sample_sha256,
                sample_name=run.sample_name, status=run.status,
                report=to_cape_shaped_dict(run.report), error=run.error,
                normalized=run.report,
            )

        def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
            if not self._provider.capabilities.can_fetch_pcap:
                return None
            return self._provider.fetch_pcap(task_id, dest_dir)

        def close(self) -> None:
            self._provider.close()

    return _ProviderBackedClient()  # type: ignore[return-value]
```
`fetch_pcap` is defined unconditionally, so `hasattr(client, "fetch_pcap")` in `app.py:178` stays true; the capability check inside is what makes a non-PCAP sandbox a no-op instead of an error.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/providers tests/unit/test_sandbox_client.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers src/maljan/loaders/sandbox_client.py tests/providers
uv run ruff format --check src/maljan/providers src/maljan/loaders/sandbox_client.py tests/providers
uv run mypy src/ apps/api/
git add src/maljan/providers/sandbox src/maljan/loaders/sandbox_client.py tests/providers/sandbox
git commit -m "feat(providers): CAPEv2 and mock sandbox adapters behind the legacy client protocol"
```

---

### Task 8: Container wiring

**Files:**
- Modify: `src/maljan/core/container.py:108` (cache field), `:224-259` (`get_sandbox_client` rewritten over the provider), plus a new `get_sandbox_provider` and `get_static_provider`
- Test: `tests/unit/test_sandbox_container.py` (extended), `tests/providers/test_container_wiring.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/container.py
  def get_sandbox_provider(self) -> SandboxProvider   # cached, mock=True forces the mock provider
  def get_static_provider(self) -> StaticProvider     # cached
  def get_sandbox_client(self) -> SandboxClient       # as_sandbox_client(get_sandbox_provider())
  ```
- Consumes: `maljan.providers.registry.get_sandbox_provider/get_static_provider`, `maljan.providers.sandbox._legacy.as_sandbox_client`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/test_container_wiring.py
from __future__ import annotations

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.loaders.sandbox_client import SandboxClient


def test_cape2_settings_select_the_cape2_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=False)
    assert container.get_sandbox_provider().id == "cape2"
    assert isinstance(container.get_sandbox_client(), SandboxClient)


def test_mock_mode_overrides_the_configured_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=True)
    assert container.get_sandbox_provider().id == "mock"


def test_providers_are_cached():
    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_sandbox_provider() is container.get_sandbox_provider()
    assert container.get_static_provider() is container.get_static_provider()


def test_the_default_profile_is_ghidra_plus_the_cape_equivalent():
    """The smoke test the spec's gate (6) names: today's .env, today's wiring."""
    container = ServiceContainer(config=Settings(_env_file=None), mock=False)
    assert container.get_static_provider().id == "ghidra"
    assert container.get_sandbox_provider().id == "mock"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/test_container_wiring.py -q`
Expected: FAIL — `AttributeError: 'ServiceContainer' object has no attribute 'get_sandbox_provider'`.

- [ ] **Step 3: Rewrite the accessors**

```python
    def get_sandbox_provider(self) -> SandboxProvider:
        """The configured sandbox adapter, or the mock one in mock mode.

        ``mock=True`` is the container's own switch (the CLI's ``--mock``, the
        API's mock jobs) and outranks the setting, exactly as it did when this
        method built clients directly.
        """
        with self._lock:
            if self._sandbox_provider_cache is not None:
                return self._sandbox_provider_cache
            from maljan.providers.registry import get_sandbox_provider as build

            cfg = self.config
            if self.mock and cfg.sandbox.provider != "mock":
                cfg = cfg.model_copy(deep=True)
                cfg.sandbox.provider = "mock"
            provider = build(cfg)
            fixtures = getattr(provider, "fixtures_dir", None)
            if fixtures is not None:
                provider.fixtures_dir = self._samples_dir
            logger.info("Sandbox provider: %s.", provider.id)
            self._sandbox_provider_cache = provider
            return provider

    def get_static_provider(self) -> StaticProvider:
        with self._lock:
            if self._static_provider_cache is None:
                from maljan.providers.registry import get_static_provider as build

                self._static_provider_cache = build(self.config)
                logger.info("Static provider: %s.", self._static_provider_cache.id)
            return self._static_provider_cache

    def get_sandbox_client(self) -> SandboxClient:
        """The provider, dressed as the client the pipeline already speaks."""
        with self._lock:
            if self._sandbox_client_cache is None:
                from maljan.providers.sandbox._legacy import as_sandbox_client

                self._sandbox_client_cache = as_sandbox_client(self.get_sandbox_provider())
            return self._sandbox_client_cache
```
`aclose()` gains `self.get_static_provider().close()` and `self.get_sandbox_provider().close()` inside its existing best-effort block, so a provider that opened a subprocess or an HTTP pool releases it at job end alongside the agents' toolkits.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/providers/test_container_wiring.py tests/unit/test_sandbox_container.py tests/unit/test_sandbox_client.py -q`
Expected: PASS. `test_cape2_backend_raises_without_httpx` still passes because the provider builds `CAPEv2Client` lazily inside `submit`/`fetch` — adjust that test to call `container.get_sandbox_client().submit(...)` inside the `patch.dict` block, which is where the import now happens, and say so in a one-line comment.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core/container.py tests/providers/test_container_wiring.py tests/unit/test_sandbox_container.py
uv run ruff format --check src/maljan/core/container.py tests/providers/test_container_wiring.py tests/unit/test_sandbox_container.py
uv run mypy src/ apps/api/
git add src/maljan/core/container.py tests/providers/test_container_wiring.py tests/unit/test_sandbox_container.py
git commit -m "feat(container): build the sandbox client from the configured provider"
```

---

### Task 9: `GhidraStaticProvider` — the moved constants and the moved init

**Files:**
- Create: `src/maljan/providers/static/ghidra.py` (replaces the Task 5 stub)
- Modify: `src/maljan/agents/static_analyst.py` (the moved members become deprecated re-exports; no behaviour change yet — the analyst still calls its own `_initialize_mcp_client`)
- Test: `tests/providers/static/__init__.py`, `tests/providers/static/test_ghidra_provider.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/static/ghidra.py
  GHIDRA_ALLOWED_TOOLS: frozenset[str]           # the 20 names, moved verbatim
  GHIDRA_PROMPT_FRAGMENT: str                    # filled in Task 10
  @register_static_provider("ghidra")
  class GhidraStaticProvider(StaticProvider):
      def open(self, job: StaticJobContext) -> None
      def get_tools(self) -> list[BaseTool]
      def select_tools(self, tools, categories=None) -> list[BaseTool]
      def function_hashes(self, job) -> list[tuple[str, str]]
      def mirror_spec(self) -> MirrorSpec
  select_relevant_ghidra_tools(...)              # re-exported from the moved selector
  ```
- Consumes: `maljan.agents.ghidra_http_client.GhidraHTTPClient`, `maljan.agents.mcp_client.MCPLangChainToolkit`, `maljan.agents.subprocess_env.child_env`, `maljan.core.paths.resolve_mcp_args`, `maljan.agents.base_agent._run_coro_blocking`, `maljan.analysis.function_hash_attribution.fetch_bulk_function_hashes`.

**The moves are cuts, not rewrites.** Every line below is transplanted with its comments intact; the only edits are the mechanical ones named after each cut.

| Cut from `static_analyst.py` | First line | Last line | Becomes |
| :-- | :-- | :-- | :-- |
| 130–179 | `    # Allowlist of Ghidra MCP tools exposed to the ReAct agent.` | `    # the loop, offsetting the larger tool manifest.` | module-level `GHIDRA_ALLOWED_TOOLS` (de-indent one level, drop the `_` and the `: frozenset[str]` stays) |
| 187–194 | `    def _ghidra_tool_mode(self) -> str:` | `        return str(getattr(ghidra, "tool_selection", "dynamic"))` | `GhidraStaticProvider._tool_mode` (reads `self._cfg` instead of `get_settings().mcp.ghidra`) |
| 196–238 | `    def _select_ghidra_tools(` | `        return self._pin_load_program_path(kept)` | `GhidraStaticProvider.select_tools` (signature `(self, tools, categories=None)`; `self.logger` becomes the module `logger`; `self._sample_categories` fallback becomes `self._job.capability_categories`) |
| 240–260 | `    def _pin_load_program_path(self, tools: list[Any]) -> list[Any]:` | `        return out` | `GhidraStaticProvider._pin_load_program_path` |
| 262–292 | `    def _wrap_load_program(self, tool: Any) -> Any:` | `        )` | `GhidraStaticProvider._wrap_load_program` (`agent = self` becomes `provider = self`; `agent._analysis_file_path` becomes `provider._job.mirror_sample_path`) |
| 319–419 (the body from `from maljan.core.config import get_settings` on) | `        if not cfg.mcp.ghidra.enabled:` | `        )` (the closing paren of the final `self.logger.info(...)`) | `GhidraStaticProvider.open` (see Step 3) |
| 421–441 | `    def _run_async(self, coro: Any) -> None:` | `        _run_coro_blocking(coro, hard_timeout=120.0, label="ghidra-mcp-init")` | `GhidraStaticProvider._run_async`, **docstring included** — the shared-agent-loop rationale is the reason the method exists |
| `agents/ghidra_tool_selector.py` (whole file, 139 lines) | `"""Dynamic, per-sample Ghidra MCP tool selection (2026-07 round 3).` | `    return selected` | `src/maljan/providers/static/ghidra_tool_selector.py`, moved with `git mv` in Task 23; until then `providers/static/ghidra.py` imports it from its current home |

After each cut, run `git diff -- src/maljan/agents/static_analyst.py` and confirm the removed hunks appear unchanged in the new file except for the mechanical edits listed.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/static/test_ghidra_provider.py
"""The Ghidra provider is the static analyst's Ghidra code, moved."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.ghidra import GHIDRA_ALLOWED_TOOLS, GhidraStaticProvider

ROOT = Path(__file__).resolve().parents[3]


class _Tool:
    def __init__(self, name: str, description: str = "") -> None:
        self.name, self.description = name, description


def _provider(**over):
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = True
    cfg.static.ghidra.transport = "http"
    cfg.static.ghidra.url = "http://ghidra.example:8089"
    for k, v in over.items():
        setattr(cfg.static.ghidra, k, v)
    return GhidraStaticProvider.from_settings(cfg)


def test_the_allow_list_is_the_golden_one():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(GHIDRA_ALLOWED_TOOLS) == golden["ghidra_allowed_tools"]


def test_the_analyst_still_exports_the_allow_list_under_its_old_name():
    from maljan.agents.static_analyst import StaticAnalyst

    assert StaticAnalyst._GHIDRA_ALLOWED_TOOLS is GHIDRA_ALLOWED_TOOLS


def test_capabilities_track_the_transport():
    http = _provider().capabilities
    assert http.provides_tools and http.supports_tool_curation and http.needs_sample_mirror
    assert http.provides_function_hashes is True
    assert http.degrade_on_failure is False, "Ghidra is the static evidence; it fails loudly"
    stdio = _provider(transport="stdio").capabilities
    assert stdio.provides_function_hashes is False, "the hash pre-pass speaks the REST API"


def test_curated_mode_keeps_exactly_the_allow_list():
    provider = _provider(tool_selection="curated")
    tools = [_Tool(n) for n in sorted(GHIDRA_ALLOWED_TOOLS)] + [_Tool("unrelated_tool")]
    kept = {t.name for t in provider.select_tools(tools)}
    assert kept == set(GHIDRA_ALLOWED_TOOLS)


def test_all_mode_keeps_everything():
    provider = _provider(tool_selection="all")
    tools = [_Tool(f"t{i}") for i in range(50)]
    assert len(provider.select_tools(tools)) == 50


def test_dynamic_mode_uses_the_categories_from_the_job():
    provider = _provider(tool_selection="dynamic")
    provider.open(StaticJobContext(capability_categories=frozenset({"crypto"})))
    tools = [_Tool(f"filler_{i}") for i in range(80)] + [
        _Tool("detect_crypto_constants", "find AES and RC4 constants")
    ]
    names = {t.name for t in provider.select_tools(tools)}
    assert "detect_crypto_constants" in names
    assert len(names) <= 40


def test_use_all_tools_still_forces_all():
    provider = _provider(tool_selection="curated", use_all_tools=True)
    assert len(provider.select_tools([_Tool(f"t{i}") for i in range(30)])) == 30


def test_load_program_is_pinned_to_the_mirror_path():
    import asyncio

    from langchain_core.tools import StructuredTool
    from pydantic import create_model

    seen: dict[str, object] = {}

    async def inner(**kwargs):
        seen.update(kwargs)
        return "loaded"

    tool = StructuredTool.from_function(
        func=None, coroutine=inner, name="load_program", description="load",
        args_schema=create_model("Args", file=(str, ...)),
    )
    provider = _provider()
    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe"))
    pinned = provider.select_tools([tool])[0]
    asyncio.run(pinned.coroutine(file="/home/user/invented.exe"))
    assert seen["file"] == "/data/samples/.work/abc.exe"


def test_mirror_spec_is_todays_work_directory():
    spec = _provider().mirror_spec()
    assert spec.work_subdir == ".work"
    assert spec.container_prefix.endswith("/samples") or spec.container_prefix == "/data/samples"


def test_a_disabled_server_yields_no_tools_and_does_not_raise():
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = False
    provider = GhidraStaticProvider.from_settings(cfg)
    provider.open(StaticJobContext())
    assert provider.get_tools() == []
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/static/test_ghidra_provider.py -q`
Expected: FAIL — `ImportError: cannot import name 'GHIDRA_ALLOWED_TOOLS'`.

- [ ] **Step 3: Write the provider around the moved code**

`open()` is the transplanted `_initialize_mcp_client` body with four mechanical edits: `cfg.mcp.ghidra` becomes `self._cfg`; `self.logger` becomes the module `logger`; `self._all_ghidra_tools` becomes `self._all_tools`; the container lookup for the output guardrail is replaced by `job.output_guardrail` and `job.max_output_chars`, which the analyst now computes and passes in (Task 10). The http and stdio branches, the `truncation_ledger` pass-through and both log lines keep their exact wording, so `Initialized Ghidra HTTP tools: %d/%d (mode=%s).` still appears with the same numbers.

```python
@register_static_provider("ghidra")
class GhidraStaticProvider(StaticProvider):
    """Ghidra MCP, as the static analyst has always driven it.

    Every line of the attach path — the http/stdio branch, the shared-loop
    ``_run_async``, the load_program pin, the three tool-selection modes — is
    this file's, moved out of ``StaticAnalyst`` unchanged. What is new is only
    the seam: the analyst now asks a provider for tools instead of knowing how
    to build them.

    ``degrade_on_failure`` is False on purpose. Ghidra IS the static evidence;
    a toolless static run produces a confident-looking report grounded in
    nothing, which is why this analyst has always failed loudly while dynamic
    and network degrade.
    """

    def __init__(self, cfg: MCPServerConfig, preprocessing: PreprocessingConfig,
                 memory: MemoryConfig, container_samples_path: str = "/data/samples") -> None:
        self._cfg = cfg
        self._pre = preprocessing
        self._memory = memory
        self._container_samples_path = container_samples_path
        self._job = StaticJobContext()
        self._toolkit: Any = None
        self._all_tools: list[Any] = []

    @classmethod
    def from_settings(cls, cfg: Settings) -> GhidraStaticProvider:
        return cls(cfg.static.ghidra, cfg.preprocessing, cfg.memory)

    @property
    def capabilities(self) -> StaticCapabilities:
        # function hashes come from the headless REST API, so only the http
        # transport can produce them — the same condition nodes.py used to spell
        # out as ``mcp.ghidra.transport == "http"``.
        http = self._cfg.transport == "http"
        return StaticCapabilities(
            provides_tools=True, provides_evidence=False, provides_function_hashes=http,
            needs_sample_mirror=True, supports_tool_curation=True, degrade_on_failure=False,
        )

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=".work", container_prefix=self._container_samples_path)

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        """Two lines of delegation: the pre-pass itself already lives in analysis/."""
        from maljan.analysis.function_hash_attribution import fetch_bulk_function_hashes

        if not self.capabilities.provides_function_hashes or not job.mirror_sample_path:
            return []
        return fetch_bulk_function_hashes(
            base_url=self._cfg.url,
            auth_token=self._cfg.auth_token,
            file_path=job.mirror_sample_path,
            min_instructions=self._pre.function_hash_min_instructions,
        )

    async def probe(self) -> ProviderProbe:
        """The headless server's own health endpoint, with the configured token."""
        import time

        import httpx

        t0 = time.perf_counter()
        headers = {"Authorization": f"Bearer {self._cfg.auth_token}"} if self._cfg.auth_token else {}
        url = f"{self._cfg.url.rstrip('/')}/check_connection"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False, detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400, detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the toolkit or the HTTP client. Teardown that can throw is
        teardown nobody calls, so every failure here is a warning."""
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            _run_coro_blocking(closer(), hard_timeout=20.0, label="ghidra-close")
        except Exception as exc:  # noqa: BLE001 - teardown never propagates
            logger.warning("Ghidra provider teardown failed (non-fatal): %s", exc)
```

`static_analyst.py` keeps working through re-exports placed where the cut code was:

```python
# Moved to maljan.providers.static.ghidra in the provider layer (2026-09-03).
# Re-exported so the modules and tests that import them from here keep working;
# removed in the last task of the provider plan.
from maljan.providers.static.ghidra import (  # noqa: E402
    GHIDRA_ALLOWED_TOOLS as _GHIDRA_ALLOWED_TOOLS_MODULE,
)
```
with `_GHIDRA_ALLOWED_TOOLS: frozenset[str] = _GHIDRA_ALLOWED_TOOLS_MODULE` as a class attribute of `StaticAnalyst`, and `_ghidra_tool_mode` / `_select_ghidra_tools` / `_pin_load_program_path` / `_wrap_load_program` kept as three-line delegations to `self._container.get_static_provider()` when one is available and to a locally built `GhidraStaticProvider` otherwise (`tests/unit/test_load_program_pinning.py` constructs a bare analyst).

- [ ] **Step 4: Run the tests, including the ones that must not move yet**

Run: `uv run pytest tests/providers/static tests/unit/test_load_program_pinning.py tests/unit/test_wave6_ghidra_delivery.py tests/unit/agents/test_ghidra_tool_selector.py tests/unit/agents/test_ghidra_program_switch.py tests/unit/agents/test_ghidra_load_failure.py tests/agents/test_prompt_byte_identity.py -q`
Expected: PASS — the four Ghidra test modules still import from `maljan.agents.static_analyst` and still pass, which is the evidence that the move was a move.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/static src/maljan/agents/static_analyst.py tests/providers/static
uv run ruff format --check src/maljan/providers/static src/maljan/agents/static_analyst.py tests/providers/static
uv run mypy src/ apps/api/
git add src/maljan/providers/static/ghidra.py src/maljan/agents/static_analyst.py tests/providers/static
git commit -m "refactor(static): move the Ghidra attach path, allow-list and selector into a provider"
```

---

### Task 10: Static analyst decoupling — the prompt split and the provider's tools

**Files:**
- Modify: `src/maljan/agents/static_analyst.py:21-86` (the prompt splits), `:319-441` (`_initialize_mcp_client` shrinks to five lines), `:740-760` (`analyze`), `:854-940` (`analyze_isr`), `src/maljan/agents/base_agent.py:789-812` (`_try_initialize_mcp` reads the degrade flag)
- Modify: `src/maljan/providers/static/ghidra.py` (`GHIDRA_PROMPT_FRAGMENT` filled by the cut below)
- Test: `tests/agents/test_prompt_byte_identity.py` (extended), `tests/providers/static/test_ghidra_provider.py` (extended), `tests/unit/agents/test_static_bug07.py` (unchanged, must stay green)

**The prompt cut.** `_ISR_SYSTEM` (`static_analyst.py:21-86`) becomes head plus fragment:

- `_ISR_HEAD` keeps **line 22 only**: `"You are an expert Static Malware Analyst with 15 years of reverse engineering experience. "`
- `GHIDRA_PROMPT_FRAGMENT` is **lines 23–85 cut verbatim** into `providers/static/ghidra.py`. First line: `"Analyze binary files (e.g. PE, ELF) utilizing Ghidra through your available tools. "`. Last line: `"- Summarize assembly patterns instead of dumping raw hex."`. Do not retype the 63 lines; move them.
- `_ISR_TAIL = ""`, declared so the assembly shape is fixed for sub-projects B and C.
- The assembled prompt is `_ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL`, and Task 1's golden proves it is the same bytes.

The seam falls after line 22 rather than at the `=== TOOL USAGE WORKFLOW ===` marker because lines 23–24 name Ghidra: a head that mentions the tool is not provider-independent. The consequence is that the four provider-neutral sentences at lines 25–28 (cite a concrete artifact, the four ATT&CK techniques) travel inside the Ghidra fragment and are repeated in the other providers' fragments. That is the price of byte identity and it is paid deliberately; sub-project C, which builds prompts from agent definitions, is where the repetition goes away.

**Interfaces:**
- Produces: `maljan.agents.static_analyst._ISR_HEAD: str`, `_ISR_TAIL: str`, `_ISR_SYSTEM: str` (kept, now computed, so `revise_isr` and any importer are unaffected); `GhidraStaticProvider.prompt_fragment() -> str`.
- Consumes: `container.get_static_provider()`, `StaticJobContext`, `StaticCapabilities.degrade_on_failure`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/agents/test_prompt_byte_identity.py`:

```python
def test_the_assembled_static_prompt_equals_the_golden():
    from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL
    from maljan.core.config import Settings
    from maljan.providers.static.ghidra import GhidraStaticProvider

    provider = GhidraStaticProvider.from_settings(Settings(_env_file=None))
    assembled = _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL
    assert assembled == _golden("static_isr_system_ghidra.txt")


def test_the_module_constant_is_still_the_assembled_prompt():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")
```

Append to `tests/providers/static/test_ghidra_provider.py`:

```python
def test_the_analyst_asks_the_provider_for_tools(monkeypatch):
    """``_initialize_mcp_client`` resolves a provider and does nothing else."""
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    calls: list[str] = []

    class _Provider:
        id = "ghidra"
        capabilities = StaticCapabilities(provides_tools=True, supports_tool_curation=True)

        def open(self, job):
            calls.append("open")

        def get_tools(self):
            calls.append("get_tools")
            return [_Tool("load_program"), _Tool("list_imports")]

        def select_tools(self, tools, categories=None):
            calls.append("select_tools")
            return list(tools)

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = _Provider()
    analyst._container = container
    analyst._initialize_mcp_client()
    assert calls == ["open", "get_tools", "select_tools"]
    assert [t.name for t in analyst.tools] == ["load_program", "list_imports"]


def test_a_provider_without_tools_leaves_the_analyst_toolless():
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    class _Evidence:
        id = "capa_yara"
        capabilities = StaticCapabilities(provides_evidence=True, degrade_on_failure=True)

        def open(self, job):
            raise AssertionError("open must not be called for a toolless provider")

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = _Evidence()
    analyst._container = container
    analyst._initialize_mcp_client()
    assert analyst.tools == []


def test_static_still_fails_loudly_and_a_degrading_provider_does_not(monkeypatch):
    from unittest.mock import MagicMock

    from maljan.agents.static_analyst import StaticAnalyst
    from maljan.providers.base import StaticCapabilities

    analyst = StaticAnalyst(llm=MagicMock(), name="static")

    def boom():
        raise RuntimeError("ghidra is unreachable")

    monkeypatch.setattr(analyst, "_initialize_mcp_client", boom)
    monkeypatch.setattr(
        analyst, "_static_capabilities", lambda: StaticCapabilities(degrade_on_failure=False)
    )
    with pytest.raises(RuntimeError):
        analyst._try_initialize_mcp()

    monkeypatch.setattr(
        analyst, "_static_capabilities", lambda: StaticCapabilities(degrade_on_failure=True)
    )
    assert analyst._try_initialize_mcp() is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers/static/test_ghidra_provider.py -q`
Expected: FAIL — `ImportError: cannot import name '_ISR_HEAD'`.

- [ ] **Step 3: Split the prompt**

```python
# The provider-independent head of the static system prompt. Everything that
# names a tool lives in the provider's fragment, so attaching radare2 or capa
# changes the middle and nothing else. A golden test pins the assembled result
# byte for byte against the prompt this project measured its evaluation on.
_ISR_HEAD = (
    "You are an expert Static Malware Analyst with 15 years of reverse engineering experience. "
)

# Empty today. Declared because the assembly order is the contract sub-projects
# B and C build agent prompts from, and an implicit empty tail is a trap.
_ISR_TAIL = ""


def _static_prompt(provider: Any | None = None) -> str:
    """Assemble the static system prompt for ``provider`` (the configured one by default)."""
    if provider is None:
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        provider = get_static_provider(get_settings())
    return _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL


# Back-compat: several modules and tests import this name. It is the default
# profile's assembled prompt, which is what it always was.
_ISR_SYSTEM = _static_prompt()
```
`analyze` and `analyze_isr` build their system turn with `_static_prompt(self._provider())` rather than the module constant, so a per-job provider override reaches the prompt; `revise_isr` keeps `_ISR_SYSTEM + "\n\n" + ...` unchanged.

Because `_ISR_SYSTEM` is now computed at import time, it must not touch the network: `prompt_fragment()` returns a module constant and `get_static_provider` only constructs an object, so import stays cheap — assert that with `test_the_module_constant_is_still_the_assembled_prompt` running in a bare process.

- [ ] **Step 4: Shrink `_initialize_mcp_client`**

```python
    def _provider(self) -> Any:
        """The static provider for this run: the container's, or one built ad hoc."""
        container = getattr(self, "_container", None)
        if container is not None:
            return container.get_static_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        return get_static_provider(get_settings())

    def _initialize_mcp_client(self) -> None:
        """Attach the configured static provider's tools. Idempotent per sample.

        Everything this used to do — transports, clients, guardrails, the shared
        agent loop — moved into ``GhidraStaticProvider.open``. What is left is
        the analyst's half of the contract: ask, and narrow.
        """
        provider = self._provider()
        if not provider.capabilities.provides_tools:
            self.logger.info("Static provider '%s' exposes no tools.", provider.id)
            self.tools = []
            return
        provider.open(self._job_context())
        pool = provider.get_tools()
        self._all_ghidra_tools = pool          # kept: the report and tests read this name
        self.toolkit = getattr(provider, "toolkit", None)
        self.tools = provider.select_tools(pool, getattr(self, "_sample_categories", None))
        self.logger.info(
            "Static provider '%s': %d/%d tools attached.", provider.id, len(self.tools), len(pool)
        )

    def _job_context(self) -> StaticJobContext:
        from maljan.core.config import get_settings

        cfg = get_settings()
        guardrail = None
        if cfg.preprocessing.use_function_summarizer:
            container = getattr(self, "_container", None)
            if container is not None:
                summarizer = container.get_function_summarizer()
                if summarizer is not None:
                    guardrail = summarizer.summarize_chunk
        return StaticJobContext(
            host_sample_path=getattr(self, "_host_sample_path", None),
            mirror_sample_path=getattr(self, "_analysis_file_path", None),
            capability_categories=frozenset(getattr(self, "_sample_categories", None) or ()),
            output_guardrail=guardrail,
            max_output_chars=cfg.preprocessing.max_tool_output_chars,
            truncation_ledger=getattr(self, "truncation_ledger", None),
        )
```
The container reuse comment from the old body (a fresh `ServiceContainer` per chunk rebuilt the 2651-rule Sigma layer) moves into `_job_context` with it.

- [ ] **Step 5: Make the degrade policy a capability read**

In `base_agent.py::_try_initialize_mcp`, replace the prose about static being the exception with one read and keep the rest:

```python
        capabilities = self._static_capabilities()
        try:
            self._initialize_mcp_client()
            return bool(self.tools)
        except Exception as exc:
            if capabilities is not None and not capabilities.degrade_on_failure:
                # Ghidra IS the static evidence: a toolless run would produce a
                # confident-looking report grounded in nothing. Fail loudly.
                raise
            self.logger.warning(
                "%s MCP initialization failed (graceful degradation, continuing without tools): %s",
                self.name,
                describe_exception(exc),
            )
            return False

    def _static_capabilities(self) -> Any | None:
        """The provider's degrade policy, or None for an analyst without a provider."""
        return None
```
`StaticAnalyst` overrides `_static_capabilities` to return `self._provider().capabilities`; the dynamic analyst overrides it to return `self._sandbox_capabilities()` in Task 11. Both `tests/unit/agents/test_static_bug07.py` and `tests/unit/agents/test_dynamic_degrades_without_cape.py` keep passing untouched.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers tests/unit/agents/test_static_bug07.py tests/unit/agents/test_dynamic_degrades_without_cape.py tests/unit/test_load_program_pinning.py tests/unit/test_wave6_ghidra_delivery.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/agents/static_analyst.py src/maljan/agents/base_agent.py src/maljan/providers/static/ghidra.py
uv run ruff format --check src/maljan/agents/static_analyst.py src/maljan/agents/base_agent.py src/maljan/providers/static/ghidra.py
uv run mypy src/ apps/api/
git add src/maljan/agents/static_analyst.py src/maljan/agents/base_agent.py src/maljan/providers/static/ghidra.py tests/agents/test_prompt_byte_identity.py tests/providers/static/test_ghidra_provider.py
git commit -m "refactor(static): the analyst takes its prompt fragment, tools and degrade policy from the provider"
```

---

### Task 11: Dynamic analyst decoupling

**Files:**
- Modify: `src/maljan/agents/dynamic_analyst.py:17-37` (prompt split), `:48-144` (`_initialize_mcp_client` shrinks), `src/maljan/providers/sandbox/cape2.py` (`CAPE_PROMPT_FRAGMENT`, `dynamic_tools`, `dynamic_prompt_fragment`)
- Test: `tests/agents/test_prompt_byte_identity.py` (extended), `tests/providers/sandbox/test_cape2_provider.py` (extended), `tests/unit/agents/test_dynamic_degrades_without_cape.py` (unchanged, must stay green)

**The prompt cut.** `dynamic_analyst._ISR_SYSTEM` (lines 17–37) splits cleanly at the workflow marker, because its head names no tool:

- `_DYN_HEAD` keeps **lines 18–24**, first line `"You are an expert Dynamic Malware Analyst with deep knowledge of sandbox behavior. "`, last line `"T1059 (Command Execution), T1112 (Registry Modification).\n\n"`.
- `CAPE_PROMPT_FRAGMENT` is **lines 25–36 cut verbatim** into `providers/sandbox/cape2.py`. First line: `"=== TOOL USAGE WORKFLOW ===\n"`. Last line: `"If given a Task ID directly, skip to step 5."`.
- `_DYN_TAIL = ""`; `_ISR_SYSTEM = _DYN_HEAD + provider.dynamic_prompt_fragment() + _DYN_TAIL`.

**Interfaces:**
- Produces: `CAPE2SandboxProvider.dynamic_tools() -> list[BaseTool]`, `.dynamic_prompt_fragment() -> str`, `.CAPE_PROMPT_FRAGMENT`; `MockSandboxProvider.dynamic_prompt_fragment() -> ""` (no tools, no workflow).
- Consumes: `container.get_sandbox_provider()`, `SandboxCapabilities.provides_tools`, `.degrade_on_failure`.

**A fact that contradicts a comment.** `dynamic_analyst.py:117` reads `getattr(cfg.mcp.cape, "tools", [])`, but `MCPServerConfig` has no `tools` field, so the "config-driven" allow-list has always been the 13 built-in essentials. The move preserves that behaviour exactly: `CAPE_ESSENTIAL_TOOLS` is the allow-list, and the `getattr` is deleted rather than carried forward as a lie. `MCPServerConfig.tools` is a sub-project B field (spec §13); when it lands, the provider reads it here.

- [ ] **Step 1: Write the failing tests**

Append to `tests/agents/test_prompt_byte_identity.py`:

```python
def test_the_assembled_dynamic_prompt_equals_the_golden():
    from maljan.agents.dynamic_analyst import _DYN_HEAD, _DYN_TAIL
    from maljan.core.config import Settings
    from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    assert _DYN_HEAD + provider.dynamic_prompt_fragment() + _DYN_TAIL == _golden(
        "dynamic_system_cape2.txt"
    )
```

Append to `tests/providers/sandbox/test_cape2_provider.py`:

```python
def test_dynamic_tools_are_the_thirteen_essentials():
    class _T:
        def __init__(self, name):
            self.name = name

    class _Toolkit:
        def get_tools(self):
            return [_T(n) for n in CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS] + [_T("extra_tool")]

    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    provider = CAPE2SandboxProvider.from_settings(cfg)
    provider._toolkit = _Toolkit()
    assert {t.name for t in provider.dynamic_tools()} == set(
        CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS
    )


def test_a_disabled_cape_mcp_yields_no_tools_and_no_workflow():
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = False
    provider = CAPE2SandboxProvider.from_settings(cfg)
    assert provider.dynamic_tools() == []
    # The prompt fragment is a property of the sandbox, not of its MCP server:
    # the workflow text is what the analyst was measured with either way.
    assert provider.dynamic_prompt_fragment() == CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT


def test_the_mock_provider_offers_no_tool_workflow():
    from maljan.providers.sandbox.mock import MockSandboxProvider

    provider = MockSandboxProvider.from_settings(Settings(_env_file=None))
    assert provider.dynamic_tools() == []
    assert provider.dynamic_prompt_fragment() == ""
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers/sandbox -q`
Expected: FAIL — `ImportError: cannot import name '_DYN_HEAD'`.

- [ ] **Step 3: Move the CAPE init into the provider**

`CAPE2SandboxProvider.dynamic_tools()` is `dynamic_analyst._initialize_mcp_client` lines 52–144 with three mechanical edits: `cfg.mcp.cape` becomes `self._cfg.mcp`; `self.logger` becomes the module `logger`; the `configured = list(getattr(cfg.mcp.cape, "tools", []) or [])` branch collapses to `CAPE_ESSENTIAL_TOOLS`. The http/stdio branch, the empty-url guard, the `cwd=project_root` for stdio and the shared-loop `_run_coro_blocking(..., label="cape-mcp-init")` with its comment move unchanged. The `Initialized CAPEv2 MCP tools: %d/%d (essential only): %s` log line keeps its wording.

The analyst becomes:

```python
    def _sandbox_provider(self) -> Any:
        container = getattr(self, "_container", None)
        if container is not None:
            return container.get_sandbox_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_sandbox_provider

        return get_sandbox_provider(get_settings())

    def _static_capabilities(self) -> Any:
        # Read by BaseAnalyst._try_initialize_mcp. Every sandbox degrades: the
        # report JSON in ``data`` is evidence on its own, so an unreachable
        # tool server costs depth, not the analyst.
        return self._sandbox_provider().capabilities

    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return
        provider = self._sandbox_provider()
        if not provider.capabilities.provides_tools:
            self.logger.info("Sandbox provider '%s' exposes no tools.", provider.id)
            return
        self.tools = provider.dynamic_tools()
        self.toolkit = getattr(provider, "_toolkit", None)
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers tests/unit/agents/test_dynamic_degrades_without_cape.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/agents/dynamic_analyst.py src/maljan/providers/sandbox/cape2.py src/maljan/providers/sandbox/mock.py
uv run ruff format --check src/maljan/agents/dynamic_analyst.py src/maljan/providers/sandbox/cape2.py src/maljan/providers/sandbox/mock.py
uv run mypy src/ apps/api/
git add src/maljan/agents/dynamic_analyst.py src/maljan/providers/sandbox tests/agents/test_prompt_byte_identity.py tests/providers/sandbox
git commit -m "refactor(dynamic): the analyst takes its CAPE workflow and tools from the sandbox provider"
```

---

### Task 12: Function hashes and the sample mirror become capabilities

**Files:**
- Modify: `src/maljan/pipeline/nodes.py:1516-1524` (the function-hash gate), `src/maljan/agents/static_analyst.py:540-556` (the pre-pass gate), `apps/api/app/worker/analysis_worker.py:517-556` (the mirror), `src/maljan/core/config.py` (`MCPConfig.ghidra` and `.cape` removed together with the `model_post_init` mirror)
- Test: `tests/providers/test_capability_gates.py`, `tests/unit/api/test_worker_mirror.py`

**Interfaces:**
- Consumes: `StaticCapabilities.provides_function_hashes`, `.needs_sample_mirror`, `StaticProvider.function_hashes`, `.mirror_spec()`
- Produces: no new names. This task is a subtraction: after it, `grep -rn "mcp\.ghidra\|mcp\.cape" src apps/api` returns only the alias table in `config.py` and the two provider modules.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/test_capability_gates.py
"""Nothing outside the providers names a provider."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {
    "src/maljan/core/config.py",                    # the alias table
    "src/maljan/providers/static/ghidra.py",
    "src/maljan/providers/sandbox/cape2.py",
}


def test_no_module_outside_the_providers_reads_the_legacy_mcp_paths():
    out = subprocess.run(
        ["grep", "-rn", r"mcp\.ghidra\|mcp\.cape", "src", "apps/api"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    offenders = {line.split(":", 1)[0] for line in out.splitlines() if line.strip()}
    assert offenders <= ALLOWED, sorted(offenders - ALLOWED)


def test_the_function_hash_gate_is_a_capability_read():
    source = (ROOT / "src" / "maljan" / "pipeline" / "nodes.py").read_text(encoding="utf-8")
    assert "provides_function_hashes" in source
    assert 'transport == "http"' not in source


def test_the_mirror_gate_is_a_capability_read():
    source = (
        ROOT / "apps" / "api" / "app" / "worker" / "analysis_worker.py"
    ).read_text(encoding="utf-8")
    assert "needs_sample_mirror" in source
    assert "ghidra_container_samples_path" in source, "the compose bind mount is still the path"
```

```python
# tests/unit/api/test_worker_mirror.py
"""The mirror runs when the provider needs one, and not otherwise."""

from __future__ import annotations

import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import mirror_target_for  # noqa: E402


class _Caps:
    def __init__(self, needed):
        self.needs_sample_mirror = needed


class _Provider:
    def __init__(self, needed, spec):
        self.capabilities = _Caps(needed)
        self._spec = spec

    def mirror_spec(self):
        return self._spec


def test_no_mirror_when_the_provider_does_not_need_one():
    assert mirror_target_for(_Provider(False, None), sha256="a" * 64, extension=".exe") is None


def test_the_mirror_path_comes_from_the_provider_spec():
    from maljan.providers.base import MirrorSpec

    spec = MirrorSpec(work_subdir=".work", container_prefix="/data/samples")
    host, container = mirror_target_for(_Provider(True, spec), sha256="b" * 64, extension=".exe")
    assert host.name == f"{'b' * 64}.exe"
    assert host.parent.name == ".work"
    assert container == f"/data/samples/.work/{'b' * 64}.exe"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/test_capability_gates.py tests/unit/api/test_worker_mirror.py -q`
Expected: FAIL — `ImportError: cannot import name 'mirror_target_for'`, and the grep test lists `src/maljan/pipeline/nodes.py`, `src/maljan/agents/static_analyst.py`, `apps/api/app/worker/analysis_worker.py`.

- [ ] **Step 3: Re-gate the function-hash attribution**

`nodes.py:1516-1524` becomes:

```python
                _provider = container.get_static_provider()
                _static_path = state.get("static_sample_path")
                if (
                    _cfg.preprocessing.use_function_hash_attribution
                    and _provider.capabilities.provides_function_hashes
                    and _cfg.memory.backend == "qdrant"
                    and _static_path
                ):
                    # unchanged: the FunctionHashStore import and construction
                    _funcs = _provider.function_hashes(
                        StaticJobContext(mirror_sample_path=str(_static_path))
                    )
```
The `FunctionHashStore` read side, the family gate on the write side and the fail-safe `except` are unchanged. `static_analyst._compute_function_hash_hint` gets the same treatment: `if cfg.mcp.ghidra.transport != "http": return ""` becomes `if not self._provider().capabilities.provides_function_hashes: return ""`, and the `fetch_bulk_function_hashes(...)` call becomes `self._provider().function_hashes(...)`. `_compute_sink_priority_hint` keeps its own `transport != "http"` guard but reads it from `cfg.static.ghidra.transport` — it drives the Ghidra REST API directly and is Ghidra-specific by construction; a one-line comment says so and points at sub-project C.

- [ ] **Step 4: Re-gate the worker's mirror**

Add the helper next to `build_job_settings` and call it in place of the inline Ghidra block:

```python
def mirror_target_for(
    provider: Any, *, sha256: str, extension: str
) -> tuple[Path, str] | None:
    """Where this sample has to be copied for the static provider to read it.

    Returns (host path, container-visible path), or None when the provider does
    not need a copy at all — a capa/YARA or radare2 run that reads the bytes in
    place, and every future provider that does the same. The host directory and
    its 0o700/0o600 handling stay in ``sample_files``; only the decision moved.
    """
    from app.worker import sample_files

    if not provider.capabilities.needs_sample_mirror:
        return None
    spec = provider.mirror_spec()
    if spec is None:
        return None
    host = sample_files.work_dir() / f"{sha256}{extension}"
    container = f"{settings.ghidra_container_samples_path.rstrip('/')}/{spec.work_subdir}/{sha256}{extension}"
    return host, container
```
and in `analysis_worker.py:517-546`:

```python
                target = mirror_target_for(
                    container.get_static_provider(), sha256=sample.sha256, extension=_orig_ext
                )
                if target is None:
                    logger.info(
                        "Static provider needs no sample mirror; skipping the copy.",
                        extra={"job_id": job_id, "component": "sample-mirror"},
                    )
                else:
                    host_mirror, static_sample_path = target
                    sample_files.private_copy(Path(temp_path), host_mirror)
                    logger.info(
                        "Mirrored sample to %s for the static provider (%s).",
                        host_mirror, static_sample_path,
                        extra={"job_id": job_id, "component": "sample-mirror"},
                    )
```
The surrounding `try`/`except Exception as mirror_exc` with its "Static analyst will fall back to metadata-only prompt" warning stays, as does the `finally` that removes the mirror at job end.

- [ ] **Step 5: Delete the transitional mirror**

Remove `MCPConfig.ghidra`, `MCPConfig.cape` and the `model_post_init` block Task 2 added; `MCPConfig` becomes an empty model with a docstring saying sub-project B fills it with `servers: dict[str, MCPServerConfig]`. Delete the `mcp.ghidra.*` and `mcp.cape.*` entries from `ANNOTATIONS` (18 of them) — the leaves are gone, so `test_every_leaf_is_annotated_and_no_annotation_is_orphaned` fails on the orphans otherwise. The alias table keeps translating `MCP__GHIDRA__*` and `MCP__CAPE__*`, so the environment contract is unchanged; only the settings *paths* are gone.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/providers tests/unit/api/test_worker_mirror.py tests/unit/core/test_settings_catalog.py tests/unit/core/test_settings_aliases.py tests/unit/agents tests/unit/test_wave6_ghidra_delivery.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan apps/api/app/worker/analysis_worker.py tests/providers tests/unit/api/test_worker_mirror.py
uv run ruff format --check src/maljan apps/api/app/worker/analysis_worker.py tests/providers tests/unit/api/test_worker_mirror.py
uv run mypy src/ apps/api/
git add src/maljan/pipeline/nodes.py src/maljan/agents/static_analyst.py src/maljan/core/config.py src/maljan/core/settings_annotations.py apps/api/app/worker/analysis_worker.py tests/providers/test_capability_gates.py tests/unit/api/test_worker_mirror.py
git commit -m "refactor(pipeline): gate function hashes and the sample mirror on provider capabilities"
```

---

### Task 13: The null and generic-MCP static providers

**Files:**
- Create: `src/maljan/providers/static/null.py`, `src/maljan/providers/static/generic_mcp.py` (replacing the Task 5 stubs)
- Test: `tests/providers/static/test_null_provider.py`, `tests/providers/static/test_generic_mcp_provider.py`

**Interfaces:**
- Produces:
  ```python
  @register_static_provider("none")
  class NullStaticProvider(StaticProvider)          # every capability False
  @register_static_provider("generic_mcp")
  class GenericMCPStaticProvider(StaticProvider):
      def __init__(self, cfg: MCPServerConfig, *, label: str = "MCP",
                   allowed_tools: frozenset[str] | None = None,
                   prompt_fragment_text: str = "") -> None
  ```
  `GenericMCPStaticProvider` is the class Task 18's `R2StaticProvider` subclasses with defaults, so its constructor takes the three things a specific tool server differs in.
- Consumes: `maljan.agents.mcp_client.MCPLangChainToolkit`, `maljan.agents.subprocess_env.child_env`, `maljan.core.paths.resolve_mcp_args`, `maljan.agents.base_agent._run_coro_blocking`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/static/test_null_provider.py
"""``static.provider=none`` is an analyst with no tools and no evidence."""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.core.config import Settings
from maljan.providers.registry import get_static_provider


def _cfg():
    cfg = Settings(_env_file=None)
    cfg.static.provider = "none"
    return cfg


def test_every_capability_is_off():
    caps = get_static_provider(_cfg()).capabilities
    assert not any(vars(caps).values()) if hasattr(caps, "__dict__") else True
    assert caps.provides_tools is False
    assert caps.provides_evidence is False
    assert caps.provides_function_hashes is False
    assert caps.needs_sample_mirror is False
    assert caps.supports_tool_curation is False


def test_it_degrades_rather_than_raising():
    assert get_static_provider(_cfg()).capabilities.degrade_on_failure is True


def test_the_analyst_runs_toolless_and_says_so(caplog):
    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = get_static_provider(_cfg())
    analyst._container = container
    with caplog.at_level("INFO"):
        analyst._initialize_mcp_client()
    assert analyst.tools == []
    assert any("exposes no tools" in r.getMessage() for r in caplog.records)


def test_its_prompt_fragment_keeps_the_provider_neutral_instructions():
    fragment = get_static_provider(_cfg()).prompt_fragment()
    assert "cite a concrete artifact" in fragment
    assert "Ghidra" not in fragment
    assert "load_program" not in fragment
```

```python
# tests/providers/static/test_generic_mcp_provider.py
"""Any MCP server attaches as a static provider through settings alone."""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider


class _T:
    def __init__(self, name):
        self.name = name


def _cfg(**over):
    cfg = Settings(_env_file=None)
    cfg.static.provider = "generic_mcp"
    cfg.static.generic.enabled = True
    cfg.static.generic.command = "my-mcp"
    cfg.static.generic.args = ["--stdio"]
    for k, v in over.items():
        setattr(cfg.static.generic, k, v)
    return cfg


def test_capabilities():
    caps = GenericMCPStaticProvider.from_settings(_cfg()).capabilities
    assert caps.provides_tools and caps.supports_tool_curation and caps.needs_sample_mirror
    assert caps.degrade_on_failure is True, "an operator's own server must not fail a run"
    assert caps.provides_function_hashes is False


def test_curated_mode_without_an_allow_list_keeps_everything():
    provider = GenericMCPStaticProvider.from_settings(_cfg(tool_selection="curated"))
    tools = [_T("a"), _T("b")]
    assert len(provider.select_tools(tools)) == 2


def test_an_allow_list_narrows_the_manifest():
    provider = GenericMCPStaticProvider(
        _cfg().static.generic, label="Test MCP", allowed_tools=frozenset({"keep"})
    )
    assert [t.name for t in provider.select_tools([_T("keep"), _T("drop")])] == ["keep"]


def test_a_disabled_server_attaches_nothing():
    provider = GenericMCPStaticProvider.from_settings(_cfg(enabled=False))
    provider.open(StaticJobContext())
    assert provider.get_tools() == []
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/static -q`
Expected: FAIL — `NotImplementedError` from the stubs.

- [ ] **Step 3: Write `null.py`**

```python
@register_static_provider("none")
class NullStaticProvider(StaticProvider):
    """No static tool at all.

    The honest choice when a deployment has no reverse-engineering server: the
    analyst reasons over the deterministic PE extraction it already receives,
    and nothing pretends a tool loop happened. Its prompt fragment keeps the
    provider-neutral instructions (cite a concrete artifact, the four ATT&CK
    techniques) and drops every tool name, so the model is not told to call
    tools it does not have.
    """

    NO_TOOLS_FRAGMENT: ClassVar[str] = (
        "Analyze the deterministic static evidence you are given. "
        "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
        "string offset (.data+0xNN), API import, or hex pattern. "
        "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
        "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
        "You have no analysis tools in this configuration. Do not describe tool "
        "calls you did not make, and do not claim analysis was impossible: the "
        "extracted imports, sections and strings are real evidence."
    )

    @classmethod
    def from_settings(cls, cfg: Settings) -> NullStaticProvider:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(degrade_on_failure=True)

    def prompt_fragment(self) -> str:
        return self.NO_TOOLS_FRAGMENT
```

- [ ] **Step 4: Write `generic_mcp.py`**

The stdio and http attach paths are the same shape as the Ghidra provider's, built from `MCPLangChainToolkit` and `child_env` / `resolve_mcp_args`, initialised through `_run_coro_blocking(..., label=f"{self._label}-mcp-init")` on the shared agent loop. Selection is: `all` keeps everything, `curated` keeps `allowed_tools` (everything when the set is empty), `dynamic` falls back to `curated` because a generic server has no capability-keyword map. `prompt_fragment()` returns `prompt_fragment_text` when the caller supplied one and otherwise a generated paragraph naming the server's tools:

```python
    def prompt_fragment(self) -> str:
        if self._prompt_fragment_text:
            return self._prompt_fragment_text
        names = [t.name for t in self.get_tools()]
        listed = ", ".join(f"`{n}`" for n in names[:20]) if names else "the tools you are given"
        return (
            f"Analyze the binary using the {self._label} tools available to you. "
            "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
            "string offset (.data+0xNN), API import, or hex pattern. "
            "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
            "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
            "=== TOOL USAGE WORKFLOW ===\n"
            f"Available tools: {listed}.\n"
            "Load or open the sample first, enumerate what the binary imports and "
            "contains, then examine the few most suspicious functions in depth. "
            "Prefer one summarising call over many narrow ones.\n"
        )
```

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/providers -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/static tests/providers/static
uv run ruff format --check src/maljan/providers/static tests/providers/static
uv run mypy src/ apps/api/
git add src/maljan/providers/static/null.py src/maljan/providers/static/generic_mcp.py tests/providers/static/test_null_provider.py tests/providers/static/test_generic_mcp_provider.py
git commit -m "feat(providers): the null static provider and the generic MCP static adapter"
```

---

### Task 14: Sandbox-report upload — table, storage and API

**Files:**
- Create: `apps/api/app/models/sandbox_report.py`, `apps/api/alembic/versions/20260904000000_add_sandbox_reports.py`, `apps/api/app/api/v1/sandbox_reports.py`
- Modify: `apps/api/app/schemas/job.py` (three response models), `apps/api/app/main.py` (router include, next to the samples router), `apps/api/app/models/sample.py` (the `sandbox_reports` relationship)
- Test: `tests/api/test_sandbox_report_upload.py`, `tests/unit/api/test_sandbox_report_sniff.py`

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/models/sandbox_report.py
  class SandboxReportRow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
      __tablename__ = "sandbox_reports"
      sample_id: uuid.UUID          # FK samples.id, ondelete CASCADE, indexed
      storage_path: str             # sandbox-reports/{sha[:2]}/{sha}/{report_id}.json
      format: str                   # cape2 | cuckoo | triage
      task_id: str | None
      size_bytes: int
      sha256_of_blob: str
      uploaded_by: uuid.UUID        # FK users.id
  ```
  ```python
  # apps/api/app/schemas/job.py
  class SandboxReportResponse(BaseModel):
      id: uuid.UUID; format: str; task_id: str | None; size_bytes: int
      sample_sha256_match: bool; warning: str | None = None
      uploaded_at: datetime = Field(validation_alias="created_at")
  class SandboxReportListResponse(BaseModel):
      items: list[SandboxReportResponse]; total: int
  ```
  Routes: `POST /api/v1/samples/{sample_id}/sandbox-reports` (multipart `file`), `GET /api/v1/samples/{sample_id}/sandbox-reports`, `DELETE /api/v1/samples/{sample_id}/sandbox-reports/{report_id}`.
- Consumes: `maljan.providers.sandbox.formats.sniff_format`, `maljan.core.config.get_settings().sandbox.upload`, the MinIO client style of `apps/api/app/api/v1/samples.py:43-61`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_sandbox_report_upload.py
"""Uploading a sandbox report: limits, sniffing, storage and the hash warning."""

from __future__ import annotations

import gzip
import io
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import sandbox_reports as module  # noqa: E402

SHA = "a" * 64


def _cape_blob(sha: str = SHA) -> bytes:
    return json.dumps(
        {
            "info": {"version": "CAPEv2 2.4", "id": 4242},
            "target": {"sha256": sha, "name": "x.exe", "md5": "b" * 32},
            "behavior": {"processes": [], "apistats": {}, "generic": []},
            "signatures": [],
            "network": {},
            "CAPE": {"payloads": []},
        }
    ).encode()


@pytest.fixture
def client(monkeypatch, tmp_path):
    from app.database import get_db
    from app.deps import get_current_user

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256=SHA, uploaded_by=user.id)
    db = MagicMock()
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    stored: dict[str, bytes] = {}
    monkeypatch.setattr(module, "_put_object", lambda path, blob, **kw: stored.setdefault(path, blob))
    monkeypatch.setattr(module, "_persist", MagicMock(side_effect=lambda db, row: row))
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    yield TestClient(app), sample, stored


def test_a_cape_json_is_accepted_and_sniffed(client):
    api, sample, stored = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob(), "application/json")},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["format"] == "cape2"
    assert body["task_id"] == "4242"
    assert body["sample_sha256_match"] is True
    assert body["warning"] is None
    assert any(p.startswith(f"sandbox-reports/{SHA[:2]}/{SHA}/") for p in stored)


def test_a_gzipped_report_is_inflated_and_stored_as_json(client):
    api, sample, stored = client
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(_cape_blob())
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json.gz", buf.getvalue(), "application/gzip")},
    )
    assert r.status_code == 201
    assert json.loads(next(iter(stored.values())))["info"]["id"] == 4242


def test_a_hash_mismatch_is_a_warning_and_not_a_refusal(client):
    api, sample, _ = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob("c" * 64), "application/json")},
    )
    assert r.status_code == 201
    assert r.json()["sample_sha256_match"] is False
    assert "does not match" in r.json()["warning"]


def test_an_unrecognised_format_is_refused(client):
    api, sample, _ = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("x.json", b'{"hello": "world"}', "application/json")},
    )
    assert r.status_code == 415
    assert "cape2" in r.json()["detail"]


def test_a_non_json_body_is_refused_before_anything_is_stored(client):
    api, sample, stored = client
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("x.json", b"not json at all", "application/json")},
    )
    assert r.status_code == 400
    assert stored == {}


def test_the_size_cap_is_enforced_while_streaming(client, monkeypatch):
    api, sample, stored = client
    monkeypatch.setattr(module, "_max_report_bytes", lambda: 64)
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json", _cape_blob(), "application/json")},
    )
    assert r.status_code == 413
    assert stored == {}


def test_the_inflated_size_cap_is_enforced_too(client, monkeypatch):
    api, sample, stored = client
    monkeypatch.setattr(module, "_max_report_bytes", lambda: 4096)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b'{"info": {"version": "CAPEv2"}, "pad": "' + b"A" * 200_000 + b'"}')
    r = api.post(
        f"/api/v1/samples/{sample.id}/sandbox-reports",
        files={"file": ("report.json.gz", buf.getvalue(), "application/gzip")},
    )
    assert r.status_code == 413
    assert stored == {}
```

`tests/unit/api/test_sandbox_report_sniff.py` covers `_read_payload` alone: a `.json.gz` whose magic bytes are not gzip is treated as plain JSON, a UTF-8 BOM is tolerated, and a top-level JSON list is refused with 400.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/api/test_sandbox_report_upload.py tests/unit/api/test_sandbox_report_sniff.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.api.v1.sandbox_reports'`.

- [ ] **Step 3: Write the model and the migration**

```python
# apps/api/app/models/sandbox_report.py
"""A sandbox report an operator uploaded for a sample.

The bytes live in MinIO under a sha-derived path, not in the database: a CAPE
report is routinely tens of megabytes and this row is metadata. Storage is keyed
by the *sample's* sha256 so a report can never be written outside its sample's
prefix, and by the report id so a sample can carry several (a second detonation,
a colleague's run).
"""

import uuid

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class SandboxReportRow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "sandbox_reports"

    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False
    )
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    task_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_of_blob: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )

    sample = relationship("Sample", back_populates="sandbox_reports")
```

```python
# apps/api/alembic/versions/20260904000000_add_sandbox_reports.py
"""Add ``sandbox_reports`` — operator-uploaded sandbox reports.

The upload sandbox provider runs no detonation of its own: the operator brings
a report from whatever sandbox they already run, and the job reads it instead of
submitting. This table is the metadata; the bytes are in object storage.

Revision ID: 20260904000000
Revises: 20260903000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260904000000"
down_revision = "20260903000000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_reports",
        sa.Column(
            "id", postgresql.UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "sample_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("samples.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("task_id", sa.String(128), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_of_blob", sa.String(64), nullable=False),
        sa.Column(
            "uploaded_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_sandbox_reports_sample_id", "sandbox_reports", ["sample_id"])


def downgrade() -> None:
    op.drop_index("ix_sandbox_reports_sample_id", table_name="sandbox_reports")
    op.drop_table("sandbox_reports")
```
(`gen_random_uuid()` matches the default the other tables use through `UUIDPrimaryKeyMixin`; check that mixin and copy whichever server default it declares.)

- [ ] **Step 4: Write the route**

```python
# apps/api/app/api/v1/sandbox_reports.py
"""Upload, list and delete the sandbox reports attached to a sample.

The sandbox provider ``upload`` reads these instead of detonating: a shop that
already runs its own sandbox brings the report it has. Validation is layered so
nothing is stored before it is known to be a sandbox report: stream to a size
cap, inflate a gzip under the same cap, parse the JSON, sniff the format, and
only then put the object. A ``target.sha256`` that disagrees with the sample is
a warning carried into the run summary, not a refusal — re-hashing a sample the
sandbox unpacked is a legitimate reason for the two to differ.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
import zlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from maljan.core.config import get_settings
from maljan.providers.sandbox.formats import sniff_format
from pydantic import SecretStr
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.sample import Sample
from app.models.sandbox_report import SandboxReportRow
from app.models.user import User
from app.schemas.job import SandboxReportListResponse, SandboxReportResponse

logger = get_logger("api.sandbox_reports")

router = APIRouter(prefix="/samples", tags=["Sandbox reports"])

_CHUNK = 64 * 1024


def _max_report_bytes() -> int:
    return int(get_settings().sandbox.upload.max_report_bytes)


def _allowed_formats() -> set[str]:
    return set(get_settings().sandbox.upload.allowed_formats)


def _minio_client() -> Any:
    from minio import Minio

    raw = settings.minio_secret_key
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw),
        secure=settings.minio_secure,
    )


def _put_object(path: str, blob: bytes, *, content_type: str = "application/json") -> None:
    import io as _io

    client = _minio_client()
    if not client.bucket_exists(settings.minio_bucket):
        client.make_bucket(settings.minio_bucket)
    client.put_object(
        settings.minio_bucket, path, _io.BytesIO(blob), length=len(blob), content_type=content_type
    )


def get_object(path: str) -> bytes:
    """Read an uploaded report back. The worker calls this, hence the public name."""
    response = _minio_client().get_object(settings.minio_bucket, path)
    try:
        return bytes(response.read())
    finally:
        response.close()
        response.release_conn()


def _read_payload(file: UploadFile, filename: str) -> tuple[bytes, dict[str, Any]]:
    """Stream, size-cap, inflate and parse. Returns (canonical json bytes, payload)."""
    limit = _max_report_bytes()
    raw = bytearray()
    while True:
        chunk = file.file.read(_CHUNK)
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > limit:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"Report too large. Maximum: {limit // (1024 * 1024)} MB",
            )
    body = bytes(raw)
    if body[:2] == b"\x1f\x8b":
        try:
            # Inflate incrementally so a zip bomb hits the cap instead of RAM.
            decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
            inflated = bytearray()
            for offset in range(0, len(body), _CHUNK):
                inflated.extend(decompressor.decompress(body[offset : offset + _CHUNK], limit + 1))
                if len(inflated) > limit:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"Report too large once decompressed. Maximum: "
                        f"{limit // (1024 * 1024)} MB",
                    )
            inflated.extend(decompressor.flush())
            body = bytes(inflated)
        except (zlib.error, gzip.BadGzipFile) as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "File looks gzipped but could not be decompressed"
            ) from exc
    try:
        payload = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "A sandbox report must be a JSON object"
        )
    return body, payload


def _task_id_of(payload: dict[str, Any], fmt: str) -> str | None:
    if fmt == "triage":
        sample = payload.get("sample")
        return str(sample.get("id")) if isinstance(sample, dict) and sample.get("id") else None
    info = payload.get("info")
    return str(info.get("id")) if isinstance(info, dict) and info.get("id") is not None else None


def _target_sha(payload: dict[str, Any], fmt: str) -> str:
    block = payload.get("sample") if fmt == "triage" else payload.get("target")
    return str(block.get("sha256") or "") if isinstance(block, dict) else ""


async def _load_sample(db: AsyncSession, sample_id: uuid.UUID, user: User) -> Sample:
    row = (
        await db.execute(
            select(Sample).where(Sample.id == sample_id, Sample.uploaded_by == user.id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found")
    return row


async def _persist(db: AsyncSession, row: SandboxReportRow) -> SandboxReportRow:
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return row


@router.post(
    "/{sample_id}/sandbox-reports",
    response_model=SandboxReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_sandbox_report(
    sample_id: uuid.UUID,
    file: UploadFile,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportResponse:
    sample = await _load_sample(db, sample_id, user)
    body, payload = _read_payload(file, file.filename or "report.json")
    fmt = sniff_format(payload)
    allowed = _allowed_formats()
    if fmt not in allowed:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Unrecognised sandbox report format. Accepted: {', '.join(sorted(allowed))}",
        )
    report_id = uuid.uuid4()
    storage_path = f"sandbox-reports/{sample.sha256[:2]}/{sample.sha256}/{report_id}.json"
    _put_object(storage_path, body)
    target_sha = _target_sha(payload, fmt)
    matches = bool(target_sha) and target_sha.lower() == sample.sha256.lower()
    row = await _persist(
        db,
        SandboxReportRow(
            id=report_id,
            sample_id=sample.id,
            storage_path=storage_path,
            format=fmt,
            task_id=_task_id_of(payload, fmt),
            size_bytes=len(body),
            sha256_of_blob=hashlib.sha256(body).hexdigest(),
            uploaded_by=user.id,
        ),
    )
    warning = None
    if not matches:
        warning = (
            f"The report's target sha256 ({target_sha[:12] or 'absent'}…) does not match this "
            f"sample ({sample.sha256[:12]}…). The analysis will run and say so."
        )
        logger.warning(
            "Uploaded sandbox report sha mismatch for sample %s", sample.id,
            extra={"sample_id": str(sample.id), "component": "sandbox-report"},
        )
    return SandboxReportResponse(
        id=row.id, format=row.format, task_id=row.task_id, size_bytes=row.size_bytes,
        sample_sha256_match=matches, warning=warning, created_at=row.created_at,
    )


@router.get("/{sample_id}/sandbox-reports", response_model=SandboxReportListResponse)
async def list_sandbox_reports(
    sample_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportListResponse:
    sample = await _load_sample(db, sample_id, user)
    rows = (
        (
            await db.execute(
                select(SandboxReportRow)
                .where(SandboxReportRow.sample_id == sample.id)
                .order_by(SandboxReportRow.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    items = [
        SandboxReportResponse(
            id=r.id, format=r.format, task_id=r.task_id, size_bytes=r.size_bytes,
            sample_sha256_match=True, warning=None, created_at=r.created_at,
        )
        for r in rows
    ]
    return SandboxReportListResponse(items=items, total=len(items))


@router.delete("/{sample_id}/sandbox-reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_report(
    sample_id: uuid.UUID,
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    sample = await _load_sample(db, sample_id, user)
    row = (
        await db.execute(
            select(SandboxReportRow).where(
                SandboxReportRow.id == report_id, SandboxReportRow.sample_id == sample.id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sandbox report not found")
    try:
        _minio_client().remove_object(settings.minio_bucket, row.storage_path)
    except Exception as exc:  # noqa: BLE001 — an orphaned object is not a failed delete
        logger.warning("Could not remove %s from storage: %s", row.storage_path, exc)
    await db.execute(delete(SandboxReportRow).where(SandboxReportRow.id == row.id))
```

`Sample` gains `sandbox_reports = relationship("SandboxReportRow", back_populates="sample", cascade="all, delete-orphan", lazy="selectin")`, and `main.py` includes the router beside the samples one.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/api/test_sandbox_report_upload.py tests/unit/api/test_sandbox_report_sniff.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app/api/v1/sandbox_reports.py apps/api/app/models/sandbox_report.py apps/api/alembic/versions/20260904000000_add_sandbox_reports.py apps/api/app/schemas/job.py tests/api/test_sandbox_report_upload.py
uv run ruff format --check apps/api/app/api/v1/sandbox_reports.py apps/api/app/models/sandbox_report.py apps/api/alembic/versions/20260904000000_add_sandbox_reports.py apps/api/app/schemas/job.py tests/api/test_sandbox_report_upload.py
uv run mypy src/ apps/api/
git add apps/api/app/api/v1/sandbox_reports.py apps/api/app/models/sandbox_report.py apps/api/app/models/sample.py apps/api/alembic/versions/20260904000000_add_sandbox_reports.py apps/api/app/schemas/job.py apps/api/app/main.py tests/api/test_sandbox_report_upload.py tests/unit/api/test_sandbox_report_sniff.py
git commit -m "feat(api): upload, list and delete sandbox reports for a sample"
```

---

### Task 15: `UploadSandboxProvider` and the worker's routing

**Files:**
- Create: `src/maljan/providers/sandbox/upload.py` (replacing the stub)
- Modify: `apps/api/app/worker/analysis_worker.py:43-58` (`build_job_settings`), `:330-370` (the report blob reaches the provider), `src/maljan/app.py:136-152` (the attach path)
- Test: `tests/providers/sandbox/test_upload_provider.py`, `tests/unit/api/test_worker_settings_overrides.py` (extended)

**Interfaces:**
- Produces:
  ```python
  @register_sandbox_provider("upload")
  class UploadSandboxProvider(SandboxProvider):
      def attach_report(self, blob: bytes, *, filename: str = "report.json") -> SandboxRun
      def set_pending_blob(self, blob: bytes, *, filename: str) -> None   # worker hands it over
  ```
  ```python
  # apps/api/app/worker/analysis_worker.py
  def build_job_settings(overrides, job_config) -> _CoreSettings   # folds three more keys
  ```
- Consumes: `sniff_format`, `cape_report_to_sandbox_report`, `app.api.v1.sandbox_reports.get_object`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/sandbox/test_upload_provider.py
"""No detonation: the operator's report is the run."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.upload import UploadSandboxProvider

ROOT = Path(__file__).resolve().parents[3]


def _blob() -> bytes:
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    return path.read_bytes()


def _provider() -> UploadSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "upload"
    return UploadSandboxProvider.from_settings(cfg)


def test_capabilities():
    caps = _provider().capabilities
    assert caps.accepts_uploaded_report is True and caps.can_fetch_report is True
    assert caps.can_submit is False and caps.can_poll is False and caps.can_fetch_pcap is False
    assert caps.provides_tools is False


def test_submitting_is_refused_with_a_legible_message():
    with pytest.raises(ProviderError) as exc:
        _provider().submit("/tmp/sample.exe")
    assert "does not detonate" in str(exc.value)


def test_a_cape_upload_re_sniffs_and_keeps_identity():
    raw = json.loads(_blob().decode())
    run = _provider().attach_report(_blob(), filename="report.json")
    assert run.report.source_format == "cape2"
    assert run.status == "reported"
    assert to_cape_shaped_dict(run.report) == raw
    assert run.sample_sha256 == raw["target"]["sha256"]


def test_a_format_outside_the_allow_list_is_refused():
    cfg = Settings(_env_file=None)
    cfg.sandbox.upload.allowed_formats = ["triage"]
    provider = UploadSandboxProvider.from_settings(cfg)
    with pytest.raises(ProviderError) as exc:
        provider.attach_report(_blob(), filename="report.json")
    assert "cape2" in str(exc.value)


def test_fetch_returns_the_attached_run():
    provider = _provider()
    provider.set_pending_blob(_blob(), filename="report.json")
    assert provider.fetch("uploaded").report.source_format == "cape2"
```

Append to `tests/unit/api/test_worker_settings_overrides.py`:

```python
def test_the_job_config_can_choose_providers():
    s = build_job_settings({}, {"static_provider": "capa_yara", "sandbox_provider": "triage"})
    assert s.static.provider == "capa_yara"
    assert s.sandbox.provider == "triage"


def test_a_sandbox_report_id_forces_the_upload_provider():
    s = build_job_settings(
        {"sandbox.provider": "cape2"},
        {"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"},
    )
    assert s.sandbox.provider == "upload"


def test_an_explicit_provider_still_loses_to_an_attached_report():
    s = build_job_settings({}, {"sandbox_provider": "cape2", "sandbox_report_id": "x"})
    assert s.sandbox.provider == "upload"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/sandbox/test_upload_provider.py tests/unit/api/test_worker_settings_overrides.py -q`
Expected: FAIL — `NotImplementedError` from the stub; `assert 'cape2' == 'upload'`.

- [ ] **Step 3: Write the provider**

```python
@register_sandbox_provider("upload")
class UploadSandboxProvider(SandboxProvider):
    """A sandbox that runs nothing and reads what the operator already has.

    This is sub-project A's answer to "any sandbox": whatever your shop runs,
    export its report and attach it to the sample. The format is sniffed again
    here rather than trusted from the upload row, because the row is metadata
    and the bytes are the evidence.
    """

    def __init__(self, cfg: SandboxUploadConfig) -> None:
        self._cfg = cfg
        self._blob: bytes | None = None
        self._filename = "report.json"

    @classmethod
    def from_settings(cls, cfg: Settings) -> UploadSandboxProvider:
        return cls(cfg.sandbox.upload)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=False, can_poll=False, can_fetch_report=True, can_fetch_pcap=False,
            accepts_uploaded_report=True, provides_tools=False, report_format="generic",
            degrade_on_failure=True,
        )

    def set_pending_blob(self, blob: bytes, *, filename: str = "report.json") -> None:
        self._blob, self._filename = blob, filename

    def submit(self, sample_path: str | Path) -> str:
        raise ProviderError(
            "The upload sandbox does not detonate samples; attach a report to the job instead."
        )

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def attach_report(self, blob: bytes, *, filename: str = "report.json") -> SandboxRun:
        payload = self._parse(blob)
        fmt = sniff_format(payload)
        if fmt not in set(self._cfg.allowed_formats):
            raise ProviderError(
                f"Uploaded report sniffed as {fmt!r}; accepted formats are "
                f"{', '.join(sorted(self._cfg.allowed_formats))}."
            )
        report = cape_report_to_sandbox_report(
            payload, provider="upload", source_format=fmt  # type: ignore[arg-type]
        )
        if fmt == "triage":
            report = triage_overview_to_sandbox_report(payload, provider="upload")
        return SandboxRun(
            task_id=report.task_id or "uploaded", sample_sha256=report.target.sha256,
            sample_name=report.target.name or filename, status="reported",
            report=report, raw=payload,
        )

    def fetch(self, task_id: str) -> SandboxRun:
        if self._blob is None:
            raise ProviderError("No sandbox report is attached to this job.")
        return self.attach_report(self._blob, filename=self._filename)
```
`source_format` for a `cape2`/`cuckoo` upload is the sniffed value, so a `cuckoo` upload does **not** take the identity short circuit (its raw dict is close but not the same schema) and goes through the render; a `cape2` upload does, and the golden test covers it. `triage_overview_to_sandbox_report` arrives in Task 16 — until then `attach_report` refuses `triage` with "the Triage reader lands in the next task", and Task 16 removes that line.

- [ ] **Step 4: Fold the three job keys**

```python
def build_job_settings(
    overrides: dict[str, Any], job_config: dict[str, Any] | None
) -> _CoreSettings:
    merged = dict(overrides)
    if job_config:
        if job_config.get("max_iterations") is not None:
            merged["negotiation.max_iterations"] = job_config["max_iterations"]
        if job_config.get("llm_provider") is not None:
            merged["llm.provider"] = job_config["llm_provider"]
        if job_config.get("static_provider") is not None:
            merged["static.provider"] = job_config["static_provider"]
        if job_config.get("sandbox_provider") is not None:
            merged["sandbox.provider"] = job_config["sandbox_provider"]
        if job_config.get("sandbox_report_id") is not None:
            # An attached report is the strongest statement of intent there is:
            # it names the evidence, so it also names the provider that reads it.
            merged["sandbox.provider"] = "upload"
    return build_settings(merged)
```
In the job body, after `install_settings(core_settings)`, the worker loads the blob and hands it over:

```python
            report_id = (job.config or {}).get("sandbox_report_id")
            if report_id:
                from app.api.v1.sandbox_reports import get_object
                from app.models.sandbox_report import SandboxReportRow

                row = (
                    await db.execute(
                        select(SandboxReportRow).where(SandboxReportRow.id == uuid.UUID(str(report_id)))
                    )
                ).scalar_one_or_none()
                if row is None or row.sample_id != sample.id:
                    raise ValueError("The attached sandbox report does not belong to this sample.")
                provider = container.get_sandbox_provider()
                provider.set_pending_blob(await asyncio.to_thread(get_object, row.storage_path),
                                          filename=f"{row.id}.json")
```

- [ ] **Step 5: Take the attach path in `MaljanApp`**

`app.py::_submit_to_sandbox` gains one branch at the top, leaving the submit-and-wait path exactly as it is:

```python
        client = self.container.get_sandbox_client()
        provider = self.container.get_sandbox_provider()
        if not provider.capabilities.can_submit and provider.capabilities.accepts_uploaded_report:
            # No detonation: the evidence is already here.
            try:
                run = provider.fetch("uploaded")
            except Exception as exc:  # noqa: BLE001 — same degrade contract as a failed submit
                logger.error("Attached sandbox report unusable: %s", exc)
                return None
            from maljan.providers.cape_view import to_cape_shaped_dict

            return to_cape_shaped_dict(run.report)
```

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/providers tests/unit/api/test_worker_settings_overrides.py tests/unit/test_sandbox_container.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/sandbox/upload.py src/maljan/app.py apps/api/app/worker/analysis_worker.py tests/providers/sandbox/test_upload_provider.py
uv run ruff format --check src/maljan/providers/sandbox/upload.py src/maljan/app.py apps/api/app/worker/analysis_worker.py tests/providers/sandbox/test_upload_provider.py
uv run mypy src/ apps/api/
git add src/maljan/providers/sandbox/upload.py src/maljan/app.py apps/api/app/worker/analysis_worker.py tests/providers/sandbox/test_upload_provider.py tests/unit/api/test_worker_settings_overrides.py
git commit -m "feat(providers): run a job from an uploaded sandbox report instead of a detonation"
```

---

### Task 16: `TriageSandboxProvider`

**Files:**
- Create: `src/maljan/providers/sandbox/triage.py` (replacing the stub), `tests/fixtures/sandbox/triage_overview.json`, `tests/fixtures/sandbox/triage_report_behavioral1.json`
- Modify: `apps/api/app/services/settings_probes.py` (`probe_triage`, `_INPUTS["triage"]`, `PROBES["triage"]`), `src/maljan/schemas/sandbox_report.py` (`triage_overview_to_sandbox_report`)
- Test: `tests/providers/sandbox/test_triage_provider.py`, `tests/unit/api/test_settings_probes.py` (extended)

- [ ] **Step 1: Verify the endpoints before writing anything**

Read https://tria.ge/docs/cloud-api/ (submit, samples, reports, PCAP) and confirm each constant below against it. Adjust the constant, never the design; write what you confirmed into the module docstring with the date you read it.

```python
# The five calls this provider makes, as named constants so a documentation
# change is a one-line edit. Verified against https://tria.ge/docs/cloud-api/
# on <date the implementer read it>.
SUBMIT_PATH = "/samples"                               # POST, multipart: file + _json
STATUS_PATH = "/samples/{sample_id}"                   # GET, status "reported" is terminal
OVERVIEW_PATH = "/samples/{sample_id}/overview.json"   # GET
TASK_REPORT_PATH = "/samples/{sample_id}/{task}/report_triage.json"  # GET
PCAP_PATH = "/samples/{sample_id}/{task}/dump.pcap"    # GET, streamed
TERMINAL_STATUSES = frozenset({"reported", "failed"})
```
If a path or the terminal status differs, change the constant and the fixture, and note the difference in the commit message.

Then capture the two fixtures. With no Triage key available, hand-write them from the documented schema (sample, tasks, analysis.score, analysis.family, signatures, network, processes) — they are golden inputs for the mapper, not evidence about Triage's availability.

**Interfaces:**
- Produces:
  ```python
  @register_sandbox_provider("triage")
  class TriageSandboxProvider(SandboxProvider):
      UNAVAILABLE: ClassVar[tuple[str, ...]] = ("apistats", "calls", "registry", "generic_events")
  def triage_overview_to_sandbox_report(
      overview: dict[str, Any], *, provider: str = "triage",
      task_reports: dict[str, dict[str, Any]] | None = None, task_id: str = "",
  ) -> SandboxReport
  ```
- Consumes: `httpx`, `SandboxReport`, `providers.errors`.

- [ ] **Step 2: Write the failing tests**

```python
# tests/providers/sandbox/test_triage_provider.py
"""Triage over httpx.MockTransport: no network, real request shapes."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.triage import TriageSandboxProvider

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"


def _provider(handler, **over):
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = __import__("pydantic").SecretStr("not-a-real-token")
    for k, v in over.items():
        setattr(cfg.sandbox.triage, k, v)
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


def test_submit_posts_the_file_and_the_json_part():
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "260904-abcdefgh1"})

    provider = _provider(handler, profile="win10")
    tmp = FIX / "triage_overview.json"  # any readable file works as the upload body
    assert provider.submit(tmp) == "260904-abcdefgh1"
    assert seen["path"].endswith("/samples")
    assert seen["auth"] == "Bearer not-a-real-token"
    assert b'"kind": "file"' in seen["body"] and b"win10" in seen["body"]


def test_polling_stops_at_reported_and_backs_off():
    states = iter(["pending", "static_analysis", "running", "reported"])
    slept: list[float] = []

    def handler(request):
        return httpx.Response(200, json={"id": "s1", "status": next(states)})

    provider = _provider(handler, poll_interval_seconds=2)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [2, 3.0, 4.5], "1.5x backoff, capped at 60 s"


def test_a_retry_after_header_is_honoured():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, json={})
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    slept: list[float] = []
    provider = _provider(handler)
    provider._sleep = slept.append
    assert provider.wait_for_completion("s1", timeout_seconds=600) == "reported"
    assert slept == [7.0]


def test_a_timeout_raises_rather_than_reporting_success():
    def handler(request):
        return httpx.Response(200, json={"id": "s1", "status": "running"})

    provider = _provider(handler)
    provider._sleep = lambda _s: None
    provider._now = iter([0.0, 100.0, 100000.0]).__next__
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("s1", timeout_seconds=900)
    assert "did not complete" in str(exc.value)


def test_fetch_maps_overview_and_task_report_into_a_sandbox_report():
    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    task = json.loads((FIX / "triage_report_behavioral1.json").read_text(encoding="utf-8"))

    def handler(request):
        if request.url.path.endswith("overview.json"):
            return httpx.Response(200, json=overview)
        if request.url.path.endswith("report_triage.json"):
            return httpx.Response(200, json=task)
        return httpx.Response(200, json={"id": "s1", "status": "reported"})

    run = _provider(handler).fetch("260904-abcdefgh1")
    report = run.report
    assert report.source_format == "triage"
    assert report.target.sha256 == overview["sample"]["sha256"]
    assert report.cti["family"] == overview["analysis"]["family"]
    assert [s.name for s in report.signatures] == [s["name"] for s in overview["signatures"]]
    assert [p.name for p in report.processes] == [
        p["procid_parent"] and p["image"] or p["image"] for p in task["processes"]
    ]
    assert sorted(report.unavailable) == ["apistats", "calls", "generic_events", "registry"]
    assert report.apistats == {}


def test_the_rendered_dict_names_what_this_sandbox_cannot_provide():
    from maljan.providers.cape_view import to_cape_shaped_dict
    from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

    overview = json.loads((FIX / "triage_overview.json").read_text(encoding="utf-8"))
    rendered = to_cape_shaped_dict(triage_overview_to_sandbox_report(overview))
    assert rendered["behavior"]["apistats"] == {}
    assert "apistats" in rendered["unavailable"]


def test_pcap_is_written_only_when_it_is_a_real_capture(tmp_path):
    def handler(request):
        if request.url.path.endswith("dump.pcap"):
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return httpx.Response(404, json={})

    path = _provider(handler).fetch_pcap("260904-abcdefgh1", tmp_path)
    assert path is not None and Path(path).stat().st_size >= 24


def test_an_empty_pcap_is_not_written(tmp_path):
    def handler(request):
        return httpx.Response(200, content=b"tiny")

    assert _provider(handler).fetch_pcap("s1", tmp_path) is None


def test_a_missing_token_fails_before_any_request():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    with pytest.raises(ProviderError) as exc:
        TriageSandboxProvider.from_settings(cfg).submit("/tmp/x.exe")
    assert "sandbox.triage.api_token" in str(exc.value)
```

Append to `tests/unit/api/test_settings_probes.py`: `probe_triage` with a MockTransport that answers 200 reports `ok`, 401 reports `HTTP 401` and mentions no token value, and a missing token reports "no API token configured" without making a request.

- [ ] **Step 3: Write the provider**

Structure: `_http` is a lazily built `httpx.Client(base_url=..., headers={"Authorization": f"Bearer {token}"}, timeout=60.0)`; `_sleep` and `_now` are instance attributes (`time.sleep`, `time.monotonic`) so the tests can drive the clock. `submit` posts `files={"file": (path.name, fh, "application/octet-stream"), "_json": (None, json.dumps(payload), "application/json")}` with `payload = {"kind": "file", "interactive": False}` plus `"profiles": [{"profile": self._cfg.profile, "pick": "default"}]` when a profile is configured. `wait_for_completion` polls `STATUS_PATH`, honours `Retry-After` on 429/503, multiplies the interval by 1.5 up to 60 s, and raises `ProviderError` at the deadline — never returns a status it did not read. `fetch` reads the overview, then each behavioural task's `report_triage.json`, and maps them; `fetch_pcap` streams the first behavioural task's `dump.pcap` with the same 24-byte floor `CAPEv2Client.fetch_pcap` uses.

The mapper lives beside the CAPE one so both readers of `SandboxReport` sit in one file:

```python
def triage_overview_to_sandbox_report(
    overview: dict[str, Any],
    *,
    provider: str = "triage",
    task_reports: dict[str, dict[str, Any]] | None = None,
    task_id: str = "",
) -> SandboxReport:
    """Map a Triage overview (plus its behavioural task reports) onto the model.

    Triage reports what it observed, not every API call: there is no per-call
    log, no apistats and no registry timeline. Those four sections are listed in
    ``unavailable`` rather than left empty and silent, because an empty dynamic
    section reads exactly like a clean sample — and the report renderers say so
    out loud (Task 17).
    """
    sample = overview.get("sample") if isinstance(overview.get("sample"), dict) else {}
    analysis = overview.get("analysis") if isinstance(overview.get("analysis"), dict) else {}
    processes: list[SandboxProcess] = []
    network = SandboxNetwork()
    for task in (task_reports or {}).values():
        for proc in task.get("processes") or []:
            if not isinstance(proc, dict):
                continue
            processes.append(
                SandboxProcess(
                    pid=_int(proc.get("procid") or proc.get("pid")),
                    ppid=_int(proc.get("procid_parent") or proc.get("ppid")),
                    name=str(proc.get("image") or proc.get("name") or ""),
                    command_line=str(proc.get("cmd") or ""),
                    first_seen=str(proc.get("started") or ""),
                    calls=[],
                )
            )
        net = task.get("network") if isinstance(task.get("network"), dict) else {}
        network.dns.extend(_rows(net.get("requests")))
        network.http.extend(_rows(net.get("flows")))
        network.domains.extend(
            [r.get("domain") for r in _rows(net.get("requests")) if r.get("domain")]
        )
    return SandboxReport(
        provider=provider,
        source_format="triage",
        task_id=str(task_id or sample.get("id") or ""),
        target=SandboxTarget(
            sha256=str(sample.get("sha256") or ""),
            md5=str(sample.get("md5") or ""),
            name=str(sample.get("target") or ""),
            file_type=str(sample.get("kind") or ""),
            mime_type=str(sample.get("kind") or ""),
            size=_int(sample.get("size")),
        ),
        processes=processes,
        apistats={},
        generic_events=[],
        signatures=[
            SandboxSignatureRow(
                name=str(s.get("name") or ""),
                description=str(s.get("desc") or s.get("name") or ""),
                severity=_int(s.get("score")),
                marks=list(s.get("indicators") or []),
                ttp_tags=_as_str_list(s.get("ttp")),
            )
            for s in (overview.get("signatures") or [])
            if isinstance(s, dict)
        ],
        network=network,
        dropped_files=[],
        registry=[],
        screenshots=[],
        cti={"family": _as_str_list(analysis.get("family")), "score": analysis.get("score")},
        unavailable=list(TriageSandboxProvider.UNAVAILABLE),
        raw=overview,
    )
```

`UploadSandboxProvider.attach_report` drops its temporary Triage refusal and calls this mapper.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/providers/sandbox tests/unit/api/test_settings_probes.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/sandbox/triage.py src/maljan/schemas/sandbox_report.py apps/api/app/services/settings_probes.py tests/providers/sandbox/test_triage_provider.py
uv run ruff format --check src/maljan/providers/sandbox/triage.py src/maljan/schemas/sandbox_report.py apps/api/app/services/settings_probes.py tests/providers/sandbox/test_triage_provider.py
uv run mypy src/ apps/api/
git add src/maljan/providers/sandbox/triage.py src/maljan/providers/sandbox/upload.py src/maljan/schemas/sandbox_report.py apps/api/app/services/settings_probes.py tests/fixtures/sandbox tests/providers/sandbox/test_triage_provider.py tests/unit/api/test_settings_probes.py
git commit -m "feat(providers): Hatching Triage sandbox adapter with its connection test"
```

---

### Task 17: Saying what a sandbox did not provide

**Files:**
- Modify: `src/maljan/reporting/models.py` (`DynamicBehavior.unavailable`), `src/maljan/extractors/dynamic_extractor.py:57-97` (`build_dynamic_behavior` reads it), `src/maljan/reporting/renderers.py` (Markdown), `src/maljan/reporting/html_report.py` (HTML), `apps/web/src/app/(app)/analysis/[id]/dynamic/page.tsx`
- Test: `tests/providers/test_unavailable_sections.py`, `tests/agents/test_prompt_byte_identity.py` (re-run), `tests/providers/test_extractor_golden.py` (re-run — the goldens must not move)

**Interfaces:**
- Produces: `DynamicBehavior.unavailable: list[str] = Field(default_factory=list)`; the renderers emit `Not provided by this sandbox` for each named section.
- Consumes: `sandbox_report["unavailable"]`, written by `to_cape_shaped_dict`.

**The constraint that shapes this task:** `DynamicBehavior` is dumped into the goldens from Task 1. A new field with a default of `[]` adds `"unavailable": []` to every dump and breaks all 98 goldens. So the field is added **and the goldens are regenerated in this task**, by re-running the capture script with the extractors' behaviour otherwise unchanged, and the diff is reviewed to be exactly one added key per file:

```bash
uv run python scripts/capture_provider_goldens.py
git diff --stat tests/fixtures/golden/extractors | tail -1
git diff tests/fixtures/golden/extractors | grep '^[+-]' | grep -v '^[+-][+-]' | sort | uniq -c
```
Expected: every changed line is `+    "unavailable": [],` and nothing else. If any other line moves, the change is not additive and the task stops.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/test_unavailable_sections.py
"""An empty section from a sandbox that cannot fill it is not a clean sample."""

from __future__ import annotations

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.reporting.models import DynamicBehavior


def test_a_cape_report_declares_nothing_unavailable():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
    }
    behavior = build_dynamic_behavior(report)
    assert behavior is not None and behavior.unavailable == []


def test_the_unavailable_list_travels_from_the_report_into_the_model():
    report = {
        "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}], "apistats": {}},
        "signatures": [],
        "network": {},
        "unavailable": ["apistats", "calls", "registry", "generic_events"],
    }
    behavior = build_dynamic_behavior(report)
    assert behavior is not None
    assert behavior.unavailable == ["apistats", "calls", "registry", "generic_events"]


def test_a_report_with_only_unavailable_sections_is_still_none():
    """Nothing observed and nothing available is still no dynamic behaviour."""
    assert build_dynamic_behavior({"unavailable": ["apistats"]}) is None


def test_the_markdown_renderer_names_the_gaps():
    from maljan.reporting.renderers import MarkdownRenderer

    behavior = DynamicBehavior(
        process_tree=[], registry_mods=[], file_operations=[], notable_apis=[],
        sandbox_signatures=[], unavailable=["apistats", "registry"],
    )
    text = MarkdownRenderer().render_dynamic_section(behavior)
    assert "Not provided by this sandbox" in text
    assert "apistats" in text and "registry" in text


def test_the_html_report_names_the_gaps():
    from maljan.reporting.html_report import render_unavailable_note

    html = render_unavailable_note(["apistats"])
    assert "Not provided by this sandbox" in html
    assert "<" in html and "apistats" in html
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/test_unavailable_sections.py -q`
Expected: FAIL — `DynamicBehavior` has no field `unavailable` (`_STRICT_CONFIG` forbids the extra).

- [ ] **Step 3: Add the field and thread it**

```python
    # Sections this sandbox structurally cannot produce, e.g. ["apistats",
    # "calls", "registry", "generic_events"] for Hatching Triage. Named rather
    # than left empty: an empty API-call table reads as "the sample did
    # nothing", which is the opposite of "we could not see". Every renderer
    # prints "Not provided by this sandbox" for these, and no detection layer
    # treats them as negative evidence.
    unavailable: list[str] = Field(default_factory=list)
```
`build_dynamic_behavior` reads `sandbox_report.get("unavailable")` (list of str, else `[]`) and passes it to the constructor; its early `return None` when nothing was found is unchanged, so a report that is only gaps still yields no dynamic section. Both renderers grow a small note block; the dynamic page renders the same sentence above the empty table.

- [ ] **Step 4: Regenerate the goldens and review the diff**

Run the two commands from the top of this task, then:

Run: `uv run pytest tests/providers/test_extractor_golden.py tests/providers/test_cape_normalization_golden.py tests/providers/test_unavailable_sections.py -q`
Expected: PASS.

- [ ] **Step 5: Frontend check, lint, type-check and commit**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && cd ../..
uv run ruff check src/maljan/reporting src/maljan/extractors/dynamic_extractor.py tests/providers/test_unavailable_sections.py
uv run ruff format --check src/maljan/reporting src/maljan/extractors/dynamic_extractor.py tests/providers/test_unavailable_sections.py
uv run mypy src/ apps/api/
git add src/maljan/reporting src/maljan/extractors/dynamic_extractor.py "apps/web/src/app/(app)/analysis/[id]/dynamic/page.tsx" tests/fixtures/golden/extractors tests/providers/test_unavailable_sections.py
git commit -m "feat(reporting): name the sections a sandbox cannot provide instead of showing them empty"
```

---

### Task 18: `R2StaticProvider`

**Files:**
- Create: `scripts/probe_r2_tools.py`, `tests/fixtures/golden/r2_tools.json`, `src/maljan/providers/static/r2.py` (replacing the stub)
- Modify: `apps/api/app/services/settings_probes.py` (`probe_r2`, `_INPUTS["r2"]`, `PROBES["r2"]`)
- Test: `tests/providers/static/test_r2_provider.py`, `tests/unit/api/test_settings_probes.py` (extended)

- [ ] **Step 1: Enumerate the tools and pin them**

`radareorg/radare2-mcp` names its tools; this project has never spoken to it, so the names are discovered rather than guessed. The probe speaks raw MCP over stdio — `initialize`, then `tools/list` — and writes the answer to the fixture:

```python
# scripts/probe_r2_tools.py
"""List the tools an installed r2mcp offers, and pin them for the r2 provider.

    uv run python scripts/probe_r2_tools.py            # uses `r2mcp` on PATH
    uv run python scripts/probe_r2_tools.py /path/r2mcp

Writes tests/fixtures/golden/r2_tools.json. The provider's allow-list constant
is filled from that file; running this again on a newer r2mcp shows, as a diff,
exactly which names moved.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "golden" / "r2_tools.json"


async def enumerate_tools(command: str) -> list[dict[str, str]]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from maljan.agents.subprocess_env import child_env

    params = StdioServerParameters(command=command, args=[], env=child_env())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        response = await session.list_tools()
        return [
            {"name": t.name, "description": (t.description or "").strip()[:200]}
            for t in response.tools
        ]


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "r2mcp"
    tools = asyncio.run(enumerate_tools(command))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps({"command": command, "tools": sorted(tools, key=lambda t: t["name"])}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(f"{len(tools)} tools -> {OUT}")


if __name__ == "__main__":
    main()
```

Run: `uv run python scripts/probe_r2_tools.py`

If r2mcp is not installed, install it (`r2pm -ci r2mcp`, or the repository's own instructions) and run again. If it cannot be installed on this machine, write the fixture by hand from the upstream README's tool table, mark it `"source": "documentation"` in the JSON, and say so in the commit message — the provider code does not change either way, only the constant's contents.

**Interfaces:**
- Produces:
  ```python
  @register_static_provider("r2")
  class R2StaticProvider(GenericMCPStaticProvider):
      R2_ALLOWED_TOOLS: ClassVar[frozenset[str]]   # filled from tests/fixtures/golden/r2_tools.json
      R2_PROMPT_FRAGMENT: ClassVar[str]
  ```
- Consumes: `GenericMCPStaticProvider`, `StaticR2Config`.

- [ ] **Step 2: Write the failing tests**

```python
# tests/providers/static/test_r2_provider.py
"""radare2 is the generic MCP provider with radare2's defaults."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.providers.static.r2 import R2StaticProvider

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "r2_tools.json"


class _T:
    def __init__(self, name):
        self.name = name


def _cfg():
    cfg = Settings(_env_file=None)
    cfg.static.provider = "r2"
    cfg.static.r2.enabled = True
    return cfg


def test_it_is_the_generic_adapter_with_defaults():
    assert issubclass(R2StaticProvider, GenericMCPStaticProvider)


def test_the_allow_list_is_the_pinned_fixture():
    pinned = {t["name"] for t in json.loads(FIX.read_text(encoding="utf-8"))["tools"]}
    assert R2StaticProvider.R2_ALLOWED_TOOLS <= pinned, "the allow-list names tools r2mcp has"
    assert R2StaticProvider.R2_ALLOWED_TOOLS, "an empty allow-list would expose everything"


def test_capabilities():
    caps = R2StaticProvider.from_settings(_cfg()).capabilities
    assert caps.provides_tools and caps.needs_sample_mirror and caps.supports_tool_curation
    assert caps.degrade_on_failure is True
    assert caps.provides_function_hashes is False


def test_the_command_defaults_to_the_configured_binary():
    cfg = _cfg()
    cfg.static.r2.binary_path = "/opt/r2/bin/r2mcp"
    provider = R2StaticProvider.from_settings(cfg)
    assert provider.server_command() == "/opt/r2/bin/r2mcp"


def test_selection_narrows_to_the_allow_list():
    provider = R2StaticProvider.from_settings(_cfg())
    tools = [_T(n) for n in sorted(R2StaticProvider.R2_ALLOWED_TOOLS)] + [_T("not_an_r2_tool")]
    assert {t.name for t in provider.select_tools(tools)} == R2StaticProvider.R2_ALLOWED_TOOLS


def test_the_prompt_fragment_names_r2_tools_and_no_ghidra_tool():
    fragment = R2StaticProvider.from_settings(_cfg()).prompt_fragment()
    assert "cite a concrete artifact" in fragment
    assert "load_program" not in fragment and "Ghidra" not in fragment
    assert any(name in fragment for name in R2StaticProvider.R2_ALLOWED_TOOLS)


def test_the_mirror_spec_uses_the_configured_directory():
    cfg = _cfg()
    cfg.static.r2.mirror_dir = "data/samples/.work"
    spec = R2StaticProvider.from_settings(cfg).mirror_spec()
    assert spec is not None and spec.work_subdir == ".work"
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/providers/static/test_r2_provider.py -q`
Expected: FAIL — `NotImplementedError` from the stub.

- [ ] **Step 4: Write the provider**

```python
@register_static_provider("r2")
class R2StaticProvider(GenericMCPStaticProvider):
    """radare2 over ``radareorg/radare2-mcp``, stdio.

    Structurally this is the generic MCP adapter with three defaults: the
    command comes from ``static.r2.binary_path``, the allow-list is the pinned
    tool set below, and the prompt fragment describes an r2 workflow rather than
    a Ghidra one. The tool names were enumerated from a running r2mcp with
    ``scripts/probe_r2_tools.py`` and pinned in
    ``tests/fixtures/golden/r2_tools.json``; if a future r2mcp renames one, this
    constant changes and nothing else does.

    ``degrade_on_failure`` is True, unlike Ghidra's: r2 is an alternative here,
    not the profile this project's evaluation was measured on, so an operator
    whose r2mcp is missing gets a degraded run and a legible probe failure
    rather than a failed job.
    """

    R2_ALLOWED_TOOLS: ClassVar[frozenset[str]] = frozenset(
        {
            # Filled from tests/fixtures/golden/r2_tools.json in Step 1: the
            # open/analyse/enumerate/decompile/xref core of the server, and
            # nothing else, for the same prompt-size reason the Ghidra
            # allow-list exists.
        }
    )

    R2_PROMPT_FRAGMENT: ClassVar[str] = (
        "Analyze binary files (e.g. PE, ELF) utilizing radare2 through your available tools. "
        "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
        "string offset (.data+0xNN), API import, or hex pattern. "
        "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
        "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
        "=== TOOL USAGE WORKFLOW ===\n"
        "1. Open the binary at the path you are given, then run the analysis pass.\n"
        "2. List the imports and the strings to see what the binary can reach.\n"
        "3. List the functions and pick the 3-5 that reference crypto, network or\n"
        "   process APIs; decompile those and read their cross-references.\n"
        "4. Summarise assembly patterns instead of dumping raw hex, and prefer one\n"
        "   summarising call over many narrow ones.\n"
    )

    @classmethod
    def from_settings(cls, cfg: Settings) -> R2StaticProvider:
        return cls(
            cfg.static.r2,
            label="radare2 MCP",
            allowed_tools=cls.R2_ALLOWED_TOOLS,
            prompt_fragment_text=cls.R2_PROMPT_FRAGMENT,
        )

    def server_command(self) -> str:
        return self._cfg.command or self._cfg.binary_path

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=Path(self._cfg.mirror_dir).name, container_prefix="")
```
An empty `container_prefix` means the mirror's **host** path is what reaches the analyst: a co-located r2mcp opens the file directly, so `state["static_sample_path"]` is the host path there. `mirror_target_for` (Task 12) already returns the host path first; when `container_prefix` is empty it returns `str(host)` as the second element.

`probe_r2` in `settings_probes.py` runs the stdio handshake with a 5 s budget:

```python
async def probe_r2(v: dict[str, Any]) -> ProbeResult:
    """Launch the configured r2mcp and count the tools it offers, in 5 seconds.

    A stdio handshake is the only honest test of a subprocess-backed server: a
    binary that exists but cannot serve MCP is exactly the failure an operator
    needs named before a job fails on it.
    """
    t0 = time.perf_counter()
    command = str(v.get("binary_path") or "r2mcp")
    try:
        from maljan.providers.static.r2 import enumerate_r2_tools

        names = await asyncio.wait_for(enumerate_r2_tools(command), timeout=5.0)
    except FileNotFoundError:
        return ProbeResult(False, _ms(t0), f"{command!r} not found on PATH")
    except TimeoutError:
        return ProbeResult(False, _ms(t0), "no MCP handshake within 5 s")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    return ProbeResult(True, _ms(t0), f"{len(names)} tools offered by {command!r}")
```
with `_INPUTS["r2"] = {"core.static.r2.binary_path": "binary_path"}` and `enumerate_r2_tools` the async function `scripts/probe_r2_tools.py` also calls, so the script and the probe cannot diverge.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/providers/static tests/unit/api/test_settings_probes.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/static/r2.py scripts/probe_r2_tools.py apps/api/app/services/settings_probes.py tests/providers/static/test_r2_provider.py
uv run ruff format --check src/maljan/providers/static/r2.py scripts/probe_r2_tools.py apps/api/app/services/settings_probes.py tests/providers/static/test_r2_provider.py
uv run mypy src/ apps/api/
git add src/maljan/providers/static/r2.py scripts/probe_r2_tools.py tests/fixtures/golden/r2_tools.json apps/api/app/services/settings_probes.py tests/providers/static/test_r2_provider.py tests/unit/api/test_settings_probes.py
git commit -m "feat(providers): radare2 static adapter with its tool set pinned from a live handshake"
```

---

### Task 19: `CapaYaraStaticProvider` and evidence in the preparation node

**Files:**
- Create: `src/maljan/providers/static/capa_yara.py` (replacing the stub)
- Modify: `src/maljan/pipeline/nodes.py:1122-1136` (the evidence merge, beside `build_import_capability_isr`), `apps/api/app/services/settings_probes.py` (`probe_capa`), `pyproject.toml` (`capa` optional-dependency group)
- Test: `tests/providers/static/test_capa_yara_provider.py`, `tests/providers/test_evidence_merge.py`

**Interfaces:**
- Produces:
  ```python
  @register_static_provider("capa_yara")
  class CapaYaraStaticProvider(StaticProvider):
      def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None
  def merge_static_evidence(static: StaticAnalysis, bundle: StaticEvidenceBundle) -> StaticAnalysis
  ```
- Consumes: `flare-capa` (guarded), `maljan.analysis.yara_layer.YaraLayer` (the existing one — no second YARA path), `maljan.schemas.tool_evidence.trim_output`, `StaticAnalysis.api_capabilities` / `.api_technique_hits`, `MalwareReport.technical_evidence`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/providers/static/test_capa_yara_provider.py
"""Evidence, not tools — and a missing library is a warning, not a failure."""

from __future__ import annotations

import builtins

import pytest

from maljan.core.config import Settings
from maljan.providers.static.capa_yara import CapaYaraStaticProvider


def _provider(tmp_path=None):
    cfg = Settings(_env_file=None)
    cfg.static.provider = "capa_yara"
    if tmp_path is not None:
        cfg.static.capa.rules_dir = str(tmp_path)
        cfg.static.yara.rules_dir = str(tmp_path)
    return CapaYaraStaticProvider.from_settings(cfg)


def test_capabilities_are_evidence_only():
    caps = _provider().capabilities
    assert caps.provides_evidence is True
    assert caps.provides_tools is False and caps.supports_tool_curation is False
    assert caps.needs_sample_mirror is False, "capa and YARA read the host bytes in place"
    assert caps.degrade_on_failure is True


def test_a_missing_capa_lowers_the_capability_and_warns(monkeypatch, tmp_path, caplog):
    real_import = builtins.__import__

    def no_capa(name, *args, **kwargs):
        if name.startswith("capa"):
            raise ImportError("No module named 'capa'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_capa)
    provider = _provider(tmp_path)
    with caplog.at_level("WARNING"):
        bundle = provider.collect_evidence(str(tmp_path / "missing.exe"))
    assert bundle is None or bundle.api_capabilities == {}
    assert any("capa" in r.getMessage() for r in caplog.records)
    assert provider.capabilities.provides_evidence is False


def test_capa_results_become_capabilities_techniques_and_a_table(monkeypatch, tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    provider = _provider(tmp_path)
    monkeypatch.setattr(
        provider,
        "_run_capa",
        lambda path: {
            "rules": {
                "encrypt data using RC4": {
                    "meta": {
                        "namespace": "data-manipulation/encryption/rc4",
                        "attack": [{"id": "T1027", "technique": "Obfuscated Files or Information"}],
                    },
                    "matches": [[{"type": "absolute", "value": 4198400}, {}]],
                },
                "create process": {
                    "meta": {
                        "namespace": "host-interaction/process/create",
                        "attack": [{"id": "T1106", "technique": "Native API"}],
                    },
                    "matches": [[{"type": "absolute", "value": 4198500}, {}]],
                },
            }
        },
    )
    monkeypatch.setattr(provider, "_run_yara", lambda path: [])
    bundle = provider.collect_evidence(str(sample))
    assert bundle is not None
    assert bundle.api_capabilities["data-manipulation"] == 1
    assert bundle.api_capabilities["host-interaction"] == 1
    ids = {hit["technique_id"] for hit in bundle.technique_hits}
    assert ids == {"T1027", "T1106"}
    assert all(hit["evidence"] for hit in bundle.technique_hits)
    assert "encrypt data using RC4" in bundle.technical_evidence["capa"]


def test_yara_hits_land_in_the_technical_evidence(monkeypatch, tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    provider = _provider(tmp_path)
    monkeypatch.setattr(provider, "_run_capa", lambda path: {"rules": {}})
    monkeypatch.setattr(
        provider, "_run_yara", lambda path: [{"rule": "ransom_note", "strings": ["$a at 0x40"]}]
    )
    bundle = provider.collect_evidence(str(sample))
    assert bundle is not None
    assert "ransom_note" in bundle.technical_evidence["yara"]


def test_the_evidence_text_is_capped():
    from maljan.schemas.tool_evidence import MAX_OUTPUT_CHARS
    from maljan.providers.static.capa_yara import _render_table

    text = _render_table([{"rule": f"rule_{i}", "namespace": "x"} for i in range(5000)])
    assert len(text) <= MAX_OUTPUT_CHARS
```

```python
# tests/providers/test_evidence_merge.py
"""Evidence merges into StaticAnalysis without disturbing what is already there."""

from __future__ import annotations

from maljan.providers.base import StaticEvidenceBundle
from maljan.providers.static.capa_yara import merge_static_evidence
from maljan.reporting.models import StaticAnalysis


def test_counters_are_summed_and_hits_extended():
    static = StaticAnalysis(
        api_capabilities={"network": 2, "crypto": 1},
        api_technique_hits=[{"technique_id": "T1071", "evidence": ["WS2_32.dll"]}],
    )
    merged = merge_static_evidence(
        static,
        StaticEvidenceBundle(
            api_capabilities={"crypto": 3, "anti-analysis": 1},
            technique_hits=[{"technique_id": "T1027", "evidence": ["capa: RC4"]}],
            technical_evidence={"capa": "…"},
        ),
    )
    assert merged.api_capabilities == {"network": 2, "crypto": 4, "anti-analysis": 1}
    assert [h["technique_id"] for h in merged.api_technique_hits] == ["T1071", "T1027"]


def test_the_merge_does_not_mutate_its_input():
    static = StaticAnalysis(api_capabilities={"network": 1})
    merge_static_evidence(static, StaticEvidenceBundle(api_capabilities={"network": 5}))
    assert static.api_capabilities == {"network": 1}


def test_an_empty_bundle_changes_nothing():
    static = StaticAnalysis(api_capabilities={"network": 1})
    assert merge_static_evidence(static, StaticEvidenceBundle()) == static
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/providers/static/test_capa_yara_provider.py tests/providers/test_evidence_merge.py -q`
Expected: FAIL — `NotImplementedError` from the stub.

- [ ] **Step 3: Write the provider**

```python
@register_static_provider("capa_yara")
class CapaYaraStaticProvider(StaticProvider):
    """capa and YARA: evidence for the analyst, not tools for the model.

    No tool server and no ReAct loop — this provider runs two deterministic
    passes over the sample's bytes and hands the pipeline a
    ``StaticEvidenceBundle`` that the preparation node folds into the same
    ``StaticAnalysis`` the PE extractor fills. capa namespaces become capability
    counters, capa's ATT&CK metadata becomes technique hits with the matching
    rule as evidence, and the rendered tables plus any YARA hits become
    ``technical_evidence`` for the report's technical spine.

    Both libraries are optional. A missing one lowers ``provides_evidence`` to
    False with one warning — the same shape as ``SandboxNotAvailableError`` —
    rather than failing a job over an integration the operator may not want.
    """

    def __init__(self, capa: StaticCapaConfig, yara: StaticYaraConfig) -> None:
        self._capa, self._yara = capa, yara
        self._capa_available: bool | None = None

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_evidence=self._capa_available is not False,
            degrade_on_failure=True,
        )

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        capa_result = self._run_capa(sample_path)
        yara_hits = self._run_yara(sample_path)
        if capa_result is None and not yara_hits:
            return None
        capabilities: dict[str, int] = {}
        hits: list[dict[str, Any]] = []
        rows: list[dict[str, str]] = []
        for name, rule in ((capa_result or {}).get("rules") or {}).items():
            meta = rule.get("meta") or {}
            namespace = str(meta.get("namespace") or "")
            top = namespace.split("/", 1)[0] if namespace else "uncategorised"
            capabilities[top] = capabilities.get(top, 0) + 1
            rows.append({"rule": str(name), "namespace": namespace})
            for attack in meta.get("attack") or []:
                tid = str((attack or {}).get("id") or "")
                if not tid:
                    continue
                hits.append(
                    {
                        "technique_id": tid,
                        "technique": str(attack.get("technique") or ""),
                        "evidence": [f"capa: {name}"],
                        "source": "capa",
                    }
                )
        evidence: dict[str, str] = {}
        if rows:
            evidence["capa"] = _render_table(rows)
        if yara_hits:
            evidence["yara"] = _render_yara(yara_hits)
        return StaticEvidenceBundle(
            api_capabilities=capabilities, technique_hits=hits, strings=[],
            technical_evidence=evidence,
        )

    def _run_capa(self, sample_path: str) -> dict[str, Any] | None:
        """Run capa, or return None and warn once when it is unavailable."""
        try:
            import capa.main  # noqa: F401
            import capa.rules  # noqa: F401
        except ImportError as exc:
            if self._capa_available is not False:
                logger.warning(
                    "capa is not installed (%s); the capa_yara provider contributes no "
                    "capa evidence. Install it with: uv sync --extra capa",
                    exc,
                )
            self._capa_available = False
            return None
        rules_dir = Path(resolve_data(self._capa.rules_dir))
        if not rules_dir.is_dir() or not any(rules_dir.rglob("*.yml")):
            if self._capa_available is not False:
                logger.warning(
                    "capa rules directory %s is missing or empty; no capa evidence.", rules_dir
                )
            self._capa_available = False
            return None
        self._capa_available = True
        try:
            import capa.capabilities.common as capa_capabilities
            import capa.loader as capa_loader
            import capa.render.result_document as capa_rd

            rules = capa_loader.get_rules([rules_dir])
            extractor = capa_loader.get_extractor(
                Path(sample_path),
                capa_loader.BACKEND_MAP.get(self._capa.backend, capa_loader.BACKEND_VIV),
                os_=capa_loader.OS_AUTO,
                sigpaths=capa_loader.get_signatures(Path(resolve_data(self._capa.signatures_dir)))
                if Path(resolve_data(self._capa.signatures_dir)).is_dir()
                else [],
                should_save_workspace=False,
            )
            capabilities = capa_capabilities.find_capabilities(rules, extractor, disable_progress=True)
            document = capa_rd.ResultDocument.from_capa(
                capa_loader.collect_metadata([], Path(sample_path), "", "", [rules_dir], extractor, capabilities),
                rules,
                capabilities,
            )
            return document.model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - capa must never fail a run
            logger.warning(
                "capa failed on %s (%s: %s); continuing without capa evidence.",
                sample_path, type(exc).__name__, exc,
            )
            return None

    def _run_yara(self, sample_path: str) -> list[dict[str, Any]]:
        """Scan with the operator's own rules directory, reusing the YARA layer.

        The deterministic ``analysis/yara_layer.YaraLayer`` already owns rule
        compilation and matching; a second YARA code path in this project would
        be a second place for rule handling to be wrong. Anything this cannot
        load is a warning and an empty list.
        """
        rules_dir = Path(resolve_data(self._yara.rules_dir))
        if not rules_dir.is_dir():
            return []
        try:
            from maljan.analysis.yara_layer import YaraLayer

            layer = YaraLayer.from_yaml(str(rules_dir))
            data = Path(sample_path).read_bytes()
            return [
                {"rule": m.rule_id, "strings": [m.evidence_ref()], "technique": m.technique_id}
                for m in layer.scan(data)
            ]
        except Exception as exc:  # noqa: BLE001 - YARA must never fail a run
            logger.warning(
                "YARA scan of %s failed (%s: %s); continuing without YARA evidence.",
                sample_path, type(exc).__name__, exc,
            )
            return []
```

The `capa` API names above are the 7.x shape; the first thing this step does is
`uv run python -c "import capa.loader, capa.capabilities.common; print(capa.version.__version__)"`
after `uv sync --extra capa`, and any name that moved in the installed version is
corrected there and then — the surrounding contract (a rules dict in, a bundle
out, every failure a warning) does not change with it.
`merge_static_evidence` is a module function returning a new `StaticAnalysis` (`model_copy(update=...)` over summed counters and extended hits), and the preparation node calls it beside `build_import_capability_isr`:

```python
                _static_provider = container.get_static_provider()
                if _static_provider.capabilities.provides_evidence and _host_imp:
                    _bundle = _static_provider.collect_evidence(str(_host_imp))
                    if _bundle is not None:
                        _static_imp = merge_static_evidence(_static_imp, _bundle)
                        for _agent, _text in _bundle.technical_evidence.items():
                            _evidence_sections.setdefault(_agent, []).append(
                                {"agent_id": _agent, "tool_name": _agent, "args": {},
                                 "symbol": None, "output": _text, "seq": 0}
                            )
```
so capa and YARA text reaches `MalwareReport.technical_evidence` through the same `state["tool_evidence"]` channel the ReAct loop uses, already capped by `schemas/tool_evidence.trim_output`.

`probe_capa` reports the rule count: `{n} rules under {dir}` when capa imports and the directory has rules, and names which of the two is missing otherwise.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/providers tests/unit/api/test_settings_probes.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/static/capa_yara.py src/maljan/pipeline/nodes.py apps/api/app/services/settings_probes.py tests/providers
uv run ruff format --check src/maljan/providers/static/capa_yara.py src/maljan/pipeline/nodes.py apps/api/app/services/settings_probes.py tests/providers
uv run mypy src/ apps/api/
git add src/maljan/providers/static/capa_yara.py src/maljan/pipeline/nodes.py apps/api/app/services/settings_probes.py pyproject.toml tests/providers/static/test_capa_yara_provider.py tests/providers/test_evidence_merge.py
git commit -m "feat(providers): capa and YARA as an evidence-only static provider"
```

---

### Task 20: Per-job provider overrides

**Files:**
- Modify: `apps/api/app/schemas/job.py:12-45` (`_KnownJobConfig`), `apps/api/app/worker/analysis_worker.py` (settings snapshot check only — the folding landed in Task 15)
- Test: `tests/api/test_job_provider_overrides.py`

**Interfaces:**
- Produces:
  ```python
  class _KnownJobConfig(BaseModel):
      max_iterations: Annotated[int, Field(ge=1)] | None = None
      llm_provider: Literal["openai", "anthropic", "ollama", "gemini"] | None = None
      mock_mode: bool | None = None
      static_provider: Literal["ghidra", "r2", "capa_yara", "generic_mcp", "none"] | None = None
      sandbox_provider: Literal["mock", "cape2", "upload", "triage"] | None = None
      sandbox_report_id: uuid.UUID | None = None
  ```
- Consumes: `build_job_settings` (Task 15), `settings_snapshot`.

The `Literal`s repeat the config's rather than importing them, matching the existing `llm_provider` field; the registry-parity test from Task 5 plus a new test here keep all three in step.

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_job_provider_overrides.py
"""A job can name its providers, and a bad name is a 422 at submit time."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.schemas.job import JobCreateRequest, _KnownJobConfig  # noqa: E402


def test_the_job_choices_equal_the_registry_ids():
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    static = get_args(_KnownJobConfig.model_fields["static_provider"].annotation)
    sandbox = get_args(_KnownJobConfig.model_fields["sandbox_provider"].annotation)
    assert set(static_provider_ids()) <= set(static)
    assert set(sandbox_provider_ids()) <= set(sandbox)


def test_valid_providers_pass():
    cfg = {"static_provider": "r2", "sandbox_provider": "triage"}
    JobCreateRequest(sample_id=uuid.uuid4(), config=cfg)


def test_an_unknown_provider_is_refused_at_submit_time():
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(sample_id=uuid.uuid4(), config={"static_provider": "ida"})
    assert "static_provider" in str(exc.value)


def test_a_malformed_report_id_is_refused():
    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_report_id": "not-a-uuid"})


def test_an_explicit_null_is_still_refused():
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_provider": None})
    assert "explicit null" in str(exc.value)


def test_omitting_the_keys_leaves_todays_payload_untouched():
    req = JobCreateRequest(sample_id=uuid.uuid4(), config={"max_iterations": 2})
    assert req.config == {"max_iterations": 2}


def test_the_choice_shows_up_in_the_settings_snapshot():
    from app.worker.analysis_worker import build_job_settings, settings_snapshot

    snap = settings_snapshot(build_job_settings({}, {"static_provider": "capa_yara"}))
    assert snap["static.provider"] == "capa_yara"
    assert snap["sandbox.provider"] == "mock"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/api/test_job_provider_overrides.py -q`
Expected: FAIL — `KeyError: 'static_provider'`.

- [ ] **Step 3: Add the three fields**

Add them to `_KnownJobConfig` with a docstring line each; the existing `_known_keys_are_valid` validator already rejects explicit nulls and validates the model, so the 422 comes for free. `sandbox_report_id` is `uuid.UUID | None` so a malformed id fails at submit rather than in the worker.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/api/test_job_provider_overrides.py tests/unit/api/test_worker_settings_overrides.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app/schemas/job.py tests/api/test_job_provider_overrides.py
uv run ruff format --check apps/api/app/schemas/job.py tests/api/test_job_provider_overrides.py
uv run mypy src/ apps/api/
git add apps/api/app/schemas/job.py tests/api/test_job_provider_overrides.py
git commit -m "feat(api): let a job choose its static and sandbox providers"
```

---

### Task 21: Settings UI — conditional fields, ordering and the hidden-dirty count

**Files:**
- Modify: `apps/web/src/types/settings.ts` (`CatalogEntry`), `apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx:55-68,194-227`, `ApplyBar.tsx:255-294`, `GroupHeader.tsx:337-361`, `apps/web/e2e/mocks.ts` (a `static` group with `applies_when`), `apps/web/e2e/settings-configuration.spec.ts` (two cases)
- Test: `cd apps/web && npx playwright test e2e/settings-configuration.spec.ts --project=chromium`

**Interfaces:**
- Consumes: `CatalogEntry.applies_when`, `.order` from `GET /api/v1/settings/schema` (Task 3).
- Produces: `visibleEntries(entries, values, pending)` in `ConfigurationTab.tsx`; `ApplyBar` gains `hiddenKeys: string[]`.

- [ ] **Step 1: Add the e2e cases first**

In `apps/web/e2e/mocks.ts`, add a third group to `MOCK_SETTINGS_SCHEMA` so the fixture exercises the feature (comment: "Task A21: `applies_when` drives conditional visibility; `order: -1` puts the selector first"):

```ts
    {
      key: "sandbox",
      title: "Sandbox provider",
      entries: [
        {
          key: "core.sandbox.provider", namespace: "core", path: "sandbox.provider",
          type: "enum", default: "mock", nullable: false,
          choices: ["mock", "cape2", "upload", "triage"],
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Sandbox provider", description: "Which sandbox produces the dynamic evidence.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1,
        },
        {
          key: "core.sandbox.cape2.base_url", namespace: "core", path: "sandbox.cape2.base_url",
          type: "str", default: "http://localhost:8000", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "CAPEv2 base URL", description: "Base URL of the CAPEv2 REST API.",
          applies: "next_job", editable: true, reason: null, probe: "cape2",
          applies_when: { "core.sandbox.provider": ["cape2"] }, order: 0,
        },
        {
          key: "core.sandbox.triage.base_url", namespace: "core", path: "sandbox.triage.base_url",
          type: "str", default: "https://tria.ge/api/v0", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Triage API base URL", description: "Hatching Triage cloud API root.",
          applies: "next_job", editable: true, reason: null, probe: "triage",
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
        },
      ],
    },
```
with matching rows in `MOCK_SETTINGS_VALUES` (`source: "default"` for all three, `core.sandbox.provider` value `"cape2"`), and `applies_when: null, order: 0` added to every existing fixture entry so the mock matches the DTO.

In `apps/web/e2e/settings-configuration.spec.ts`:

```ts
  test("switching the sandbox provider reveals the Triage fields and hides the CAPE ones", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();

    await expect(page.getByText("core.sandbox.cape2.base_url")).toBeVisible();
    await expect(page.getByText("core.sandbox.triage.base_url")).toHaveCount(0);

    await page
      .locator("#setting-core\\.sandbox\\.provider select")
      .selectOption("triage");

    await expect(page.getByText("core.sandbox.triage.base_url")).toBeVisible();
    await expect(page.getByText("core.sandbox.cape2.base_url")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Test triage" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Test cape2" })).toHaveCount(0);
  });

  test("an edit that a provider switch hides is still staged and is counted", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();

    await page
      .locator("#setting-core\\.sandbox\\.cape2\\.base_url input[type=text]")
      .fill("http://cape.example:8000");
    await expect(page.getByText("1 change pending")).toBeVisible();

    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("triage");

    await expect(page.getByText("core.sandbox.cape2.base_url")).toHaveCount(0);
    await expect(page.getByText("2 changes pending")).toBeVisible();
    await expect(page.getByText("1 in a hidden field")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: { next_job: 2 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    expect(patches).toEqual([
      {
        changes: {
          "core.sandbox.cape2.base_url": "http://cape.example:8000",
          "core.sandbox.provider": "triage",
        },
      },
    ]);
  });
```
The second case is the whole point of keeping hidden edits in `pending`: a staged value that scrolls out of view because of an unrelated switch must not be silently dropped, and the operator must be told it is still there.

- [ ] **Step 2: Run the spec to verify it fails**

Run (after `free -g` shows >= 6 GB and no `next dev` is running): `cd apps/web && npx playwright test e2e/settings-configuration.spec.ts --project=chromium`
Expected: FAIL — the Triage row is visible from the start (nothing filters) and the pending count reads "2 changes pending" without the hidden note.

- [ ] **Step 3: Mirror the DTO in TypeScript**

```ts
export interface CatalogEntry {
  // …existing fields unchanged…
  /** Show this entry only while every listed key holds one of the listed
   *  values. Null means "always". The API never hides anything: a setting the
   *  form does not show is still in effect, and the values endpoint says so. */
  applies_when: Record<string, string[]> | null;
  /** Rank inside the group; lower first. Provider selectors use -1. */
  order: number;
}
```

- [ ] **Step 4: Filter, sort and count**

In `ConfigurationTab.tsx`:

```tsx
/** The value a dependency currently holds: what the user staged, else what the
 *  server reports. Staged wins so the form reacts to the switch immediately,
 *  before anything is applied. */
function effectiveValue(
  key: string,
  values: Record<string, SettingValue>,
  pending: Record<string, unknown>
): unknown {
  return key in pending ? pending[key] : values[key]?.value;
}

function isVisible(
  entry: CatalogEntry,
  values: Record<string, SettingValue>,
  pending: Record<string, unknown>
): boolean {
  if (!entry.applies_when) return true;
  return Object.entries(entry.applies_when).every(([key, allowed]) =>
    allowed.includes(String(effectiveValue(key, values, pending) ?? ""))
  );
}
```
and inside `visibleGroups`, after the search filter, `entries: entries.filter((e) => isVisible(e, s.values, s.pending)).sort((a, b) => a.order - b.order || a.key.localeCompare(b.key))`. The group rail's dirty dot keeps using the group's **full** entry list, so a group holding only hidden staged edits still shows one.

`GroupHeader` receives `probes` computed from the **visible** entries (the existing `g.entries.map(...)` call site now sees the filtered list, so this needs no change beyond passing the filtered group) and its label becomes `` `Test ${name}` `` unchanged.

`ApplyBar` gains the count:

```tsx
  const keys = Object.keys(pending);
  const hidden = keys.filter((k) => hiddenKeys.includes(k));
  // ...the early return and the confirmation list are unchanged; the counter
  // line becomes:
        <span className="text-sm text-text-primary">
          {keys.length} change{keys.length === 1 ? "" : "s"} pending
          {hidden.length > 0 && (
            <span className="text-text-muted">
              {" "}· {hidden.length} in a hidden field{hidden.length === 1 ? "" : "s"}
            </span>
          )}
        </span>
```
with `hiddenKeys` passed from `ConfigurationTab` as the staged keys whose entry is not currently visible. In the confirmation list a hidden row is annotated `(hidden by the current provider selection)` so "Confirm and apply" never sends a value the operator cannot see without saying so.

- [ ] **Step 5: Run the spec and the type checks**

Run: `cd apps/web && npx tsc --noEmit && npm run lint && npx playwright test e2e/settings-configuration.spec.ts --project=chromium`
Expected: PASS; lint shows the 10 pre-existing warnings and no new ones.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/types/settings.ts "apps/web/src/app/(app)/settings/configuration" apps/web/e2e/mocks.ts apps/web/e2e/settings-configuration.spec.ts
git commit -m "feat(web): show only the settings the selected providers use, and count the hidden edits"
```

---

### Task 22: Job submission — provider selects and the attached report

**Files:**
- Modify: `apps/web/src/lib/api.ts:514-545` (`createJob`, `uploadSandboxReport`, `getSandboxReports`), `apps/web/src/app/(app)/samples/page.tsx:249-275` (the Analyze button becomes a small dialog)
- Create: `apps/web/e2e/job-submit-providers.spec.ts`
- Test: `cd apps/web && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`

**Interfaces:**
- Produces:
  ```ts
  export interface SandboxReportDTO {
    id: string; format: string; task_id: string | null; size_bytes: number;
    sample_sha256_match: boolean; warning: string | null; uploaded_at: string;
  }
  uploadSandboxReport(sampleId: string, file: File): Promise<SandboxReportDTO>
  getSandboxReports(sampleId: string): Promise<{ items: SandboxReportDTO[]; total: number }>
  createJob(sampleId: string, config?: Record<string, unknown>): Promise<JobDTO>   // unchanged
  ```
- Consumes: the Task 14 routes and the Task 20 job keys.

**The default is "inherit".** An omitted key means the settings decide, so a submission with neither select touched sends exactly today's payload (`{sample_id, config: null}`) and the existing `test_omitting_the_keys_leaves_todays_payload_untouched` is its server-side twin.

- [ ] **Step 1: Write the e2e spec first**

```ts
// apps/web/e2e/job-submit-providers.spec.ts
import { test, expect } from "./fixtures";

/**
 * The submit dialog on /samples: two optional provider selects and an
 * "Attach sandbox report" input. "Inherit from settings" is the default for
 * both selects and sends no key at all, so an operator who has configured the
 * providers once never sees the difference.
 */
test.describe("Job submission with providers", () => {
  test("submitting without touching the selects sends today's payload", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-1", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ config: null });
  });

  test("choosing providers sends them in the job config", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-2", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Static provider").selectOption("capa_yara");
    await page.getByLabel("Sandbox provider").selectOption("triage");
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies[0]).toMatchObject({
      config: { static_provider: "capa_yara", sandbox_provider: "triage" },
    });
  });

  test("attaching a report uploads it and pins the job to the upload provider", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/samples/*/sandbox-reports", (r) =>
      r.request().method() === "POST"
        ? r.fulfill({
            status: 201,
            json: {
              id: "rep-1", format: "cape2", task_id: "4242", size_bytes: 1234,
              sample_sha256_match: true, warning: null,
              uploaded_at: "2026-09-04T10:00:00Z",
            },
          })
        : r.fulfill({ json: { items: [], total: 0 } })
    );
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-3", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Attach sandbox report").setInputFiles({
      name: "report.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify({ info: { version: "CAPEv2", id: 4242 } })),
    });
    await expect(page.getByText("cape2 · task 4242")).toBeVisible();
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies[0]).toMatchObject({ config: { sandbox_report_id: "rep-1" } });
  });

  test("a hash mismatch on the uploaded report is shown before submitting", async ({
    authenticatedPage: page,
  }) => {
    await page.route("**/api/v1/samples/*/sandbox-reports", (r) =>
      r.request().method() === "POST"
        ? r.fulfill({
            status: 201,
            json: {
              id: "rep-2", format: "cape2", task_id: null, size_bytes: 10,
              sample_sha256_match: false,
              warning: "The report's target sha256 (cccccccccccc…) does not match this sample.",
              uploaded_at: "2026-09-04T10:00:00Z",
            },
          })
        : r.fulfill({ json: { items: [], total: 0 } })
    );

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Attach sandbox report").setInputFiles({
      name: "other.json",
      mimeType: "application/json",
      buffer: Buffer.from("{}"),
    });
    await expect(page.getByRole("alert")).toContainText("does not match this sample");
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd apps/web && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`
Expected: FAIL — clicking Analyze starts a job immediately; there is no dialog and no "Start analysis" button.

- [ ] **Step 3: Add the API client methods**

```ts
  /* ── Sandbox reports ───────────────────────────────── */
  uploadSandboxReport(sampleId: string, file: File) {
    const fd = new FormData();
    fd.append("file", file);
    return this.uploadRequest<SandboxReportDTO>(
      `/api/v1/samples/${sampleId}/sandbox-reports`,
      fd
    );
  }

  getSandboxReports(sampleId: string) {
    return this.request<{ items: SandboxReportDTO[]; total: number }>(
      `/api/v1/samples/${sampleId}/sandbox-reports`
    );
  }

  deleteSandboxReport(sampleId: string, reportId: string) {
    return this.request<void>(
      `/api/v1/samples/${sampleId}/sandbox-reports/${reportId}`,
      { method: "DELETE" }
    );
  }
```

- [ ] **Step 4: Turn the Analyze button into a dialog**

The row's button opens `submitFor`, a small modal built on the same shape as the existing sample-detail modal (`role="dialog"`, `aria-modal`, Escape closes, backdrop click closes):

```tsx
const STATIC_PROVIDERS = ["ghidra", "r2", "capa_yara", "generic_mcp", "none"] as const;
const SANDBOX_PROVIDERS = ["mock", "cape2", "upload", "triage"] as const;

async function startAnalysis(sampleId: string) {
  // Omitted keys mean "inherit from settings", so a submission that touches
  // nothing sends the payload this page has always sent.
  const config: Record<string, unknown> = {};
  if (staticProvider) config.static_provider = staticProvider;
  if (sandboxProvider) config.sandbox_provider = sandboxProvider;
  if (attachedReport) config.sandbox_report_id = attachedReport.id;
  const job = await api.createJob(
    sampleId,
    Object.keys(config).length > 0 ? config : undefined
  );
  window.location.href = `/analysis/${job.id}/live`;
}
```
The two `<select>`s are labelled "Static provider" and "Sandbox provider" with a first `<option value="">Inherit from settings</option>`; the file input is labelled "Attach sandbox report" and accepts `.json,.json.gz`. On change it calls `uploadSandboxReport`, then renders `` `${r.format} · task ${r.task_id ?? "unknown"}` `` and, when `sample_sha256_match` is false, the returned `warning` in a `role="alert"` block — the operator decides whether to go ahead. Uploading a report disables the sandbox select and shows "Sandbox: upload (from the attached report)", which is what the worker will force anyway.

- [ ] **Step 5: Run the spec and the type checks**

Run: `cd apps/web && npx tsc --noEmit && npm run lint && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/lib/api.ts "apps/web/src/app/(app)/samples/page.tsx" apps/web/e2e/job-submit-providers.spec.ts
git commit -m "feat(web): choose providers and attach a sandbox report when starting an analysis"
```

---

### Task 23: Move the tests, drop the re-exports, update the documentation and compose

**Files:**
- Move (`git mv`, import paths only — no test body changes beyond the import lines):
  ```bash
  git mv src/maljan/agents/ghidra_tool_selector.py src/maljan/providers/static/ghidra_tool_selector.py
  git mv tests/unit/test_load_program_pinning.py tests/providers/static/test_load_program_pinning.py
  git mv tests/unit/test_wave6_ghidra_delivery.py tests/providers/static/test_wave6_ghidra_delivery.py
  git mv tests/unit/agents/test_ghidra_tool_selector.py tests/providers/static/test_ghidra_tool_selector.py
  git mv tests/unit/agents/test_ghidra_program_switch.py tests/providers/static/test_ghidra_program_switch.py
  git mv tests/unit/agents/test_ghidra_load_failure.py tests/providers/static/test_ghidra_load_failure.py
  git mv tests/unit/agents/test_dynamic_degrades_without_cape.py tests/providers/sandbox/test_dynamic_degrades_without_cape.py
  ```
  `tests/unit/agents/test_static_bug07.py` **stays**: BUG-07 is about the analyst's meta-claim handling, not about Ghidra.
- Modify: `src/maljan/agents/static_analyst.py` (delete the deprecated re-exports and delegations added in Task 9), `README.md:180-200`, `.env.example:225-300`, `docker/docker-compose.yml:160-200,240-280`, `src/maljan/core/config.py` (`MCPConfig` docstring only)
- Test: the seven moved modules, plus `tests/providers/test_capability_gates.py`

- [ ] **Step 1: Move the files and fix the imports**

After the `git mv` block, the only edits inside the moved test modules are import lines: `from maljan.agents.static_analyst import StaticAnalyst` becomes `from maljan.providers.static.ghidra import GhidraStaticProvider` where the test exercises provider behaviour, and stays as-is where it exercises the analyst (`test_wave6_ghidra_delivery.py` tests `_extract_load_hint`, which is still the analyst's). `git diff -M --stat` must show the moves as renames with a small similarity loss.

Run: `uv run pytest tests/providers -q`
Expected: PASS.

- [ ] **Step 2: Delete the deprecated re-exports**

Remove from `static_analyst.py`: `StaticAnalyst._GHIDRA_ALLOWED_TOOLS`, `_ghidra_tool_mode`, `_select_ghidra_tools`, `_pin_load_program_path`, `_wrap_load_program` and the `maljan.providers.static.ghidra` import that fed them. `_refine_tools_for_sample` stays, now a two-line call into `provider.select_tools`. Then:

Run: `grep -rn "_GHIDRA_ALLOWED_TOOLS\|_select_ghidra_tools\|_pin_load_program_path" src tests apps`
Expected: hits only under `src/maljan/providers/static/` and `tests/providers/`.

- [ ] **Step 3: Rename the environment variables in the templates**

`.env.example`: rename in place and keep every comment, adding one line above each renamed block naming the old name:

| Old | New |
| :-- | :-- |
| `SANDBOX__BACKEND` | `SANDBOX__PROVIDER` |
| `SANDBOX__CAPE2_BASE_URL` | `SANDBOX__CAPE2__BASE_URL` |
| `SANDBOX__CAPE2_API_TOKEN` | `SANDBOX__CAPE2__API_TOKEN` |
| `SANDBOX__CAPE2_TIMEOUT_SECONDS` | `SANDBOX__CAPE2__TIMEOUT_SECONDS` |
| `SANDBOX__CAPE2_POLL_INTERVAL_SECONDS` | `SANDBOX__CAPE2__POLL_INTERVAL_SECONDS` |
| `MCP__GHIDRA__*` | `STATIC__GHIDRA__*` |
| `MCP__CAPE__*` | `SANDBOX__CAPE2__MCP__*` |

plus a new commented block for the settings that did not exist before: `STATIC__PROVIDER=ghidra`, `STATIC__R2__*`, `STATIC__CAPA__*`, `STATIC__YARA__*`, `STATIC__GENERIC__*`, `SANDBOX__TRIAGE__*`, `SANDBOX__UPLOAD__*`, each with its default and a one-line explanation, and a header paragraph:

```
# ---------------------------------------------------------------------------
# Static analysis provider and sandbox provider
# ---------------------------------------------------------------------------
# STATIC__PROVIDER picks the tool the static analyst uses; SANDBOX__PROVIDER
# picks where the dynamic evidence comes from. Everything under a provider's
# own prefix is inert unless that provider is selected.
#
# The pre-2026-09 names (MCP__GHIDRA__*, MCP__CAPE__*, SANDBOX__BACKEND,
# SANDBOX__CAPE2_*) still work: they are translated on startup and logged once.
# ---------------------------------------------------------------------------
```

`docker/docker-compose.yml`: rename the same variables in both service blocks (api at :166-199, worker at :247-278). The `${SANDBOX_BACKEND:-cape2}` style host-side variable names stay as they are — they are the compose `.env`'s names, not the application's — so `docker/.env` needs no edit; only the container-side key changes: `SANDBOX__PROVIDER: ${SANDBOX_BACKEND:-cape2}`. Add a comment above the first renamed line saying exactly that, so nobody "fixes" the mismatch.

`README.md:180-200`: replace the CAPE-only paragraph with one that states the choice — the default profile is Ghidra plus CAPEv2 (and mock without one), and any of radare2, capa+YARA, an uploaded report or Hatching Triage can be selected from Settings → Static analysis provider / Sandbox provider or per job. Neither Ghidra nor CAPE is required to run Maljan; `STATIC__PROVIDER=capa_yara` with `SANDBOX__PROVIDER=upload` needs no external service at all. Keep the two renamed env lines in the CAPE snippet.

- [ ] **Step 4: Verify compose still parses and the aliases still resolve**

```bash
docker compose -f docker/docker-compose.yml config >/dev/null && echo "compose ok"
uv run python - <<'PY'
from maljan.core.config import Settings
import os
os.environ["MCP__GHIDRA__URL"] = "http://legacy:8089"
os.environ["SANDBOX__BACKEND"] = "cape2"
s = Settings(_env_file=None)
assert s.static.ghidra.url == "http://legacy:8089"
assert s.sandbox.provider == "cape2"
print("legacy env still resolves")
PY
grep -c "MCP__GHIDRA__\|SANDBOX__CAPE2_[A-Z]" .env.example docker/docker-compose.yml
```
Expected: `compose ok`, `legacy env still resolves`, and the grep count is 0 in both files except inside the comment blocks that name the old spellings (check the hits by eye if the count is non-zero).

- [ ] **Step 5: Run the moved tests and lint**

Run: `uv run pytest tests/providers tests/unit/agents tests/unit/core tests/unit/api -q`
Expected: PASS.

```bash
uv run ruff check src/maljan tests/providers
uv run ruff format --check src/maljan tests/providers
uv run mypy src/ apps/api/
```

- [ ] **Step 6: Commit**

```bash
git add src/maljan/providers/static/ghidra_tool_selector.py src/maljan/agents/static_analyst.py src/maljan/core/config.py tests/providers tests/unit README.md .env.example docker/docker-compose.yml
git commit -m "refactor: move the provider tests, drop the deprecated re-exports and rename the provider env vars"
```

---

### Task 24: The final gate

**Files:**
- Create: `.github/workflows/ci.yml` gains one step (the evaluation-diff gate)
- Modify: `docs/specs/2026-09-03-provider-layer-design.md` (status line only)
- Test: everything

- [ ] **Step 1: Add the CI gate that protects the paper**

In `.github/workflows/ci.yml`, in the `quality` job before the tests:

```yaml
      - name: Evaluation artefacts are untouched
        run: |
          # Sub-project A is a refactor: the measured numbers in the paper come
          # from tests/evaluation/, and nothing on this branch may change them.
          git fetch --no-tags --depth=50 origin dev
          changed="$(git diff --name-only origin/dev... -- tests/evaluation/ || true)"
          if [ -n "$changed" ]; then
            echo "tests/evaluation/ must not change on this branch:"
            echo "$changed"
            exit 1
          fi
```

- [ ] **Step 2: Run the full verification list**

Each command with its expected result; a failure stops the task rather than being worked around.

```bash
make lint format-check typecheck                      # clean
uv run pytest tests/ -q                               # all green
make facts && git status --short tests/evaluation/    # no output
git diff dev -- tests/evaluation/                     # no output
git diff --name-only dev... | grep '^tests/evaluation/' ; echo "exit=$?"   # exit=1 (no matches)
uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers -q  # the six gates
grep -rn "mcp\.ghidra\|mcp\.cape" src apps/api        # only config.py's alias table
cd apps/web && npx tsc --noEmit && npm run lint && npm run build && cd ../..
cd apps/web && npx playwright test e2e/settings-configuration.spec.ts e2e/job-submit-providers.spec.ts --project=chromium --project=firefox && cd ../..
```
The test count is **not** re-pinned: `tests/evaluation/test_suite_count.json` is a committed artefact and `paper_facts.py` reads it; the live count is higher after this branch and that is expected and noted in the PR body, not written into the artefact.

- [ ] **Step 3: Live verification**

Recipe in the `local-observation-run-recipe` memory; cap the CPU before starting llama, confirm `free -g` >= 10 GB, and stop `next dev` before any browser check.

1. Default profile: today's `.env`, one job to completion. `run_summary.settings_snapshot` shows `static.provider=ghidra`, `sandbox.provider=mock`; the report carries the same sections as the previous run.
2. `sandbox.provider=upload`: attach a CAPE JSON from `data/cape_reports/` through the submit dialog; the job completes with no detonation and the dynamic section is populated.
3. `static.provider=capa_yara` with Ghidra off: the static section fills with capa hits and the report's technical evidence has a `capa` block.
4. In Settings, switch the sandbox selector to Triage: the CAPE fields disappear, the Triage fields appear, and "Test triage" fails legibly with no token configured.
5. `static.provider=r2`: end to end when r2mcp is installed; otherwise "Test r2" names the missing binary and the run degrades rather than failing.

- [ ] **Step 4: Update the spec's status line and open the PR**

The spec's status line becomes `implemented on branch feat/provider-layer; PR into dev on <date>`. PR body: the invariant and how it is enforced, the six gates, the live-run results, the note that the pinned test count is unchanged while the live count grew, and the two follow-ups sub-project B inherits (`mcp.servers` as a dict, `MCPServerConfig.tools`).

```bash
git add .github/workflows/ci.yml docs/specs/2026-09-03-provider-layer-design.md
git commit -m "ci: refuse any change to the evaluation artefacts on a refactor branch"
```

---

## Verification before merge

1. `make lint format-check typecheck` — clean.
2. `uv run pytest tests/ -q` — all green.
3. `make facts && git status --short tests/evaluation/` — empty; `git diff dev -- tests/evaluation/` — empty.
4. The six gates green — prompt byte identity (static ghidra, dynamic cape2), allow-list identity (20 Ghidra names, 13 CAPE essentials), the CAPE normalisation golden, the legacy env aliases, `tests/unit/core/test_settings_catalog.py`, and the default-profile smoke test; `grep -rn "mcp\.ghidra\|mcp\.cape" src apps/api` shows only the alias table in `config.py` and the Ghidra and CAPE provider modules.
5. `cd apps/web && npx tsc --noEmit && npm run lint && npm run build`; `npx playwright test e2e/settings-configuration.spec.ts e2e/job-submit-providers.spec.ts --project=chromium --project=firefox`.
6. Live run (mock sandbox, local llama, CPU cap first): the five scenarios in Task 24 Step 3.
7. PR into `dev`, CI green including Semgrep and the new evaluation-diff gate; merging is left to the user.

## Self-review notes

- **Spec coverage:** §1→T1 (the goldens that make the problem statement testable), §3→T1+T24, §4→T5, §4.1→T5, §4.2→T5+T7+T9, §5→T6+T7, §6→T2+T3+T4+T20, §7→T9+T10+T11+T12+T19, §8→T14+T15, §9→T16+T17, §10→T18+T19, §11→T21+T22, §12→T1+T23+T24, §13→T5 (frozen ids and shapes; nothing in A changes them), §14→"Verification before merge". Out-of-scope items (the generic REST sandbox, `mcp.servers`, agent definitions, moving the nine raw-CAPE consumers) are untouched.
- **Type consistency across tasks:** `StaticCapabilities` (T5, T9, T10, T13, T18, T19), `SandboxCapabilities` (T5, T7, T11, T15, T16), `StaticJobContext` (T5, T9, T10, T12), `StaticEvidenceBundle` (T5, T19), `MirrorSpec` (T5, T9, T12, T18), `SandboxRun` (T6, T7, T15, T16), `SandboxReport` (T6, T7, T15, T16, T17), `to_cape_shaped_dict` (T6, T7, T15, T16, T17), `sniff_format` (T6, T14, T15), `as_sandbox_client` (T7, T8), `get_static_provider` / `get_sandbox_provider` (T5, T8, T10, T11, T12, T19), `static_provider_ids` / `sandbox_provider_ids` (T5, T20), settings keys `static.provider`, `static.ghidra.*`, `static.r2.*`, `static.capa.*`, `static.yara.*`, `static.generic.*`, `sandbox.provider`, `sandbox.cape2.*`, `sandbox.cape2.mcp.*`, `sandbox.triage.*`, `sandbox.upload.*` (T2 declares, T3 annotates, T4 migrates, T20 overrides per job, T21 renders, T23 documents).
- **Order dependencies:** T1 must be green on unmodified code before T2 (a golden captured from changed code proves nothing). T2 before T3 before T4. T5 before every adapter. T6 before T7. T9 before T10 (the fragment must exist before the prompt is assembled from it). T7+T11 before T15 (the upload provider reuses the CAPE reader). T16 before T17 is convenient but not required; T17 regenerates the goldens, so it must come after every task that reads them unchanged. T14 before T15. T20 before T22. T23 last but one; T24 last. Everything else follows the numbering.
- **Deliberate compromises, named rather than hidden:** (a) the static prompt's seam falls after one sentence, so four provider-neutral sentences are repeated in each provider's fragment — byte identity is worth more than the duplication, and sub-project C removes it; (b) `Settings.mcp` survives tasks 2-11 as a mirror so intermediate commits stay green, and Task 12 deletes it; (c) `to_cape_shaped_dict`'s identity short circuit means the CAPE render path is only exercised by tests, which is why test (c) forces `raw={}` over real fixtures; (d) `MCPServerConfig.tools` is read by today's dynamic analyst through a `getattr` that can never hit, so the move drops it rather than carrying a dead branch — sub-project B adds the real field.
- **Source facts worth knowing before starting:** the CAPE golden corpus is `data/cape_reports/*.json` (97 reports), not `data/samples/*/sample_1.json` — only `data/samples/dynamic/sample_1.json` is CAPE-shaped there, and `network/sample_1.json` and `static/sample_1.json` are JSON *lists*. `tests/fixtures/` does not exist yet; Task 1 creates it.
