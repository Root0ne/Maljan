# Tool Servers Implementation Plan (sub-project B)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator connect any MCP tool server to any analyst, and any HTTP sandbox to the dynamic path, from the settings UI — by turning `mcp.servers` into a real registry of `MCPServerConfig` entries with an allow-list and an agent binding, moving the two built-in sidecars (`network-mcp`, `threatintel-mcp`) into that registry with byte-identical launch parameters, extracting one `ServerHandle`/`ServerRegistry` lifecycle from `GenericMCPStaticProvider.open`, and adding a `rest` sandbox provider whose report fields are selected with RFC 9535 JSONPath — **without changing a single prompt byte, tool name, sandbox report dict or extractor output on the default `ghidra` + `cape2`/`mock` profile**.

**Architecture:** Twenty-two sequential tasks on one branch, one commit each. Task 1 pins today's built-in sidecar tool sets from a live handshake before anything moves, exactly as sub-project A's Task 1 pinned prompts and extractor output; every later task runs that fixture. `src/maljan/providers/servers.py` holds the only MCP attach/detach implementation in the project — the static `generic_mcp` provider becomes a thin wrapper over a `ServerHandle`, the network analyst and the judge read handles out of `ServerRegistry.for_agent(...)`, and the settings probe launches the same handle, so a stdio handshake cannot behave one way in a job and another in a connection test. `sandbox.provider=rest` is one more `SandboxProvider` behind A's contract: it reuses Triage's poll loop shape (`_parse_retry_after`, deadline per iteration, 1.5× backoff to 60 s, `ProviderError` on non-2xx) and either hands its body to the mappers the upload provider already uses (`cape2`/`cuckoo`/`triage`) or to `rest_mapping.py`, which compiles the configured JSONPaths once and coerces each match into the consumer row shapes `SandboxReport` already declares. The settings UI gains exactly two composite editors (`ServerMapEditor`, `RestSandboxEditor`); everything else stays an ordinary catalog leaf so A's staging, hidden-dirty, reset and export behaviour is unchanged.

**Tech Stack:** Python 3.13, pydantic / pydantic-settings, LangChain + LangGraph, MCP (stdio + streamable-http), `jsonpath-rfc9535`, httpx, FastAPI, SQLAlchemy async + alembic, MinIO, arq; Next.js 16 / React 19 / TypeScript; Playwright; Docker Compose.

**Spec:** docs/specs/2026-09-04-tool-servers-design.md

## Global Constraints

- Branch `feat/tool-servers` (from `feat/provider-layer` at c25ee7f until PR #5 lands in `dev`, then rebased; plan HEAD 2744dd9), one commit per task, imperative messages in the repository's voice, no AI attribution anywhere.
- Every task: TDD (failing test first), then `uv run ruff check <files>`, `uv run ruff format --check <files>`, `uv run mypy src/ apps/api/` clean; frontend tasks also `cd apps/web && npx tsc --noEmit && npm run lint` (10 pre-existing warnings, none new).
- Run only the test modules the task names (`uv run pytest <paths> -q`), never the whole suite mid-task; Playwright only the single spec a task names, `--project=chromium` only, after `free -g` shows >= 6 GB available and no `next dev` is running.
- The default profile stays byte-identical: the prompt byte-identity test, the extractor goldens, the CAPE identity test and the new built-in tool-set fixture (`tests/fixtures/golden/mcp_tools/{network,threatintel}.json`) all pass unchanged from Task 1 to Task 22.
- `tests/evaluation/**` is not modified at all (the CI gate from A enforces it), `make facts` output is byte-identical, and `tests/evaluation/test_suite_count.json` is not re-measured.
- Every new core setting needs an `ANNOTATIONS` leaf in `src/maljan/core/settings_annotations.py` (`tests/unit/core/test_settings_catalog.py` enforces it); every new `APISettings` field needs an `API_EDITABLE` or `API_READONLY` entry in `apps/api/app/services/settings_catalog_api.py`.
- Registry ids, the `Settings` provider `Literal`s and the job schema literal in `apps/api/app/schemas/job.py` stay in parity; a test refuses any drift.
- Never print or read the real `.env`; never log or return a secret value; test credentials are built at runtime (see `_dsn()` in `tests/unit/api/test_settings_probes.py`), never a literal `scheme://user:pass@host`. A per-server MCP token is stored as its own encrypted `is_secret` row and never inside the `core.mcp.servers` JSON row, never in an audit detail, and never in a response body — only ever the mask `"**********"`.
- No question sentences in headings, comments or docs.
- Playwright runs only the spec a task names, `--project=chromium` in the task, `--project=chromium --project=firefox` in the final gate.
- Every subprocess is started through `maljan.agents.subprocess_env.child_env`, with an argv **list** and never through a shell.
- Goldens are regenerated only by their capture script, and only for additive keys.
- Local development with an unchanged `.env` keeps working: every legacy environment variable resolves through the alias table to the same effective value.
- Do not run `git checkout`, `git stash` or `git reset`; `git add` explicit paths only.
- Implementers do not spawn subagents.

## Names fixed by this plan

The spec leaves these internal names open. They are chosen once here and used identically in every task below.

| Name | Where | Meaning |
| :-- | :-- | :-- |
| `AgentRole` | `src/maljan/core/config.py` | `Literal["static", "dynamic", "network", "judge"]` |
| `_builtin_servers()` | `src/maljan/core/config.py` | default factory of `MCPConfig.servers` |
| `BUILTIN_SERVER_KEYS` | `src/maljan/core/config.py` | `("network", "threatintel")` |
| `RESERVED_SERVER_KEYS` | `src/maljan/core/config.py` | `("network", "threatintel", "ghidra", "cape")` |
| `SERVER_KEY_PATTERN` | `src/maljan/core/config.py` | `r"^[a-z][a-z0-9_-]{0,31}$"` |
| `ServerHandle` / `ServerRegistry` | `src/maljan/providers/servers.py` | one server's lifecycle / all of them |
| `ServiceContainer.get_server_registry()` | `src/maljan/core/container.py` | per-container registry, closed by `aclose` |
| `BaseAnalyst._attach_registry_tools(role)` | `src/maljan/agents/base_agent.py` | appends `for_agent(role)` tools, returns degradation reasons |
| `mcp server '<name>' unavailable` | degradation reason text | one per failed server |
| `<key>__<tool>` | collision rename | later server's tools are prefixed with its key |
| `RestSandboxProvider` | `src/maljan/providers/sandbox/rest.py` | `@register_sandbox_provider("rest")` |
| `compile_mapping` / `apply_mapping` | `src/maljan/providers/sandbox/rest_mapping.py` | compile JSONPaths once / map one payload |
| `CompiledMapping`, `MappingResult`, `ChannelStats` | `rest_mapping.py` | compiled paths, one payload's outcome, per-channel counts |
| `CHANNELS`, `MAX_ROWS_PER_CHANNEL` | `rest_mapping.py` | the 12 mapped channels, 5 000 |
| `build_stub_app()` | `tests/servers/rest_stub.py` | the FastAPI stub sandbox |
| `validate_server_map` / `ServerMapError` | `apps/api/app/services/server_map.py` | PATCH-time validation of `core.mcp.servers` |
| `split_server_secrets` / `merge_server_secrets` | `apps/api/app/services/server_map.py` | tokens out of the map on save, back in on load |
| `server_token_key(server)` | `apps/api/app/services/server_map.py` | `core.mcp.servers.<server>.auth_token` |
| `SERVER_MAP_KEY` / `TOKEN_MASK` | `apps/api/app/services/server_map.py` | `"core.mcp.servers"` / `"**********"` |
| `SettingsService._save_server_tokens` / `._masked_server_map` | `apps/api/app/services/settings_service.py` | write the runtime-keyed secret rows / show the mask |
| `auth_token_source` | the `core.mcp.servers` value shape | `"ui"` / `"env"` / `"default"`, view-only, stripped on save |
| `POST /api/v1/settings/test/mcp?server=<key>` | API | the MCP probe route |
| `POST /api/v1/settings/sandbox-rest/preview` | API | the mapping preview route |
| `ServerMapEditor.tsx` / `RestSandboxEditor.tsx` | `apps/web/src/app/(app)/settings/configuration/` | the two composite editors |
| `useProviderChoices()` | `apps/web/src/app/(app)/samples/useProviderChoices.ts` | catalog-driven provider selects |

---

### Task 1: Pin the built-in sidecar tool sets from a live handshake

**Files:**
- Create: `scripts/capture_builtin_tool_sets.py`, `tests/fixtures/golden/mcp_tools/network.json`, `tests/fixtures/golden/mcp_tools/threatintel.json`, `tests/servers/__init__.py`, `tests/servers/test_builtin_tool_sets.py`
- Modify: nothing. This task must not touch `src/`.
- Test: `tests/servers/test_builtin_tool_sets.py`

**Interfaces:**
- Consumes: `network-mcp/server.py`, `threatintel-mcp/server.py`, `maljan.agents.subprocess_env.child_env`, `maljan.core.paths.get_project_root`.
- Produces:
  ```python
  # scripts/capture_builtin_tool_sets.py
  SIDECARS: dict[str, tuple[str, tuple[str, ...]]]     # key -> (cwd subdir, env_allow)
  async def enumerate_stdio_tools(command: str, args: list[str], cwd: str, env: dict[str, str]) -> list[str]
  # tests/servers/test_builtin_tool_sets.py
  def load_golden(name: str) -> list[str]              # sorted tool names, read by Task 7
  ```
  `tests/fixtures/golden/mcp_tools/<key>.json` is the single source of truth for tasks 5, 7 and 22.

- [ ] **Step 1: Write the failing test**

```python
# tests/servers/test_builtin_tool_sets.py
"""The two built-in sidecars must expose exactly the tools they expose today.

Sub-project B moves ``network-mcp`` and ``threatintel-mcp`` out of constants
inside the agents and into ``mcp.servers`` entries. The move is only free if
the tool names the model sees do not change, so they are pinned here from a
live handshake before anything moves. Names only, not schemas: the fixture is
captured on one machine and the sidecars' argument descriptions are free to
improve (risk R1 in the spec).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"


def load_golden(name: str) -> list[str]:
    """The pinned tool names for one built-in server, sorted."""
    payload = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    return sorted(payload["tools"])


@pytest.mark.parametrize("name", ["network", "threatintel"])
def test_the_golden_names_a_non_empty_tool_set(name: str) -> None:
    names = load_golden(name)
    assert names, f"{name} golden is empty"
    assert names == sorted(set(names)), "tool names must be unique and sorted"


@pytest.mark.parametrize("name", ["network", "threatintel"])
def test_the_live_sidecar_still_offers_exactly_the_pinned_tools(name: str) -> None:
    """Skipped where the sidecar cannot start; asserted where it can."""
    from scripts.capture_builtin_tool_sets import SIDECARS, enumerate_stdio_tools

    import sys

    from maljan.agents.subprocess_env import child_env

    subdir, allow = SIDECARS[name]
    try:
        live = asyncio.run(
            asyncio.wait_for(
                enumerate_stdio_tools(
                    sys.executable,
                    [str(ROOT / subdir / "server.py")],
                    str(ROOT / subdir),
                    child_env(allow=allow),
                ),
                timeout=30.0,
            )
        )
    except Exception as exc:  # noqa: BLE001 — a sidecar that cannot start is not a failure here
        pytest.skip(f"{name}-mcp did not start in this environment: {type(exc).__name__}: {exc}")
    assert sorted(live) == load_golden(name)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/servers/test_builtin_tool_sets.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts.capture_builtin_tool_sets'` and `FileNotFoundError` on the two golden files.

- [ ] **Step 3: Write the capture script**

```python
# scripts/capture_builtin_tool_sets.py
"""Freeze the tool names of the two built-in MCP sidecars as golden fixtures.

Run once, on the branch point, before the sidecars move into ``mcp.servers``:

    uv run python scripts/capture_builtin_tool_sets.py

It speaks raw stdio MCP to each server with exactly the launch parameters the
agents use today (``network_analyst.py:73-111``, ``judge_agent.py:131-158``)
and writes the tool names it is offered. Committed so a reviewer can re-run it
on ``dev`` and diff the result: the whole claim that moving the sidecars into
settings is behaviour-free rests on these names.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from maljan.agents.subprocess_env import child_env

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

# key -> (directory holding server.py and used as cwd, env names passed through)
SIDECARS: dict[str, tuple[str, tuple[str, ...]]] = {
    "network": ("network-mcp", ()),
    "threatintel": ("threatintel-mcp", ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")),
}


async def enumerate_stdio_tools(
    command: str, args: list[str], cwd: str, env: dict[str, str]
) -> list[str]:
    """Tool names a stdio MCP server offers, over one initialize + tools/list."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        response = await session.list_tools()
        return [tool.name for tool in response.tools]


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for key, (subdir, allow) in SIDECARS.items():
        names = asyncio.run(
            enumerate_stdio_tools(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            )
        )
        dest = GOLDEN / f"{key}.json"
        dest.write_text(
            json.dumps(
                {"server": key, "source": "live handshake", "tools": sorted(names)},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"{key}: {len(names)} tools -> {dest}")


if __name__ == "__main__":
    main()
```

`tests/servers/__init__.py` is an empty file, so `tests/servers` is a package like `tests/providers`.

- [ ] **Step 4: Capture the fixtures**

Run: `uv run python scripts/capture_builtin_tool_sets.py`
Expected: two files written. `network.json` holds `["extract_dns", "extract_http", "read_pcap_summary"]`; `threatintel.json` holds `["check_domain_reputation", "check_hash", "check_ip_reputation", "get_threatintel_status"]`. Commit whatever the live handshake reports — if it differs from those lists, the fixture is right and this sentence is stale.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/servers/test_builtin_tool_sets.py -q`
Expected: PASS (4 tests; the two live ones skip only where the sidecar cannot start).

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check scripts/capture_builtin_tool_sets.py tests/servers && \
uv run ruff format --check scripts/capture_builtin_tool_sets.py tests/servers && \
uv run mypy src/ apps/api/
git add scripts/capture_builtin_tool_sets.py tests/servers tests/fixtures/golden/mcp_tools
git commit -m "test(servers): pin the built-in sidecar tool sets from a live handshake"
```

---

### Task 2: The settings shape — server registry, server reference, REST sandbox

**Files:**
- Modify: `src/maljan/core/config.py:680-707` (`MCPServerConfig` gains `cwd`, `env_allow`, `tools`, `agents`, `label`; `auth_token` becomes `SecretStr`), `src/maljan/core/config.py:710-757` (`MCPConfig` gains `servers`), `src/maljan/core/config.py:800-814` (`StaticConfig.generic` becomes `StaticGenericConfig`), `src/maljan/core/config.py:855-871` (`SandboxConfig` gains `rest` and the `"rest"` literal member)
- Test: `tests/unit/core/test_server_settings.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/config.py
  AgentRole = Literal["static", "dynamic", "network", "judge"]
  SERVER_KEY_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
  BUILTIN_SERVER_KEYS: tuple[str, ...] = ("network", "threatintel")
  RESERVED_SERVER_KEYS: tuple[str, ...] = ("network", "threatintel", "ghidra", "cape")

  class MCPServerConfig(BaseModel):     # + cwd, env_allow, tools, agents, label; auth_token: SecretStr
  def _builtin_servers() -> dict[str, MCPServerConfig]
  class MCPConfig(BaseModel):           # + servers: dict[str, MCPServerConfig]
  class StaticGenericConfig(BaseModel): # server: str = ""
  class RestAuthConfig(BaseModel)
  class RestSubmitConfig(BaseModel)
  class RestStatusConfig(BaseModel)
  class RestReportConfig(BaseModel)
  class RestMappingConfig(BaseModel)
  class SandboxRestConfig(BaseModel)
  class SandboxConfig(BaseModel):       # provider Literal gains "rest"; + rest: SandboxRestConfig
  ```
- Consumes: `pydantic.SecretStr`, `sys.executable`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_server_settings.py
"""The registry of tool servers, and the REST sandbox's shape."""

from __future__ import annotations

import re
import sys
from typing import get_args

import pytest
from pydantic import SecretStr

from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    MCPServerConfig,
    SandboxConfig,
    Settings,
)


def test_the_two_sidecars_are_seeded_with_todays_launch_parameters():
    cfg = Settings(_env_file=None)
    network = cfg.mcp.servers["network"]
    assert network.enabled is True
    assert network.command == sys.executable
    assert network.args == ["network-mcp/server.py"]
    assert network.cwd == "network-mcp"
    assert network.env_allow == []
    assert network.agents == ["network"]
    assert network.tools is None, "None means every tool, which is today's behaviour"

    intel = cfg.mcp.servers["threatintel"]
    assert intel.enabled is True
    assert intel.command == sys.executable
    assert intel.args == ["threatintel-mcp/server.py"]
    assert intel.cwd == "threatintel-mcp"
    assert intel.env_allow == ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
    assert intel.agents == ["judge"]
    assert intel.tools is None


def test_builtin_keys_are_reserved_and_the_key_pattern_is_a_slug():
    assert set(BUILTIN_SERVER_KEYS) <= set(RESERVED_SERVER_KEYS)
    assert set(RESERVED_SERVER_KEYS) == {"network", "threatintel", "ghidra", "cape"}
    pattern = re.compile(SERVER_KEY_PATTERN)
    assert pattern.match("r2custom") and pattern.match("a")
    assert not pattern.match("R2") and not pattern.match("1a") and not pattern.match("a" * 33)


def test_an_auth_token_is_a_secret_everywhere_it_appears():
    cfg = Settings(_env_file=None)
    assert isinstance(MCPServerConfig().auth_token, SecretStr)
    assert isinstance(cfg.static.ghidra.auth_token, SecretStr)
    assert isinstance(cfg.sandbox.cape2.mcp.auth_token, SecretStr)
    server = MCPServerConfig(auth_token="hunter2")
    assert "hunter2" not in repr(server)
    assert server.model_dump(mode="json")["auth_token"] == "**********"


def test_static_generic_is_a_reference_to_a_server_key():
    cfg = Settings(_env_file=None)
    assert cfg.static.generic.server == ""
    assert not hasattr(cfg.static.generic, "command")


def test_the_sandbox_gains_rest_with_a_full_default_tree():
    assert "rest" in get_args(SandboxConfig.model_fields["provider"].annotation)
    rest = Settings(_env_file=None).sandbox.rest
    assert rest.base_url == ""
    assert rest.auth.header == "Authorization" and rest.auth.scheme == "Bearer"
    assert rest.submit.method == "POST" and rest.submit.task_id_path == "$.id"
    assert rest.status.done_values == ["reported", "completed", "finished"]
    assert rest.report.format == "generic" and rest.report.pcap_path == ""
    assert rest.mapping.target_sha256 == "$.target.sha256"
    assert rest.mapping.processes == "" and rest.mapping.field_names == {}
    assert rest.timeout_seconds == 900 and rest.poll_interval_seconds == 15
    assert rest.verify_tls is True


def test_a_server_entry_carries_an_allow_list_and_an_agent_binding():
    server = MCPServerConfig(tools=["open_file"], agents=["static"], label="xyz")
    assert server.tools == ["open_file"] and server.agents == ["static"]
    with pytest.raises(ValueError):
        MCPServerConfig(agents=["auditor"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/core/test_server_settings.py -q`
Expected: FAIL — `ImportError: cannot import name 'BUILTIN_SERVER_KEYS'`.

- [ ] **Step 3: Extend `MCPServerConfig` and seed the registry**

In `src/maljan/core/config.py`, add `import sys` beside `import json` (line 23), then replace the field block at lines 688-707 and the `MCPConfig` body:

```python
AgentRole = Literal["static", "dynamic", "network", "judge"]

# A server key is a slug: lowercase, starts with a letter, at most 32 chars.
# It is a path segment in the probe URL and a prefix in a renamed tool name,
# so it is validated in the model rather than only in the API.
SERVER_KEY_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
BUILTIN_SERVER_KEYS: tuple[str, ...] = ("network", "threatintel")
RESERVED_SERVER_KEYS: tuple[str, ...] = ("network", "threatintel", "ghidra", "cape")
```

`MCPServerConfig` keeps `enabled`, `transport`, `command`, `args`, `env`, `url`, `tool_selection` and `use_all_tools` exactly as they are, and gains:

```python
    # New in sub-project B.
    # Working directory for the stdio child; empty means the repository root.
    cwd: str = ""
    # Names copied out of the API process's own environment into the child.
    # The only way a credential reaches a sidecar: ``env`` below is a visible
    # setting, so a token written there would be readable in the UI.
    env_allow: list[str] = Field(default_factory=list)
    # Allow-list. ``None`` exposes every tool the server advertises (what the
    # built-ins do today); ``[]`` exposes nothing, which is what a freshly
    # added custom server does until the operator ticks tools from its probe.
    tools: list[str] | None = None
    # Which analysts receive this server's tools.
    agents: list[AgentRole] = Field(default_factory=list)
    # Display name; empty means "use the key".
    label: str = ""
```

and `auth_token` becomes `auth_token: SecretStr = SecretStr("")`. Every existing reader of `.auth_token` is updated in the same commit: `src/maljan/providers/static/generic_mcp.py`'s http branch (`self._cfg.auth_token.get_secret_value()`), `src/maljan/providers/static/ghidra.py` and `src/maljan/agents/ghidra_http_client.py` wherever they build a bearer header. Find them with `grep -rn "auth_token" src/ apps/api/` and unwrap each with `.get_secret_value()`.

```python
def _builtin_servers() -> dict[str, MCPServerConfig]:
    """The two sidecars every run depends on, as settings rather than constants.

    Byte-for-byte the launch parameters ``NetworkAnalyst._initialize_mcp_client``
    and ``JudgeAgent._initialize_mcp_client`` used before sub-project B:
    ``sys.executable`` running ``<dir>/server.py`` with ``<dir>`` as cwd, the
    threat-intel one alone allowed to see the two intel keys. ``tools=None``
    keeps the whole manifest, which is what those agents did, and what
    ``tests/fixtures/golden/mcp_tools/*.json`` pins.
    """
    return {
        "network": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["network-mcp/server.py"],
            cwd="network-mcp",
            agents=["network"],
            label="Network MCP",
        ),
        "threatintel": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["threatintel-mcp/server.py"],
            cwd="threatintel-mcp",
            env_allow=["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"],
            agents=["judge"],
            label="Threat intel MCP",
        ),
    }
```

`MCPConfig` keeps its two deprecated read-only properties (`ghidra`, `cape`) and its docstring's compatibility-view paragraph, and gains one real field above them:

```python
    # The operator-visible registry of tool servers, keyed by slug. Built-in
    # entries are re-seeded on load, so "delete" in the UI means enabled=False
    # for them and a real removal for a custom key.
    servers: dict[str, MCPServerConfig] = Field(default_factory=_builtin_servers)

    @model_validator(mode="after")
    def _reseed_builtins(self) -> "MCPConfig":
        """A built-in key that is absent comes back; one that is present is kept.

        An operator who disables ``threatintel`` stores ``enabled=False`` and
        keeps every other field they set. An override written before a built-in
        existed simply gains it. Neither can end with a run silently missing a
        sidecar the pipeline assumes.
        """
        for key, default in _builtin_servers().items():
            self.servers.setdefault(key, default)
        return self
```

`StaticConfig.generic` becomes a reference:

```python
class StaticGenericConfig(BaseModel):
    """Which entry of ``mcp.servers`` the ``generic_mcp`` static provider drives.

    Sub-project A gave this provider its own copy of an ``MCPServerConfig``.
    One server can now serve several analysts, so the configuration lives in
    ``mcp.servers`` and this is only the name of the one the static provider
    owns. Empty means the provider has nothing to attach, and its probe says
    exactly that rather than failing obscurely.
    """

    server: str = ""
```

with `generic: StaticGenericConfig = Field(default_factory=StaticGenericConfig)` on `StaticConfig` (line 814).

- [ ] **Step 4: Write the REST sandbox settings**

Immediately after `SandboxUploadConfig` (line 853), the six models exactly as the spec's §3.4 declares them:

```python
class RestAuthConfig(BaseModel):
    """How the credential is presented to the sandbox's API."""

    header: str = "Authorization"
    scheme: str = "Bearer"  # empty sends the token as the raw header value
    token: SecretStr = SecretStr("")


class RestSubmitConfig(BaseModel):
    """The multipart submission and where the task id is read from its answer."""

    method: Literal["POST", "PUT"] = "POST"
    path: str = "/samples"
    file_field: str = "file"
    extra_fields: dict[str, str] = Field(default_factory=dict)
    task_id_path: str = "$.id"


class RestStatusConfig(BaseModel):
    """The poll endpoint and the two terminal state sets."""

    path: str = "/samples/{task_id}"
    state_path: str = "$.status"
    done_values: list[str] = Field(
        default_factory=lambda: ["reported", "completed", "finished"]
    )
    failed_values: list[str] = Field(default_factory=lambda: ["failed", "error"])


class RestReportConfig(BaseModel):
    """Where the report is, what shape it is in, and the optional capture."""

    path: str = "/samples/{task_id}/report"
    format: Literal["cape2", "cuckoo", "triage", "generic"] = "generic"
    pcap_path: str = ""


class RestMappingConfig(BaseModel):
    """RFC 9535 JSONPaths selecting each consumer channel out of a report.

    Read only when ``report.format`` is ``generic``. An empty path is not a
    mistake: it says the sandbox does not publish that channel, and the
    provider lists it in ``SandboxReport.unavailable`` so a rendered report
    never reads like a clean sample by omission.
    """

    target_sha256: str = "$.target.sha256"
    processes: str = ""      # each match: {pid, ppid, name, command_line}
    calls: str = ""          # each match: {pid, api, args, timestamp}
    signatures: str = ""     # each match: {name, description, severity, ttps}
    dns: str = ""            # each match: {request, type, answers[]}
    http: str = ""
    tcp: str = ""            # each match: {dst, dport}
    udp: str = ""
    hosts: str = ""          # each match: a string
    domains: str = ""
    dropped_files: str = ""  # each match: {name, sha256, size}
    registry: str = ""       # each match: a string
    # "<channel>.<consumer field>" -> the field name this sandbox uses,
    # e.g. {"processes.command_line": "cmdline"}.
    field_names: dict[str, str] = Field(default_factory=dict)


class SandboxRestConfig(BaseModel):
    """Any HTTP sandbox, described rather than coded."""

    base_url: str = ""
    auth: RestAuthConfig = Field(default_factory=RestAuthConfig)
    submit: RestSubmitConfig = Field(default_factory=RestSubmitConfig)
    status: RestStatusConfig = Field(default_factory=RestStatusConfig)
    report: RestReportConfig = Field(default_factory=RestReportConfig)
    mapping: RestMappingConfig = Field(default_factory=RestMappingConfig)
    timeout_seconds: Annotated[int, Field(ge=1)] = 900
    poll_interval_seconds: Annotated[int, Field(ge=1)] = 15
    verify_tls: bool = True
```

`SandboxConfig` (line 868) gains the member and the field:

```python
    provider: Literal["mock", "cape2", "upload", "triage", "rest"] = "mock"
    cape2: SandboxCape2Config = Field(default_factory=SandboxCape2Config)
    triage: SandboxTriageConfig = Field(default_factory=SandboxTriageConfig)
    upload: SandboxUploadConfig = Field(default_factory=SandboxUploadConfig)
    rest: SandboxRestConfig = Field(default_factory=SandboxRestConfig)
```
and its docstring's provider list gains one line: `"rest"   — any HTTP sandbox, described by sandbox.rest.*`.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/core/test_server_settings.py tests/unit/core/test_settings_aliases.py tests/providers/test_registry.py -q`
Expected: `test_server_settings.py` PASS; `test_registry.py::test_sandbox_ids_equal_the_settings_choices` FAILS (`rest` has no adapter yet) and `tests/unit/core/test_settings_catalog.py` would fail on unannotated leaves — both are Task 3's and Task 11's business. Note the two expected failures in the commit body rather than papering over them.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core/config.py tests/unit/core/test_server_settings.py && \
uv run ruff format --check src/maljan/core/config.py tests/unit/core/test_server_settings.py && \
uv run mypy src/ apps/api/
git add src/maljan/core/config.py src/maljan/providers src/maljan/agents/ghidra_http_client.py tests/unit/core/test_server_settings.py
git commit -m "feat(config): mcp.servers as a registry, static.generic as a reference, and the rest sandbox tree"
```

---

### Task 3: Annotations, conditional visibility, and the catalog's two new columns

**Files:**
- Modify: `src/maljan/core/settings_annotations.py:16-24` (`Annotation` gains `choices_from` and `editor`), `:26-43` (`GROUP_ORDER` retitles the `mcp` group), `:956-1029` (`mcp_server_annotations` drops nothing and stays as it is for the provider-owned blocks), `:1034-1040` (the `applies_when` constants), `:1240-1252` (the per-block `ANNOTATIONS.update` calls); `src/maljan/core/settings_catalog.py:38-65` (`CatalogEntry`), `:150-185` (`core_catalog`); `apps/api/app/schemas/settings.py:16-35` (`CatalogEntryDTO`)
- Test: `tests/unit/core/test_settings_catalog.py` (modify — two new cases)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/settings_annotations.py
  class Annotation(TypedDict):
      # title, description, applies, probe, group, applies_when, order: unchanged
      choices_from: NotRequired[Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles"]]
      editor: NotRequired[Literal["server_map", "rest_sandbox"]]
  _SANDBOX_REST = {"core.sandbox.provider": ["rest"]}
  _SANDBOX_REST_GENERIC = {"core.sandbox.provider": ["rest"], "core.sandbox.rest.report.format": ["generic"]}

  # src/maljan/core/settings_catalog.py
  ChoicesFrom = Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles"]
  Editor = Literal["server_map", "rest_sandbox"]
  @dataclass(frozen=True)
  class CatalogEntry:
      # key … applies_when, order: unchanged
      choices_from: ChoicesFrom | None = None
      editor: Editor | None = None
  ```
- Consumes: `ANNOTATIONS`, `GROUP_ORDER` (Task 2's new leaves).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/core/test_settings_catalog.py`:

```python
def test_the_server_map_is_one_leaf_with_its_own_editor():
    by_path = {e.path: e for e in cat.core_catalog()}
    servers = by_path["mcp.servers"]
    assert servers.type == "json"
    assert servers.editor == "server_map"
    assert servers.group == "mcp"
    assert servers.applies_when is None


def test_the_generic_static_provider_points_at_a_server_key():
    by_path = {e.path: e for e in cat.core_catalog()}
    entry = by_path["static.generic.server"]
    assert entry.type == "str"
    assert entry.choices_from == "mcp_servers"
    assert entry.applies_when == {"core.static.provider": ["generic_mcp"]}


def test_the_rest_sandbox_leaves_are_gated_and_the_mapping_twice_over():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["sandbox.rest.base_url"].applies_when == {"core.sandbox.provider": ["rest"]}
    assert by_path["sandbox.rest.base_url"].editor == "rest_sandbox"
    assert by_path["sandbox.rest.auth.token"].type == "secret"
    assert by_path["sandbox.rest.mapping.processes"].applies_when == {
        "core.sandbox.provider": ["rest"],
        "core.sandbox.rest.report.format": ["generic"],
    }
    assert by_path["sandbox.rest.report.format"].applies_when == {
        "core.sandbox.provider": ["rest"]
    }


def test_the_sandbox_selector_offers_rest():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["sandbox.provider"].choices == ["mock", "cape2", "upload", "triage", "rest"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_settings_catalog.py -q`
Expected: FAIL — `test_every_leaf_is_annotated_and_no_annotation_is_orphaned` lists every `sandbox.rest.*` leaf plus `mcp.servers` and `static.generic.server` as unannotated, and the annotations for the nine removed `static.generic.*` leaves as orphaned; the four new cases fail on the missing `editor` / `choices_from` attributes.

- [ ] **Step 3: Add the two catalog columns**

In `src/maljan/core/settings_catalog.py`, beside `FieldType` (line 24):

```python
ChoicesFrom = Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles"]
Editor = Literal["server_map", "rest_sandbox"]
```

and at the end of `CatalogEntry` (after `order`, line 62):

```python
    # A choice list the API fills in when it serialises the catalog: registry
    # ids, or the keys of ``mcp.servers`` as they currently stand. The core
    # catalog cannot compute these — it is a pure function of the models and
    # the effective settings are not in scope here — and the web must never
    # compute them either, or two places decide what a valid provider is.
    choices_from: ChoicesFrom | None = None
    # A composite editor renders this leaf instead of the type's widget.
    editor: Editor | None = None
```

with the matching two lines in `core_catalog`'s `CatalogEntry(...)` call (after `order=...`):

```python
                choices_from=(ann.get("choices_from") if ann else None),
                editor=(ann.get("editor") if ann else None),
```

`apps/api/app/services/settings_catalog_api.py` builds `CatalogEntry(...)` twice (the `API_EDITABLE` and `API_READONLY` loops); both gain `choices_from=None, editor=None` after their `order=0`.

`apps/api/app/schemas/settings.py`'s `CatalogEntryDTO` gains, after `order: int = 0`:

```python
    choices_from: str | None = None
    editor: str | None = None
```

- [ ] **Step 4: Annotate every new leaf**

In `src/maljan/core/settings_annotations.py`, `Annotation` (line 16) gains two optional keys:

```python
    choices_from: NotRequired[
        Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles"]
    ]
    editor: NotRequired[Literal["server_map", "rest_sandbox"]]
```

`GROUP_ORDER`'s `mcp` row (line 32) becomes `("mcp", "Tool servers (MCP)")` — the group now holds the whole registry, not two named servers.

Beside the existing `applies_when` constants (line 1034):

```python
_STATIC_GENERIC = {"core.static.provider": ["generic_mcp"]}
_SANDBOX_REST = {"core.sandbox.provider": ["rest"]}
_SANDBOX_REST_GENERIC = {
    "core.sandbox.provider": ["rest"],
    "core.sandbox.rest.report.format": ["generic"],
}
```

Replace the `ANNOTATIONS.update(mcp_server_annotations("static.generic", ...))` call at line 1248-1250 with the reference leaf, and add the registry leaf plus the REST tree:

```python
ANNOTATIONS.update(
    {
        "mcp.servers": {
            "title": "Tool servers",
            "description": (
                "Every MCP server Maljan can attach, keyed by a short name. Each "
                "entry says how to reach the server, which of its tools the model "
                "may call, and which analysts receive them. A newly added server "
                "exposes nothing until its tools are ticked."
            ),
            "group": "mcp",
            "editor": "server_map",
            "order": -1,
        },
        "static.generic.server": {
            "title": "Custom MCP server",
            "description": (
                "Which entry of the tool-server registry the generic_mcp static "
                "provider drives. Empty leaves that provider with nothing to attach."
            ),
            "applies_when": _STATIC_GENERIC,
            "choices_from": "mcp_servers",
        },
    }
)
```

and, for `sandbox.rest.*`, one entry per leaf. Written out rather than generated, because each says something different:

```python
def _rest(title: str, description: str, *, generic_only: bool = False) -> Annotation:
    """One ``sandbox.rest.*`` leaf: gated on the provider, drawn by one editor.

    ``generic_only`` adds the second gate the mapping leaves need — the
    catalog's ``applies_when`` is a conjunction of key/value sets, so two keys
    in one dict is exactly "the REST provider AND the generic report format".
    """
    return {
        "title": title,
        "description": description,
        "applies_when": _SANDBOX_REST_GENERIC if generic_only else _SANDBOX_REST,
        "editor": "rest_sandbox",
    }


ANNOTATIONS.update(
    {
        "sandbox.rest.base_url": _rest(
            "Sandbox API base URL",
            "Root of the sandbox's HTTP API; every path below is appended to it.",
        ),
        "sandbox.rest.auth.header": _rest(
            "Auth header", "Header carrying the credential, e.g. Authorization or X-API-Key."
        ),
        "sandbox.rest.auth.scheme": _rest(
            "Auth scheme",
            "Prefix written before the token, e.g. Bearer. Empty sends the token alone.",
        ),
        "sandbox.rest.auth.token": _rest(
            "Sandbox API token", "Credential sent in the configured header. Stored encrypted."
        ),
        "sandbox.rest.submit.method": _rest(
            "Submit method", "HTTP method for the submission, POST or PUT."
        ),
        "sandbox.rest.submit.path": _rest(
            "Submit path", "Path the sample is uploaded to, appended to the base URL."
        ),
        "sandbox.rest.submit.file_field": _rest(
            "Submit file field", "Name of the multipart field carrying the sample bytes."
        ),
        "sandbox.rest.submit.extra_fields": _rest(
            "Submit extra fields",
            "Additional multipart fields sent with the sample, as name/value pairs.",
        ),
        "sandbox.rest.submit.task_id_path": _rest(
            "Task id path",
            "JSONPath selecting the task identifier out of the submit response, e.g. $.id.",
        ),
        "sandbox.rest.status.path": _rest(
            "Status path", "Poll path; {task_id} is replaced by the submitted task's id."
        ),
        "sandbox.rest.status.state_path": _rest(
            "Status field path", "JSONPath selecting the state value out of the status response."
        ),
        "sandbox.rest.status.done_values": _rest(
            "Completed states", "State values that mean the run finished, compared case-insensitively."
        ),
        "sandbox.rest.status.failed_values": _rest(
            "Failed states", "State values that mean the run failed and must not be polled further."
        ),
        "sandbox.rest.report.path": _rest(
            "Report path", "Path the finished report is fetched from; {task_id} is substituted."
        ),
        "sandbox.rest.report.format": _rest(
            "Report format",
            "Shape of the fetched report. cape2, cuckoo and triage reuse the mappers the "
            "report-upload provider already uses; generic maps the response with the "
            "JSONPaths below.",
        ),
        "sandbox.rest.report.pcap_path": _rest(
            "PCAP path", "Optional capture path; empty means this sandbox publishes no PCAP."
        ),
        "sandbox.rest.mapping.target_sha256": _rest(
            "Mapping: sample hash", "JSONPath to the detonated sample's SHA-256.", generic_only=True
        ),
        "sandbox.rest.mapping.processes": _rest(
            "Mapping: processes",
            "JSONPath to the process rows; each match supplies pid, ppid, name and command_line.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.calls": _rest(
            "Mapping: API calls",
            "JSONPath to the API-call rows; each match supplies pid, api, args and timestamp.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.signatures": _rest(
            "Mapping: signatures",
            "JSONPath to the signature hits; each match supplies name, description, "
            "severity and ttps.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.dns": _rest(
            "Mapping: DNS",
            "JSONPath to the DNS rows; each match supplies request, type and answers.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.http": _rest(
            "Mapping: HTTP", "JSONPath to the HTTP request rows.", generic_only=True
        ),
        "sandbox.rest.mapping.tcp": _rest(
            "Mapping: TCP",
            "JSONPath to the TCP flows; each match supplies dst and dport.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.udp": _rest(
            "Mapping: UDP",
            "JSONPath to the UDP flows; each match supplies dst and dport.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.hosts": _rest(
            "Mapping: hosts", "JSONPath to the contacted hosts, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.domains": _rest(
            "Mapping: domains", "JSONPath to the resolved domains, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.dropped_files": _rest(
            "Mapping: dropped files",
            "JSONPath to the dropped files; each match supplies name, sha256 and size.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.registry": _rest(
            "Mapping: registry", "JSONPath to the touched registry paths, one string per match.",
            generic_only=True,
        ),
        "sandbox.rest.mapping.field_names": _rest(
            "Mapping: field renames",
            "Per-row field renames, keyed 'channel.field', e.g. processes.command_line -> cmdline.",
            generic_only=True,
        ),
        "sandbox.rest.timeout_seconds": _rest(
            "Sandbox timeout (s)", "How long a detonation may take before the run is abandoned."
        ),
        "sandbox.rest.poll_interval_seconds": _rest(
            "Poll interval (s)", "Delay between status checks; backs off to 60 s under pressure."
        ),
        "sandbox.rest.verify_tls": _rest(
            "Verify TLS",
            "Check the sandbox's certificate. Turning this off is reported in the "
            "connection test's detail.",
        ),
    }
)
```

The `sandbox.provider` annotation's description (line ~1053) gains one clause: `rest drives any HTTP sandbox from the endpoints and JSONPaths you describe.`

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/core/test_server_settings.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core apps/api/app tests/unit/core && \
uv run ruff format --check src/maljan/core apps/api/app tests/unit/core && \
uv run mypy src/ apps/api/
git add src/maljan/core/settings_annotations.py src/maljan/core/settings_catalog.py apps/api/app/schemas/settings.py apps/api/app/services/settings_catalog_api.py tests/unit/core/test_settings_catalog.py
git commit -m "feat(settings): annotate the tool-server registry and the rest sandbox, and give the catalog a choices source and an editor"
```

---

### Task 4: The `STATIC__GENERIC__*` aliases and their stored-override migration

**Files:**
- Modify: `src/maljan/core/config.py:896-904` (`SETTINGS_ALIASES`), `:989-1024` (the JSON re-decode helper), `:1026-1031` (`apply_settings_aliases`)
- Create: `apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py`
- Test: `tests/unit/core/test_generic_server_aliases.py` (create), `tests/unit/api/test_generic_server_migration.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/config.py
  GENERIC_SERVER_KEY = "custom"          # the slug a migrated static.generic block lands on
  # apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py
  KEY_RENAMES: dict[str, str]
  def upgrade() -> None
  def downgrade() -> None
  ```
- Consumes: `SETTINGS_ALIASES`, `_alias_within`, `_warn_once` (`src/maljan/core/config.py:917-990`), the migration shape of `apps/api/alembic/versions/20260903000000_rename_provider_setting_keys.py`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/test_generic_server_aliases.py
"""A .env written for sub-project A's static.generic block still works."""

from __future__ import annotations

from maljan.core.config import GENERIC_SERVER_KEY, Settings, apply_settings_aliases


def test_a_legacy_command_lands_on_the_custom_server_and_binds_it_to_static():
    out = apply_settings_aliases({"static": {"generic": {"command": "my-mcp", "enabled": True}}})
    server = out["mcp"]["servers"][GENERIC_SERVER_KEY]
    assert server["command"] == "my-mcp" and server["enabled"] is True
    assert server["agents"] == ["static"]
    assert out["static"]["generic"]["server"] == GENERIC_SERVER_KEY
    assert "command" not in out["static"]["generic"]


def test_the_json_leaves_survive_the_move():
    out = apply_settings_aliases(
        {"static": {"generic": {"args": '["--stdio"]', "env": '{"A": "b"}'}}}
    )
    server = out["mcp"]["servers"][GENERIC_SERVER_KEY]
    assert server["args"] == ["--stdio"] and server["env"] == {"A": "b"}


def test_a_settings_built_from_the_legacy_shape_attaches_the_custom_server():
    cfg = Settings(_env_file=None, static={"generic": {"command": "my-mcp", "enabled": True}})
    assert cfg.static.generic.server == GENERIC_SERVER_KEY
    assert cfg.mcp.servers[GENERIC_SERVER_KEY].command == "my-mcp"
    assert cfg.mcp.servers[GENERIC_SERVER_KEY].agents == ["static"]
    assert set(cfg.mcp.servers) >= {"network", "threatintel", GENERIC_SERVER_KEY}


def test_nothing_is_invented_when_no_legacy_key_is_present():
    cfg = Settings(_env_file=None)
    assert cfg.static.generic.server == ""
    assert set(cfg.mcp.servers) == {"network", "threatintel"}
```

```python
# tests/unit/api/test_generic_server_migration.py
"""Stored UI overrides for static.generic become the custom server's."""

from __future__ import annotations

import importlib.util
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("move_generic", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_moved_leaf_is_named_and_points_into_the_custom_server():
    renames = _module().KEY_RENAMES
    assert renames["core.static.generic.command"] == "core.mcp.servers.custom.command"
    assert renames["core.static.generic.auth_token"] == "core.mcp.servers.custom.auth_token"
    assert renames["core.static.generic.tool_selection"] == (
        "core.mcp.servers.custom.tool_selection"
    )
    assert len(renames) == 9, "the nine MCPServerConfig leaves sub-project A stored"


def test_the_reference_row_is_written_alongside_the_move():
    mod = _module()
    assert mod.REFERENCE_KEY == "core.static.generic.server"
    assert mod.REFERENCE_VALUE == "custom"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_generic_server_aliases.py tests/unit/api/test_generic_server_migration.py -q`
Expected: FAIL — `ImportError: cannot import name 'GENERIC_SERVER_KEY'` and `FileNotFoundError` on the migration.

- [ ] **Step 3: Extend the alias table**

In `src/maljan/core/config.py`, above `SETTINGS_ALIASES` (line 896):

```python
# Where a sub-project A ``static.generic.*`` block lands in the registry.
GENERIC_SERVER_KEY = "custom"
```

and six rows appended to `SETTINGS_ALIASES` (line 903, before the closing paren):

```python
    ("static.generic.transport", f"mcp.servers.{GENERIC_SERVER_KEY}.transport"),
    ("static.generic.command", f"mcp.servers.{GENERIC_SERVER_KEY}.command"),
    ("static.generic.args", f"mcp.servers.{GENERIC_SERVER_KEY}.args"),
    ("static.generic.env", f"mcp.servers.{GENERIC_SERVER_KEY}.env"),
    ("static.generic.url", f"mcp.servers.{GENERIC_SERVER_KEY}.url"),
    ("static.generic.auth_token", f"mcp.servers.{GENERIC_SERVER_KEY}.auth_token"),
```

`static.generic.enabled`, `.tool_selection` and `.use_all_tools` move with the same shape; add them too so all nine leaves of the old block are covered (the test above counts nine in the migration, and the alias table must not be narrower than the migration).

`apply_settings_aliases` (line 1026) gains the two things a plain rename cannot express — the reference and the binding:

```python
def apply_settings_aliases(data: dict[str, Any]) -> dict[str, Any]:
    """Public, pure form of the alias pass — used by the validator and by tests."""
    out = _alias_within(data, SETTINGS_ALIASES)
    _redecode_json_leaves_stranded_by_the_mcp_alias(out)
    _finish_generic_server_move(out)
    return out


def _finish_generic_server_move(data: dict[str, Any]) -> None:
    """Point ``static.generic.server`` at the migrated block and bind it to static.

    The alias table can move a value; it cannot say that moving it also means
    "and this is the server the static provider drives, and its tools go to
    the static analyst". A legacy ``.env`` set neither, because neither
    existed — so both are filled in here, and only when the move actually
    happened and the new keys are not already set explicitly.
    """
    servers = data.get("mcp", {}).get("servers")
    if not isinstance(servers, dict):
        return
    entry = servers.get(GENERIC_SERVER_KEY)
    if not isinstance(entry, dict):
        return
    entry.setdefault("agents", ["static"])
    generic = data.setdefault("static", {}).setdefault("generic", {})
    if isinstance(generic, dict):
        generic.setdefault("server", GENERIC_SERVER_KEY)
```

`_redecode_json_leaves_stranded_by_the_mcp_alias` (line 989) currently only walks aliases rooted at `mcp`; the `static.generic.*` rows are rooted at `static`, and `StaticGenericConfig` no longer declares `args`/`env`, so pydantic-settings hands those back as raw JSON text exactly as it did for the `mcp.*` aliases. Widen the loop's guard from `if old.partition(".")[0] != "mcp": continue` to also accept the generic rows, and make the leaf lookup use the *new* path directly:

```python
def _redecode_json_leaves_stranded_by_an_alias(data: dict[str, Any]) -> None:
    """JSON-decode an ``args``/``env`` an alias left as raw text.

    pydantic-settings' nested-env decoder resolves ``MCP__GHIDRA__ARGS``
    against whatever type it finds along that path. When the legacy path no
    longer has a type — ``MCPConfig`` has no ``ghidra`` field, and
    ``StaticGenericConfig`` has no ``args`` — it hands back the raw JSON text
    under the *new* path instead, one validation error away from a silently
    broken ``.env``. A value that already decoded correctly (set under the new
    name, where the schema is real) is a list or dict and is left alone.
    Mutates ``data`` in place.
    """
    for old, new in SETTINGS_ALIASES:
        head, _, _tail = old.partition(".")
        last = old.rsplit(".", 1)[-1]
        if head == "mcp":
            # A whole-block alias: the JSON leaves hang one level below it.
            paths = [f"{new}.{leaf}" for leaf in _MCP_ALIAS_JSON_LEAVES]
        elif old.startswith("static.generic.") and last in _MCP_ALIAS_JSON_LEAVES:
            # A per-leaf alias: the new path already names the leaf.
            paths = [new]
        else:
            continue
        for path in paths:
            owner, key = _dig(data, path)
            if owner is None:
                continue
            value = owner.get(key)
            if isinstance(value, str):
                try:
                    owner[key] = json.loads(value)
                except ValueError:
                    pass  # let ordinary model validation raise on the bad value
```

The function is renamed from `_redecode_json_leaves_stranded_by_the_mcp_alias`, and `apply_settings_aliases` calls it under the new name.

- [ ] **Step 4: Write the data migration**

```python
# apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py
"""Move a stored static.generic block into the tool-server registry.

Sub-project B turns ``static.generic`` from a server's configuration into the
*name* of a server in ``mcp.servers``. An operator who configured a custom MCP
server through the UI on sub-project A has nine ``core.static.generic.*`` rows;
without this they would stop matching a catalog entry and be ignored in
silence. Each moves to ``core.mcp.servers.custom.*`` and one new row points
``core.static.generic.server`` at it.

The registry leaf is stored as one JSON document, so the moved rows are folded
into a single ``core.mcp.servers`` row rather than left as dotted keys: the
catalog has exactly one entry for the whole map, and a key it does not know is
a key the settings service refuses.

Idempotent by construction: a run that finds no legacy row writes nothing.

Revision ID: 20260905000000
Revises: 20260904000000
"""

from __future__ import annotations

import json
import logging

import sqlalchemy as sa
from alembic import op

# ``20260904000000`` is already taken by ``add_sandbox_reports`` on this branch
# (sub-project A shipped it), so this one is dated a day later and chains after
# it rather than forking a second head off ``20260903000000``.
revision = "20260905000000"
down_revision = "20260904000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

SERVER_KEY = "custom"
MAP_KEY = "core.mcp.servers"
REFERENCE_KEY = "core.static.generic.server"
REFERENCE_VALUE = SERVER_KEY

_LEAVES = (
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

KEY_RENAMES: dict[str, str] = {
    f"core.static.generic.{leaf}": f"core.mcp.servers.{SERVER_KEY}.{leaf}" for leaf in _LEAVES
}


def _load_map(conn: sa.engine.Connection) -> dict:
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": MAP_KEY}
    ).fetchone()
    if row is None:
        return {}
    value = row[0]
    return json.loads(value) if isinstance(value, str) else dict(value)


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    conn.execute(
        sa.text(
            "INSERT INTO runtime_settings (key, value, is_secret) "
            "VALUES (:k, CAST(:v AS JSONB), false) "
            "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB)"
        ),
        {"k": MAP_KEY, "v": json.dumps(servers)},
    )


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT key, value FROM runtime_settings WHERE key = ANY(:keys)"),
        {"keys": list(KEY_RENAMES)},
    ).fetchall()
    if not rows:
        return
    servers = _load_map(conn)
    entry = dict(servers.get(SERVER_KEY) or {})
    for key, value in rows:
        leaf = key.rsplit(".", 1)[1]
        # An encrypted auth_token is carried across as stored: the registry
        # leaf is not a secret entry, so the API refuses to write a token
        # there and this value is only ever cleared by the operator. Never
        # logged, here or anywhere else in this file.
        entry[leaf] = json.loads(value) if isinstance(value, str) else value
    entry.setdefault("agents", ["static"])
    servers[SERVER_KEY] = entry
    _store_map(conn, servers)
    conn.execute(
        sa.text(
            "INSERT INTO runtime_settings (key, value, is_secret) "
            "VALUES (:k, CAST(:v AS JSONB), false) "
            "ON CONFLICT (key) DO NOTHING"
        ),
        {"k": REFERENCE_KEY, "v": json.dumps(REFERENCE_VALUE)},
    )
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key = ANY(:keys)"), {"keys": list(KEY_RENAMES)}
    )
    logger.info("runtime_settings: moved %d static.generic override(s) into %s", len(rows), MAP_KEY)


def downgrade() -> None:
    conn = op.get_bind()
    servers = _load_map(conn)
    entry = servers.pop(SERVER_KEY, None)
    if entry is None:
        return
    for leaf in _LEAVES:
        if leaf not in entry:
            continue
        conn.execute(
            sa.text(
                "INSERT INTO runtime_settings (key, value, is_secret) "
                "VALUES (:k, CAST(:v AS JSONB), false) "
                "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB)"
            ),
            {"k": f"core.static.generic.{leaf}", "v": json.dumps(entry[leaf])},
        )
    _store_map(conn, servers)
    conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": REFERENCE_KEY})
```

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/core/test_generic_server_aliases.py tests/unit/api/test_generic_server_migration.py tests/unit/core/test_settings_aliases.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core/config.py apps/api/alembic/versions tests/unit/core tests/unit/api && \
uv run ruff format --check src/maljan/core/config.py apps/api/alembic/versions tests/unit/core tests/unit/api && \
uv run mypy src/ apps/api/
git add src/maljan/core/config.py apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py tests/unit/core/test_generic_server_aliases.py tests/unit/api/test_generic_server_migration.py
git commit -m "feat(config): map the legacy static.generic block onto the custom tool server, in env and in stored overrides"
```

---

### Task 5: `ServerHandle` and `ServerRegistry` — one MCP lifecycle for the whole project

**Files:**
- Create: `src/maljan/providers/servers.py`
- Modify: `src/maljan/providers/static/generic_mcp.py:1-27` (docstring), `:60-79` (constructor and `from_settings`), `:117-197` (`open`, `_run_async`, `get_tools`), `:243-270` (`_close_toolkit`, `close`)
- Test: `tests/servers/test_server_registry.py` (create), `tests/providers/static/test_generic_mcp_provider.py` (modify — it constructs from `cfg.static.generic`)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/servers.py
  class ServerHandle:
      def __init__(self, name: str, config: MCPServerConfig) -> None
      name: str
      config: MCPServerConfig
      @property
      def is_open(self) -> bool
      def open(
          self,
          job_id: str,
          *,
          output_guardrail: Callable[[str], str] | None = None,
          max_output_chars: int = 8000,
          truncation_ledger: Any | None = None,
      ) -> None
      def tools(self) -> list[BaseTool]          # already filtered by the allow-list
      def all_tool_names(self) -> list[str]      # the whole manifest, for the probe
      def close(self) -> None                    # idempotent

  class ServerRegistry:
      def __init__(self, cfg: Settings) -> None
      degradation_reasons: list[str]             # every reason tools_for has produced
      def for_agent(self, role: str) -> list[ServerHandle]
      def get(self, name: str) -> ServerHandle
      def tools_for(self, role: str, job_id: str, **context: Any) -> tuple[list[BaseTool], list[str]]
      def close_all(self) -> None
  ```
- Consumes: `maljan.core.config.MCPServerConfig`, `Settings`, `maljan.agents.mcp_client.MCPLangChainToolkit`, `maljan.agents.subprocess_env.child_env`, `maljan.agents.base_agent._run_coro_blocking`, `maljan.core.paths.resolve_mcp_args`, `get_project_root`, `maljan.providers.errors.ProviderConfigurationError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/servers/test_server_registry.py
"""One attach implementation, one allow-list, one collision rule."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.servers import ServerHandle, ServerRegistry


class _T:
    """A stand-in LangChain tool: the registry only reads and rewrites ``name``."""

    def __init__(self, name: str) -> None:
        self.name = name

    def model_copy(self, *, update: dict) -> "_T":
        return _T(update.get("name", self.name))


def _toolkit(names: list[str]) -> MagicMock:
    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=[_T(n) for n in names])
    instance.cleanup = AsyncMock(return_value=None)
    return instance


@pytest.fixture()
def patched(monkeypatch):
    """Attach without a live MCP server, and without a real event loop hop."""
    made: list[MagicMock] = []

    def factory(*args, **kwargs):
        made.append(_toolkit(factory.names))
        return made[-1]

    factory.names = ["alpha", "beta"]
    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)
    monkeypatch.setattr("maljan.providers.servers._run_async", lambda coro, label: None)
    return factory, made


def test_a_disabled_server_attaches_nothing(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=False, command="mcp"))
    handle.open("job-1")
    assert handle.tools() == [] and handle.is_open is False


def test_none_keeps_every_tool_and_an_empty_list_keeps_none(patched):
    keep_all = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", tools=None))
    keep_all.open("job-1")
    assert [t.name for t in keep_all.tools()] == ["alpha", "beta"]

    keep_none = ServerHandle("y", MCPServerConfig(enabled=True, command="mcp", tools=[]))
    keep_none.open("job-1")
    assert keep_none.tools() == []
    assert keep_none.all_tool_names() == ["alpha", "beta"], "the manifest is still readable"


def test_an_allow_list_narrows_and_ignores_names_the_server_does_not_offer(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", tools=["beta", "nope"]))
    handle.open("job-1")
    assert [t.name for t in handle.tools()] == ["beta"]


def test_reopening_for_the_same_job_is_a_no_op_and_a_new_job_reattaches(patched):
    _, made = patched
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    handle.open("job-1")
    handle.open("job-1")
    assert len(made) == 1
    handle.open("job-2")
    assert len(made) == 2
    made[0].cleanup.assert_called_once()


def test_close_is_idempotent_and_drops_the_tools(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    handle.open("job-1")
    handle.close()
    handle.close()
    assert handle.tools() == [] and handle.is_open is False


def test_a_cwd_outside_the_repository_is_refused():
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd="../../etc"))
    with pytest.raises(ProviderConfigurationError) as exc:
        handle.open("job-1")
    assert "cwd" in str(exc.value) and "x" in str(exc.value)


def test_for_agent_returns_only_enabled_servers_bound_to_that_role():
    cfg = Settings(_env_file=None)
    registry = ServerRegistry(cfg)
    assert [h.name for h in registry.for_agent("network")] == ["network"]
    assert [h.name for h in registry.for_agent("judge")] == ["threatintel"]
    assert registry.for_agent("static") == []
    cfg.mcp.servers["threatintel"].enabled = False
    assert ServerRegistry(cfg).for_agent("judge") == []


def test_get_names_the_servers_that_exist():
    registry = ServerRegistry(Settings(_env_file=None))
    assert registry.get("network").name == "network"
    with pytest.raises(ProviderConfigurationError) as exc:
        registry.get("nope")
    assert "network" in str(exc.value) and "threatintel" in str(exc.value)


def test_a_collision_prefixes_the_later_server_and_the_first_keeps_its_name(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["network"].agents = ["network"]
    cfg.mcp.servers["zzz"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    tools, reasons = registry.tools_for("network", "job-1")
    assert reasons == []
    assert [t.name for t in tools] == ["alpha", "beta", "zzz__alpha", "zzz__beta"]


def test_a_server_that_cannot_open_degrades_and_names_itself(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["broken"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    real_open = ServerHandle.open

    def flaky(self, job_id, **kwargs):
        if self.name == "broken":
            raise RuntimeError("no such file")
        return real_open(self, job_id, **kwargs)

    monkeypatch.setattr(ServerHandle, "open", flaky)
    tools, reasons = registry.tools_for("network", "job-1")
    assert reasons == ["mcp server 'broken' unavailable"]
    assert [t.name for t in tools] == ["alpha", "beta"]


def test_the_reasons_accumulate_on_the_registry_for_the_run_summary(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["broken"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    monkeypatch.setattr(
        ServerHandle, "open", lambda self, job_id, **kw: (_ for _ in ()).throw(RuntimeError("x"))
    )
    registry.tools_for("network", "job-1")
    registry.tools_for("network", "job-1")
    assert registry.degradation_reasons == [
        "mcp server 'network' unavailable",
        "mcp server 'broken' unavailable",
    ], "built-ins are attached first, so they are also reported first"


def test_close_all_closes_every_opened_handle(patched):
    _, made = patched
    registry = ServerRegistry(Settings(_env_file=None))
    registry.tools_for("network", "job-1")
    registry.close_all()
    assert made[0].cleanup.await_count + made[0].cleanup.call_count >= 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/servers/test_server_registry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.providers.servers'`.

- [ ] **Step 3: Write `servers.py`**

```python
# src/maljan/providers/servers.py
"""Every MCP server Maljan attaches, and the one lifecycle they share.

Before sub-project B there were three copies of "start an MCP server and take
its tools": ``GhidraStaticProvider.open``, ``GenericMCPStaticProvider.open``,
and a hand-rolled pair inside the network analyst and the judge. They drifted
— only one of them honoured an output guardrail, only one closed its child on
a re-attach, and none of them could be exercised by a settings probe, so the
UI's "Test" button spoke a different dialect to the same server than the job
did. ``ServerHandle`` is that code, once; ``ServerRegistry`` is the set of
them a job holds, keyed by the operator's own slug.

The registry never decides policy. It attaches what settings say to attach,
filters to the allow-list the operator ticked, renames a colliding tool, and
reports which servers failed. Whether a failure degrades a run or fails it is
the analyst's question, answered by the provider's capability flags — and for
a registry server the answer is always "degrade", because a server an operator
added is never the evidence the run was measured on.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import MCPServerConfig, Settings

# The reason string a failed server contributes to ``degradation_reasons``.
UNAVAILABLE_REASON = "mcp server '{name}' unavailable"


def _run_async(coro: Any, label: str) -> None:
    """Run an MCP-client coroutine on the shared agent loop.

    Same rationale as ``GenericMCPStaticProvider._run_async``: a toolkit's
    transport binds its async primitives to whichever loop first creates it,
    and the ReAct tool calls later run on the process-wide agent loop, so init
    has to run there too rather than on a throwaway loop. A module-level
    function rather than a method so a test can replace it in one place.
    """
    from maljan.agents.base_agent import _run_coro_blocking

    _run_coro_blocking(coro, hard_timeout=120.0, label=label)


class ServerHandle:
    """One configured MCP server, attached for at most one job at a time."""

    def __init__(self, name: str, config: MCPServerConfig) -> None:
        self.name = name
        self.config = config
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self._job_id: str = ""

    @property
    def is_open(self) -> bool:
        return self._toolkit is not None

    @property
    def label(self) -> str:
        return self.config.label or self.name

    def _resolve_cwd(self) -> str | None:
        """The child's working directory, refused when it escapes the project.

        ``cwd`` is an operator setting that becomes a subprocess's working
        directory, so it gets the same treatment every other path-shaped
        setting gets: a relative value is rooted at the project directory and
        must stay inside it; an absolute value is allowed but must exist.
        Neither check is a sandbox — an operator who can edit settings can
        already run a command — it is there so a typo fails loudly at attach
        time instead of starting a server in an unexpected directory.
        """
        from maljan.core.paths import get_project_root

        if not self.config.cwd:
            return None
        root = Path(get_project_root()).resolve()
        candidate = Path(self.config.cwd)
        if candidate.is_absolute():
            resolved = candidate.resolve()
            if not resolved.is_dir():
                raise ProviderConfigurationError(
                    f"mcp server {self.name!r}: cwd {resolved} does not exist"
                )
            return str(resolved)
        resolved = (root / candidate).resolve()
        if not resolved.is_relative_to(root):
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {self.config.cwd!r} resolves outside the project"
            )
        if not resolved.is_dir():
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {resolved} does not exist"
            )
        return str(resolved)

    def open(
        self,
        job_id: str,
        *,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 8000,
        truncation_ledger: Any | None = None,
    ) -> None:
        """Attach for ``job_id``. Same id is a no-op; a different id reattaches."""
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            logger.info(
                "mcp server '%s' re-opened for a different job; closing the stale toolkit first.",
                self.name,
            )
            self.close()
        self._job_id = job_id
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return

        from maljan.agents.mcp_client import MCPLangChainToolkit

        if self.config.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import child_env
            from maljan.core.paths import resolve_mcp_args

            env = child_env(self.config.env, allow=tuple(self.config.env_allow))
            env.setdefault("PYTHONIOENCODING", "utf-8")
            params = StdioServerParameters(
                command=self.config.command,
                args=resolve_mcp_args(list(self.config.args)),
                env=env,
                cwd=self._resolve_cwd(),
            )
            toolkit = MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )
        else:
            token = self.config.auth_token.get_secret_value()
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            toolkit = MCPLangChainToolkit(
                transport=self.config.transport,
                http_url=self.config.url,
                http_headers=headers,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )

        _run_async(toolkit.initialize(), label=f"{self.name}-mcp-init")
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())
        logger.info(
            "mcp server '%s': %d/%d tools exposed.",
            self.name,
            len(self.tools()),
            len(self._all_tools),
        )

    def all_tool_names(self) -> list[str]:
        """Every tool the server advertises, allow-list ignored."""
        return [str(getattr(t, "name", "")) for t in self._all_tools]

    def tools(self) -> list[BaseTool]:
        """The tools the model may call: the allow-list applied to the manifest.

        ``None`` is "everything the server offers" and is what the two
        built-in sidecars carry, so their tool lists are byte-for-byte what
        the agents attached before this existed. ``[]`` is "nothing", which is
        what a newly registered custom server carries until the operator ticks
        tools off its probe result — a server is connected and inert until
        somebody says which of its tools may run.
        """
        allowed = self.config.tools
        if allowed is None:
            return list(self._all_tools)
        keep = set(allowed)
        return [t for t in self._all_tools if str(getattr(t, "name", "")) in keep]

    def close(self) -> None:
        """Release the client or subprocess. Never raises."""
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            from maljan.agents.base_agent import _run_coro_blocking

            _run_coro_blocking(closer(), hard_timeout=20.0, label=f"{self.name}-mcp-close")
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)


class ServerRegistry:
    """The tool servers one job may attach, built from ``cfg.mcp.servers``."""

    def __init__(self, cfg: Settings) -> None:
        self._handles = {
            name: ServerHandle(name, config) for name, config in cfg.mcp.servers.items()
        }
        # Every reason ``tools_for`` has produced this job, in order and
        # without duplicates. The judge node reads it into
        # ``degradation_reasons`` so the run summary says which server was
        # missing, rather than the report simply being thinner than the last.
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> ServerHandle:
        handle = self._handles.get(name)
        if handle is None:
            available = ", ".join(sorted(self._handles)) or "(none)"
            raise ProviderConfigurationError(
                f"Unknown mcp server: {name!r}. Available: {available}"
            )
        return handle

    def for_agent(self, role: str) -> list[ServerHandle]:
        """Enabled servers bound to ``role``, built-ins first then by key.

        Order is what makes the collision rule predictable: a built-in is
        attached before any custom server, so a custom server that happens to
        name a tool ``extract_dns`` is the one that gets renamed, and the
        pinned built-in tool names never move.
        """
        from maljan.core.config import BUILTIN_SERVER_KEYS

        bound = [
            handle
            for handle in self._handles.values()
            if handle.config.enabled and role in handle.config.agents
        ]
        return sorted(bound, key=lambda h: (h.name not in BUILTIN_SERVER_KEYS, h.name))

    def tools_for(self, role: str, job_id: str, **context: Any) -> tuple[list[BaseTool], list[str]]:
        """Open every server bound to ``role`` and concatenate their tools.

        Returns the tools and the degradation reasons: one per server that
        could not be opened. A failure here is never raised — the caller keeps
        the tools it did get, and the run summary says which server is missing
        rather than the report quietly being thinner than the last one.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        for handle in self.for_agent(role):
            try:
                handle.open(job_id, **context)
            except Exception as exc:  # noqa: BLE001 — a registry server always degrades
                logger.warning(
                    "mcp server '%s' could not be attached for the %s analyst: %s",
                    handle.name,
                    role,
                    exc,
                )
                reason = UNAVAILABLE_REASON.format(name=handle.name)
                reasons.append(reason)
                if reason not in self.degradation_reasons:
                    self.degradation_reasons.append(reason)
                continue
            renamed = 0
            for tool in handle.tools():
                name = str(getattr(tool, "name", ""))
                if name in seen:
                    tool = tool.model_copy(update={"name": f"{handle.name}__{name}"})
                    name = str(tool.name)
                    renamed += 1
                seen.add(name)
                tools.append(tool)
            if renamed:
                logger.info(
                    "mcp server '%s': %d tool name(s) already taken, prefixed with '%s__'.",
                    handle.name,
                    renamed,
                    handle.name,
                )
        return tools, reasons

    def close_all(self) -> None:
        for handle in self._handles.values():
            handle.close()
```

- [ ] **Step 4: Make the static provider a wrapper**

`GenericMCPStaticProvider` keeps its identity — the id, the capabilities, the prompt fragment, `select_tools`, `mirror_spec` — and delegates the lifecycle. Replace the constructor, `from_settings`, `open`, `_run_async`, `get_tools`, `_close_toolkit` and `close` with:

```python
    def __init__(
        self,
        handle: ServerHandle,
        *,
        label: str = "MCP",
        allowed_tools: frozenset[str] | None = None,
        prompt_fragment_text: str = "",
    ) -> None:
        self._handle = handle
        self._label = label
        self._allowed_tools = allowed_tools or frozenset()
        self._prompt_fragment_text = prompt_fragment_text
        self._job = StaticJobContext()
        self.tools: list[Any] = []

    @classmethod
    def from_settings(cls, cfg: Settings) -> GenericMCPStaticProvider:
        """The registry entry ``static.generic.server`` names, or an inert handle.

        An unset (or unknown) reference is not an error here: the provider is
        constructed eagerly by the container, and an operator who selected
        generic_mcp without picking a server should learn that from the probe,
        not from a container that refuses to build.
        """
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        name = cfg.static.generic.server
        entry = cfg.mcp.servers.get(name) if name else None
        if entry is None:
            if name:
                logger.warning(
                    "static.generic.server names %r, which is not in mcp.servers; "
                    "the generic_mcp provider has nothing to attach.",
                    name,
                )
            return cls(ServerHandle(name or "generic", MCPServerConfig()))
        return cls(ServerHandle(name, entry), label=entry.label or name)

    @property
    def server_name(self) -> str:
        """The registry key this provider owns; the static analyst excludes it."""
        return self._handle.name

    def open(self, job: StaticJobContext) -> None:
        if self._handle.is_open:
            if job == self._job:
                return
            self._handle.close()
        self._job = job
        self._handle.open(
            job.sha256 or "static",
            output_guardrail=job.output_guardrail,
            max_output_chars=job.max_output_chars,
            truncation_ledger=job.truncation_ledger,
        )
        self.tools = self.select_tools(self._handle.tools())

    def get_tools(self) -> list[BaseTool]:
        return self._handle.tools()

    def close(self) -> None:
        self.tools = []
        self._handle.close()
```

`server_command()` disappears with the config copy; `R2StaticProvider` (Task 9) is the only caller and is updated there. `select_tools` and `_tool_mode` keep reading `self._handle.config` instead of `self._cfg` — a one-word substitution in each.

The module docstring's second and third paragraphs (lines 10-27) are rewritten: the allow-list is a setting now (`MCPServerConfig.tools`), applied by `ServerHandle`, and the constructor's `allowed_tools` is the subclass default that the setting overrides.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/servers tests/providers/static/test_generic_mcp_provider.py -q`
Expected: PASS. `test_generic_mcp_provider.py` is updated in this commit: `_cfg()` now writes `cfg.mcp.servers["custom"] = MCPServerConfig(...)` and `cfg.static.generic.server = "custom"`, and the two toolkit-patching cases patch `maljan.providers.servers._run_async` instead of the provider's own method.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers tests/servers tests/providers && \
uv run ruff format --check src/maljan/providers tests/servers tests/providers && \
uv run mypy src/ apps/api/
git add src/maljan/providers/servers.py src/maljan/providers/static/generic_mcp.py tests/servers/test_server_registry.py tests/providers/static/test_generic_mcp_provider.py
git commit -m "feat(providers): one MCP server lifecycle, with an allow-list and a collision rule"
```

---

### Task 6: The container owns one registry per job

**Files:**
- Modify: `src/maljan/core/container.py:103-117` (caches), `:253-261` (beside `get_static_provider`), `:359-381` (`aclose`)
- Test: `tests/providers/test_container_wiring.py` (modify — two new cases)

**Interfaces:**
- Produces: `ServiceContainer.get_server_registry() -> ServerRegistry`
- Consumes: `maljan.providers.servers.ServerRegistry`, `ServiceContainer.config`.

- [ ] **Step 1: Write the failing test**

Append to `tests/providers/test_container_wiring.py`:

```python
def test_the_registry_is_built_once_per_container():
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_server_registry() is container.get_server_registry()
    assert [h.name for h in container.get_server_registry().for_agent("judge")] == ["threatintel"]


@pytest.mark.asyncio
async def test_aclose_closes_the_registry_only_when_one_was_built():
    from unittest.mock import MagicMock

    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    def _container() -> ServiceContainer:
        return ServiceContainer(config=Settings(_env_file=None), mock=True)

    container = _container()
    await container.aclose()  # never touched the registry: nothing to close

    container = _container()
    registry = container.get_server_registry()
    registry.close_all = MagicMock()
    await container.aclose()
    registry.close_all.assert_called_once()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/providers/test_container_wiring.py -q`
Expected: FAIL — `AttributeError: 'ServiceContainer' object has no attribute 'get_server_registry'`.

- [ ] **Step 3: Write the implementation**

In `src/maljan/core/container.py`, beside `_static_provider_cache` (line 113):

```python
        self._server_registry_cache: ServerRegistry | None = None
```

with `ServerRegistry` added to the `TYPE_CHECKING` import block at line 57, and the accessor after `get_static_provider` (line 261):

```python
    def get_server_registry(self) -> ServerRegistry:
        """The tool servers this job may attach, built from the job's settings.

        One registry per container, and the container is per job, so a stdio
        server's subprocess lives for exactly one analysis and is closed by
        ``aclose`` at the end of it — the same lifetime the static and sandbox
        providers already have.
        """
        with self._lock:
            if self._server_registry_cache is None:
                from maljan.providers.servers import ServerRegistry

                self._server_registry_cache = ServerRegistry(self.config)
                logger.info(
                    "Tool servers: %s.",
                    ", ".join(sorted(self.config.mcp.servers)) or "(none)",
                )
            return self._server_registry_cache
```

and in `aclose`, immediately after the sandbox provider block (line 381):

```python
        # Same rule as the providers above: close the *cached* registry, never
        # ``get_server_registry()`` — a job that never attached a tool server
        # must not build one here for the sole purpose of closing it.
        if self._server_registry_cache is not None:
            try:
                self._server_registry_cache.close_all()
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing the tool-server registry failed (non-fatal): %s", exc)
```

with `self._server_registry_cache = None` added to the final cache-clearing block (line 386-392).

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/providers/test_container_wiring.py tests/servers -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core/container.py tests/providers/test_container_wiring.py && \
uv run ruff format --check src/maljan/core/container.py tests/providers/test_container_wiring.py && \
uv run mypy src/ apps/api/
git add src/maljan/core/container.py tests/providers/test_container_wiring.py
git commit -m "feat(container): one tool-server registry per job, closed with everything else"
```

---

### Task 7: The network analyst and the judge read the registry

**Files:**
- Modify: `src/maljan/providers/servers.py` (adds the async twins), `src/maljan/agents/network_analyst.py:73-111` (`_initialize_mcp_client`), `src/maljan/agents/judge_agent.py:131-158` (`_initialize_mcp_client`), `:160-193` (`aclose`)
- Test: `tests/servers/test_builtin_tool_sets.py` (modify — the registry assertions the spec's §8.1 names), `tests/agents/test_sidecar_registry_wiring.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/servers.py — the async twins, for callers on the graph's own loop
  class ServerHandle:
      async def aopen(self, job_id: str, **context: Any) -> None
      async def aclose(self) -> None
  class ServerRegistry:
      async def atools_for(self, role: str, job_id: str, **context: Any) -> tuple[list[BaseTool], list[str]]
  ```
- Consumes: `ServiceContainer.get_server_registry`, `tests/fixtures/golden/mcp_tools/*.json` (Task 1's `load_golden`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/servers/test_builtin_tool_sets.py`:

```python
def test_the_registry_attaches_exactly_the_pinned_tools(monkeypatch):
    """The move into settings changed no tool the model can see.

    The point of the fixture: ``for_agent`` must hand the network analyst the
    same names ``NetworkAnalyst._initialize_mcp_client`` handed it before, and
    the judge the same names the judge had. Names, not schemas.
    """
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    registry = ServerRegistry(Settings(_env_file=None))
    for role, key in (("network", "network"), ("judge", "threatintel")):
        handles = registry.for_agent(role)
        assert [h.name for h in handles] == [key]
        try:
            handles[0].open("golden")
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"{key}-mcp did not start in this environment: {exc}")
        try:
            assert sorted(t.name for t in handles[0].tools()) == load_golden(key)
        finally:
            handles[0].close()
```

```python
# tests/agents/test_sidecar_registry_wiring.py
"""Neither sidecar is launched from a constant inside an agent any more."""

from __future__ import annotations

import inspect

import pytest

from maljan.agents import judge_agent, network_analyst


def test_no_agent_names_a_sidecar_script_any_more():
    for module in (network_analyst, judge_agent):
        source = inspect.getsource(module)
        assert "server.py" not in source, f"{module.__name__} still launches a server itself"
        assert "StdioServerParameters" not in source


def _wired(container, name: str):
    """An analyst with this container behind it, without building an LLM.

    ``container.get_agent`` needs a real model and refuses in mock mode; the
    only thing these tests need is the ``_container`` back-reference that
    ``BaseAnalyst._server_registry`` reads.
    """
    from unittest.mock import MagicMock

    agent = container.agent_registry.create(name, MagicMock())
    agent._container = container
    return agent


def test_the_network_analyst_takes_its_tools_from_the_registry(monkeypatch):
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    registry = container.get_server_registry()

    class _T:
        name = "extract_dns"

    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([_T()], []))
    agent = _wired(container, "network")
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["extract_dns"]


@pytest.mark.asyncio
async def test_the_judge_takes_its_tools_from_the_registry(monkeypatch):
    from unittest.mock import MagicMock

    from maljan.agents.judge_agent import JudgeAgent
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    container = ServiceContainer(config=cfg, mock=True)
    registry = container.get_server_registry()

    class _T:
        name = "check_ip_reputation"

    async def fake(role, job_id, **kw):
        assert role == "judge"
        return [_T()], []

    monkeypatch.setattr(registry, "atools_for", fake)
    judge = JudgeAgent(llm=MagicMock(), config=cfg)
    judge._container = container
    await judge._initialize_mcp_client()
    assert [t.name for t in judge.tools] == ["check_ip_reputation"]
    await judge.aclose()
    assert judge.tools == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/servers/test_builtin_tool_sets.py tests/agents/test_sidecar_registry_wiring.py -q`
Expected: FAIL — `assert "server.py" not in source` fails for both modules, and `AttributeError: 'ServerRegistry' object has no attribute 'atools_for'`.

- [ ] **Step 3: Add the async twins**

In `src/maljan/providers/servers.py`, `ServerHandle` gains a coroutine pair that does exactly what `open`/`close` do without the loop hop, and `open`/`close` become thin wrappers around the shared body so the two cannot drift:

```python
    def _build_toolkit(
        self,
        output_guardrail: Callable[[str], str] | None,
        max_output_chars: int,
        truncation_ledger: Any | None,
    ) -> Any:
        """Everything ``open`` does except awaiting ``initialize``.

        Factored out because the judge enters its toolkit with a plain
        ``await`` on the graph's own loop while the analysts hand theirs to
        the shared agent loop — the asymmetry ``JudgeAgent.aclose`` documents
        — and the only safe way to have both is one construction path and two
        ways of running the coroutine it returns.
        """
        from maljan.agents.mcp_client import MCPLangChainToolkit

        if self.config.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import child_env
            from maljan.core.paths import resolve_mcp_args

            env = child_env(self.config.env, allow=tuple(self.config.env_allow))
            env.setdefault("PYTHONIOENCODING", "utf-8")
            params = StdioServerParameters(
                command=self.config.command,
                args=resolve_mcp_args(list(self.config.args)),
                env=env,
                cwd=self._resolve_cwd(),
            )
            return MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )
        token = self.config.auth_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return MCPLangChainToolkit(
            transport=self.config.transport,
            http_url=self.config.url,
            http_headers=headers,
            output_guardrail=output_guardrail,
            max_output_chars=max_output_chars,
            truncation_ledger=truncation_ledger,
        )

    async def aopen(self, job_id: str, **context: Any) -> None:
        """Attach on the caller's own loop; the exit stack stays where it was wound."""
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            await self.aclose()
        self._job_id = job_id
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return
        toolkit = self._build_toolkit(
            context.get("output_guardrail"),
            int(context.get("max_output_chars", 8000)),
            context.get("truncation_ledger"),
        )
        await toolkit.initialize()
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())

    async def aclose(self) -> None:
        """Close on the caller's own loop. Bounded, and never raises."""
        import asyncio

        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            # A stdio transport's exit stack waits on the child process, and a
            # child that does not exit waits forever — the 42-minute teardown
            # ``JudgeAgent.aclose`` was written for.
            await asyncio.wait_for(closer(), timeout=20.0)
        except TimeoutError:
            logger.warning(
                "mcp server '%s' cleanup did not finish in 20s; abandoning it. "
                "The subprocess may outlive this job.",
                self.name,
            )
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)
```

Task 5's `open()` loses its inline construction and becomes:

```python
        toolkit = self._build_toolkit(output_guardrail, max_output_chars, truncation_ledger)
        _run_async(toolkit.initialize(), label=f"{self.name}-mcp-init")
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())
        logger.info(
            "mcp server '%s': %d/%d tools exposed.",
            self.name,
            len(self.tools()),
            len(self._all_tools),
        )
```

`ServerRegistry.atools_for` is `tools_for` with `await handle.aopen(...)` in place of `handle.open(...)`; the allow-list, the collision prefix and the reason accumulation are the same lines. Factor the per-handle tool merge into `_merge(handle, tools, seen) -> int` so both loops call it rather than repeating the rename.

- [ ] **Step 4: Rewrite the two agents' attach**

`src/maljan/agents/network_analyst.py`, replacing lines 73-111 in full:

```python
    def _initialize_mcp_client(self) -> None:
        """Attach every tool server bound to the ``network`` role.

        With default settings that is exactly ``mcp.servers["network"]`` — the
        same ``network-mcp`` sidecar, the same command, cwd and environment
        this method used to spell out inline — so the tool names are
        unchanged, and ``tests/servers/test_builtin_tool_sets.py`` says so.
        An operator who adds a second network server gets both.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        tools, reasons = registry.tools_for("network", self._job_key())
        self.tools = tools
        self.degradation_reasons = reasons
        self.logger.info("Network tool servers: %d tools attached.", len(self.tools))
```

with two small helpers on `BaseAnalyst` (`src/maljan/agents/base_agent.py`, beside `_static_capabilities` at line 822):

```python
    def _server_registry(self) -> Any | None:
        """The job's tool-server registry, or None when this agent runs bare."""
        container = getattr(self, "_container", None)
        if container is None:
            return None
        return container.get_server_registry()

    def _job_key(self) -> str:
        """A per-job identity for the handles' same-job short circuit."""
        return str(getattr(self, "_job_id", "") or "job")

    # Reasons the run summary should carry, filled in by whoever attaches
    # tool servers. Empty for an agent that attached none.
    degradation_reasons: list[str] = []
```

`src/maljan/agents/judge_agent.py`, replacing lines 131-158:

```python
    async def _initialize_mcp_client(self) -> None:
        """Attach every tool server bound to the ``judge`` role, on this loop.

        Awaited rather than handed to the shared agent loop, for the reason
        ``aclose`` below spells out: whichever loop enters the toolkit's exit
        stack has to be the one that unwinds it.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        tools, reasons = await registry.atools_for("judge", self._job_key())
        self.tools = tools
        self.degradation_reasons = reasons
        self.logger.info("Judge tool servers: %s", [t.name for t in self.tools])
```

and `aclose` (lines 160-193) closes the handles instead of a single toolkit:

```python
    async def aclose(self) -> None:
        """Release every judge-bound tool server and its stdio subprocess.

        Deliberately *not* routed through the shared agent loop, unlike the
        analysts'. The judge enters its toolkits with a plain ``await`` on
        whichever loop the graph node is running — see
        ``_initialize_mcp_client`` above — so that is the loop that owns the
        exit stacks, and handing the close to a different one is exactly how
        anyio's "cancel scope in a different task" error is produced.

        Without this, every mediation round that failed to initialise left
        another ``threatintel-mcp`` subprocess running: the guard on the
        caller is ``if self.tools: return``, and a failed init never sets
        ``tools``. ``ServerHandle.aclose`` carries the bound this used to
        apply itself.
        """
        self.tools = []
        registry = self._server_registry()
        if registry is None:
            return
        for handle in registry.for_agent("judge"):
            await handle.aclose()
```

`CLOSE_TOOLS_TIMEOUT` keeps its other callers; the `import sys`, `StdioServerParameters`, `MCPLangChainToolkit`, `child_env` and `get_project_root` imports leave both agent modules.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/servers tests/agents/test_sidecar_registry_wiring.py tests/agents/test_prompt_byte_identity.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/servers.py src/maljan/agents tests/servers tests/agents && \
uv run ruff format --check src/maljan/providers/servers.py src/maljan/agents tests/servers tests/agents && \
uv run mypy src/ apps/api/
git add src/maljan/providers/servers.py src/maljan/agents/network_analyst.py src/maljan/agents/judge_agent.py src/maljan/agents/base_agent.py tests/servers/test_builtin_tool_sets.py tests/agents/test_sidecar_registry_wiring.py
git commit -m "refactor(agents): the network analyst and the judge take their sidecars from the tool-server registry"
```

---

### Task 8: Bound servers reach the static and dynamic analysts, and a failure is said out loud

**Files:**
- Modify: `src/maljan/agents/base_agent.py:822-825` (the helper from Task 7 gains the append), `src/maljan/agents/static_analyst.py:127-149` (`_initialize_mcp_client`), `src/maljan/agents/dynamic_analyst.py:72-81` (`_initialize_mcp_client`), `src/maljan/core/container.py` (`server_degradation_reasons`), `src/maljan/pipeline/nodes.py:1393-1395` (the reason list)
- Test: `tests/agents/test_bound_servers.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/agents/base_agent.py
  def _attach_registry_tools(self, role: str, *, exclude: str = "", **context: Any) -> list[Any]
  # src/maljan/core/container.py
  def server_degradation_reasons(self) -> list[str]
  ```
- Consumes: `ServerRegistry.tools_for`, `GenericMCPStaticProvider.server_name` (Task 5).

- [ ] **Step 1: Write the failing test**

```python
# tests/agents/test_bound_servers.py
"""A server bound to static or dynamic is appended, never substituted."""

from __future__ import annotations

import pytest

from maljan.core.config import MCPServerConfig, Settings


class _T:
    def __init__(self, name: str) -> None:
        self.name = name

    def model_copy(self, *, update: dict) -> "_T":
        return _T(update.get("name", self.name))


def _container(monkeypatch, **servers):
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    for key, entry in servers.items():
        cfg.mcp.servers[key] = entry
    return ServiceContainer(config=cfg, mock=True)


def _wired(container, name: str):
    """An analyst with this container behind it, without building an LLM.

    ``container.get_agent`` needs a real model and refuses in mock mode; these
    tests only need the ``_container`` back-reference the registry helper reads.
    """
    from unittest.mock import MagicMock

    agent = container.agent_registry.create(name, MagicMock())
    agent._container = container
    return agent


def test_the_provider_tools_come_first_and_the_bound_server_after(monkeypatch):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["static"], tools=["helper"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([_T("helper")], []))
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["ghidra_tool", "helper"]


class _StubProvider:
    id = "ghidra"

    class capabilities:  # noqa: N801 — a stand-in for the frozen dataclass
        provides_tools = True
        degrade_on_failure = False

    server_name = ""

    def open(self, job):
        return None

    def get_tools(self):
        return [_T("ghidra_tool")]

    def select_tools(self, tools, categories=None):
        return list(tools)


def test_the_server_the_provider_already_owns_is_not_attached_twice(monkeypatch):
    container = _container(
        monkeypatch,
        mine=MCPServerConfig(enabled=True, command="mcp", agents=["static"]),
    )
    registry = container.get_server_registry()
    asked: list[str] = []

    def spy(role, job_id, *, exclude=None, **kw):
        asked.append(exclude or "")
        return [], []

    monkeypatch.setattr(registry, "tools_for", spy)
    agent = _wired(container, "static")

    provider = _StubProvider()
    provider.server_name = "mine"
    monkeypatch.setattr(type(agent), "_provider", lambda self: provider)
    agent._initialize_mcp_client()
    assert asked == ["mine"]


def test_a_failed_bound_server_degrades_a_static_run_that_would_otherwise_fail(monkeypatch):
    """Ghidra's loud failure is untouched; a registry server never fails a job."""
    container = _container(
        monkeypatch,
        broken=MCPServerConfig(enabled=True, command="nope", agents=["static"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(
        registry,
        "tools_for",
        lambda role, job_id, **kw: ([], ["mcp server 'broken' unavailable"]),
    )
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["ghidra_tool"]
    assert container.server_degradation_reasons() == []  # the registry itself never failed
    assert agent.degradation_reasons == ["mcp server 'broken' unavailable"]


@pytest.mark.parametrize("role", ["dynamic"])
def test_the_dynamic_analyst_appends_after_the_sandbox_tools(monkeypatch, role):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["dynamic"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda r, job_id, **kw: ([_T("extra")], []))
    agent = _wired(container, "dynamic")
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools][-1] == "extra"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/agents/test_bound_servers.py -q`
Expected: FAIL — the static analyst's tool list is `["ghidra_tool"]` (nothing appends), and `AttributeError: 'ServiceContainer' object has no attribute 'server_degradation_reasons'`.

- [ ] **Step 3: Write the shared append**

On `BaseAnalyst` (`src/maljan/agents/base_agent.py`, beside `_server_registry`):

```python
    def _attach_registry_tools(self, role: str, *, exclude: str = "", **context: Any) -> list[Any]:
        """Tools from every server bound to ``role``, minus one this agent owns.

        ``exclude`` is the static provider's own server: a ``generic_mcp``
        provider driving ``mcp.servers["mine"]`` and an ``agents: ["static"]``
        binding on that same entry are two ways of saying the same thing, and
        attaching it twice would show the model two copies of every tool.

        A failure here never raises. Whether a *provider* failure degrades or
        fails is the provider's capability flag; a registry server is always
        an addition, so it always degrades, and the reason travels to the run
        summary through ``degradation_reasons``.
        """
        registry = self._server_registry()
        if registry is None:
            return []
        tools, reasons = registry.tools_for(role, self._job_key(), exclude=exclude, **context)
        if reasons:
            self.degradation_reasons = [*self.degradation_reasons, *reasons]
        return tools
```

`ServerRegistry.tools_for` and `atools_for` gain the keyword: `def tools_for(self, role, job_id, *, exclude: str = "", **context)`, and `for_agent`'s result is filtered with `if handle.name != exclude`.

`src/maljan/agents/static_analyst.py:146` — after `self.tools = provider.select_tools(...)`:

```python
        self.tools = [
            *provider.select_tools(pool, getattr(self, "_sample_categories", None)),
            *self._attach_registry_tools(
                "static", exclude=str(getattr(provider, "server_name", ""))
            ),
        ]
```

and the `provides_tools=False` early return at lines 135-138 becomes `self.tools = self._attach_registry_tools("static")` instead of `self.tools = []`, so `static.provider=none` plus one bound server still gives the analyst that server's tools — the second live-verification scenario in the spec's §10.

`src/maljan/agents/dynamic_analyst.py:72-81`:

```python
    def _initialize_mcp_client(self) -> None:
        if getattr(self, "tools", None):
            return
        provider = self._sandbox_provider()
        sandbox_tools: list[Any] = []
        if provider.capabilities.provides_tools:
            sandbox_tools = list(provider.dynamic_tools())
            self.toolkit = getattr(provider, "_toolkit", None)
        else:
            self.logger.info("Sandbox provider '%s' exposes no tools.", provider.id)
        self.tools = [*sandbox_tools, *self._attach_registry_tools("dynamic")]
```

- [ ] **Step 4: Carry the reasons into the run summary**

`src/maljan/core/container.py`, beside `get_server_registry`:

```python
    def server_degradation_reasons(self) -> list[str]:
        """Tool servers that could not be attached this job, or an empty list.

        Reads the *cached* registry only: a job that never attached a tool
        server has nothing to report and must not build a registry here to
        discover that.
        """
        registry = self._server_registry_cache
        return list(registry.degradation_reasons) if registry is not None else []
```

`src/maljan/pipeline/nodes.py`, immediately before the `_failed_analysts` block at line 1394:

```python
            # A tool server an operator added is never the evidence a verdict
            # rests on, so it degrades rather than failing — but the reader of
            # the report is entitled to know the judge ran without its
            # threat-intel lookups.
            _degradation_reasons.extend(container.server_degradation_reasons())
```

An analyst's own `degradation_reasons` reach the same list through the registry, because both come from the one `ServerRegistry` the container holds; the per-agent copy exists so a unit test can see which analyst was affected.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/agents/test_bound_servers.py tests/servers tests/providers -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan tests/agents && uv run ruff format --check src/maljan tests/agents && \
uv run mypy src/ apps/api/
git add src/maljan/agents src/maljan/providers/servers.py src/maljan/core/container.py src/maljan/pipeline/nodes.py tests/agents/test_bound_servers.py
git commit -m "feat(agents): bind extra tool servers to the static and dynamic analysts, degrading with a named reason"
```

---

### Task 9: One stdio handshake behind every connection test

**Files:**
- Modify: `apps/api/app/services/settings_probes.py:24-29` (`ProbeResult` gains `tools`), `:165-184` (`probe_r2`), `:294-311` (`PROBES`), `:313-366` (`_INPUTS`), `:372-407` (`run_probe`, plus the new `run_mcp_probe`); `apps/api/app/schemas/settings.py:76-81` (`ProbeResponse`); `src/maljan/providers/static/r2.py:27-43` (`enumerate_r2_tools`)
- Test: `tests/unit/api/test_mcp_probe.py` (create)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/services/settings_probes.py
  @dataclass
  class ProbeResult:
      ok: bool
      latency_ms: int
      detail: str
      models: list[str] | None = None
      tools: list[str] | None = None            # new
  PROBE_BUDGET_SECONDS = 5.0
  async def handshake_tools(config: MCPServerConfig, name: str) -> list[str]
  async def probe_mcp(v: dict[str, Any]) -> ProbeResult          # v: {"name": str, "entry": dict}
  async def run_mcp_probe(server: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult
  # apps/api/app/schemas/settings.py
  class ProbeResponse(BaseModel):
      # ok, latency_ms, detail, models: unchanged
      tools: list[str] | None = None
  # src/maljan/providers/static/r2.py
  async def enumerate_r2_tools(command: str) -> list[str]        # names, not mcp.types.Tool
  ```
- Consumes: `maljan.providers.servers.ServerHandle`, `maljan.core.config.MCPServerConfig`, `maljan.core.settings_overrides.build_settings`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/api/test_mcp_probe.py
"""The connection test launches the same server a job launches."""

from __future__ import annotations

import pytest

from app.services.settings_probes import PROBES, handshake_tools, probe_mcp, run_mcp_probe


class _Handle:
    """Records what it was asked to attach, and answers with a manifest."""

    made: list = []

    def __init__(self, name, config):
        self.name = name
        self.config = config
        _Handle.made.append(self)
        self.closed = False

    async def aopen(self, job_id, **kw):
        return None

    async def aclose(self):
        self.closed = True

    def all_tool_names(self):
        return ["open_file", "analyze", "list_imports"]


@pytest.fixture(autouse=True)
def _no_live_server(monkeypatch):
    _Handle.made = []
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _Handle)


@pytest.mark.asyncio
async def test_the_probe_reports_the_manifest_and_names_it_in_the_detail():
    result = await probe_mcp({"name": "r2custom", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is True
    assert result.tools == ["open_file", "analyze", "list_imports"]
    assert "3 tools" in result.detail and "open_file" in result.detail


@pytest.mark.asyncio
async def test_the_probe_forces_the_server_on_and_ignores_the_stored_allow_list():
    """A probe exists to read the manifest, so it must not be narrowed by it."""
    await probe_mcp({"name": "x", "entry": {"enabled": False, "command": "mcp", "tools": []}})
    assert _Handle.made[-1].config.enabled is True
    assert _Handle.made[-1].config.tools is None


@pytest.mark.asyncio
async def test_a_hanging_server_is_killed_and_reported(monkeypatch):
    import asyncio

    async def hang(self, job_id, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(_Handle, "aopen", hang)
    monkeypatch.setattr("app.services.settings_probes.PROBE_BUDGET_SECONDS", 0.05)
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "mcp"}})
    assert result.ok is False and "no MCP handshake" in result.detail
    assert _Handle.made[-1].closed is True, "the child is killed, not left running"


@pytest.mark.asyncio
async def test_a_missing_binary_names_itself():
    async def boom(self, job_id, **kw):
        raise FileNotFoundError("r2mcp")

    _Handle.aopen = boom
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is False and "r2mcp" in result.detail


@pytest.mark.asyncio
async def test_run_mcp_probe_layers_staged_values_over_the_stored_map():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "staged"}}},
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "stored"}}},
    )
    assert result.ok is True
    assert _Handle.made[-1].config.command == "staged"


@pytest.mark.asyncio
async def test_an_unknown_server_is_a_legible_failure():
    result = await run_mcp_probe("nope", {}, {})
    assert result.ok is False and "nope" in result.detail


def test_the_probe_is_registered_under_its_own_name():
    assert "mcp" in PROBES


@pytest.mark.asyncio
async def test_the_r2_probe_speaks_the_same_handshake(monkeypatch):
    from app.services.settings_probes import probe_r2

    result = await probe_r2({"binary_path": "r2mcp"})
    assert result.ok is True and result.tools == ["open_file", "analyze", "list_imports"]
    assert _Handle.made[-1].config.command == "r2mcp"
    assert handshake_tools is not None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/api/test_mcp_probe.py -q`
Expected: FAIL — `ImportError: cannot import name 'handshake_tools' from 'app.services.settings_probes'`.

- [ ] **Step 3: Write the shared handshake and the probe**

In `apps/api/app/services/settings_probes.py`, beside the imports:

```python
from maljan.core.config import MCPServerConfig
from maljan.providers.servers import ServerHandle

# A connection test is a person waiting at a button. Five seconds is long
# enough for a local stdio server to answer tools/list and short enough that a
# wedged one is reported rather than endured.
PROBE_BUDGET_SECONDS = 5.0
```

`ProbeResult` gains `tools: list[str] | None = None`, and `ProbeResponse` in `apps/api/app/schemas/settings.py` gains the same field with the comment "the server's whole manifest, so the editor can render it as tick boxes".

```python
async def handshake_tools(config: MCPServerConfig, name: str) -> list[str]:
    """Attach ``config`` long enough to read its manifest, then let go.

    The only stdio handshake in the project besides a job's own: it is
    ``ServerHandle``, so a server that answers here answers the same way in a
    run. Whatever happens, the handle is closed — a probe that leaves a child
    process behind turns a mis-typed command into a slow leak of subprocesses,
    which is exactly what a person clicking "Test" twice would produce.
    """
    handle = ServerHandle(name, config)
    try:
        await asyncio.wait_for(handle.aopen(f"probe-{name}"), timeout=PROBE_BUDGET_SECONDS)
        return handle.all_tool_names()
    finally:
        await handle.aclose()


def _probe_config(entry: dict[str, Any]) -> MCPServerConfig:
    """The entry as configured, forced on and un-narrowed.

    A probe answers "what does this server offer"; a disabled entry or an
    empty allow-list are answers to a different question ("what may the model
    call"), and applying them here would make the manifest unreadable exactly
    when the operator needs it to pick from.
    """
    config = MCPServerConfig.model_validate(entry)
    return config.model_copy(update={"enabled": True, "tools": None})


async def probe_mcp(v: dict[str, Any]) -> ProbeResult:
    """Launch one configured MCP server and list the tools it offers."""
    t0 = time.perf_counter()
    name = str(v.get("name") or "server")
    try:
        config = _probe_config(dict(v.get("entry") or {}))
    except ValidationError as exc:
        fields = "; ".join(".".join(str(x) for x in e["loc"]) for e in exc.errors())
        return ProbeResult(False, _ms(t0), f"invalid server settings: {fields}")
    try:
        names = await handshake_tools(config, name)
    except TimeoutError:
        return ProbeResult(False, _ms(t0), f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s")
    except FileNotFoundError as exc:
        return ProbeResult(False, _ms(t0), f"{exc} not found on PATH")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    listed = ", ".join(names[:8]) + ("…" if len(names) > 8 else "")
    return ProbeResult(True, _ms(t0), f"{len(names)} tools: {listed}", None, names)


async def run_mcp_probe(
    server: str, values: dict[str, Any], stored: dict[str, Any]
) -> ProbeResult:
    """Probe one entry of the server map, staged values winning over stored ones.

    Separate from ``run_probe`` because this probe is addressed to a *key*
    inside one setting rather than to a set of settings: ``_INPUTS`` maps
    catalog keys to short names, and there is no catalog key for "the r2custom
    entry".
    """
    servers: dict[str, Any] = {}
    for layer in (stored, values):
        candidate = layer.get("core.mcp.servers")
        if isinstance(candidate, dict):
            servers.update(candidate)
    if server not in servers:
        # Fall back to the effective settings: a built-in the operator has
        # never edited has no stored row at all.
        from maljan.core.config import Settings

        effective = Settings().mcp.servers
        if server not in effective:
            available = ", ".join(sorted(set(servers) | set(effective))) or "(none)"
            return ProbeResult(False, 0, f"unknown server: {server!r}. Available: {available}")
        servers[server] = effective[server].model_dump(mode="json")
    return await probe_mcp({"name": server, "entry": servers[server]})
```

`PROBES` gains `"mcp": probe_mcp` and `_INPUTS` gains `"mcp": {}` so the generic route's key lookup stays total; the dedicated route in Task 14 calls `run_mcp_probe` instead.

- [ ] **Step 4: Re-base the r2 probe and `enumerate_r2_tools`**

`src/maljan/providers/static/r2.py:27-43`:

```python
async def enumerate_r2_tools(command: str) -> list[str]:
    """Names of the tools an r2mcp at ``command`` offers, over one stdio handshake.

    Used both to pin the golden fixture (``scripts/probe_r2_tools.py``) and to
    answer the settings-page connection test: the same ``ServerHandle`` either
    way, which is now the same one a job uses, so none of the three can report
    a different tool set than the others.
    """
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("r2", MCPServerConfig(enabled=True, transport="stdio", command=command))
    try:
        await handle.aopen("probe-r2")
        return handle.all_tool_names()
    finally:
        await handle.aclose()
```

`scripts/probe_r2_tools.py` writes `{"name": n}` rows from the names it now receives; its golden `tests/fixtures/golden/r2_tools.json` is **not** regenerated — the file keeps its `description` fields and the script's writer keeps them when re-run against a live server. `R2StaticProvider.from_settings` builds `ServerHandle("r2", MCPServerConfig(enabled=cfg.static.r2.enabled, transport="stdio", command=cfg.static.r2.binary_path, args=cfg.static.r2.args, env=cfg.static.r2.env))` and passes it to `GenericMCPStaticProvider.__init__`, replacing the deleted `server_command()` override.

`probe_r2` (line 165) becomes:

```python
async def probe_r2(v: dict[str, Any]) -> ProbeResult:
    """Launch the configured r2mcp and count the tools it offers, in 5 seconds.

    A stdio handshake is the only honest test of a subprocess-backed server: a
    binary that exists but cannot serve MCP is exactly the failure an operator
    needs named before a job fails on it.
    """
    command = str(v.get("binary_path") or "r2mcp")
    return await probe_mcp(
        {"name": "r2", "entry": {"enabled": True, "transport": "stdio", "command": command}}
    )
```

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/api/test_mcp_probe.py tests/unit/api/test_settings_probes.py tests/providers/static/test_r2_provider.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app src/maljan/providers scripts/probe_r2_tools.py tests/unit/api && \
uv run ruff format --check apps/api/app src/maljan/providers scripts/probe_r2_tools.py tests/unit/api && \
uv run mypy src/ apps/api/
git add apps/api/app/services/settings_probes.py apps/api/app/schemas/settings.py src/maljan/providers/static/r2.py scripts/probe_r2_tools.py tests/unit/api/test_mcp_probe.py
git commit -m "feat(api): one stdio handshake behind the MCP and radare2 connection tests, returning the manifest"
```

---

### Task 10: JSONPath mapping from an unknown report shape to `SandboxReport`

**Files:**
- Modify: `pyproject.toml:7-53` (the `jsonpath-rfc9535` dependency)
- Create: `src/maljan/providers/sandbox/rest_mapping.py`, `tests/providers/sandbox/test_rest_mapping.py`, `tests/fixtures/golden/rest_mapping/xyz_report.json`, `tests/fixtures/golden/rest_mapping/xyz_mapped.json`
- Test: `tests/providers/sandbox/test_rest_mapping.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/sandbox/rest_mapping.py
  CHANNELS: tuple[str, ...] = (
      "processes", "calls", "signatures", "dns", "http", "tcp", "udp",
      "hosts", "domains", "dropped_files", "registry",
  )
  MAX_ROWS_PER_CHANNEL = 5000

  @dataclass(frozen=True)
  class ChannelStats:
      matched: int = 0
      kept: int = 0
      dropped: int = 0
      sample_rows: list[Any] = field(default_factory=list)   # at most 3
      error: str = ""

  @dataclass(frozen=True)
  class CompiledMapping:
      config: RestMappingConfig
      target_sha256: Any | None
      paths: dict[str, Any]

  @dataclass(frozen=True)
  class MappingResult:
      report: SandboxReport
      stats: dict[str, ChannelStats]

  def compile_mapping(cfg: RestMappingConfig) -> CompiledMapping     # raises ProviderConfigurationError
  def apply_mapping(compiled: CompiledMapping, payload: dict[str, Any], *, provider: str, task_id: str) -> MappingResult
  ```
- Consumes: `jsonpath_rfc9535.findall`/`compile`, `maljan.schemas.sandbox_report.{SandboxReport, SandboxProcess, SandboxSignatureRow, SandboxNetwork, SandboxTarget}`, `maljan.providers.errors.ProviderConfigurationError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/providers/sandbox/test_rest_mapping.py
"""Any sandbox's JSON, described by JSONPath, becomes a SandboxReport."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import RestMappingConfig
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import (
    CHANNELS,
    MAX_ROWS_PER_CHANNEL,
    apply_mapping,
    compile_mapping,
)

GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "rest_mapping"

XYZ_MAPPING = RestMappingConfig(
    target_sha256="$.sample.hashes.sha256",
    processes="$.run.processes[*]",
    calls="$.run.processes[*].syscalls[*]",
    signatures="$.detections[*]",
    dns="$.net.lookups[*]",
    tcp="$.net.streams[*]",
    dropped_files="$.artifacts[*]",
    registry="$.run.registry[*]",
    field_names={
        "processes.command_line": "cmdline",
        "processes.name": "image",
        "calls.api": "syscall",
        "signatures.severity": "score",
        "signatures.ttps": "attack",
        "dns.request": "qname",
        "tcp.dst": "peer",
        "tcp.dport": "peer_port",
        "dropped_files.name": "filename",
    },
)


def test_a_bad_path_names_the_channel_it_came_from():
    with pytest.raises(ProviderConfigurationError) as exc:
        compile_mapping(RestMappingConfig(processes="$[["))
    assert "processes" in str(exc.value)


def test_an_unmapped_channel_is_reported_as_unavailable():
    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]"))
    result = apply_mapping(compiled, {"p": [{"pid": 1}]}, provider="rest", task_id="t")
    assert "processes" not in result.report.unavailable
    assert set(result.report.unavailable) == set(CHANNELS) - {"processes"}


def test_rows_missing_a_required_field_are_dropped_and_counted():
    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]"))
    result = apply_mapping(
        compiled, {"p": [{"pid": 4}, {"nope": 1}, "not a row"]}, provider="rest", task_id="t"
    )
    stats = result.stats["processes"]
    assert (stats.matched, stats.kept, stats.dropped) == (3, 1, 2)
    assert [p.pid for p in result.report.processes] == [4]


def test_a_channel_is_capped_and_the_cap_is_visible_in_the_stats():
    compiled = compile_mapping(RestMappingConfig(registry="$.r[*]"))
    payload = {"r": [f"HKLM\\k{i}" for i in range(MAX_ROWS_PER_CHANNEL + 10)]}
    result = apply_mapping(compiled, payload, provider="rest", task_id="t")
    assert len(result.report.registry) == MAX_ROWS_PER_CHANNEL
    assert result.stats["registry"].matched == MAX_ROWS_PER_CHANNEL + 10


def test_field_names_rename_per_channel_without_touching_the_others():
    compiled = compile_mapping(
        RestMappingConfig(processes="$.p[*]", field_names={"processes.command_line": "cmdline"})
    )
    result = apply_mapping(
        compiled, {"p": [{"pid": 1, "cmdline": "x.exe /q", "command_line": "ignored"}]},
        provider="rest", task_id="t",
    )
    assert result.report.processes[0].command_line == "x.exe /q"


def test_the_stats_carry_at_most_three_sample_rows():
    compiled = compile_mapping(RestMappingConfig(registry="$.r[*]"))
    result = apply_mapping(compiled, {"r": ["a", "b", "c", "d"]}, provider="rest", task_id="t")
    assert result.stats["registry"].sample_rows == ["a", "b", "c"]


def test_calls_are_attached_to_their_process_and_counted_into_apistats():
    compiled = compile_mapping(
        RestMappingConfig(processes="$.p[*]", calls="$.p[*].c[*]")
    )
    payload = {
        "p": [
            {"pid": 7, "c": [{"pid": 7, "api": "WriteProcessMemory"}, {"pid": 7, "api": "Sleep"}]},
            {"pid": 8, "c": [{"pid": 9, "api": "Orphan"}]},
        ]
    }
    result = apply_mapping(compiled, payload, provider="rest", task_id="t")
    assert [c["api"] for c in result.report.processes[0].calls] == [
        "WriteProcessMemory",
        "Sleep",
    ]
    assert result.report.apistats["7"] == {"WriteProcessMemory": 1, "Sleep": 1}
    assert result.stats["calls"].dropped == 1, "a call for a process nobody declared is dropped"


def test_the_xyz_golden_maps_exactly_as_recorded():
    """A synthetic sandbox nobody has ever integrated, mapped from settings alone."""
    payload = json.loads((GOLDEN / "xyz_report.json").read_text(encoding="utf-8"))
    expected = json.loads((GOLDEN / "xyz_mapped.json").read_text(encoding="utf-8"))
    compiled = compile_mapping(XYZ_MAPPING)
    result = apply_mapping(compiled, payload, provider="rest", task_id="xyz-1")
    assert result.report.model_dump(mode="json") == expected
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/providers/sandbox/test_rest_mapping.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.providers.sandbox.rest_mapping'`.

- [ ] **Step 3: Add the dependency**

In `pyproject.toml`, in `[project].dependencies` after `"filetype>=1.2.0",`:

```toml
    # RFC 9535 JSONPath, the standardised selector language, used to describe a
    # sandbox's report shape in settings rather than in code. Pure Python and
    # dependency-free, which is why it is a direct dependency rather than an
    # extra: sandbox.provider=rest must work on a plain `uv sync`.
    "jsonpath-rfc9535>=1.0.0",
```

Run `uv sync` and commit the resulting `uv.lock` with this task.

- [ ] **Step 4: Write `rest_mapping.py`**

```python
# src/maljan/providers/sandbox/rest_mapping.py
"""Turn any sandbox's JSON into a ``SandboxReport``, using settings alone.

Every other sandbox this project speaks to has an adapter written against its
documented shape. This one has no shape: the operator describes where each
channel lives with an RFC 9535 JSONPath, and this module compiles those paths
once and coerces whatever they select into the row shapes the consumers
already read.

Three rules make that safe to run against a report nobody has seen:

* A row that lacks the field its consumer indexes on is dropped, not guessed
  at, and the drop is counted — the preview endpoint shows those counts before
  a job is ever submitted.
* A channel with no path goes into ``SandboxReport.unavailable``. An empty
  ``network.dns`` and a sandbox that publishes no DNS at all look identical in
  a rendered report, and only one of them means the sample was quiet.
* Every channel is capped at ``MAX_ROWS_PER_CHANNEL``. A JSONPath over a
  200 MB report can select a million rows, and a report nobody can render is
  not more evidence than one that stops at five thousand and says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from maljan.core.config import RestMappingConfig
    from maljan.schemas.sandbox_report import SandboxReport

CHANNELS: tuple[str, ...] = (
    "processes",
    "calls",
    "signatures",
    "dns",
    "http",
    "tcp",
    "udp",
    "hosts",
    "domains",
    "dropped_files",
    "registry",
)

MAX_ROWS_PER_CHANNEL = 5000

# The field each channel's consumer indexes on. A row without it is not a
# thinner row, it is a row the consumer will skip or crash on.
_REQUIRED: dict[str, tuple[str, ...]] = {
    "processes": ("pid",),
    "calls": ("pid", "api"),
    "signatures": ("name",),
    "dns": ("request",),
    "http": (),
    "tcp": ("dst",),
    "udp": ("dst",),
    "dropped_files": ("name",),
}

# Channels whose rows are plain strings rather than mappings.
_STRING_CHANNELS = frozenset({"hosts", "domains", "registry"})

# The fields each mapping-shaped channel carries into its consumer row.
_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("pid", "ppid", "name", "command_line"),
    "calls": ("pid", "api", "args", "timestamp"),
    "signatures": ("name", "description", "severity", "ttps"),
    "dns": ("request", "type", "answers"),
    "tcp": ("dst", "dport"),
    "udp": ("dst", "dport"),
    "dropped_files": ("name", "sha256", "size"),
}


@dataclass(frozen=True)
class ChannelStats:
    """What one channel's path selected, and what survived coercion."""

    matched: int = 0
    kept: int = 0
    dropped: int = 0
    sample_rows: list[Any] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class CompiledMapping:
    config: RestMappingConfig
    target_sha256: Any | None
    paths: dict[str, Any]


@dataclass(frozen=True)
class MappingResult:
    report: SandboxReport
    stats: dict[str, ChannelStats]


def _compile_one(expression: str, channel: str) -> Any:
    import jsonpath_rfc9535

    try:
        return jsonpath_rfc9535.compile(expression)
    except Exception as exc:  # noqa: BLE001 — the library raises its own error type
        raise ProviderConfigurationError(
            f"sandbox.rest.mapping.{channel}: {expression!r} is not a valid JSONPath ({exc})"
        ) from exc


def compile_mapping(cfg: RestMappingConfig) -> CompiledMapping:
    """Compile every non-empty path once, naming the channel that fails.

    Called by ``RestSandboxProvider.from_settings`` and by the preview
    endpoint, so a typo is an error an operator sees at save or preview time
    rather than a job that detonates a sample and then produces nothing.
    """
    paths = {
        channel: _compile_one(getattr(cfg, channel), channel)
        for channel in CHANNELS
        if getattr(cfg, channel)
    }
    target = _compile_one(cfg.target_sha256, "target_sha256") if cfg.target_sha256 else None
    return CompiledMapping(config=cfg, target_sha256=target, paths=paths)


def _rename(channel: str, names: dict[str, str], row: dict[str, Any], want: str) -> Any:
    """One consumer field out of ``row``, under this sandbox's own name for it."""
    return row.get(names.get(f"{channel}.{want}", want))


def _coerce(channel: str, names: dict[str, str], raw: Any) -> Any | None:
    """One selected match as its consumer row, or None when it cannot be one."""
    if channel in _STRING_CHANNELS:
        text = raw if isinstance(raw, str) else raw.get("value") if isinstance(raw, dict) else None
        return text if isinstance(text, str) and text else None
    if not isinstance(raw, dict):
        return None
    row = {want: _rename(channel, names, raw, want) for want in _FIELDS.get(channel, ())}
    if channel == "http":
        row = dict(raw)
    for required in _REQUIRED.get(channel, ()):
        if row.get(required) in (None, ""):
            return None
    return row


def _select(compiled: CompiledMapping, channel: str, payload: dict[str, Any]) -> ChannelStats:
    """Run one channel's path and coerce what it selected."""
    path = compiled.paths.get(channel)
    if path is None:
        return ChannelStats()
    try:
        matches = [node.value for node in path.finditer(payload)]
    except Exception as exc:  # noqa: BLE001 — a path valid in isolation can still fail on data
        return ChannelStats(error=f"{type(exc).__name__}: {exc}")
    names = compiled.config.field_names
    kept: list[Any] = []
    dropped = 0
    for raw in matches[:MAX_ROWS_PER_CHANNEL]:
        row = _coerce(channel, names, raw)
        if row is None:
            dropped += 1
        else:
            kept.append(row)
    stats = ChannelStats(
        matched=len(matches),
        kept=len(kept),
        dropped=dropped,
        sample_rows=kept[:3],
    )
    object.__setattr__(stats, "_rows", kept)  # carried to the builder, not part of the wire shape
    return stats


def apply_mapping(
    compiled: CompiledMapping, payload: dict[str, Any], *, provider: str, task_id: str
) -> MappingResult:
    """Map one report payload, and say per channel what happened."""
    from maljan.schemas.sandbox_report import (
        SandboxNetwork,
        SandboxProcess,
        SandboxReport,
        SandboxSignatureRow,
        SandboxTarget,
    )

    stats = {channel: _select(compiled, channel, payload) for channel in CHANNELS}
    rows: dict[str, list[Any]] = {c: list(getattr(s, "_rows", [])) for c, s in stats.items()}

    processes = [
        SandboxProcess(
            pid=int(r.get("pid") or 0),
            ppid=int(r.get("ppid") or 0),
            name=str(r.get("name") or ""),
            command_line=str(r.get("command_line") or ""),
        )
        for r in rows["processes"]
    ]
    by_pid = {p.pid: p for p in processes}
    apistats: dict[str, dict[str, int]] = {}
    orphaned = 0
    for call in rows["calls"]:
        pid = int(call.get("pid") or 0)
        process = by_pid.get(pid)
        if process is None:
            orphaned += 1
            continue
        process.calls.append(call)
        api = str(call.get("api") or "")
        apistats.setdefault(str(pid), {})
        apistats[str(pid)][api] = apistats[str(pid)].get(api, 0) + 1
    if orphaned:
        stats["calls"] = ChannelStats(
            matched=stats["calls"].matched,
            kept=stats["calls"].kept - orphaned,
            dropped=stats["calls"].dropped + orphaned,
            sample_rows=stats["calls"].sample_rows,
        )

    signatures = [
        SandboxSignatureRow(
            name=str(r.get("name") or ""),
            description=str(r.get("description") or ""),
            severity=int(r.get("severity") or 0),
            ttp_tags=[str(t) for t in (r.get("ttps") or []) if t],
        )
        for r in rows["signatures"]
    ]

    network = SandboxNetwork(
        dns=rows["dns"],
        http=rows["http"],
        tcp=rows["tcp"],
        udp=rows["udp"],
        # The consumers read ``hosts`` as rows; a sandbox that publishes bare
        # addresses gets them wrapped rather than a second row shape.
        hosts=[{"ip": h} for h in rows["hosts"]],
        domains=rows["domains"],
    )

    sha256 = ""
    if compiled.target_sha256 is not None:
        found = [node.value for node in compiled.target_sha256.finditer(payload)]
        if found and isinstance(found[0], str):
            sha256 = found[0]

    unavailable = sorted(c for c in CHANNELS if c not in compiled.paths)
    for channel, stat in stats.items():
        if stat.error:
            logger.warning("rest mapping: channel %s failed on this report: %s", channel, stat.error)
        elif stat.dropped:
            logger.info(
                "rest mapping: channel %s kept %d of %d rows (%d dropped for missing fields).",
                channel,
                stat.kept,
                stat.matched,
                stat.dropped,
            )

    report = SandboxReport(
        provider=provider,
        source_format="generic",
        task_id=task_id,
        target=SandboxTarget(sha256=sha256),
        processes=processes,
        apistats=apistats,
        signatures=signatures,
        network=network,
        dropped_files=rows["dropped_files"],
        registry=rows["registry"],
        unavailable=unavailable,
        raw=payload,
    )
    return MappingResult(report=report, stats=stats)
```

- [ ] **Step 5: Write the golden pair**

`tests/fixtures/golden/rest_mapping/xyz_report.json` is a small synthetic report in a shape no sandbox this project supports uses — that is the point, since a shape one of them uses would prove nothing about the general path. Six processes' worth is unnecessary; two processes, three syscalls, two detections, one DNS lookup, one TCP stream, one artifact and two registry paths are enough to exercise every coercion and one drop:

```json
{
  "sample": {"hashes": {"sha256": "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"}},
  "run": {
    "processes": [
      {"pid": 100, "ppid": 4, "image": "loader.exe", "cmdline": "loader.exe /q",
       "syscalls": [{"pid": 100, "syscall": "NtCreateFile", "args": {"path": "C:\\t"}, "timestamp": 1},
                    {"pid": 100, "syscall": "NtWriteFile", "args": {}, "timestamp": 2}]},
      {"pid": 101, "ppid": 100, "image": "svc.exe", "cmdline": "svc.exe",
       "syscalls": [{"syscall": "NtOpenKey", "timestamp": 3}]}
    ],
    "registry": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc", ""]
  },
  "detections": [
    {"name": "persistence_run_key", "description": "Writes a Run key", "score": 3, "attack": ["T1547.001"]},
    {"description": "unnamed rule", "score": 1}
  ],
  "net": {
    "lookups": [{"qname": "c2.example", "type": "A", "answers": ["203.0.113.9"]}],
    "streams": [{"peer": "203.0.113.9", "peer_port": 443}]
  },
  "artifacts": [{"filename": "svc.exe", "sha256": "0f", "size": 2048}]
}
```

`xyz_mapped.json` is written once by running the mapping and dumping it, then read back by the test:

```bash
uv run python -c "
import json, pathlib
from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping
import sys; sys.path.insert(0, 'tests')
from providers.sandbox.test_rest_mapping import XYZ_MAPPING, GOLDEN
payload = json.loads((GOLDEN / 'xyz_report.json').read_text())
result = apply_mapping(compile_mapping(XYZ_MAPPING), payload, provider='rest', task_id='xyz-1')
(GOLDEN / 'xyz_mapped.json').write_text(
    json.dumps(result.report.model_dump(mode='json'), indent=2, sort_keys=True) + '\n')
"
```
Read the written file before committing it: `processes` must hold two rows (pids 100 and 101), the second detection must be absent (no `name`), the second registry entry must be absent (empty string), `unavailable` must list `hosts`, `http`, `domains` and `udp`, and `apistats` must read `{"100": {"NtCreateFile": 1, "NtWriteFile": 1}}` — the third syscall has no `pid` and is dropped. If any of those is wrong the mapping is wrong, not the golden.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/providers/sandbox/test_rest_mapping.py -q`
Expected: PASS (9 tests).

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers/sandbox/rest_mapping.py tests/providers/sandbox/test_rest_mapping.py && \
uv run ruff format --check src/maljan/providers/sandbox/rest_mapping.py tests/providers/sandbox/test_rest_mapping.py && \
uv run mypy src/ apps/api/
git add pyproject.toml uv.lock src/maljan/providers/sandbox/rest_mapping.py tests/providers/sandbox/test_rest_mapping.py tests/fixtures/golden/rest_mapping
git commit -m "feat(sandbox): map an arbitrary sandbox report onto SandboxReport with RFC 9535 JSONPath"
```

---

### Task 11: The generic REST sandbox provider

**Files:**
- Create: `src/maljan/providers/sandbox/rest.py`, `tests/providers/sandbox/test_rest_provider.py`
- Modify: `src/maljan/providers/registry.py:52-70` (`discover_providers` imports the new adapter)
- Test: `tests/providers/sandbox/test_rest_provider.py`, `tests/providers/test_registry.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/providers/sandbox/rest.py
  @register_sandbox_provider("rest")
  class RestSandboxProvider(SandboxProvider):
      def __init__(self, cfg: SandboxRestConfig, mapping: CompiledMapping) -> None
      @classmethod
      def from_settings(cls, cfg: Settings) -> RestSandboxProvider   # compiles the mapping
      @property
      def capabilities(self) -> SandboxCapabilities
      def submit(self, sample_path: str | Path) -> str
      def wait_for_completion(self, task_id, timeout_seconds=None, poll_interval_seconds=None) -> str
      def fetch(self, task_id: str) -> SandboxRun
      def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None
      async def probe(self) -> ProviderProbe
      def close(self) -> None
  ```
- Consumes: `maljan.providers.sandbox.triage._parse_retry_after`, `_BACKOFF_FACTOR`, `_MAX_INTERVAL_SECONDS`, `_safe_path_component`; `rest_mapping.compile_mapping`/`apply_mapping`; `maljan.schemas.sandbox_report.{cape_report_to_sandbox_report, triage_overview_to_sandbox_report, SandboxRun}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/providers/sandbox/test_rest_provider.py
"""A sandbox Maljan has never heard of, driven from settings."""

from __future__ import annotations

import json

import httpx
import pytest

from maljan.core.config import Settings
from maljan.providers.errors import ProviderConfigurationError, ProviderError
from maljan.providers.sandbox.rest import RestSandboxProvider


def _cfg(**over):
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    for key, value in over.items():
        setattr(cfg.sandbox.rest, key, value)
    return cfg


def _provider(handler, cfg=None):
    """A provider whose HTTP client answers from ``handler`` instead of a network."""
    provider = RestSandboxProvider.from_settings(cfg or _cfg())
    provider._http = httpx.Client(
        base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
    )
    provider._sleep = lambda seconds: None
    return provider


def test_capabilities_follow_the_configuration():
    caps = RestSandboxProvider.from_settings(_cfg()).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report
    assert caps.can_fetch_pcap is False and caps.report_format == "generic"
    assert caps.accepts_uploaded_report is False and caps.provides_tools is False
    assert caps.degrade_on_failure is True

    cfg = _cfg()
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/dump.pcap"
    cfg.sandbox.rest.report.format = "cape2"
    caps = RestSandboxProvider.from_settings(cfg).capabilities
    assert caps.can_fetch_pcap is True and caps.report_format == "cape2"


def test_a_broken_mapping_path_is_refused_at_construction():
    cfg = _cfg()
    cfg.sandbox.rest.mapping.processes = "$[["
    with pytest.raises(ProviderConfigurationError):
        RestSandboxProvider.from_settings(cfg)


def test_submit_posts_the_configured_field_and_reads_the_task_id(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["body"] = request.content
        return httpx.Response(200, json={"id": "T-9"})

    cfg = _cfg()
    cfg.sandbox.rest.submit.file_field = "binary"
    cfg.sandbox.rest.submit.extra_fields = {"profile": "win10"}
    cfg.sandbox.rest.auth.header = "X-Api-Key"
    cfg.sandbox.rest.auth.scheme = ""
    cfg.sandbox.rest.auth.token = "tok"
    assert _provider(handler, cfg).submit(sample) == "T-9"
    assert seen["method"] == "POST" and seen["url"].endswith("/samples")
    assert b'name="binary"' in seen["body"] and b'name="profile"' in seen["body"]


def test_a_missing_task_id_names_the_path_that_did_not_match(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    provider = _provider(lambda r: httpx.Response(200, json={"other": 1}))
    with pytest.raises(ProviderError) as exc:
        provider.submit(sample)
    assert "$.id" in str(exc.value)


def test_a_non_2xx_submit_is_a_provider_error(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ")
    provider = _provider(lambda r: httpx.Response(503, text="busy"))
    with pytest.raises(ProviderError) as exc:
        provider.submit(sample)
    assert "503" in str(exc.value)


def test_polling_stops_on_a_done_value_case_insensitively():
    states = iter(["queued", "Running", "REPORTED"])
    provider = _provider(lambda r: httpx.Response(200, json={"status": next(states)}))
    assert provider.wait_for_completion("T-9") == "reported"


def test_a_failed_state_stops_the_poll_and_says_so():
    provider = _provider(lambda r: httpx.Response(200, json={"status": "error"}))
    assert provider.wait_for_completion("T-9") == "failed"


def test_the_deadline_is_honoured():
    clock = iter([0.0, 0.0, 1000.0])
    provider = _provider(lambda r: httpx.Response(200, json={"status": "running"}))
    provider._now = lambda: next(clock)
    with pytest.raises(ProviderError) as exc:
        provider.wait_for_completion("T-9", timeout_seconds=10)
    assert "did not complete" in str(exc.value)


def test_retry_after_is_honoured_and_clamped():
    slept: list[float] = []
    answers = iter(
        [
            httpx.Response(429, headers={"Retry-After": "86400"}),
            httpx.Response(200, json={"status": "reported"}),
        ]
    )
    provider = _provider(lambda r: next(answers))
    provider._sleep = slept.append
    assert provider.wait_for_completion("T-9", timeout_seconds=120) == "reported"
    assert slept and max(slept) <= 60.0


def test_fetch_maps_a_generic_report_through_the_configured_paths():
    cfg = _cfg()
    cfg.sandbox.rest.mapping.processes = "$.procs[*]"
    body = {"procs": [{"pid": 3, "name": "a.exe"}], "target": {"sha256": "ab"}}
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("T-9")
    assert run.task_id == "T-9" and run.status == "reported"
    assert [p.pid for p in run.report.processes] == [3]
    assert run.report.source_format == "generic"
    assert run.raw is not None and run.report.raw == body


def test_a_cape_shaped_body_goes_through_the_cape_reader_untouched():
    cfg = _cfg()
    cfg.sandbox.rest.report.format = "cape2"
    body = {"target": {"file": {"sha256": "ab", "name": "s.bin"}}, "behavior": {"processes": []}}
    provider = _provider(lambda r: httpx.Response(200, json=body), cfg)
    run = provider.fetch("T-9")
    assert run.report.source_format == "cape2"
    from maljan.providers.cape_view import to_cape_shaped_dict

    assert to_cape_shaped_dict(run.report) is run.report.raw, "identity, as for every CAPE source"


def test_fetch_pcap_is_none_when_no_path_is_configured(tmp_path):
    provider = _provider(lambda r: httpx.Response(200, content=b"x" * 64))
    assert provider.fetch_pcap("T-9", tmp_path) is None


def test_fetch_pcap_streams_to_the_destination(tmp_path):
    cfg = _cfg()
    cfg.sandbox.rest.report.pcap_path = "/samples/{task_id}/dump.pcap"
    provider = _provider(lambda r: httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"y" * 64), cfg)
    out = provider.fetch_pcap("T-9", tmp_path)
    assert out is not None and out.endswith("rest_T-9.pcap")


def test_verify_tls_off_is_visible_in_the_probe_detail():
    cfg = _cfg()
    cfg.sandbox.rest.verify_tls = False
    provider = RestSandboxProvider.from_settings(cfg)
    assert "TLS verification is off" in provider._tls_note()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/providers/sandbox/test_rest_provider.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.providers.sandbox.rest'`.

- [ ] **Step 3: Write the provider**

```python
# src/maljan/providers/sandbox/rest.py
"""Any HTTP sandbox, described rather than coded.

CAPEv2 and Triage each get an adapter because each has a documented API worth
writing against. A lab running something else — a home-grown detonation
service, a vendor appliance, a fork of Cuckoo — has an API too, and it is
almost always the same four calls in a different order with different field
names. This provider is those four calls with the names in settings: where to
POST the sample, where the task id is in the answer, where to poll, which
state values are terminal, where the report is, and (when the report is in no
shape this project already reads) where each channel of it lives.

The poll loop is Triage's, deliberately and by import rather than by copy: the
deadline is checked at the top of every iteration including the rate-limited
branch, ``Retry-After`` is parsed as delta-seconds or an HTTP-date and clamped
to what remains of the budget, and the interval backs off 1.5x to 60 s.
"""

from __future__ import annotations

import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from maljan.core.logger import logger
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping
from maljan.providers.sandbox.triage import (
    _BACKOFF_FACTOR,
    _MAX_INTERVAL_SECONDS,
    _parse_retry_after,
    _safe_path_component,
)

if TYPE_CHECKING:
    from maljan.core.config import SandboxRestConfig, Settings
    from maljan.providers.sandbox.rest_mapping import CompiledMapping
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("rest")
class RestSandboxProvider(SandboxProvider):
    """Submit, poll, fetch and (optionally) capture, all from configuration."""

    def __init__(self, cfg: SandboxRestConfig, mapping: CompiledMapping) -> None:
        self._cfg = cfg
        self._mapping = mapping
        self._http: httpx.Client | None = None
        # Instance attributes, not module functions, so a test can drive the
        # clock and the sleeps without patching the stdlib.
        self._sleep = time.sleep
        self._now = time.monotonic

    @classmethod
    def from_settings(cls, cfg: Settings) -> RestSandboxProvider:
        """Compile the mapping here: a bad JSONPath must not reach a job."""
        rest = cfg.sandbox.rest
        return cls(rest, compile_mapping(rest.mapping))

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=bool(self._cfg.report.pcap_path),
            accepts_uploaded_report=False,
            provides_tools=False,
            report_format=self._cfg.report.format,
            degrade_on_failure=True,
        )

    # ---- plumbing ----------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        token = self._cfg.auth.token.get_secret_value()
        if not token:
            return {}
        scheme = self._cfg.auth.scheme.strip()
        return {self._cfg.auth.header: f"{scheme} {token}".strip() if scheme else token}

    def _tls_note(self) -> str:
        return " TLS verification is off." if not self._cfg.verify_tls else ""

    def _get_http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._cfg.base_url,
                headers=self._auth_headers(),
                timeout=60.0,
                verify=self._cfg.verify_tls,
            )
        return self._http

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str) -> None:
        if response.status_code >= 400:
            raise ProviderError(
                f"Sandbox {operation} failed (HTTP {response.status_code}): {response.text[:200]}"
            )

    def _select_one(self, expression: str, payload: Any, what: str) -> str:
        """One scalar out of a response, or a failure that names the path."""
        import jsonpath_rfc9535

        try:
            found = [node.value for node in jsonpath_rfc9535.compile(expression).finditer(payload)]
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"{what}: {expression!r} is not a usable JSONPath ({exc})") from exc
        if not found:
            raise ProviderError(f"{what}: {expression!r} matched nothing in the response")
        value = found[0]
        if isinstance(value, (dict, list)):
            raise ProviderError(f"{what}: {expression!r} matched a {type(value).__name__}, not a value")
        return str(value)

    # ---- the four calls ----------------------------------------------

    def submit(self, sample_path: str | Path) -> str:
        path = Path(sample_path)
        files: dict[str, Any] = {
            self._cfg.submit.file_field: (path.name, path.read_bytes(), "application/octet-stream")
        }
        for name, value in self._cfg.submit.extra_fields.items():
            files[name] = (None, value)
        response = self._get_http().request(self._cfg.submit.method, self._cfg.submit.path, files=files)
        self._raise_for_status(response, "submit")
        return self._select_one(self._cfg.submit.task_id_path, response.json(), "task id")

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        interval = float(poll_interval_seconds or self._cfg.poll_interval_seconds)
        budget = float(timeout_seconds if timeout_seconds is not None else self._cfg.timeout_seconds)
        deadline = self._now() + budget
        http = self._get_http()
        url = self._cfg.status.path.format(task_id=task_id)
        done = {v.lower() for v in self._cfg.status.done_values}
        failed = {v.lower() for v in self._cfg.status.failed_values}
        while True:
            # Checked at the top of every iteration, including the rate-limit
            # branch: a server that keeps answering 429 past the deadline must
            # raise rather than loop forever.
            if self._now() >= deadline:
                raise ProviderError(f"Sandbox task {task_id} did not complete within {budget:.0f}s.")
            response = http.get(url)
            if response.status_code in (429, 503):
                retry_after = response.headers.get("Retry-After")
                parsed = _parse_retry_after(retry_after, self._now()) if retry_after else None
                wait_seconds = parsed if parsed is not None else interval
                clamped = min(wait_seconds, _MAX_INTERVAL_SECONDS, deadline - self._now())
                if clamped > 0:
                    self._sleep(clamped)
                if parsed is None:
                    interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
                continue
            self._raise_for_status(response, "status check")
            state = self._select_one(
                self._cfg.status.state_path, response.json(), "status"
            ).lower()
            if state in done:
                return "reported"
            if state in failed:
                return "failed"
            self._sleep(interval)
            interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import (
            SandboxRun,
            cape_report_to_sandbox_report,
            triage_overview_to_sandbox_report,
        )

        response = self._get_http().get(self._cfg.report.path.format(task_id=task_id))
        self._raise_for_status(response, "report fetch")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProviderError("Sandbox report is not a JSON object.")

        fmt = self._cfg.report.format
        if fmt == "triage":
            report = triage_overview_to_sandbox_report(payload, provider="rest", task_id=str(task_id))
        elif fmt in ("cape2", "cuckoo"):
            # The same readers the report-upload provider uses, so a CAPE-shaped
            # body reaches the nine raw-CAPE consumers by identity here too.
            report = cape_report_to_sandbox_report(
                payload, provider="rest", source_format=fmt, task_id=str(task_id)
            )
        else:
            result = apply_mapping(self._mapping, payload, provider="rest", task_id=str(task_id))
            report = result.report
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=report.target.sha256,
            sample_name=report.target.name,
            status="reported",
            report=report,
            raw=payload,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        if not self._cfg.report.pcap_path:
            return None
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        safe = _safe_path_component(str(task_id))
        out = dest / f"rest_{safe}.pcap"
        url = self._cfg.report.pcap_path.format(task_id=safe)
        try:
            with self._get_http().stream("GET", url) as response:
                if response.status_code >= 400:
                    return None
                with open(out, "wb") as fh:
                    for chunk in response.iter_bytes(65536):
                        fh.write(chunk)
        except Exception:  # noqa: BLE001 — never a hard failure, as for every sandbox
            return None
        # libpcap/pcapng global header is 24 bytes; anything smaller is empty.
        if not out.exists() or out.stat().st_size < 24:
            return None
        return str(out)

    async def probe(self) -> ProviderProbe:
        """Ask the status endpoint about a task that does not exist.

        Any HTTP answer proves the URL resolves and the credential was
        accepted or rejected legibly — a 404 for a fake task is a *pass*, and
        the detail says so, because the alternative is asking an operator to
        detonate something to find out whether their base URL is right.
        """
        t0 = time.perf_counter()
        if not self._cfg.base_url:
            return ProviderProbe(ok=False, detail="no base URL configured")
        url = f"{self._cfg.base_url.rstrip('/')}{self._cfg.status.path.format(task_id='probe')}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=self._cfg.verify_tls) as client:
                response = await client.get(url, headers=self._auth_headers())
        except httpx.HTTPError as exc:
            from maljan.core.settings_overrides import redact_url

            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}") + self._tls_note(),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        ok = response.status_code not in (401, 403)
        detail = f"reachable, status endpoint answered {response.status_code} for a fake task"
        if not ok:
            detail = f"HTTP {response.status_code}: the credential was refused"
        return ProviderProbe(
            ok=ok,
            detail=detail + self._tls_note(),
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        client, self._http = self._http, None
        if client is not None:
            with suppress(Exception):
                client.close()
        logger.debug("rest sandbox provider closed.")
```

`src/maljan/providers/registry.py`'s `discover_providers` gains `import maljan.providers.sandbox.rest  # noqa: F401` in its alphabetically-ordered block.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/providers/sandbox/test_rest_provider.py tests/providers/test_registry.py tests/providers/test_capability_gates.py -q`
Expected: PASS — including `test_sandbox_ids_equal_the_settings_choices`, which has been red since Task 2.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/providers tests/providers && \
uv run ruff format --check src/maljan/providers tests/providers && \
uv run mypy src/ apps/api/
git add src/maljan/providers/sandbox/rest.py src/maljan/providers/registry.py tests/providers/sandbox/test_rest_provider.py
git commit -m "feat(sandbox): drive any HTTP sandbox from its endpoints and a JSONPath mapping"
```

---

### Task 12: A stub sandbox, and one job that goes through it end to end

**Files:**
- Create: `tests/servers/rest_stub.py`, `tests/integration/test_rest_sandbox_end_to_end.py`
- Modify: `src/maljan/app.py:176-183` (the poll budget)
- Test: `tests/integration/test_rest_sandbox_end_to_end.py`

**Interfaces:**
- Produces:
  ```python
  # tests/servers/rest_stub.py
  @dataclass
  class StubState:
      submitted: list[str]
      states: list[str]                    # popped one per status call, last one repeats
      report: dict[str, Any]
      pcap: bytes
  def build_stub_app(state: StubState) -> FastAPI     # POST /xyz/submit, GET /xyz/task/{id}, /report, /pcap
  # src/maljan/app.py
  def _poll_budget(self, provider: Any) -> tuple[int, int]
  ```
- Consumes: `RestSandboxProvider`, `MaljanApp`, `ServiceContainer`, `tests/fixtures/golden/rest_mapping/xyz_report.json`.

- [ ] **Step 1: Write the failing test**

```python
# tests/servers/rest_stub.py
"""A sandbox that does not exist, so the REST provider can be driven for real.

Deliberately not shaped like CAPE or Triage: field names, paths and the state
progression are all its own, because a stub that resembled a sandbox we
already support would pass with a mapping that only happens to work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "golden"
    / "rest_mapping"
    / "xyz_report.json"
)


@dataclass
class StubState:
    submitted: list[str] = field(default_factory=list)
    states: list[str] = field(default_factory=lambda: ["queued", "running", "finished"])
    report: dict[str, Any] = field(
        default_factory=lambda: json.loads(FIXTURE.read_text(encoding="utf-8"))
    )
    pcap: bytes = b"\xd4\xc3\xb2\xa1" + b"\0" * 64


def build_stub_app(state: StubState) -> FastAPI:
    app = FastAPI()

    @app.post("/xyz/submit")
    async def submit(request: Request) -> dict[str, Any]:
        form = await request.form()
        upload = form["binary"]
        state.submitted.append(getattr(upload, "filename", "unknown"))
        return {"task": {"ref": "XYZ-1"}}

    @app.get("/xyz/task/{task_id}")
    async def status(task_id: str) -> dict[str, Any]:
        current = state.states[0] if len(state.states) == 1 else state.states.pop(0)
        return {"task": {"ref": task_id, "state": current}}

    @app.get("/xyz/task/{task_id}/result")
    async def report(task_id: str) -> dict[str, Any]:
        return state.report

    @app.get("/xyz/task/{task_id}/capture")
    async def pcap(task_id: str) -> bytes:
        from fastapi.responses import Response

        return Response(content=state.pcap, media_type="application/vnd.tcpdump.pcap")

    return app
```

```python
# tests/integration/test_rest_sandbox_end_to_end.py
"""One analysis, through a sandbox that only exists in this test."""

from __future__ import annotations

import httpx
import pytest

from maljan.core.config import Settings
from tests.servers.rest_stub import StubState, build_stub_app


def _settings() -> Settings:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    rest = cfg.sandbox.rest
    rest.base_url = "http://stub"
    rest.submit.path = "/xyz/submit"
    rest.submit.file_field = "binary"
    rest.submit.task_id_path = "$.task.ref"
    rest.status.path = "/xyz/task/{task_id}"
    rest.status.state_path = "$.task.state"
    rest.status.done_values = ["finished"]
    rest.report.path = "/xyz/task/{task_id}/result"
    rest.report.pcap_path = "/xyz/task/{task_id}/capture"
    rest.poll_interval_seconds = 1
    mapping = rest.mapping
    mapping.target_sha256 = "$.sample.hashes.sha256"
    mapping.processes = "$.run.processes[*]"
    mapping.calls = "$.run.processes[*].syscalls[*]"
    mapping.signatures = "$.detections[*]"
    mapping.dns = "$.net.lookups[*]"
    mapping.tcp = "$.net.streams[*]"
    mapping.dropped_files = "$.artifacts[*]"
    mapping.registry = "$.run.registry[*]"
    mapping.field_names = {
        "processes.command_line": "cmdline",
        "processes.name": "image",
        "calls.api": "syscall",
        "signatures.severity": "score",
        "signatures.ttps": "attack",
        "dns.request": "qname",
        "tcp.dst": "peer",
        "tcp.dport": "peer_port",
        "dropped_files.name": "filename",
    }
    return cfg


@pytest.fixture()
def stub(monkeypatch):
    state = StubState()
    transport = httpx.ASGITransport(app=build_stub_app(state))
    real_client = httpx.Client

    def client(*args, **kwargs):
        kwargs["transport"] = transport
        kwargs.pop("verify", None)
        return real_client(*args, **kwargs)

    monkeypatch.setattr("maljan.providers.sandbox.rest.httpx.Client", client)
    return state


@pytest.mark.asyncio
async def test_a_job_detonates_and_the_dynamic_sections_are_filled(stub, tmp_path):
    from maljan.app import MaljanApp
    from maljan.core.container import ServiceContainer

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    app = MaljanApp(config=_settings(), mock=False)
    container = app.container

    report = await app._submit_to_sandbox(str(sample))
    assert stub.submitted == ["s.bin"], "the stub received the sample under the configured field"
    assert report is not None
    assert [p["pid"] for p in report["behavior"]["processes"]] == [100, 101]
    assert report["network"]["dns"][0]["request"] == "c2.example"
    await container.aclose()


@pytest.mark.asyncio
async def test_the_unmapped_channels_are_named_rather_than_left_empty(stub, tmp_path):
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(config=_settings(), mock=False)
    provider = container.get_sandbox_provider()
    provider.submit(str(tmp_path))  # the stub ignores the path; only the id matters
    run = provider.fetch("XYZ-1")
    assert set(run.report.unavailable) == {"domains", "hosts", "http", "udp"}
    await container.aclose()


@pytest.mark.asyncio
async def test_the_rest_provider_polls_on_its_own_budget(stub, tmp_path):
    """The app used to thread CAPE's timeout into every provider's poll loop."""
    from maljan.app import MaljanApp

    cfg = _settings()
    cfg.sandbox.rest.timeout_seconds = 42
    cfg.sandbox.rest.poll_interval_seconds = 1
    cfg.sandbox.cape2.timeout_seconds = 300
    app = MaljanApp(config=cfg, mock=False)
    assert app._poll_budget(app.container.get_sandbox_provider()) == (42, 1)
    await app.aclose()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/integration/test_rest_sandbox_end_to_end.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'tests.servers.rest_stub'`, and once that exists, `AttributeError: 'MaljanApp' object has no attribute '_poll_budget'`.

- [ ] **Step 3: Give the app a per-provider poll budget**

`src/maljan/app.py`, replacing the two literal reads at lines 180-182:

```python
    def _poll_budget(self, provider: Any) -> tuple[int, int]:
        """How long to wait for this provider, and how often to ask.

        Sub-project A threaded ``sandbox.cape2.*`` into every provider's poll
        loop, which was harmless while every provider that polled was CAPE.
        A provider with its own configured budget reads it; everything else
        keeps CAPE's values, so the cape2, mock, upload and triage paths are
        byte-for-byte what they were.
        """
        block = getattr(self.config.sandbox, str(provider.id), None)
        timeout = getattr(block, "timeout_seconds", None)
        interval = getattr(block, "poll_interval_seconds", None)
        if timeout is None or interval is None:
            return (
                self.config.sandbox.cape2.timeout_seconds,
                self.config.sandbox.cape2.poll_interval_seconds,
            )
        return int(timeout), int(interval)
```

and at the call site:

```python
                timeout_seconds, poll_interval_seconds = self._poll_budget(provider)
                status = client.wait_for_completion(
                    task_id,
                    timeout_seconds=timeout_seconds,
                    poll_interval_seconds=poll_interval_seconds,
                )
```

`sandbox.triage` and `sandbox.cape2` both declare those two fields, so `triage` now reads its own — which is what its settings say and what its own docstring already promised; note it in the commit body.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/integration/test_rest_sandbox_end_to_end.py tests/providers/sandbox -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/app.py tests/servers tests/integration && \
uv run ruff format --check src/maljan/app.py tests/servers tests/integration && \
uv run mypy src/ apps/api/
git add src/maljan/app.py tests/servers/rest_stub.py tests/integration/test_rest_sandbox_end_to_end.py
git commit -m "test(sandbox): drive one analysis through a stub REST sandbox, and give each provider its own poll budget"
```

---

### Task 13: The REST connection test and the mapping preview

**Files:**
- Modify: `apps/api/app/services/settings_probes.py:294-311` (`PROBES`), `:313-366` (`_INPUTS`); `apps/api/app/schemas/settings.py` (three new models); `apps/api/app/api/v1/settings.py:147-160` (the preview route beside `test_probe`)
- Create: `apps/api/app/services/mapping_preview.py`
- Test: `tests/unit/api/test_mapping_preview.py` (create), `tests/api/test_settings_routes.py` (modify — three route cases)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/services/settings_probes.py
  async def probe_rest(v: dict[str, Any]) -> ProbeResult
  # apps/api/app/services/mapping_preview.py
  PREVIEW_MAX_BYTES = 4 * 1024 * 1024
  def preview_mapping(sample: dict[str, Any], mapping: dict[str, Any]) -> dict[str, dict[str, Any]]
  # apps/api/app/schemas/settings.py
  class MappingPreviewRequest(BaseModel):
      sample: dict[str, Any]
      mapping: dict[str, Any]
  class ChannelPreview(BaseModel):
      matched: int; kept: int; dropped: int; sample_rows: list[Any]; error: str | None = None
  class MappingPreviewResponse(BaseModel):
      target_sha256: str
      channels: dict[str, ChannelPreview]
  ```
- Consumes: `RestSandboxProvider.probe`, `rest_mapping.compile_mapping`/`apply_mapping`, `maljan.core.config.RestMappingConfig`, `app.deps.require_admin`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/api/test_mapping_preview.py
"""The one place a mapping's errors are shown before a job is submitted."""

from __future__ import annotations

import pytest

from app.services.mapping_preview import PREVIEW_MAX_BYTES, preview_mapping


def test_a_channel_reports_matched_kept_and_dropped():
    out = preview_mapping(
        {"p": [{"pid": 1}, {"nope": 2}]}, {"processes": "$.p[*]"}
    )
    assert out["channels"]["processes"]["matched"] == 2
    assert out["channels"]["processes"]["kept"] == 1
    assert out["channels"]["processes"]["dropped"] == 1
    assert len(out["channels"]["processes"]["sample_rows"]) == 1


def test_the_target_hash_is_shown_as_a_value_not_a_row():
    out = preview_mapping({"t": {"h": "abc"}}, {"target_sha256": "$.t.h"})
    assert out["target_sha256"] == "abc"


def test_a_bad_path_reports_on_its_own_channel_and_leaves_the_others_alone():
    out = preview_mapping({"p": [{"pid": 1}]}, {"processes": "$.p[*]", "dns": "$[["})
    assert out["channels"]["dns"]["error"]
    assert "dns" in out["channels"]["dns"]["error"]
    assert out["channels"]["processes"]["kept"] == 1


def test_an_unmapped_channel_is_reported_as_zero_rather_than_missing():
    out = preview_mapping({}, {})
    assert out["channels"]["http"] == {
        "matched": 0,
        "kept": 0,
        "dropped": 0,
        "sample_rows": [],
        "error": None,
    }


def test_the_cap_is_four_mebibytes():
    assert PREVIEW_MAX_BYTES == 4 * 1024 * 1024


def test_the_rest_probe_is_registered_and_reads_the_rest_settings():
    from app.services.settings_probes import PROBES, _INPUTS

    assert "rest" in PROBES
    assert "core.sandbox.rest.base_url" in _INPUTS["rest"]
    assert "core.sandbox.rest.auth.token" in _INPUTS["rest"]
```

and, for the route itself, in `tests/api/test_settings_routes.py` — the module that already
builds a `FastAPI` app around the settings router and overrides `require_admin` and `get_db`,
so the admin gate and the size cap are exercised the same way every other settings route is:

```python
def test_the_preview_route_caps_the_pasted_sample(client):
    from app.services.mapping_preview import PREVIEW_MAX_BYTES

    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"pad": "x" * (PREVIEW_MAX_BYTES + 1)}, "mapping": {}},
    )
    assert r.status_code == 413


def test_the_preview_route_counts_rows_per_channel(client):
    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"p": [{"pid": 1}, {"nope": 2}]}, "mapping": {"processes": "$.p[*]"}},
    )
    assert r.status_code == 200
    assert r.json()["channels"]["processes"] == {
        "matched": 2, "kept": 1, "dropped": 1, "sample_rows": [{"pid": 1}], "error": None,
    }


def test_the_preview_route_is_admin_only():
    """Without the ``require_admin`` override the real dependency runs and refuses."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1.settings import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    r = TestClient(app).post(
        "/api/v1/settings/sandbox-rest/preview", json={"sample": {}, "mapping": {}}
    )
    assert r.status_code in (401, 403)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/api/test_mapping_preview.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.mapping_preview'`.

- [ ] **Step 3: Write the preview service**

```python
# apps/api/app/services/mapping_preview.py
"""Run a REST-sandbox mapping against a pasted response, and count what it did.

An operator configuring a sandbox nobody has integrated has exactly one hard
question: does this JSONPath select the thing I think it selects. Answering it
by submitting a sample and reading the report afterwards costs a detonation
and several minutes. Answering it here costs a paste.

Server-side because the mapping has one implementation
(``providers/sandbox/rest_mapping.py``) and one set of error messages; a
JSONPath engine in the browser would be a second of both.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.core.config import RestMappingConfig
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import CHANNELS, apply_mapping, compile_mapping

# A pasted sample response, not a real report: 4 MiB is generous for one and
# far below the 64 MiB an uploaded report is allowed, which is deliberate —
# this endpoint parses and walks whatever it is given, inside a request.
PREVIEW_MAX_BYTES = 4 * 1024 * 1024

_EMPTY = {"matched": 0, "kept": 0, "dropped": 0, "sample_rows": [], "error": None}


def preview_mapping(sample: dict[str, Any], mapping: dict[str, Any]) -> dict[str, Any]:
    """Per channel: what the path selected, what survived, and what went wrong.

    A channel whose path does not compile reports its own error and does not
    stop the others: an operator fixing six paths wants six answers, not the
    first failure six times.
    """
    channels: dict[str, Any] = {name: dict(_EMPTY) for name in CHANNELS}
    target = ""
    per_channel: dict[str, str] = {}
    for name in (*CHANNELS, "target_sha256"):
        value = mapping.get(name)
        if isinstance(value, str) and value:
            per_channel[name] = value

    for name, expression in per_channel.items():
        try:
            compiled = compile_mapping(RestMappingConfig(**{name: expression}))
        except ProviderConfigurationError as exc:
            if name != "target_sha256":
                channels[name] = {**_EMPTY, "error": str(exc)}
            continue
        result = apply_mapping(compiled, sample, provider="preview", task_id="preview")
        if name == "target_sha256":
            target = result.report.target.sha256
            continue
        stats = result.stats[name]
        channels[name] = {
            "matched": stats.matched,
            "kept": stats.kept,
            "dropped": stats.dropped,
            "sample_rows": json.loads(json.dumps(stats.sample_rows, default=str)),
            "error": stats.error or None,
        }
    return {"target_sha256": target, "channels": channels}
```

- [ ] **Step 4: Wire the route and the probe**

`apps/api/app/schemas/settings.py` gains the three models from the Interfaces block. `apps/api/app/api/v1/settings.py`, after `test_probe`:

```python
@router.post("/sandbox-rest/preview", response_model=MappingPreviewResponse)
async def preview_sandbox_mapping(
    body: MappingPreviewRequest,
    _: User = Depends(require_admin),
) -> MappingPreviewResponse:
    """Run a mapping against a pasted response. Nothing is stored or submitted."""
    if len(json.dumps(body.sample)) > PREVIEW_MAX_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"the pasted response exceeds {PREVIEW_MAX_BYTES} bytes",
        )
    return MappingPreviewResponse(**preview_mapping(body.sample, body.mapping))
```

`apps/api/app/services/settings_probes.py`:

```python
async def probe_rest(v: dict[str, Any]) -> ProbeResult:
    """Ask the configured sandbox's status endpoint about a task that does not exist."""
    t0 = time.perf_counter()
    from maljan.core.config import Settings
    from maljan.providers.sandbox.rest import RestSandboxProvider

    cfg = Settings()
    rest = cfg.sandbox.rest.model_copy(deep=True)
    rest.base_url = str(v.get("base_url") or rest.base_url)
    rest.auth.token = SecretStr(str(v.get("token") or rest.auth.token.get_secret_value()))
    rest.status.path = str(v.get("status_path") or rest.status.path)
    rest.verify_tls = bool(v.get("verify_tls", rest.verify_tls))
    try:
        provider = RestSandboxProvider(rest, compile_mapping(rest.mapping))
    except ProviderConfigurationError as exc:
        return ProbeResult(False, _ms(t0), str(exc))
    result = await provider.probe()
    return ProbeResult(result.ok, result.latency_ms or _ms(t0), result.detail)
```

with `PROBES["rest"] = probe_rest` and

```python
    "rest": {
        "core.sandbox.rest.base_url": "base_url",
        "core.sandbox.rest.auth.token": "token",
        "core.sandbox.rest.status.path": "status_path",
        "core.sandbox.rest.verify_tls": "verify_tls",
    },
```

and one annotation change in `src/maljan/core/settings_annotations.py`: `sandbox.rest.base_url`'s entry gains `"probe": "rest"` so the group header renders the button. `apps/web/src/app/(app)/settings/configuration/GroupHeader.tsx`'s `PROBE_LABEL` gains `rest: "Test sandbox API"` and `mcp: "Test MCP server"` (Task 15 touches that file too; either order works as long as both labels land).

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/api/test_mapping_preview.py tests/api/test_settings_routes.py tests/unit/api/test_settings_probes.py tests/unit/core/test_settings_catalog.py -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app src/maljan/core/settings_annotations.py tests/unit/api && \
uv run ruff format --check apps/api/app src/maljan/core/settings_annotations.py tests/unit/api && \
uv run mypy src/ apps/api/
git add apps/api/app src/maljan/core/settings_annotations.py tests/unit/api/test_mapping_preview.py tests/api/test_settings_routes.py
git commit -m "feat(api): test a REST sandbox's endpoint and preview its mapping before a job runs"
```

---

### Task 14: The API resolves the choices, validates the server map, and probes one key of it

**A per-server `auth_token` is stored, not refused (controller ruling A1).** `core.mcp.servers` is one
non-secret JSONB row, so a token written into it would sit in the database in clear beside values the UI
echoes back. It is therefore split out on the way in and put back on the way out: the PATCH stores the map
without any token and one `is_secret` row per server keyed `core.mcp.servers.<key>.auth_token`, encrypted by
the same Fernet box every other secret uses; `load_overrides` merges the rows back into the map before the
worker builds `Settings`; and the values endpoint shows the mask, never the value. That needs one new
capability in `SettingsService` — secret rows whose key is chosen at runtime rather than declared in the
catalog — and this task builds it. Everything that makes it work is in Steps 3 and 4 below and is tested in
Step 1; nothing about it is left to a later task except the card that renders it (Task 16).

**Files:**
- Create: `apps/api/app/services/server_map.py`
- Modify: `apps/api/app/services/settings_catalog_api.py:245-258` (`full_catalog`), `apps/api/app/api/v1/settings.py:40-53` (`get_schema`), `:63-78` (`patch_values`), `:147-160` (the MCP probe route), `apps/api/app/services/settings_service.py:68-83` (`load_overrides`), `:84-163` (`values`), `:196-250` (`save`)
- Test: `tests/unit/api/test_server_map_validation.py` (create), `tests/unit/api/test_server_map_secrets.py` (create), `tests/api/test_settings_schema_choices.py` (create)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/services/server_map.py
  SERVER_MAP_KEY = "core.mcp.servers"
  TOKEN_MASK = "**********"
  class ServerMapError(Exception):
      errors: dict[str, str]
  def server_token_key(server: str) -> str          # "core.mcp.servers.<server>.auth_token"
  def validate_server_map(value: Any, *, stored: dict[str, Any] | None = None) -> dict[str, Any]
  def split_server_secrets(
      value: Any, *, stored: dict[str, Any] | None = None
  ) -> tuple[dict[str, Any], dict[str, str | None]]  # (map without tokens, {server: token or None})
  def merge_server_secrets(overrides: dict[str, Any]) -> dict[str, Any]
  # apps/api/app/services/settings_catalog_api.py
  def resolved_catalog(servers: Iterable[str]) -> list[CatalogEntry]
  # apps/api/app/services/settings_service.py
  class SettingsService:
      def _save_server_tokens(self, tokens: dict[str, str | None], kept: set[str]) -> None
      def _masked_server_map(self, stored_map, env_servers, rows) -> dict[str, Any]
  ```
- Consumes: `maljan.core.config.{SERVER_KEY_PATTERN, RESERVED_SERVER_KEYS, BUILTIN_SERVER_KEYS, MCPServerConfig, AgentRole}`, `maljan.providers.registry.{static_provider_ids, sandbox_provider_ids}`, `maljan.core.settings_secrets` (`encrypt`, `decrypt`, `is_available`, `hint`), `app.models.RuntimeSetting`, `run_mcp_probe` (Task 9).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_server_map_validation.py
"""What an admin may write into core.mcp.servers."""

from __future__ import annotations

import pytest

from app.services.server_map import ServerMapError, split_server_secrets, validate_server_map


def _entry(**over):
    base = {"enabled": True, "transport": "stdio", "command": "mcp", "agents": ["static"]}
    base.update(over)
    return base


def test_a_valid_map_comes_back_normalised():
    out = validate_server_map({"r2custom": _entry()})
    assert out["r2custom"]["command"] == "mcp"
    assert out["r2custom"]["tools"] is None


def test_a_key_that_is_not_a_slug_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"R2 Custom": _entry()})
    assert "R2 Custom" in exc.value.errors


def test_a_reserved_key_cannot_be_claimed_by_a_new_server():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"ghidra": _entry()})
    assert "ghidra" in exc.value.errors
    assert "reserved" in exc.value.errors["ghidra"]


def test_a_built_in_may_be_disabled_but_not_deleted():
    out = validate_server_map({"network": _entry(enabled=False, agents=["network"])})
    assert out["network"]["enabled"] is False
    assert "threatintel" in out, "a built-in left out of the body is re-seeded, not removed"


def test_a_custom_key_left_out_of_the_body_is_removed():
    stored = {"gone": _entry(), "kept": _entry()}
    out = validate_server_map({"kept": _entry()}, stored=stored)
    assert "gone" not in out and "kept" in out


def test_an_unknown_agent_role_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(agents=["auditor"])})
    assert "x.agents" in exc.value.errors


def test_a_token_is_split_out_of_the_map_rather_than_stored_in_it():
    """The registry leaf is one plain JSON row; a token in it would be in clear."""
    cleaned, tokens = split_server_secrets(
        {"x": _entry(transport="http", url="https://h", command="", auth_token="s3cr3t")}
    )
    assert "auth_token" not in cleaned["x"]
    assert tokens == {"x": "s3cr3t"}


def test_the_mask_means_unchanged_and_never_becomes_the_token():
    from app.services.server_map import TOKEN_MASK

    cleaned, tokens = split_server_secrets(
        {"x": _entry(transport="http", url="https://h", command="", auth_token=TOKEN_MASK)}
    )
    assert "auth_token" not in cleaned["x"]
    assert tokens == {}, "a round-tripped mask leaves the stored row alone"


def test_an_empty_or_null_token_asks_for_the_row_to_be_deleted():
    _, empty = split_server_secrets({"x": _entry(auth_token="")})
    _, nulled = split_server_secrets({"x": _entry(auth_token=None)})
    assert empty == {"x": None} and nulled == {"x": None}


def test_an_entry_that_never_mentions_a_token_leaves_the_row_untouched():
    _, tokens = split_server_secrets({"x": _entry()})
    assert tokens == {}


def test_the_token_key_is_derived_from_the_server_name():
    from app.services.server_map import server_token_key

    assert server_token_key("r2custom") == "core.mcp.servers.r2custom.auth_token"


def test_merge_puts_the_rows_back_into_the_map_and_drops_the_synthetic_keys():
    from app.services.server_map import merge_server_secrets

    merged = merge_server_secrets(
        {
            "core.mcp.servers": {"x": {"command": "mcp"}},
            "core.mcp.servers.x.auth_token": "s3cr3t",
            "core.llm.provider": "openai",
        }
    )
    assert merged["core.mcp.servers"]["x"]["auth_token"] == "s3cr3t"
    assert "core.mcp.servers.x.auth_token" not in merged
    assert merged["core.llm.provider"] == "openai"


def test_merge_ignores_a_row_whose_server_is_gone():
    from app.services.server_map import merge_server_secrets

    merged = merge_server_secrets(
        {"core.mcp.servers": {}, "core.mcp.servers.gone.auth_token": "s3cr3t"}
    )
    assert merged["core.mcp.servers"] == {}
    assert "core.mcp.servers.gone.auth_token" not in merged


def test_a_stdio_server_without_a_command_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(command="")})
    assert "x.command" in exc.value.errors


def test_an_http_server_without_a_url_is_refused():
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"x": _entry(transport="http", command="", url="")})
    assert "x.url" in exc.value.errors
```

```python
# tests/unit/api/test_server_map_secrets.py
"""A per-server token is stored the way every other secret is stored.

The map itself is one non-secret JSONB row. The tokens are not in it: each is
its own ``is_secret`` row, encrypted with the same Fernet box that protects
``core.static.ghidra.auth_token``, and merged back only when the effective
settings are assembled for a job.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from maljan.core import settings_secrets as box

from app.services.server_map import TOKEN_MASK, server_token_key
from app.services.settings_service import SettingsService, SettingsValidationError


@pytest.fixture()
def encryption_key(monkeypatch):
    """A real Fernet key, generated per run rather than committed."""
    from cryptography.fernet import Fernet

    monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())


class _Rows(list):
    """A stand-in session: records adds and deletes, replays rows."""

    def __init__(self, rows=()):
        super().__init__(rows)
        self.added: list = []
        self.deleted: list = []

    def add(self, row):
        self.added.append(row)

    async def delete(self, row):
        self.deleted.append(row)

    async def commit(self):
        return None


def _service(rows=()) -> tuple[SettingsService, _Rows]:
    session = _Rows(rows)
    service = SettingsService(MagicMock())
    service._rows = AsyncMock(return_value=list(session))  # type: ignore[method-assign]
    service.db = session
    return service, session


@pytest.mark.asyncio
async def test_a_patch_with_a_token_stores_it_as_its_own_encrypted_row(encryption_key):
    service, session = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    await service.save(
        {
            "core.mcp.servers": {
                "x": {"enabled": True, "transport": "http", "url": "https://h",
                      "auth_token": "s3cr3t"}
            }
        },
        user_id=None,
        ip=None,
    )
    map_row = next(r for r in session.added if r.key == "core.mcp.servers")
    token_row = next(r for r in session.added if r.key == server_token_key("x"))
    assert "auth_token" not in map_row.value["x"]
    assert "s3cr3t" not in str(map_row.value)
    assert token_row.is_secret is True
    assert box.is_encrypted(token_row.value)
    assert box.decrypt(str(token_row.value)) == "s3cr3t"


@pytest.mark.asyncio
async def test_a_patch_with_a_token_and_no_encryption_key_is_the_same_422(monkeypatch):
    monkeypatch.delenv(box.ENV_VAR, raising=False)
    service, _ = _service()
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    with pytest.raises(SettingsValidationError) as exc:
        await service.save(
            {"core.mcp.servers": {"x": {"enabled": True, "command": "mcp",
                                        "auth_token": "s3cr3t"}}},
            user_id=None,
            ip=None,
        )
    assert exc.value.errors[server_token_key("x")] == (
        "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
    )


@pytest.mark.asyncio
async def test_a_null_token_deletes_the_row_and_a_removed_server_deletes_its_row(encryption_key):
    from app.models import RuntimeSetting

    existing = [
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("a"), is_secret=True),
        RuntimeSetting(key=server_token_key("gone"), value=box.encrypt("b"), is_secret=True),
    ]
    service, session = _service(existing)
    service.load_overrides = AsyncMock(
        return_value={"core.mcp.servers": {"x": {"command": "mcp"}, "gone": {"command": "mcp"}}}
    )  # type: ignore[method-assign]
    await service.save(
        {"core.mcp.servers": {"x": {"enabled": True, "command": "mcp", "auth_token": None}}},
        user_id=None,
        ip=None,
    )
    deleted = {r.key for r in session.deleted}
    assert server_token_key("x") in deleted, "an explicit null clears the token"
    assert server_token_key("gone") in deleted, "a removed server takes its token with it"


@pytest.mark.asyncio
async def test_the_effective_overrides_carry_the_plain_token_to_the_worker(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": {"command": "mcp"}}, is_secret=False),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    overrides = await service.load_overrides()
    assert overrides["core.mcp.servers"]["x"]["auth_token"] == "s3cr3t"
    assert server_token_key("x") not in overrides


@pytest.mark.asyncio
async def test_the_effective_settings_build_with_the_merged_token(encryption_key):
    from maljan.core.settings_overrides import build_settings, split_key

    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(
            key="core.mcp.servers",
            value={"x": {"enabled": True, "transport": "http", "url": "https://h"}},
            is_secret=False,
        ),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    overrides = await service.load_overrides()
    core = {split_key(k)[1]: v for k, v in overrides.items() if k.startswith("core.")}
    cfg = build_settings(core)
    assert cfg.mcp.servers["x"].auth_token.get_secret_value() == "s3cr3t"


@pytest.mark.asyncio
async def test_the_values_endpoint_masks_a_set_token_and_reports_its_source(encryption_key):
    from app.models import RuntimeSetting

    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"x": {"command": "mcp"}}, is_secret=False),
        RuntimeSetting(key=server_token_key("x"), value=box.encrypt("s3cr3t"), is_secret=True),
    ]
    service, _ = _service(rows)
    values = await service.values()
    shown = values["core.mcp.servers"].value
    assert shown["x"]["auth_token"] == TOKEN_MASK
    assert shown["x"]["auth_token_source"] == "ui"
    assert "s3cr3t" not in str(shown)


@pytest.mark.asyncio
async def test_an_unset_token_shows_empty_and_a_dot_env_token_shows_env(monkeypatch, encryption_key):
    monkeypatch.setenv("MCP__SERVERS__NETWORK__AUTH_TOKEN", "from-env")
    service, _ = _service()
    values = await service.values()
    shown = values["core.mcp.servers"].value
    assert shown["network"]["auth_token"] == TOKEN_MASK
    assert shown["network"]["auth_token_source"] == "env"
    assert shown["threatintel"]["auth_token"] == ""
    assert shown["threatintel"]["auth_token_source"] == "default"
    assert "from-env" not in str(shown)
```

```python
# tests/api/test_settings_schema_choices.py
"""The API fills in every choice list; the web computes none."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.settings import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_admin  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    """The same harness ``tests/api/test_settings_routes.py`` uses."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_the_schema_carries_registry_ids_and_the_current_server_keys(client):
    with patch(
        "app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})
    ):
        response = client.get("/api/v1/settings/schema")
    entries = {e["key"]: e for g in response.json()["groups"] for e in g["entries"]}
    # No ``choices_from`` on the two provider selectors: their choices come
    # from the settings ``Literal`` and keep its declaration order, which is
    # what the submit dialog renders. The registry sources exist for a leaf
    # that needs them; the parity test is what keeps the two lists equal.
    assert entries["core.static.provider"]["choices"] == [
        "ghidra", "r2", "capa_yara", "generic_mcp", "none",
    ]
    assert entries["core.static.provider"]["choices_from"] is None
    assert "rest" in entries["core.sandbox.provider"]["choices"]
    generic = entries["core.static.generic.server"]
    assert generic["choices_from"] == "mcp_servers"
    assert generic["choices"] == ["", "network", "threatintel"]
    assert entries["core.mcp.servers"]["editor"] == "server_map"


def test_a_patch_to_the_server_map_is_validated_and_reported_per_key(client):
    with patch(
        "app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})
    ):
        response = client.patch(
            "/api/v1/settings",
            json={"changes": {"core.mcp.servers": {"Bad Key": {"command": "x"}}}},
        )
    assert response.status_code == 422
    assert "core.mcp.servers.Bad Key" in response.json()["errors"]


def test_the_mcp_probe_route_addresses_one_server(client, monkeypatch):
    from app.services.settings_probes import ProbeResult

    async def fake(server, values, stored):
        assert server == "network"
        assert values == {"core.mcp.servers": {"network": {"command": "python"}}}
        return ProbeResult(True, 12, "3 tools: a, b, c", None, ["a", "b", "c"])

    monkeypatch.setattr("app.api.v1.settings.run_mcp_probe", fake)
    with patch(
        "app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})
    ):
        response = client.post(
            "/api/v1/settings/test/mcp?server=network",
            json={"values": {"core.mcp.servers": {"network": {"command": "python"}}}},
        )
    assert response.status_code == 200
    assert response.json()["tools"] == ["a", "b", "c"]


def test_the_mcp_probe_route_needs_a_server(client):
    response = client.post("/api/v1/settings/test/mcp", json={"values": {}})
    assert response.status_code == 422
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/api/test_server_map_validation.py tests/unit/api/test_server_map_secrets.py tests/api/test_settings_schema_choices.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.server_map'`, and the schema's `core.static.generic.server` carries `choices: null`.

- [ ] **Step 3: Write the validator**

```python
# apps/api/app/services/server_map.py
"""What an admin may write into ``core.mcp.servers``, and where its tokens go.

The registry is one catalog leaf holding a whole map, so the settings
service's per-key checks (editable, secret, type) cannot see inside it. These
are the checks that belong inside: the key is a slug and not one of the names
the code reserves, every entry validates as an ``MCPServerConfig``, and a
built-in is disabled rather than deleted.

The tokens are the interesting part. The map is stored as one *non-secret*
JSONB row, so a token left inside it would sit in the database in clear text
beside values the UI echoes back. It is therefore split out on the way in and
put back on the way out: ``split_server_secrets`` returns the map to store and
the tokens to encrypt, ``SettingsService.save`` writes one ``is_secret`` row
per server, and ``merge_server_secrets`` folds them back in when the effective
overrides are assembled. The value an operator sees is always the mask, and
the mask coming back in an unchanged PATCH means exactly that — unchanged —
rather than a token whose literal characters are ten asterisks.
"""

from __future__ import annotations

from typing import Any, get_args

from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    AgentRole,
    MCPServerConfig,
    _builtin_servers,
)
from pydantic import ValidationError
import re

SERVER_MAP_KEY = "core.mcp.servers"
# What a set token looks like from outside. Identical to pydantic's own
# SecretStr JSON rendering, so a value read out of a snapshot and one read out
# of this endpoint say the same thing.
TOKEN_MASK = "**********"

_KEY_RE = re.compile(SERVER_KEY_PATTERN)
_ROLES = set(get_args(AgentRole))


def server_token_key(server: str) -> str:
    """The settings key one server's token is stored under.

    Deliberately shaped like a catalog key without being one: the catalog is a
    static list and cannot contain a name an operator invents at runtime, so
    ``SettingsService`` handles these rows itself rather than through
    ``check_keys``. Nothing else in the system may write a key of this shape.
    """
    return f"{SERVER_MAP_KEY}.{server}.auth_token"


class ServerMapError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def validate_server_map(value: Any, *, stored: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the map to store, or raise with one message per offending key."""
    errors: dict[str, str] = {}
    if not isinstance(value, dict):
        raise ServerMapError({"": "the server map must be an object keyed by server name"})

    out: dict[str, Any] = {}
    for key, entry in value.items():
        if not _KEY_RE.match(str(key)):
            errors[str(key)] = (
                "a server name is lowercase, starts with a letter, and is at most 32 "
                "characters of letters, digits, '-' or '_'"
            )
            continue
        known = set(stored or {}) | set(BUILTIN_SERVER_KEYS)
        if key in RESERVED_SERVER_KEYS and key not in BUILTIN_SERVER_KEYS and key not in known:
            errors[key] = f"{key!r} is reserved for a provider-owned server"
            continue
        if not isinstance(entry, dict):
            errors[key] = "a server entry must be an object"
            continue
        for role in entry.get("agents") or []:
            if role not in _ROLES:
                errors[f"{key}.agents"] = (
                    f"{role!r} is not an analyst; expected one of {', '.join(sorted(_ROLES))}"
                )
        try:
            # The token is validated and stored separately (``split_server_secrets``);
            # blanking it here keeps it out of the JSON row under every path.
            model = MCPServerConfig.model_validate({**entry, "auth_token": ""})
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{key}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        if model.transport == "stdio" and not model.command:
            errors[f"{key}.command"] = "a stdio server needs a command to launch"
        if model.transport != "stdio" and not model.url:
            errors[f"{key}.url"] = "an http server needs a URL"
        dumped = model.model_dump(mode="json")
        dumped.pop("auth_token", None)
        out[key] = dumped

    if errors:
        raise ServerMapError(errors)

    # A built-in the body left out is re-seeded rather than removed: the
    # settings model would put it back on the next load anyway, and a stored
    # map missing it would silently discard the operator's own edits to it.
    for key, default in _builtin_servers().items():
        if key not in out:
            entry = default.model_dump(mode="json")
            entry.pop("auth_token", None)
            out[key] = entry
    return out


def split_server_secrets(
    value: Any, *, stored: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, str | None]]:
    """Validate the map, and separate the tokens from what gets stored in it.

    The second element is an *instruction set*, not a state: a server appears
    in it only when the incoming entry actually said something about its
    token. A non-empty string means "store this"; ``None`` (from an explicit
    ``null`` or an empty string) means "delete the row"; the mask means "leave
    it alone", and so does an entry that never mentions ``auth_token`` at all.
    That distinction is what lets the editor round-trip a masked value without
    overwriting the real one with ten asterisks.
    """
    cleaned = validate_server_map(value, stored=stored)
    tokens: dict[str, str | None] = {}
    for key, entry in (value or {}).items():
        if not isinstance(entry, dict) or "auth_token" not in entry:
            continue
        token = entry["auth_token"]
        if token == TOKEN_MASK:
            continue
        tokens[key] = str(token) if token else None
    return cleaned, tokens


def merge_server_secrets(overrides: dict[str, Any]) -> dict[str, Any]:
    """Fold the per-server token rows back into the map, and drop them.

    Done here rather than by letting both key shapes reach ``nest()``: that
    function walks a flat mapping in iteration order, so a ``core.mcp.servers``
    entry arriving after ``core.mcp.servers.x.auth_token`` would overwrite the
    token instead of merging with it. Making the merge explicit makes it
    order-independent, which is the only version of this that is safe.
    """
    prefix = f"{SERVER_MAP_KEY}."
    token_keys = [
        k for k in overrides if k.startswith(prefix) and k.endswith(".auth_token")
    ]
    if not token_keys:
        return overrides
    out = {k: v for k, v in overrides.items() if k not in token_keys}
    servers = out.get(SERVER_MAP_KEY)
    if not isinstance(servers, dict):
        return out
    merged = {name: dict(entry) for name, entry in servers.items() if isinstance(entry, dict)}
    for key in token_keys:
        name = key[len(prefix) : -len(".auth_token")]
        if name in merged:
            merged[name]["auth_token"] = overrides[key]
        # A row whose server is gone is simply dropped: `save` deletes these,
        # and a stale one must never resurrect a server that is not in the map.
    out[SERVER_MAP_KEY] = merged
    return out
```

- [ ] **Step 4: Resolve the choices and route the probe**

`apps/api/app/services/settings_catalog_api.py`, after `full_catalog`:

```python
_CHOICE_SOURCES: dict[str, Callable[[Iterable[str]], list[str]]] = {}


def resolved_catalog(servers: Iterable[str]) -> list[CatalogEntry]:
    """``full_catalog`` with every ``choices_from`` turned into real ``choices``.

    The core catalog is a pure function of the models and cannot know which
    servers exist right now; the web must not decide either, or "what is a
    valid provider" has two answers. So it happens exactly here, once, on the
    way out.
    """
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    keys = sorted(servers)
    sources: dict[str, list[str]] = {
        # Declared for completeness and for sub-project C's agent definitions.
        # Neither provider selector uses them today: those two are enum leaves
        # whose choices already come from the settings Literal, in its own
        # order, and re-deriving them here would only re-sort the dropdown.
        "static_providers": static_provider_ids(),
        "sandbox_providers": sandbox_provider_ids(),
        # The empty string is a real choice: it is how an operator says the
        # generic provider has no server yet.
        "mcp_servers": ["", *keys],
        "agent_roles": ["static", "dynamic", "network", "judge"],
    }
    out: list[CatalogEntry] = []
    for entry in full_catalog():
        if entry.choices_from and entry.choices_from in sources:
            entry = replace(entry, choices=sources[entry.choices_from])
        out.append(entry)
    return out
```

with `from dataclasses import replace` and `from collections.abc import Iterable` imported. `get_schema` (`apps/api/app/api/v1/settings.py:44`) iterates `resolved_catalog(_effective_servers(db))` instead of `full_catalog()`, where:

```python
async def _effective_servers(db: AsyncSession) -> list[str]:
    """Server keys as they stand: the stored map if there is one, else the defaults."""
    stored = await SettingsService(db).load_overrides()
    servers = stored.get("core.mcp.servers")
    if isinstance(servers, dict) and servers:
        return list(servers)
    from maljan.core.config import Settings

    return list(Settings().mcp.servers)
```

and `get_schema` gains `db: AsyncSession = Depends(get_db)`.

`patch_values` validates the map before the service sees it:

```python
    changes = dict(body.changes)
    if "core.mcp.servers" in changes:
        stored = await SettingsService(db).load_overrides()
        try:
            changes["core.mcp.servers"] = validate_server_map(
                changes["core.mcp.servers"],
                stored=stored.get("core.mcp.servers") if isinstance(stored.get("core.mcp.servers"), dict) else None,
            )
        except ServerMapError as exc:
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={"errors": {f"core.mcp.servers.{k}": v for k, v in exc.errors.items()}},
            )
    try:
        res = await SettingsService(db).save(changes, user_id=user.id, ip=_client_ip(request))
```

The MCP probe gets its own route, registered **before** the generic `/test/{probe}` one so the path is unambiguous:

```python
@router.post("/test/mcp", response_model=ProbeResponse)
async def test_mcp_server(
    body: ProbeRequest,
    server: str = Query(..., description="key in mcp.servers"),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Launch one configured MCP server and report the tools it offers.

    Takes staged values so an operator can test a server they have not saved
    yet — the same contract as every other probe, addressed to one key of one
    setting rather than to a set of settings.
    """
    stored = await SettingsService(db).load_overrides()
    result = await run_mcp_probe(server, body.values, stored)
    return ProbeResponse(**vars(result))
```

- [ ] **Step 5: Teach `SettingsService` about runtime-keyed secret rows**

Three additions in `apps/api/app/services/settings_service.py`, and nothing else in that file
changes. `check_keys` is untouched: the synthetic keys never arrive in `changes` — the route sends
one `core.mcp.servers` change and the service derives the rows itself.

`load_overrides` (line 68-83) folds the rows back in before returning:

```python
    async def load_overrides(self) -> dict[str, Any]:
        """Full keys -> plain values; secrets decrypted, or dropped if they cannot be.

        The per-server MCP tokens are stored as their own ``is_secret`` rows
        (see ``server_map``); they are merged back into the ``core.mcp.servers``
        map here, so every caller downstream — the worker's ``Settings``, the
        probes, ``runtime_config`` — sees one map with the tokens in place and
        never has to know the storage was split.
        """
        out: dict[str, Any] = {}
        for row in await self._rows():
            if row.is_secret:
                try:
                    out[row.key] = box.decrypt(str(row.value))
                except box.SecretsUnavailable:
                    logger.warning(
                        "Stored override for %s cannot be decrypted (encryption key "
                        "changed?); the environment value stays in effect.",
                        row.key,
                    )
                    continue
            else:
                out[row.key] = row.value
        return merge_server_secrets(out)
```
Only the last line is new; the loop above it is today's body, repeated here so the insertion
point is unambiguous.

`save` (line 196-250) splits the map before validating it, and writes the token rows itself:

```python
        self.check_keys(changes)
        index = catalog_index()
        current = await self.load_overrides()
        changes = dict(changes)
        tokens: dict[str, str | None] = {}
        if SERVER_MAP_KEY in changes:
            # The map is one non-secret row and the tokens are not in it. Split
            # first so neither validation nor the audit trail ever sees one.
            stored_map = current.get(SERVER_MAP_KEY)
            changes[SERVER_MAP_KEY], tokens = split_server_secrets(
                changes[SERVER_MAP_KEY],
                stored=stored_map if isinstance(stored_map, dict) else None,
            )
            unstorable = [
                server_token_key(name)
                for name, token in tokens.items()
                if token and not box.is_available()
            ]
            if unstorable:
                raise SettingsValidationError(
                    {
                        key: "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
                        for key in unstorable
                    }
                )
        merged = {**current}
        for key, value in changes.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        core = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("core.")}
        api = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("api.")}
        self.validate(core, api)
```

Everything from `merged = {**current}` onwards — the `validate` call above and the row-writing
loop, `commit` and `_audit` that follow it — is today's body, unchanged, operating on
the *cleaned* `changes` — which is what keeps a token out of `before`/`after` and therefore out of
the audit row. The one insertion is immediately before the existing `await self.db.commit()`:

```python
        if SERVER_MAP_KEY in changes:
            await self._save_server_tokens(tokens, set(changes[SERVER_MAP_KEY]))
        await self.db.commit()
```

and the writer itself, beside `save`:

```python
    async def _save_server_tokens(self, tokens: dict[str, str | None], kept: set[str]) -> None:
        """One encrypted row per server that has a token, and none for one that does not.

        Runtime-keyed rows: the catalog is a static list and cannot hold a name
        an operator invents, so these are written here rather than through the
        catalog-driven path in ``save``. They are otherwise ordinary secret
        rows — same Fernet box, same ``is_secret`` flag, same decrypt-or-drop
        behaviour in ``load_overrides`` — so a rotated key degrades them the
        same way it degrades every other secret.

        ``kept`` is the set of servers the new map still holds; a token row for
        a server that is gone is deleted with it, so a re-created server never
        inherits a predecessor's credential.
        """
        rows = {r.key: r for r in await self._rows()}
        prefix = f"{SERVER_MAP_KEY}."
        for key, row in rows.items():
            if not (key.startswith(prefix) and key.endswith(".auth_token")):
                continue
            name = key[len(prefix) : -len(".auth_token")]
            if name not in kept:
                await self.db.delete(row)
        for name, token in tokens.items():
            key = server_token_key(name)
            existing = rows.get(key)
            if not token:
                if existing is not None:
                    await self.db.delete(existing)
                continue
            stored = box.encrypt(token)
            if existing is None:
                self.db.add(RuntimeSetting(key=key, value=stored, is_secret=True))
            else:
                existing.value = stored
                existing.is_secret = True
```

The audit detail for a `core.mcp.servers` change records `before`/`after` from the *cleaned* map,
so no token reaches `_audit` — the split happens before the `before`/`after` dicts are built.

`values` (line 84-163) shows the mask. `core.mcp.servers` is a non-secret entry, so the existing
code returns `row.value` — the cleaned map, with no `auth_token` key at all. One branch replaces
that value with a masked view:

```python
    def _masked_server_map(
        self, stored_map: dict[str, Any], env_servers: dict[str, Any], rows: dict[str, Any]
    ) -> dict[str, Any]:
        """The map as the UI may see it: every token a mask, never a value.

        ``auth_token_source`` rides along beside it for the same reason every
        other row carries ``source``: "set in .env" and "set from the UI" are
        different facts, and an operator deciding whether to type a new token
        needs to know which one they are looking at. The editor sends the mask
        straight back for an unchanged field, and ``split_server_secrets``
        reads that as "leave the row alone".
        """
        out: dict[str, Any] = {}
        for name, entry in stored_map.items():
            shown = dict(entry)
            if server_token_key(name) in rows:
                shown["auth_token"], shown["auth_token_source"] = TOKEN_MASK, "ui"
            else:
                env_entry = env_servers.get(name)
                from_env = bool(
                    env_entry is not None and env_entry.auth_token.get_secret_value()
                )
                shown["auth_token"] = TOKEN_MASK if from_env else ""
                shown["auth_token_source"] = "env" if from_env else "default"
            out[name] = shown
        return out
```

called from `values()` where the non-secret branch assigns `ValueInfo(row.value, ...)` and where the
no-row branch assigns `ValueInfo(shown, ...)`:

```python
            if entry.key == SERVER_MAP_KEY:
                stored_map = row.value if row is not None else env_value
                shown = self._masked_server_map(
                    dict(stored_map or {}), env_core.mcp.servers, rows
                )
                src = "ui" if row is not None else effective_source(
                    overridden=False, env_value=env_value, default_value=entry.default
                )
                out[key] = ValueInfo(
                    shown,
                    None,
                    None,
                    src,
                    row.updated_at if row is not None else None,
                    row.updated_by if row is not None else None,
                )
                continue
```

with `from app.services.server_map import SERVER_MAP_KEY, TOKEN_MASK, merge_server_secrets, server_token_key, split_server_secrets` and `from app.models import RuntimeSetting` (already imported) at the top of the module.

`.env` keeps working unchanged: `MCP__SERVERS__<KEY>__AUTH_TOKEN` is resolved by pydantic-settings
against `MCPConfig.servers`' `dict[str, MCPServerConfig]` annotation, so it reaches
`cfg.mcp.servers[key].auth_token` with no row involved — which is exactly what
`test_an_unset_token_shows_empty_and_a_dot_env_token_shows_env` asserts, and what the `env`
source above reports.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/unit/api tests/api/test_settings_schema_choices.py tests/api/test_settings_routes.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app tests/unit/api && uv run ruff format --check apps/api/app tests/unit/api && \
uv run mypy src/ apps/api/
git add apps/api/app tests/unit/api/test_server_map_validation.py tests/unit/api/test_server_map_secrets.py tests/api/test_settings_schema_choices.py
git commit -m "feat(api): resolve catalog choices server-side, store each server's token as its own secret row, and probe one server by key"
```

---

### Task 15: The web mirrors the DTO and stops carrying its own provider lists

**Files:**
- Modify: `apps/web/src/types/settings.ts:20-43` (`CatalogEntry`), `:56-80` (`ProbeResult`), `apps/web/src/lib/api.ts:502-511` (`testSettingsProbe`, plus two new methods), `apps/web/src/app/(app)/samples/page.tsx:10-11` (the constants are deleted), `:494-522` (the two selects)
- Create: `apps/web/src/app/(app)/samples/useProviderChoices.ts`
- Modify: `apps/web/e2e/mocks.ts:183-330` (the fixture gains the new DTO fields and a `mcp` group), `apps/web/e2e/job-submit-providers.spec.ts`
- Test: `cd apps/web && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`

**Interfaces:**
- Produces:
  ```ts
  // apps/web/src/types/settings.ts
  export type ChoicesFrom = "static_providers" | "sandbox_providers" | "mcp_servers" | "agent_roles";
  export type Editor = "server_map" | "rest_sandbox";
  export interface CatalogEntry { …; choices_from: ChoicesFrom | null; editor: Editor | null }
  export interface ProbeResult { …; tools: string[] | null }
  export interface McpServerEntry { enabled: boolean; transport: string; command: string;
    args: string[]; env: Record<string, string>; cwd: string; env_allow: string[]; url: string;
    auth_token: string; auth_token_source: "ui" | "env" | "default";
    tool_selection: string; use_all_tools: boolean; tools: string[] | null; agents: string[];
    label: string }
  // apps/web/src/lib/api.ts
  testMcpServer(server: string, values: Record<string, unknown>): Promise<ProbeResult>
  previewSandboxMapping(sample: unknown, mapping: Record<string, string>): Promise<MappingPreview>
  // apps/web/src/app/(app)/samples/useProviderChoices.ts
  export function useProviderChoices(): { staticProviders: string[]; sandboxProviders: string[] }
  ```
- Consumes: `GET /api/v1/settings/schema` (Task 14's resolved choices).

- [ ] **Step 1: Add the e2e case first**

In `apps/web/e2e/mocks.ts`, add `choices_from: null, editor: null` to every entry of `MOCK_SETTINGS_SCHEMA`, add `"rest"` to `core.sandbox.provider`'s choices, and append a fourth group (comment: "Task B15/B16: the server map is one leaf with its own editor; its choices come resolved from the API"):

```ts
    {
      key: "mcp",
      title: "Tool servers (MCP)",
      entries: [
        {
          key: "core.mcp.servers", namespace: "core", path: "mcp.servers",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "mcp",
          title: "Tool servers",
          description: "Every MCP server Maljan can attach, keyed by a short name.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "server_map",
        },
        {
          key: "core.static.generic.server", namespace: "core", path: "static.generic.server",
          type: "str", default: "", nullable: false, choices: ["", "network", "threatintel"],
          minimum: null, maximum: null, secret: false, group: "mcp",
          title: "Custom MCP server",
          description: "Which registry entry the generic_mcp static provider drives.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: "mcp_servers", editor: null,
        },
      ],
    },
```

with a `MOCK_SETTINGS_VALUES` row for each (`core.mcp.servers` value: `{ network: { enabled: true, transport: "stdio", command: "python", args: ["network-mcp/server.py"], env: {}, cwd: "network-mcp", env_allow: [], url: "", auth_token: "", auth_token_source: "default", tool_selection: "dynamic", use_all_tools: false, tools: null, agents: ["network"], label: "Network MCP" }, threatintel: { enabled: true, transport: "stdio", command: "python", args: ["threatintel-mcp/server.py"], env: {}, cwd: "threatintel-mcp", env_allow: ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"], url: "", auth_token: "**********", auth_token_source: "env", tool_selection: "dynamic", use_all_tools: false, tools: null, agents: ["judge"], label: "Threat intel MCP" } }`, source `"default"` — the second entry carries a set token so Task 18 can assert the mask is never the value), and a route for the new probe:

```ts
  await page.route("**/api/v1/settings/test/mcp?**", (route) =>
    json(route, { ok: true, latency_ms: 12, detail: "3 tools: open_file, analyze, list_imports",
      models: null, tools: ["open_file", "analyze", "list_imports"] })
  );
```

In `apps/web/e2e/job-submit-providers.spec.ts`:

```ts
  test("the provider selects come from the settings catalog, not from a constant", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();

    const sandbox = page.locator("#sandbox-provider");
    await expect(sandbox.locator("option")).toHaveText([
      "Inherit from settings", "mock", "cape2", "upload", "triage", "rest",
    ]);
    const staticSelect = page.locator("#static-provider");
    await expect(staticSelect.locator("option")).toHaveText([
      "Inherit from settings", "ghidra", "r2", "capa_yara", "generic_mcp", "none",
    ]);
  });
```

- [ ] **Step 2: Run the spec to verify it fails**

Run (after `free -g` shows >= 6 GB and no `next dev` is running): `cd apps/web && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`
Expected: FAIL — the sandbox select has five options; `rest` is missing, because the list is the constant at `samples/page.tsx:11`.

- [ ] **Step 3: Mirror the DTO**

`apps/web/src/types/settings.ts`, in `CatalogEntry` after `order`:

```ts
  /** A choice list the API resolves as it serialises the catalog — registry
   *  ids, or the current tool-server keys. When this is set, `choices` is
   *  already filled in: the web never computes a choice list itself. */
  choices_from: ChoicesFrom | null;
  /** A composite editor renders this leaf instead of the type's widget. */
  editor: Editor | null;
```

and `ProbeResult` gains `tools: string[] | null;` ("the probed server's whole manifest, for the allow-list tick boxes").

`McpServerEntry` is declared in the same file, and it is where the per-server token lives:

```ts
export interface McpServerEntry {
  enabled: boolean;
  transport: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  env_allow: string[];
  url: string;
  /** The mask `"**********"` when a token is set, `""` when it is not — never
   *  the value. Sending the mask back unchanged means "leave the stored token
   *  alone"; sending a new string replaces it; sending `null` clears it. The
   *  token is not a catalog entry of its own, so there is no new column on
   *  `CatalogEntry` and no second request: it rides inside this map value, and
   *  the API splits it back out into its own encrypted row on PATCH. */
  auth_token: string;
  /** Where the effective token comes from, reported the way every other row's
   *  `source` is: a UI-saved secret row, `.env`, or nothing set at all. */
  auth_token_source: "ui" | "env" | "default";
  tool_selection: string;
  use_all_tools: boolean;
  tools: string[] | null;
  agents: string[];
  label: string;
}
```

`apps/web/src/lib/api.ts`, beside `testSettingsProbe`:

```ts
  /** Probe one entry of the tool-server map, staged values included. */
  testMcpServer(server: string, values: Record<string, unknown>) {
    return this.request<ProbeResult>(
      `/api/v1/settings/test/mcp?server=${encodeURIComponent(server)}`,
      { method: "POST", body: JSON.stringify({ values }) }
    );
  }

  /** Run a REST-sandbox mapping against a pasted response. Nothing is stored. */
  previewSandboxMapping(sample: unknown, mapping: Record<string, string>) {
    return this.request<MappingPreview>("/api/v1/settings/sandbox-rest/preview", {
      method: "POST",
      body: JSON.stringify({ sample, mapping }),
    });
  }
```

with `MappingPreview` declared in `types/settings.ts`:

```ts
export interface ChannelPreview {
  matched: number;
  kept: number;
  dropped: number;
  sample_rows: unknown[];
  error: string | null;
}

export interface MappingPreview {
  target_sha256: string;
  channels: Record<string, ChannelPreview>;
}
```

- [ ] **Step 4: Read the choices from the catalog**

```ts
// apps/web/src/app/(app)/samples/useProviderChoices.ts
"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

/**
 * The provider lists the submit dialog offers, read from the settings catalog.
 *
 * They used to be two `as const` arrays in `samples/page.tsx`, which is one
 * more place than there should be for "which providers exist": adding one to
 * the registry left the dialog offering yesterday's list. The catalog already
 * carries them, resolved server-side from the registry itself.
 *
 * A failure here is not worth an error banner on a page about samples: the
 * dialog falls back to offering only "Inherit from settings", which is the
 * safe answer — the job then uses whatever the settings say.
 */
export function useProviderChoices(): {
  staticProviders: string[];
  sandboxProviders: string[];
} {
  const [choices, setChoices] = useState<{ staticProviders: string[]; sandboxProviders: string[] }>(
    { staticProviders: [], sandboxProviders: [] }
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const schema = await api.getSettingsSchema();
        const entries = schema.groups.flatMap((g) => g.entries);
        const find = (key: string) =>
          entries.find((e) => e.key === key)?.choices ?? [];
        if (!cancelled) {
          // eslint-disable-next-line react-hooks/set-state-in-effect
          setChoices({
            staticProviders: find("core.static.provider"),
            sandboxProviders: find("core.sandbox.provider"),
          });
        }
      } catch {
        // Left empty on purpose: see the doc comment above.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return choices;
}
```

`apps/web/src/app/(app)/samples/page.tsx`: delete lines 10-11, call `const { staticProviders, sandboxProviders } = useProviderChoices();` inside `SamplesPageContent`, and replace `STATIC_PROVIDERS.map(...)` / `SANDBOX_PROVIDERS.map(...)` with `staticProviders.map(...)` / `sandboxProviders.map(...)`.

- [ ] **Step 5: Run the spec and the type checks**

Run: `cd apps/web && npx tsc --noEmit && npm run lint && npx playwright test e2e/job-submit-providers.spec.ts --project=chromium`
Expected: PASS; lint shows the 10 pre-existing warnings and no new ones.

- [ ] **Step 6: Commit**

```bash
git add apps/web/src/types/settings.ts apps/web/src/lib/api.ts "apps/web/src/app/(app)/samples" apps/web/e2e/mocks.ts apps/web/e2e/job-submit-providers.spec.ts
git commit -m "feat(web): read the provider choices from the settings catalog instead of a local constant"
```

---

### Task 16: The server-map editor

**Files:**
- Create: `apps/web/src/app/(app)/settings/configuration/ServerMapEditor.tsx`
- Modify: `apps/web/src/app/(app)/settings/configuration/FieldRow.tsx:78-90` (the widget slot), `widgets.tsx:389-407` (`Widget` is untouched; the editor is chosen above it)
- Test: Task 18's spec, whose third case fills a token and asserts it never comes back; this task runs `npx tsc --noEmit && npm run lint`

**Interfaces:**
- Produces:
  ```tsx
  // ServerMapEditor.tsx
  export const EMPTY_SERVER: McpServerEntry;
  export default function ServerMapEditor(p: {
    entry: CatalogEntry;
    current: SettingValue | undefined;
    staged: unknown;
    onChange: (value: Record<string, McpServerEntry>) => void;
  }): JSX.Element
  ```
- Consumes: `api.testMcpServer`, `McpServerEntry`, `ProbeResult.tools`.

- [ ] **Step 1: Write the editor**

```tsx
// apps/web/src/app/(app)/settings/configuration/ServerMapEditor.tsx
"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, McpServerEntry, ProbeResult, SettingValue } from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Built-ins are re-seeded by the settings model, so they disable rather than delete. */
const BUILTIN = new Set(["network", "threatintel"]);
const ROLES = ["static", "dynamic", "network", "judge"] as const;
const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** What a set token looks like from outside; identical to the API's mask. */
const TOKEN_MASK = "**********";

const TOKEN_SOURCE_LABEL: Record<string, string> = {
  ui: "set from the UI",
  env: "set in .env",
  default: "not set",
};

export const EMPTY_SERVER: McpServerEntry = {
  enabled: true,
  transport: "stdio",
  command: "",
  args: [],
  env: {},
  cwd: "",
  env_allow: [],
  url: "",
  auth_token: "",
  auth_token_source: "default",
  tool_selection: "dynamic",
  use_all_tools: false,
  // A new server exposes nothing until its tools are ticked off a probe.
  tools: [],
  agents: [],
  label: "",
};

/**
 * The whole `core.mcp.servers` leaf, as a list of cards.
 *
 * One staged value for the whole map, not one per card: the PATCH body is the
 * full dict, so the apply bar, the hidden-dirty count and the reset behaviour
 * from sub-project A all apply unchanged, and a half-applied map — three
 * servers saved and the fourth rejected — cannot happen.
 *
 * The token field rides inside that same dict and behaves the way `SecretWidget`
 * behaves everywhere else: what arrives is the mask (or an empty string), the
 * input is a password field that only appears once the operator asks to edit,
 * an untouched card sends the mask straight back and the API reads that as
 * "leave the stored row alone", and "Clear" stages `null`. The value the
 * operator types exists only in this component's state until it is applied;
 * it never comes back from a GET.
 */
export default function ServerMapEditor({
  entry,
  current,
  staged,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  onChange: (value: Record<string, McpServerEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, McpServerEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  /** Which cards have their token field open for editing. A card is closed
   *  until the operator asks, so a masked value cannot be typed over by
   *  accident and cannot be read back by looking at the form. */
  const [editingToken, setEditingToken] = useState<Record<string, boolean>>({});

  const put = (key: string, next: Partial<McpServerEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const add = () => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("a server with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    onChange({ ...value, [key]: { ...EMPTY_SERVER } });
  };

  const remove = (key: string) => {
    if (BUILTIN.has(key)) {
      put(key, { enabled: false });
      return;
    }
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const probe = async (key: string) => {
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.testMcpServer(key, { "core.mcp.servers": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: { ok: false, latency_ms: 0, detail: getErrorMessage(e), models: null, tools: null },
      }));
    }
  };

  return (
    <div className="space-y-3" data-testid="server-map-editor">
      {Object.entries(value).map(([key, server]) => {
        const result = probes[key];
        const manifest = result && result !== "running" ? result.tools : null;
        const allowed = server.tools;
        return (
          <div key={key} className="border border-border rounded p-3" data-server={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">{key}</span>
              <div className="flex items-center gap-3">
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} enabled`}
                    checked={server.enabled}
                    onChange={(e) => put(key, { enabled: e.target.checked })}
                  />
                  enabled
                </label>
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void probe(key)}
                >
                  Test
                </button>
                <button
                  type="button"
                  className="text-xs text-text-secondary"
                  onClick={() => remove(key)}
                >
                  {BUILTIN.has(key) ? "Disable" : "Remove"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${key} label`}
                  value={server.label}
                  onChange={(e) => put(key, { label: e.target.value })}
                />
              </label>
              <label className="block">
                <span className="text-text-muted">Transport</span>
                <select
                  className={input}
                  aria-label={`${key} transport`}
                  value={server.transport}
                  onChange={(e) => put(key, { transport: e.target.value })}
                >
                  {["stdio", "http", "streamable-http", "sse"].map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </label>
              {server.transport === "stdio" ? (
                <>
                  <label className="block">
                    <span className="text-text-muted">Command</span>
                    <input
                      className={input}
                      aria-label={`${key} command`}
                      value={server.command}
                      onChange={(e) => put(key, { command: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Arguments (one per line)</span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${key} args`}
                      value={server.args.join("\n")}
                      onChange={(e) =>
                        put(key, { args: e.target.value.split("\n").filter((a) => a !== "") })
                      }
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Working directory</span>
                    <input
                      className={input}
                      aria-label={`${key} cwd`}
                      value={server.cwd}
                      onChange={(e) => put(key, { cwd: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">
                      Environment names passed through (one per line)
                    </span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${key} env allow`}
                      value={server.env_allow.join("\n")}
                      onChange={(e) =>
                        put(key, { env_allow: e.target.value.split("\n").filter((a) => a !== "") })
                      }
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="block">
                    <span className="text-text-muted">URL</span>
                    <input
                      className={input}
                      aria-label={`${key} url`}
                      value={server.url}
                      onChange={(e) => put(key, { url: e.target.value })}
                    />
                  </label>
                  <div className="block">
                    <span className="text-text-muted">Auth token</span>
                    {editingToken[key] ? (
                      <input
                        type="password"
                        className={input}
                        aria-label={`${key} auth token`}
                        autoComplete="new-password"
                        value={server.auth_token === TOKEN_MASK ? "" : server.auth_token}
                        onChange={(e) => put(key, { auth_token: e.target.value })}
                      />
                    ) : (
                      <p className="text-text-secondary py-1.5" data-token-state={key}>
                        {TOKEN_SOURCE_LABEL[server.auth_token_source] ?? "not set"}
                      </p>
                    )}
                    <div className="flex gap-3 mt-1">
                      <button
                        type="button"
                        className="text-[11px] text-accent-strong"
                        onClick={() => {
                          if (editingToken[key]) {
                            // Closing the field abandons whatever was typed and
                            // puts the mask back, which the API reads as
                            // "leave the stored token alone".
                            put(key, {
                              auth_token:
                                server.auth_token_source === "default" ? "" : TOKEN_MASK,
                            });
                          }
                          setEditingToken((t) => ({ ...t, [key]: !t[key] }));
                        }}
                      >
                        {editingToken[key] ? "Keep current" : "Replace token"}
                      </button>
                      {server.auth_token_source !== "default" && (
                        <button
                          type="button"
                          className="text-[11px] text-text-secondary"
                          aria-label={`${key} clear auth token`}
                          onClick={() => {
                            // `null` is how every secret in this project is
                            // cleared: the API deletes the row rather than
                            // storing an empty one.
                            put(key, { auth_token: null as unknown as string });
                            setEditingToken((t) => ({ ...t, [key]: false }));
                          }}
                        >
                          Clear
                        </button>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>

            <fieldset className="mt-2">
              <legend className="text-xs text-text-muted">Agents</legend>
              <div className="flex gap-3 flex-wrap">
                {ROLES.map((role) => (
                  <label key={role} className="text-xs text-text-secondary flex items-center gap-1">
                    <input
                      type="checkbox"
                      aria-label={`${key} agent ${role}`}
                      checked={server.agents.includes(role)}
                      onChange={(e) =>
                        put(key, {
                          agents: e.target.checked
                            ? [...server.agents, role]
                            : server.agents.filter((r) => r !== role),
                        })
                      }
                    />
                    {role}
                  </label>
                ))}
              </div>
            </fieldset>

            {result === "running" && (
              <p className="text-[11px] text-text-muted mt-2">testing…</p>
            )}
            {result && result !== "running" && (
              <p
                className={`text-[11px] mt-2 ${result.ok ? "text-status-green" : "text-status-red"}`}
                role="status"
              >
                {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
              </p>
            )}
            {manifest && manifest.length > 0 && (
              <fieldset className="mt-2">
                <legend className="text-xs text-text-muted">
                  Tools the model may call ({allowed === null ? "all" : allowed.length} of{" "}
                  {manifest.length})
                </legend>
                <div className="flex gap-3 flex-wrap">
                  {manifest.map((tool) => (
                    <label
                      key={tool}
                      className="text-xs text-text-secondary flex items-center gap-1"
                    >
                      <input
                        type="checkbox"
                        aria-label={`${key} tool ${tool}`}
                        checked={allowed === null || allowed.includes(tool)}
                        onChange={(e) => {
                          // `null` means "every tool", which only the built-ins
                          // start with. The first tick turns that into an
                          // explicit list, so a later server-side change to the
                          // manifest cannot silently widen what the model sees.
                          const base = allowed === null ? manifest : allowed;
                          put(key, {
                            tools: e.target.checked
                              ? [...base, tool]
                              : base.filter((t) => t !== tool),
                          });
                        }}
                      />
                      {tool}
                    </label>
                  ))}
                </div>
              </fieldset>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new server name"
          aria-label="new server name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={add}>
          Add server
        </button>
      </div>
      {keyError && (
        <p className="text-[11px] text-status-red" role="alert">
          {keyError}
        </p>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Route the leaf to it**

`FieldRow.tsx`, replacing the `<Widget … />` call at lines 82-89:

```tsx
          {entry.editor === "server_map" ? (
            <ServerMapEditor
              entry={entry}
              current={current}
              staged={staged}
              onChange={onChange}
            />
          ) : (
            <Widget
              entry={entry}
              current={current}
              staged={staged}
              onChange={onChange}
              onUnstage={onUnstage}
              models={models}
            />
          )}
```

`widgets.tsx` is not touched: `EnumWidget` and every other widget behave exactly as they did, and a leaf without an `editor` still reaches `Widget` by the same path.

- [ ] **Step 3: Type-check and lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: clean; 10 pre-existing warnings, none new.

- [ ] **Step 4: Commit**

```bash
git add "apps/web/src/app/(app)/settings/configuration/ServerMapEditor.tsx" "apps/web/src/app/(app)/settings/configuration/FieldRow.tsx"
git commit -m "feat(web): edit the tool-server registry as cards, with a probe that fills the allow-list"
```

---

### Task 17: The REST sandbox editor and its mapping preview

**Files:**
- Create: `apps/web/src/app/(app)/settings/configuration/RestSandboxEditor.tsx`
- Modify: `apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx:240-256` (the group's rows)
- Test: covered by Task 18's spec; this task runs `npx tsc --noEmit && npm run lint`

**Interfaces:**
- Produces:
  ```tsx
  export default function RestSandboxEditor(p: {
    entries: CatalogEntry[];
    values: Record<string, SettingValue>;
    pending: Record<string, unknown>;
    errors: Record<string, string>;
    onChange: (key: string, value: unknown) => void;
    onUnstage: (key: string) => void;
    onReset: (key: string) => void;
  }): JSX.Element
  ```
- Consumes: `api.previewSandboxMapping`, `MappingPreview`, `FieldRow`.

- [ ] **Step 1: Write the editor**

```tsx
// apps/web/src/app/(app)/settings/configuration/RestSandboxEditor.tsx
"use client";

import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, MappingPreview, SettingValue } from "@/types/settings";
import FieldRow from "./FieldRow";

const SECTIONS: { title: string; prefix: string }[] = [
  { title: "Connection", prefix: "core.sandbox.rest.auth." },
  { title: "Submit", prefix: "core.sandbox.rest.submit." },
  { title: "Status", prefix: "core.sandbox.rest.status." },
  { title: "Report", prefix: "core.sandbox.rest.report." },
];
const MAPPING_PREFIX = "core.sandbox.rest.mapping.";

/**
 * The `sandbox.rest.*` leaves, grouped, with a mapping table that can be tried.
 *
 * Every field is still an ordinary catalog leaf rendered by `FieldRow`, so
 * staging, per-key reset and `.env` export work exactly as they do everywhere
 * else. What this adds is arrangement — four fieldsets instead of thirty flat
 * rows — and the preview: paste one of the sandbox's real responses, press the
 * button, and see per channel how many rows each JSONPath selected and how
 * many survived. That answer used to cost a detonation.
 */
export default function RestSandboxEditor({
  entries,
  values,
  pending,
  errors,
  onChange,
  onUnstage,
  onReset,
}: {
  entries: CatalogEntry[];
  values: Record<string, SettingValue>;
  pending: Record<string, unknown>;
  errors: Record<string, string>;
  onChange: (key: string, value: unknown) => void;
  onUnstage: (key: string) => void;
  onReset: (key: string) => void;
}) {
  const [sample, setSample] = useState("");
  const [preview, setPreview] = useState<MappingPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const mappingEntries = useMemo(
    () => entries.filter((e) => e.key.startsWith(MAPPING_PREFIX)),
    [entries]
  );
  const plain = useMemo(
    () =>
      entries.filter(
        (e) => !e.key.startsWith(MAPPING_PREFIX) && !SECTIONS.some((s) => e.key.startsWith(s.prefix))
      ),
    [entries]
  );

  const effective = (key: string): unknown =>
    key in pending ? pending[key] : values[key]?.value;

  const runPreview = async () => {
    setRunning(true);
    setPreviewError(null);
    try {
      const parsed = JSON.parse(sample);
      const mapping: Record<string, string> = {};
      for (const e of mappingEntries) {
        const name = e.key.slice(MAPPING_PREFIX.length);
        const value = effective(e.key);
        if (typeof value === "string" && value) mapping[name] = value;
      }
      setPreview(await api.previewSandboxMapping(parsed, mapping));
    } catch (e) {
      setPreview(null);
      setPreviewError(
        e instanceof SyntaxError ? "the pasted text is not valid JSON" : getErrorMessage(e)
      );
    } finally {
      setRunning(false);
    }
  };

  const row = (entry: CatalogEntry) => (
    <FieldRow
      key={entry.key}
      entry={entry}
      current={values[entry.key]}
      staged={pending[entry.key]}
      error={errors[entry.key]}
      onChange={(v) => onChange(entry.key, v)}
      onUnstage={() => onUnstage(entry.key)}
      onReset={() => onReset(entry.key)}
    />
  );

  return (
    <div data-testid="rest-sandbox-editor">
      {plain.map(row)}
      {SECTIONS.map((section) => {
        const rows = entries.filter((e) => e.key.startsWith(section.prefix));
        if (rows.length === 0) return null;
        return (
          <fieldset key={section.prefix} className="mt-4">
            <legend className="text-xs font-medium text-text-primary uppercase tracking-wider">
              {section.title}
            </legend>
            {rows.map(row)}
          </fieldset>
        );
      })}

      {mappingEntries.length > 0 && (
        <fieldset className="mt-4">
          <legend className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Report mapping
          </legend>
          <table className="w-full text-xs mt-2">
            <thead>
              <tr className="border-b border-border text-text-muted">
                <th className="text-left font-normal py-1">Channel</th>
                <th className="text-left font-normal py-1">JSONPath</th>
                <th className="text-left font-normal py-1 w-40">Matched / kept / dropped</th>
              </tr>
            </thead>
            <tbody>
              {mappingEntries.map((entry) => {
                const name = entry.key.slice(MAPPING_PREFIX.length);
                const stats = preview?.channels[name];
                return (
                  <tr key={entry.key} className="border-b border-border align-top">
                    <td className="py-1 text-text-secondary">{name}</td>
                    <td className="py-1">
                      <input
                        className="w-full bg-bg-deep border border-border rounded px-2 py-1 font-mono text-text-primary"
                        aria-label={entry.title}
                        value={String(effective(entry.key) ?? "")}
                        onChange={(e) => onChange(entry.key, e.target.value)}
                      />
                    </td>
                    <td className="py-1 text-text-muted" data-channel={name}>
                      {stats
                        ? stats.error
                          ? stats.error
                          : `${stats.matched} / ${stats.kept} / ${stats.dropped}`
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <label htmlFor="rest-sample" className="block text-xs text-text-muted mt-3">
            Paste a sample response
          </label>
          <textarea
            id="rest-sample"
            rows={5}
            className="w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-xs font-mono text-text-primary"
            value={sample}
            onChange={(e) => setSample(e.target.value)}
          />
          <div className="flex items-center gap-3 mt-2">
            <button
              type="button"
              className="text-xs text-accent-strong disabled:opacity-50"
              disabled={running || sample.trim() === ""}
              onClick={() => void runPreview()}
            >
              Preview mapping
            </button>
            {preview && (
              <span className="text-[11px] text-text-secondary" role="status">
                sample hash: {preview.target_sha256 || "not matched"}
              </span>
            )}
            {previewError && (
              <span className="text-[11px] text-status-red" role="alert">
                {previewError}
              </span>
            )}
          </div>
        </fieldset>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Route the group's REST rows to it**

In `ConfigurationTab.tsx`'s render of one group (line 246-256), the `g.entries.map(...)` becomes:

```tsx
                {(() => {
                  const rest = g.entries.filter((e) => e.editor === "rest_sandbox");
                  const others = g.entries.filter((e) => e.editor !== "rest_sandbox");
                  return (
                    <>
                      {others.map((e) => (
                        <FieldRow
                          key={e.key}
                          entry={e}
                          current={s.values[e.key]}
                          staged={s.pending[e.key]}
                          error={s.errors[e.key]}
                          models={e.probe === "llm" ? models : undefined}
                          onChange={(v) => s.stage(e.key, v)}
                          onUnstage={() => s.unstage(e.key)}
                          onReset={() => void s.reset(e.key)}
                        />
                      ))}
                      {rest.length > 0 && (
                        <RestSandboxEditor
                          entries={rest}
                          values={s.values}
                          pending={s.pending}
                          errors={s.errors}
                          onChange={s.stage}
                          onUnstage={s.unstage}
                          onReset={(k) => void s.reset(k)}
                        />
                      )}
                    </>
                  );
                })()}
```

The REST rows keep their `applies_when` filtering, because `g.entries` is already the visible list; a sandbox provider that is not `rest` leaves `rest` empty and the editor is not rendered at all.

- [ ] **Step 3: Type-check and lint**

Run: `cd apps/web && npx tsc --noEmit && npm run lint`
Expected: clean; 10 pre-existing warnings, none new.

- [ ] **Step 4: Commit**

```bash
git add "apps/web/src/app/(app)/settings/configuration/RestSandboxEditor.tsx" "apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx"
git commit -m "feat(web): group the REST sandbox settings and try a mapping against a pasted response"
```

---

### Task 18: The end-to-end spec for both editors

**Files:**
- Create: `apps/web/e2e/settings-servers.spec.ts`
- Modify: `apps/web/e2e/mocks.ts` (a `sandbox.rest.*` fixture group and the preview route)
- Test: `cd apps/web && npx playwright test e2e/settings-servers.spec.ts --project=chromium`

**Interfaces:**
- Consumes: `MOCK_SETTINGS_SCHEMA`, `MOCK_SETTINGS_VALUES`, the `test/mcp` route (Task 15), the new preview route.

- [ ] **Step 1: Extend the fixture**

In `apps/web/e2e/mocks.ts`, add to the `sandbox` group four `rest` entries (`core.sandbox.rest.base_url`, `core.sandbox.rest.report.format`, `core.sandbox.rest.mapping.processes`, `core.sandbox.rest.mapping.dns`), each with `editor: "rest_sandbox"`, `choices_from: null`, `applies_when: { "core.sandbox.provider": ["rest"] }` — and for the two mapping rows `applies_when: { "core.sandbox.provider": ["rest"], "core.sandbox.rest.report.format": ["generic"] }` — plus `MOCK_SETTINGS_VALUES` rows for all four, and the preview route:

```ts
  await page.route("**/api/v1/settings/sandbox-rest/preview", (route) =>
    json(route, {
      target_sha256: "ab",
      channels: {
        processes: { matched: 2, kept: 1, dropped: 1, sample_rows: [{ pid: 1 }], error: null },
        dns: { matched: 0, kept: 0, dropped: 0, sample_rows: [], error: null },
      },
    })
  );
```

- [ ] **Step 2: Write the spec**

```ts
// apps/web/e2e/settings-servers.spec.ts
import { expect, test } from "./fixtures";

test.describe("tool servers and the REST sandbox", () => {
  test("a new server is added, probed, narrowed to two tools and bound to static", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Add server" }).click();
    const card = page.locator('[data-server="r2custom"]');
    await expect(card).toBeVisible();

    await card.getByLabel("r2custom command").fill("r2mcp");
    await card.getByRole("button", { name: "Test" }).click();
    await expect(card.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();

    // Every tool arrives ticked; untick one so the allow-list is explicit.
    await card.getByLabel("r2custom tool list_imports").uncheck();
    await card.getByLabel("r2custom agent static").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as { changes: Record<string, Record<string, {
      tools: string[]; agents: string[]; command: string }>> };
    const sent = body.changes["core.mcp.servers"].r2custom;
    expect(sent.command).toBe("r2mcp");
    expect(sent.tools).toEqual(["open_file", "analyze"]);
    expect(sent.agents).toEqual(["static"]);
  });

  test("a built-in offers disable rather than remove, and stays in the map", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    const network = page.locator('[data-server="network"]');
    await expect(network.getByRole("button", { name: "Disable" })).toBeVisible();
    await expect(network.getByRole("button", { name: "Remove" })).toHaveCount(0);

    await network.getByRole("button", { name: "Disable" }).click();
    await expect(network).toBeVisible();
    await expect(network.getByLabel("network enabled")).not.toBeChecked();
    await expect(page.getByText("1 change pending")).toBeVisible();
  });

  test("a token is typed once, never read back, and an untouched one stays untouched", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    // The fixture's `threatintel` entry arrives with a token set in .env: the
    // page may say so, but must never carry the value.
    const intel = page.locator('[data-server="threatintel"]');
    await intel.getByLabel("threatintel transport").selectOption("http");
    await expect(intel.locator('[data-token-state="threatintel"]')).toHaveText("set in .env");
    await expect(page.getByLabel("threatintel auth token")).toHaveCount(0);

    const custom = page.locator('[data-server="network"]');
    await custom.getByLabel("network transport").selectOption("http");
    await custom.getByRole("button", { name: "Replace token" }).click();
    await custom.getByLabel("network auth token").fill("s3cr3t");

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { auth_token: string }>>;
    };
    const sent = body.changes["core.mcp.servers"];
    expect(sent.network.auth_token).toBe("s3cr3t");
    // The card nobody edited sends the mask back, which the API reads as
    // "leave the stored row alone" — not as a token of ten asterisks.
    expect(sent.threatintel.auth_token).toBe("**********");

    // Nothing on the page renders the typed value after it is applied.
    await expect(page.getByText("s3cr3t")).toHaveCount(0);
  });

  test("the REST editor appears with the provider and its preview counts rows", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();

    await expect(page.getByTestId("rest-sandbox-editor")).toHaveCount(0);
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");
    const editor = page.getByTestId("rest-sandbox-editor");
    await expect(editor).toBeVisible();
    await expect(editor.getByRole("button", { name: "Preview mapping" })).toBeDisabled();

    await editor.getByLabel("Mapping: processes").fill("$.procs[*]");
    await page.getByLabel("Paste a sample response").fill('{"procs": [{"pid": 1}, {}]}');
    await editor.getByRole("button", { name: "Preview mapping" }).click();

    await expect(editor.locator('[data-channel="processes"]')).toHaveText("2 / 1 / 1");
    await expect(editor.getByText("sample hash: ab")).toBeVisible();
  });

  test("a mapping row is hidden when the report format is not generic", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");

    await expect(page.getByLabel("Mapping: processes")).toBeVisible();
    await page.locator("#setting-core\\.sandbox\\.rest\\.report\\.format select").selectOption("cape2");
    await expect(page.getByLabel("Mapping: processes")).toHaveCount(0);
  });
});
```

- [ ] **Step 3: Run the spec**

Run (after `free -g` shows >= 6 GB and no `next dev` is running): `cd apps/web && npx playwright test e2e/settings-servers.spec.ts --project=chromium`
Expected: PASS (4 tests). A failure here is a real defect in Task 16 or 17, not a fixture to loosen.

- [ ] **Step 4: Commit**

```bash
git add apps/web/e2e/settings-servers.spec.ts apps/web/e2e/mocks.ts
git commit -m "test(web): add a server, narrow its tools, bind it, and preview a REST mapping"
```

---

### Task 19: `rest` reaches the job schema, and the parity test says so

**Files:**
- Modify: `apps/api/app/schemas/job.py:26-30` (the two literals), `apps/api/app/worker/analysis_worker.py:58-65` (`build_job_settings` is unchanged; only the comment moves)
- Test: `tests/api/test_job_provider_overrides.py` (modify — the existing parity module gains three cases)

**Interfaces:**
- Produces: `_KnownJobConfig.sandbox_provider: Literal["mock", "cape2", "upload", "triage", "rest"] | None`
- Consumes: `maljan.providers.registry.{static_provider_ids, sandbox_provider_ids}`, `maljan.core.config.{StaticConfig, SandboxConfig}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/api/test_job_provider_overrides.py`, which already carries `_literal_choices`
and the `<=` parity assertion; these tighten it to equality across all three places and add the
`rest` case:

```python
def test_the_ids_agree_exactly_in_all_three_places():
    """A provider id exists in the registry, the settings model and this schema.

    Two of the three agreeing is how the UI ends up offering a choice that
    422s at submit time, so the assertion is equality rather than containment.
    """
    from typing import get_args

    from maljan.core.config import SandboxConfig, StaticConfig
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    static_settings = set(get_args(StaticConfig.model_fields["provider"].annotation))
    sandbox_settings = set(get_args(SandboxConfig.model_fields["provider"].annotation))
    static_job = set(_literal_choices(_KnownJobConfig.model_fields["static_provider"].annotation))
    sandbox_job = set(_literal_choices(_KnownJobConfig.model_fields["sandbox_provider"].annotation))

    assert set(static_provider_ids()) == static_settings == static_job
    assert set(sandbox_provider_ids()) == sandbox_settings == sandbox_job


def test_the_rest_sandbox_is_an_accepted_per_job_override():
    from typing import get_args

    from maljan.core.config import SandboxConfig

    assert "rest" in get_args(SandboxConfig.model_fields["provider"].annotation)
    assert "rest" in _literal_choices(
        _KnownJobConfig.model_fields["sandbox_provider"].annotation
    )
    JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_provider": "rest"})


def test_a_rest_job_override_reaches_the_settings():
    from app.worker.analysis_worker import build_job_settings

    cfg = build_job_settings({}, {"sandbox_provider": "rest"})
    assert cfg.sandbox.provider == "rest"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/api/test_job_provider_overrides.py -q`
Expected: FAIL — the sandbox literal lacks `rest`, so the equality assertion and the `rest` case both fail.

- [ ] **Step 3: Write the implementation**

`apps/api/app/schemas/job.py:28`:

```python
    # Sandbox provider for this job; repeats SandboxConfig.provider's choices.
    sandbox_provider: Literal["mock", "cape2", "upload", "triage", "rest"] | None = None
```

`build_job_settings` needs no change: it folds `sandbox_provider` into `merged["sandbox.provider"]` and the model validates the value. Add one sentence to its docstring naming the parity test as the thing that keeps the literal honest.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/api/test_job_provider_overrides.py tests/providers/test_registry.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app tests/unit/api && uv run ruff format --check apps/api/app tests/unit/api && \
uv run mypy src/ apps/api/
git add apps/api/app/schemas/job.py apps/api/app/worker/analysis_worker.py tests/api/test_job_provider_overrides.py
git commit -m "feat(api): accept the rest sandbox as a per-job override, and pin the three id lists together"
```

---

### Task 20: The security invariants, stated as tests

**Files:**
- Create: `tests/servers/test_server_security.py`
- Modify: `apps/api/app/worker/analysis_worker.py:40` (`_SECRET_PATHS` gains the nested server tokens)
- Test: `tests/servers/test_server_security.py`

**Interfaces:**
- Consumes: `ServerHandle`, `child_env`, `settings_snapshot`, `public_snapshot`, `split_server_secrets`, `preview_mapping`.
- Produces: nothing new; this task pins behaviour the earlier tasks built.

Five of the spec's §8.7 invariants already have a test: the `cwd` rule
(`tests/servers/test_server_registry.py::test_a_cwd_outside_the_repository_is_refused`),
the probe timeout kill (`tests/unit/api/test_mcp_probe.py::test_a_hanging_server_is_killed_and_reported`),
the admin gate and the 4 MiB cap (`tests/unit/api/test_mapping_preview.py`). This task adds the
two that do not, and makes the set findable in one module.

- [ ] **Step 1: Write the failing test**

```python
# tests/servers/test_server_security.py
"""What a tool server may see, and what may never leave the process.

The set of guarantees the trust-boundary paragraph in the README makes. Each
one is small; together they are the reason connecting a third party's MCP
server to a malware pipeline is a considered act rather than a reckless one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.agents.subprocess_env import child_env
from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.servers import ServerHandle


def test_a_server_token_never_appears_in_a_run_summary():
    from app.worker.analysis_worker import settings_snapshot

    cfg = Settings(_env_file=None)
    cfg.mcp.servers["custom"] = MCPServerConfig(
        enabled=True, transport="http", url="https://h", auth_token="s3cr3t"
    )
    cfg.sandbox.rest.auth.token = "r3st"
    snap = json.dumps(settings_snapshot(cfg))
    assert "s3cr3t" not in snap and "r3st" not in snap


def test_a_server_token_never_appears_in_a_repr_or_a_log_line(caplog):
    server = MCPServerConfig(enabled=True, transport="http", url="https://h", auth_token="s3cr3t")
    handle = ServerHandle("custom", server)
    assert "s3cr3t" not in repr(server)
    assert "s3cr3t" not in repr(handle.config)
    with caplog.at_level("DEBUG"):
        handle.close()
    assert "s3cr3t" not in caplog.text


def test_a_child_sees_the_base_keys_plus_only_the_names_it_was_allowed():
    source = {
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "VIRUSTOTAL_API_KEY": "vt",
        "SETTINGS_ENCRYPTION_KEY": "no",
        "DATABASE_URL": "no",
        "OPENAI_API_KEY": "no",
    }
    env = child_env({"MY": "1"}, allow=("VIRUSTOTAL_API_KEY",), source=source)
    assert env["VIRUSTOTAL_API_KEY"] == "vt" and env["MY"] == "1"
    assert "SETTINGS_ENCRYPTION_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "OPENAI_API_KEY" not in env


def test_a_server_is_launched_with_an_argv_list_and_never_through_a_shell(monkeypatch):
    seen: dict[str, object] = {}

    class _Params:
        def __init__(self, command, args, env, cwd=None):
            seen.update({"command": command, "args": args, "env": env, "cwd": cwd})

    monkeypatch.setattr("mcp.StdioServerParameters", _Params)
    monkeypatch.setattr("maljan.providers.servers._run_async", lambda coro, label: None)

    class _Toolkit:
        def __init__(self, *a, **k):
            pass

        async def initialize(self):
            return None

        def get_tools(self):
            return []

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _Toolkit)
    handle = ServerHandle(
        "x", MCPServerConfig(enabled=True, command="mcp", args=["--flag", "a b; rm -rf /"])
    )
    handle.open("job-1")
    assert isinstance(seen["args"], list)
    assert seen["args"][-1] == "a b; rm -rf /", "an argument is data, never shell syntax"
    assert "shell" not in seen


def test_an_absolute_cwd_must_exist(tmp_path):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd=str(tmp_path)))
    # An existing absolute directory is allowed; a missing one is not.
    missing = ServerHandle(
        "y", MCPServerConfig(enabled=True, command="mcp", cwd=str(tmp_path / "nope"))
    )
    assert handle._resolve_cwd() == str(Path(tmp_path).resolve())
    with pytest.raises(ProviderConfigurationError):
        missing._resolve_cwd()


def test_a_server_token_never_lands_in_the_map_row_it_arrived_in():
    """The map is one non-secret JSONB row; the token goes to its own encrypted one."""
    from app.services.server_map import split_server_secrets

    cleaned, tokens = split_server_secrets(
        {"x": {"enabled": True, "transport": "http", "url": "https://h", "auth_token": "s3cr3t"}}
    )
    assert "s3cr3t" not in str(cleaned)
    assert "auth_token" not in cleaned["x"]
    assert tokens == {"x": "s3cr3t"}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/servers/test_server_security.py -q`
Expected: FAIL — `test_a_server_token_never_appears_in_a_run_summary` finds `s3cr3t` in the snapshot, because `_SECRET_PATHS` is built from catalog leaves and `mcp.servers` is one `json` leaf whose nested tokens are not in that list.

- [ ] **Step 3: Redact the nested tokens**

`SecretStr` already dumps as `**********` under `model_dump(mode="json")`, which is what `public_snapshot` walks — so the failure above is only for a token that reached the map as a plain string through a stored override. `apps/api/app/worker/analysis_worker.py:40`:

```python
# Catalog leaves that are secrets, plus the tokens nested inside leaves the
# catalog treats as one JSON document. ``mcp.servers`` is one such leaf: its
# per-server ``auth_token`` is a SecretStr in the model and masks itself, but
# a value that arrived as a stored override is a plain string until validation
# rebuilds it, and a run summary is written from whatever is in effect.
_SECRET_PATHS = [e.path for e in core_catalog() if e.secret] + [
    f"mcp.servers.{name}.auth_token" for name in get_settings().mcp.servers
]
```

Building that at import time would freeze the server list, so make it a function instead and call it from `settings_snapshot`:

```python
def _secret_paths(core_settings: _CoreSettings) -> list[str]:
    return [e.path for e in core_catalog() if e.secret] + [
        f"mcp.servers.{name}.auth_token" for name in core_settings.mcp.servers
    ]


def settings_snapshot(
    core_settings: _CoreSettings, overridden_keys: Iterable[str] | None = None
) -> dict[str, Any]:
    snap: dict[str, Any] = public_snapshot(core_settings, _secret_paths(core_settings))
    snap["overridden_keys"] = sorted(overridden_keys or [])
    return snap
```

Keep `_SECRET_PATHS` as `_SECRET_PATHS = [e.path for e in core_catalog() if e.secret]` for its other reader (the worker's redaction list) and have `_secret_paths` extend it.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/servers tests/unit/api/test_mcp_probe.py tests/unit/api/test_mapping_preview.py -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app/worker/analysis_worker.py tests/servers && \
uv run ruff format --check apps/api/app/worker/analysis_worker.py tests/servers && \
uv run mypy src/ apps/api/
git add apps/api/app/worker/analysis_worker.py tests/servers/test_server_security.py
git commit -m "test(security): pin what a tool server may see and what may never leave the process"
```

---

### Task 21: The documentation an operator reads before connecting a stranger's server

**Files:**
- Modify: `README.md:180-200` (the provider section), `README.md:505-520` (the settings paragraph), `.env.example:222-276` (the static provider block), `:280-330` (the sandbox block)
- Test: `uv run pytest tests/unit/core/test_env_example.py -q` where that test exists; otherwise the check is the `grep` in Step 4
- Verify: `docker/docker-compose.yml` needs no change and this task proves it

**Interfaces:**
- Consumes: nothing. This task adds no code.

- [ ] **Step 1: Rewrite the README's provider and trust-boundary text**

After the "Static and sandbox providers are a choice, not a requirement" section (line 190), a new section:

```markdown
### Connecting your own tool servers

Every MCP server Maljan can attach lives in one place, `mcp.servers`, keyed by
a short name you choose. Two entries are there by default — `network` and
`threatintel`, the two sidecars that ship with the project — and you add your
own from Settings → Tool servers: a name, how to reach the server (a command
for stdio, a URL for HTTP), which analysts it serves, and which of its tools
the model may call.

**A server you add exposes nothing until you say what it may run.** That is
the trust boundary, and it is worth being exact about where it sits. Pressing
"Test" performs one MCP handshake and lists the tools the server advertises;
nothing is called. Ticking a tool adds its name to that entry's allow-list, and
only allow-listed tools are ever handed to the model. An entry with an empty
allow-list is connected and inert. The two built-in sidecars carry no
allow-list at all, which means "every tool they offer" — they are in this
repository, their tool sets are pinned by a test, and narrowing them would
change the profile the evaluation was measured on.

What a tool server's process can see is equally explicit. It is started with an
argument list, never through a shell. Its environment is a fixed base set
(`PATH`, `HOME`, locale, `TMPDIR`, `JAVA_HOME`, and a handful more) plus
exactly the variable names you list under "Environment names passed through" —
so `threatintel-mcp` sees `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` and
nothing else, and no server sees the database URL, the settings encryption key
or any LLM credential. A bearer token for an HTTP server is typed once and
stored the way every other secret in Maljan is stored: encrypted with
`SETTINGS_ENCRYPTION_KEY`, in a row of its own rather than in the server list,
never returned by the API and never written into a run summary. Without that
key set, the UI refuses a token the same way it refuses every other secret, and
`MCP__SERVERS__<KEY>__AUTH_TOKEN` in `.env` stays the way to supply one. A server bound to the static or dynamic analyst degrades
rather than failing a job: if it cannot be reached, the run says so in its
degradation reasons and continues on the evidence it has.

### A sandbox Maljan has never heard of

`SANDBOX__PROVIDER=rest` drives an HTTP sandbox you describe rather than one
this project has an adapter for. You give it a base URL, the path a sample is
POSTed to, where the task id is in the reply, where to poll and which state
values are terminal, and where the finished report is. If that report is
CAPE-, Cuckoo- or Triage-shaped, say so and it goes through the same reader the
matching adapter uses. If it is in its own shape, describe where each channel
lives with an [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535.html) JSONPath.
Paste one real response into the settings editor and press "Preview mapping" to
see, per channel, how many rows each path selected and how many survived —
before a sample is ever detonated. A channel you leave empty is reported as
unavailable in the finished report, so a sandbox that publishes no DNS log
never reads as a sample that made no DNS requests.
```

The settings paragraph at line 505-520 gains one sentence after the `capa_yara` explanation: `"Test MCP server" launches one configured tool server and lists what it offers; "Test sandbox API" asks a REST sandbox's status endpoint about a task that does not exist, so any answer other than a refused credential means the endpoint and the token are right.`

The provider list sentence at line 181-183 gains `rest` in the sandbox list.

- [ ] **Step 2: Rewrite the `.env.example` blocks**

Replace the `generic_mcp` block (lines 268-274):

```bash
# --- generic_mcp (any operator-run MCP server) ------------------------------
# The server itself is configured under MCP__SERVERS__* below; this only names
# which of those entries the static analyst drives.
# STATIC__PROVIDER=generic_mcp
# STATIC__GENERIC__SERVER=custom
#
# The pre-2026-09-04 names (STATIC__GENERIC__COMMAND, __URL, __TRANSPORT,
# __ARGS, __ENV, __AUTH_TOKEN, __ENABLED, __TOOL_SELECTION, __USE_ALL_TOOLS)
# still work: each is read as MCP__SERVERS__CUSTOM__* and sets
# STATIC__GENERIC__SERVER=custom, translated on startup and logged once.
```

and add a new block after it:

```bash
# =============================================================================
# TOOL SERVERS (MCP)
# =============================================================================
# Every MCP server Maljan can attach, keyed by a short name. Two are seeded by
# the application itself and need nothing here: `network` (the PCAP sidecar in
# network-mcp/) and `threatintel` (the reputation sidecar in threatintel-mcp/).
#
# A server added here exposes NOTHING until its allow-list names tools:
#   __TOOLS unset  -> every tool the server offers (the two built-ins)
#   __TOOLS=[]     -> nothing
#   __TOOLS=["a"]  -> exactly those names
# __AGENTS says which analysts receive them: static, dynamic, network, judge.
# __ENV_ALLOW names environment variables copied into the child process; it is
# the only way a credential reaches a tool server, because __ENV values are
# ordinary settings and are readable in the UI.
#
# MCP__SERVERS__CUSTOM__ENABLED=true
# MCP__SERVERS__CUSTOM__TRANSPORT=stdio
# MCP__SERVERS__CUSTOM__COMMAND=r2mcp
# MCP__SERVERS__CUSTOM__ARGS=[]
# MCP__SERVERS__CUSTOM__CWD=
# MCP__SERVERS__CUSTOM__ENV_ALLOW=[]
# MCP__SERVERS__CUSTOM__TOOLS=["open_file", "analyze", "list_imports"]
# MCP__SERVERS__CUSTOM__AGENTS=["static"]
# MCP__SERVERS__CUSTOM__LABEL=radare2 (custom)
# [SECRET] — http transports only. A token typed in the UI instead is stored
# encrypted in its own row (core.mcp.servers.<key>.auth_token) and takes
# precedence over this; this stays the way to set one without the UI.
# MCP__SERVERS__CUSTOM__AUTH_TOKEN=
```

and a `rest` sandbox block after the upload block (line 324):

```bash
# --- rest (any HTTP sandbox, described rather than coded) -------------------
# SANDBOX__PROVIDER=rest
# SANDBOX__REST__BASE_URL=https://sandbox.example/api
# [SECRET]
# SANDBOX__REST__AUTH__TOKEN=
# SANDBOX__REST__AUTH__HEADER=Authorization
# SANDBOX__REST__AUTH__SCHEME=Bearer
# SANDBOX__REST__SUBMIT__PATH=/samples
# SANDBOX__REST__SUBMIT__FILE_FIELD=file
# SANDBOX__REST__SUBMIT__TASK_ID_PATH=$.id
# SANDBOX__REST__STATUS__PATH=/samples/{task_id}
# SANDBOX__REST__STATUS__STATE_PATH=$.status
# SANDBOX__REST__STATUS__DONE_VALUES=["reported", "completed", "finished"]
# SANDBOX__REST__REPORT__PATH=/samples/{task_id}/report
# One of cape2 | cuckoo | triage | generic. The first three reuse the readers
# the report-upload provider uses; generic reads the JSONPaths below.
# SANDBOX__REST__REPORT__FORMAT=generic
# SANDBOX__REST__MAPPING__PROCESSES=$.behavior.processes[*]
# SANDBOX__REST__MAPPING__DNS=$.network.dns[*]
# An unmapped channel is listed as unavailable in the report rather than left
# silently empty. Preview a mapping from Settings before running a job.
```

- [ ] **Step 3: Check compose needs no change**

Run: `grep -n "MCP__\|STATIC__GENERIC\|SANDBOX__" docker/docker-compose.yml docker/.env.example 2>/dev/null`
Expected: no hit that names a moved key. The stack passes the whole environment through, and the two sidecars run inside the backend image rather than as compose services, so nothing there moves. Record the command and its empty result in the commit body rather than asserting it from memory.

- [ ] **Step 4: Check the documented keys exist**

Run:
```bash
grep -oE '^# ?(MCP__SERVERS__CUSTOM|SANDBOX__REST|STATIC__GENERIC)[A-Z_0-9]*' .env.example \
  | sed 's/^# \?//' | sort -u
```
and confirm each name maps to a real settings path: lowercase it, replace `__` with `.`, and check it against `uv run python -c "from maljan.core.settings_catalog import core_leaves; print('\n'.join(sorted(l.path for l in core_leaves())))"`. `MCP__SERVERS__CUSTOM__*` will not appear there — the catalog has one `mcp.servers` leaf — which is expected and is why those keys are checked by hand against `MCPServerConfig`'s fields instead.

- [ ] **Step 5: Commit**

```bash
git add README.md .env.example
git commit -m "docs: describe the tool-server allow-list, the trust boundary and the rest sandbox"
```

---

### Task 22: The final gate

**Files:**
- Modify: `docs/specs/2026-09-04-tool-servers-design.md` (status line only), `.github/workflows/ci.yml:39-60` (the evaluation gate's comment names sub-project B too)
- Test: everything

- [ ] **Step 1: Confirm the CI gate still guards the paper**

The evaluation-diff gate added by sub-project A's Task 24 is unchanged and still applies; only its comment moves from "Sub-project A is a refactor" to name both branches:

```yaml
      - name: Evaluation artefacts are untouched
        run: |
          # The measured numbers in the paper come from tests/evaluation/, and
          # no provider or tool-server branch may change them. Sub-project B
          # adds servers and a sandbox; it does not re-measure anything.
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
uv run pytest tests/agents/test_prompt_byte_identity.py tests/providers tests/servers -q  # the gates
uv run pytest tests/servers/test_builtin_tool_sets.py -q   # the pinned sidecar tool sets
grep -rn "network-mcp/server.py\|threatintel-mcp/server.py" src/ | grep -v config.py   # no output
grep -rn "STATIC_PROVIDERS\|SANDBOX_PROVIDERS" apps/web/src                            # no output
cd apps/web && npx tsc --noEmit && npm run lint && npm run build && cd ../..
cd apps/web && npx playwright test e2e/settings-servers.spec.ts e2e/settings-configuration.spec.ts e2e/job-submit-providers.spec.ts --project=chromium --project=firefox && cd ../..
```
The test count is **not** re-pinned: `tests/evaluation/test_suite_count.json` is a committed artefact and `paper_facts.py` reads it; the live count is higher after this branch and that is expected and noted in the PR body, not written into the artefact.

- [ ] **Step 3: Live verification**

Recipe in the `local-observation-run-recipe` memory; cap the CPU before starting llama, confirm `free -g` >= 10 GB, and stop `next dev` before any browser check. The scenarios are the spec's §10 plus the token ruling from Task 14, as a checklist:

1. **Default profile.** Today's `.env`, one job to completion. The log lines `Network tool servers: N tools attached` and `Judge tool servers: [...]` list exactly the names in `tests/fixtures/golden/mcp_tools/network.json` and `threatintel.json`. `run_summary.degradation_reasons` carries no `mcp server` entry.
2. **A custom server, narrowed.** In Settings → Tool servers, add `r2custom`, transport stdio, command `r2mcp`; press Test; tick `open_file`, `analyze`, `list_imports` and nothing else; tick the `static` agent; apply. Set `static.provider=none`. Run a job: the static analyst's log line reports three tools, and they are those three.
3. **The REST stub.** `uv run uvicorn tests.servers.rest_stub:build_stub_app --factory --port 8099` with a `StubState()`; in Settings switch the sandbox to `rest`, fill in the stub's base URL and paths, paste `tests/fixtures/golden/rest_mapping/xyz_report.json` into the preview box and press Preview mapping — the processes row reads `2 / 2 / 0`. Apply and run a job: the report's dynamic and network sections are populated and `unavailable` names `domains`, `hosts`, `http` and `udp`.
4. **A disabled built-in.** Disable `threatintel` in the editor and apply. Run a job: the judge's log line lists no tools and `run_summary.degradation_reasons` is silent — a *disabled* server is a choice, not a degradation, and only a server that fails to open produces a reason. Re-enable it and break its command instead (`MCP__SERVERS__THREATINTEL__COMMAND=/nonexistent`) to see `mcp server 'threatintel' unavailable` in the summary.
5. **A token, stored and masked.** Give `r2custom` the `http` transport and a token, apply, then re-open the page: the card reads "set from the UI" and the value is nowhere in the response — check with `psql -c "select key, is_secret from runtime_settings where key like 'core.mcp.servers%'"`, which shows one non-secret map row and one `is_secret` token row. Unset `SETTINGS_ENCRYPTION_KEY` and try again: the apply answers 422 with the same message every other secret gives.
6. **Legacy env.** With `STATIC__GENERIC__COMMAND=my-mcp` alone in the environment, `uv run python -c "from maljan.core.config import Settings; s=Settings(); print(s.static.generic.server, s.mcp.servers['custom'].command, s.mcp.servers['custom'].agents)"` prints `custom my-mcp ['static']`, and the one-time alias warning names the legacy key.

- [ ] **Step 4: Update the spec's status line and open the PR**

The spec's status line becomes `implemented on branch feat/tool-servers; PR into dev on <date>`. PR body:

- what moved (the two sidecars, `static.generic`) and the two fixtures that prove nothing changed with them;
- the allow-list and the trust boundary, in the README's words;
- the `rest` provider, the stub it is tested against, and the mapping golden;
- the six live-verification results;
- the note that the pinned test count is unchanged while the live count grew;
- the two rulings this branch made that the spec did not fix in detail: per-server `auth_token` values are split out of the `core.mcp.servers` row and stored as one encrypted `is_secret` row each — the project's first runtime-keyed secret rows, with the reader, writer and mask all in Task 14 — and `MaljanApp` now reads each provider's own poll budget rather than CAPE's (Task 12), which changes Triage's effective timeout from 300 s to its configured 900 s;
- the follow-ups sub-project C inherits: `agents` becomes the default `tools` of an agent definition, per-job server selection, and roles beyond the four.

```bash
git add .github/workflows/ci.yml docs/specs/2026-09-04-tool-servers-design.md
git commit -m "ci: name sub-project B in the evaluation-artefact gate"
```

---

## Verification before merge

1. `make lint format-check typecheck` — clean.
2. `uv run pytest tests/ -q` — all green.
3. `make facts && git status --short tests/evaluation/` — empty; `git diff dev -- tests/evaluation/` — empty.
4. The default-profile gates green — prompt byte identity, the extractor goldens, the CAPE identity test, and `tests/servers/test_builtin_tool_sets.py` (the network and judge tool sets equal the pinned fixtures); `grep -rn "network-mcp/server.py\|threatintel-mcp/server.py" src/` shows only `core/config.py`'s `_builtin_servers`.
5. Parity green — `tests/providers/test_registry.py` and `tests/api/test_job_provider_overrides.py` agree on all three id lists, `rest` included; `tests/unit/core/test_settings_catalog.py` finds every new leaf annotated.
6. `cd apps/web && npx tsc --noEmit && npm run lint && npm run build`; `npx playwright test e2e/settings-servers.spec.ts e2e/settings-configuration.spec.ts e2e/job-submit-providers.spec.ts --project=chromium --project=firefox`.
7. Live run (mock sandbox, local llama, CPU cap first): the six scenarios in Task 22 Step 3.
8. PR into `dev`, CI green including Semgrep and the evaluation-diff gate; merging is left to the user.

## Self-review notes

- **Type and name consistency across tasks:** `AgentRole` (T2, T3, T14), `_builtin_servers` (T2, T4, T14), `BUILTIN_SERVER_KEYS` / `RESERVED_SERVER_KEYS` / `SERVER_KEY_PATTERN` (T2, T5, T14, T16), `GENERIC_SERVER_KEY` (T4), `ServerHandle` (T5, T6, T7, T9, T20), `ServerRegistry` (T5, T6, T7, T8, T20), `ServerRegistry.degradation_reasons` (T5, T8), `tools_for` / `atools_for` (T5, T7, T8), `ServiceContainer.get_server_registry` (T6, T7, T8), `server_degradation_reasons` (T8), `_attach_registry_tools` (T7, T8), `GenericMCPStaticProvider.server_name` (T5, T8), `handshake_tools` / `probe_mcp` / `run_mcp_probe` (T9, T14), `ProbeResult.tools` / `ProbeResponse.tools` (T9, T14, T15, T16), `compile_mapping` / `apply_mapping` / `CompiledMapping` / `MappingResult` / `ChannelStats` / `CHANNELS` / `MAX_ROWS_PER_CHANNEL` (T10, T11, T13), `RestSandboxProvider` (T11, T12, T13), `build_stub_app` / `StubState` (T12, T22), `preview_mapping` / `PREVIEW_MAX_BYTES` (T13, T20), `validate_server_map` / `ServerMapError` (T14), `split_server_secrets` / `merge_server_secrets` / `server_token_key` / `SERVER_MAP_KEY` / `TOKEN_MASK` (T14, T16, T20), `resolved_catalog` (T14), `choices_from` / `editor` (T3, T14, T15, T16, T17), `McpServerEntry` / `MappingPreview` (T15, T16, T17), `useProviderChoices` (T15), `ServerMapEditor` (T16, T18), `RestSandboxEditor` (T17, T18). Settings keys: `mcp.servers` (T2 declares, T3 annotates, T4 migrates, T14 validates, T16 renders, T21 documents), `static.generic.server` (T2, T3, T4, T5, T14, T21), `sandbox.rest.*` (T2, T3, T11, T13, T17, T21), `sandbox.provider` (T2, T3, T11, T19).
- **Order dependencies:** T1 must be green on unmodified code before T2 — a tool set captured after the sidecars moved proves nothing. T2 before T3 before T4. T5 before T6 before T7 before T8. T9 depends on T5 (`ServerHandle`) and is what T14's route calls. T10 before T11 before T12; T13 depends on T10 and T11. T14 depends on T9 and T2. T15 before T16 and T17 (the DTO and the API client come first); T18 after both. T19 depends on T11 (`rest` must be registered for the parity test to pass). T20 after T14. T21 next to last, T22 last. Two tasks are red on purpose in between: `test_registry.py::test_sandbox_ids_equal_the_settings_choices` from T2 to T11, and `test_settings_catalog.py` from T2 to T3; both are named in the task that breaks them and in the task that fixes them.
- **Deliberate compromises, named rather than hidden:** (a) a per-server `auth_token` is stored as its own encrypted `is_secret` row keyed `core.mcp.servers.<key>.auth_token` rather than inside the map (T14 Steps 3 and 5, T16's card, T18's third case) — the map leaf is one non-secret JSONB row, so a token left in it would be in clear beside values the UI echoes back. This is the one place in the project where a secret row's key is chosen at runtime instead of declared in the catalog, so `SettingsService` handles those rows itself rather than through `check_keys`; `merge_server_secrets` is an explicit merge rather than two key shapes reaching `nest()`, because `nest()` is order-dependent and would let a late `core.mcp.servers` overwrite a token. (b) `MaljanApp._poll_budget` (T12) changes Triage's effective timeout from CAPE's 300 s to its own configured 900 s — a bug fix rather than a feature, called out in the PR body because it is a behaviour change outside sub-project B's stated scope. (c) `ServerHandle` carries both a sync and an async lifecycle (T5, T7) because the judge enters its toolkit on the graph's loop and the analysts on the shared agent loop; one construction path and two ways to run its coroutine is the smallest honest way to keep that asymmetry. (d) the built-in sidecars keep `tools=None` — "every tool" — where a custom server starts at `[]`; narrowing them would change the evaluated profile, and the fixture is what makes that safe. (e) `hosts` rows are wrapped as `{"ip": value}` by the generic mapper (T10) because `SandboxNetwork.hosts` is `list[dict]` while the spec's channel comment says one string per match; wrapping keeps one row shape for the consumers rather than teaching them a second.
- **Source facts worth knowing before starting:** `MCPConfig` keeps two deprecated read-only properties (`ghidra`, `cape`) that `tests/evaluation/` reads and that must not be touched (`src/maljan/core/config.py:710-757`); `settings_customise_sources` applies the alias table per source, so `apply_settings_aliases` runs several times per construction and must stay idempotent (`config.py:1152-1180`); `flatten_leaves` returns a dict-typed leaf whole, which is why `mcp.servers` works as one catalog entry (`settings_overrides.py:58`); `runtime_settings.value` is JSONB, so the whole map stores in one row (`apps/api/app/models/settings.py:19`); `network-mcp` offers three tools and `threatintel-mcp` four, so the fixtures are small (`network-mcp/server.py:15-57`, `threatintel-mcp/server.py:271-336`).

## Spec coverage

| Spec section | Tasks |
| :-- | :-- |
| §1 Problem | T1 (the fixture that makes "the tool sets must not change" testable), T5, T11, T15 |
| §2 Decisions — `mcp.servers` as a dict | T2, T3, T14, T16 |
| §2 — `agents` on each entry | T2, T5, T8, T16 |
| §2 — tool exposure (`None` / `[]` / names) | T2, T5, T16, T20 |
| §2 — custom sandbox with RFC 9535 | T2, T10, T11 |
| §2 — server-side mapping preview | T13, T17 |
| §2 — sidecar migration | T1, T2, T7 |
| §2 — failure policy | T5, T8 |
| §3.1 `MCPServerConfig` extended | T2, T3 |
| §3.2 `MCPConfig.servers`, `_builtin_servers`, reserved keys, disable-not-delete | T2, T14, T16 |
| §3.1 per-server `auth_token` stored as one encrypted row (ruling A1) | T14 (validator, `SettingsService`, tests), T15 (DTO), T16 (card), T18 (e2e), T20 (invariant) |
| §3.3 `static.generic` becomes a reference, aliases, migration | T2, T4, T5 |
| §3.4 `sandbox.rest` tree and its `applies_when` | T2, T3 |
| §4 `ServerHandle` / `ServerRegistry`, container, agent wiring, degrade, collisions | T5, T6, T7, T8 |
| §5 REST provider, capabilities, the four calls, mapping, preview and probe | T10, T11, T12, T13 |
| §6 Catalog columns, server-map editor, REST editor, samples page, probe labels | T3, T13, T14, T15, T16, T17 |
| §7 Probes: `mcp`, `rest`, r2 and generic re-based on `ServerHandle` | T9, T13, T14 |
| §8.1 Default profile byte-identical | T1, T7, T22 |
| §8.2 `tests/evaluation/**` untouched, `make facts`, pinned count | Global Constraints, T22 |
| §8.3 Every leaf annotated; provider literal, registry ids and job literal in parity | T3, T11, T19 |
| §8.4 Alias table and migration test | T4 |
| §8.5 REST adapter: stub, end-to-end, mapping golden, unit failures | T10, T11, T12 |
| §8.6 `settings-servers.spec.ts`, chromium in the task and firefox in the gate | T18, T22 |
| §8.7 Security tests | T5 (cwd), T9 (probe kill), T13 (admin, 4 MiB), T20 (snapshot, `env_allow`, argv) |
| §9 Security narrative, per-server token storage, and the README's trust boundary | T14, T16, T20, T21 |
| §10 Live verification | T22 |
| §11 Out of scope | not implemented, by design |
| §12 Risks — tool-set drift, per-job server lifetime, JSONPath on large reports | T1 (names only), T5 + T6 (lazy open, closed at job end), T10 (`MAX_ROWS_PER_CHANNEL`) |
