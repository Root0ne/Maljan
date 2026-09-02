# Runtime Settings (UI-managed configuration) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every pipeline setting and the API's runtime-safe knobs become editable from an admin-only Configuration tab in the web UI, persisted in Postgres over the environment, with secrets encrypted and changes reaching the worker on the next job.

**Architecture:** A catalog derived from the pydantic settings models plus a hand-maintained annotation map drives one generic form. Overrides are stored as dotted keys in `runtime_settings`; `build_settings(overrides)` calls `Settings(**nested)`, which pydantic-settings deep-merges with the environment (verified). The API reads its own knobs through a 5-second-TTL `RuntimeConfig`; the worker rebuilds `Settings` per job.

**Tech Stack:** Python 3.13, pydantic-settings, SQLAlchemy async + Alembic, FastAPI, `cryptography` (Fernet), httpx; Next.js 16 / React 19 / Tailwind 4; pytest, Playwright.

**Spec:** `docs/specs/2026-09-02-runtime-settings-design.md`

## Global Constraints

- Precedence is `UI (database) > environment / .env > code default`; nothing writes `.env`.
- Secret values are never returned by any endpoint; responses carry `{is_set, hint}` only.
- Secrets are stored as the string `enc:v1:<fernet token>` under `SETTINGS_ENCRYPTION_KEY`; without the key, secret fields are `editable: false` and everything else works.
- All `/api/v1/settings/*` routes depend on `require_admin`.
- `PATCH` is all-or-nothing: the merged `Settings` and `APISettings` must validate before a single row is written.
- Probes have a hard 10-second timeout and persist nothing.
- `make facts` must remain byte-identical (`tests/evaluation/paper_facts.json`, `cluster_analysis.json`); the paper's test count reads `tests/evaluation/test_suite_count.json` (2716) and never a live run.
- Run from the repository root; Python via `uv run`, frontend via `npm` in `apps/web`. Commit messages carry no AI attribution.
- Gates after every task: `make lint format-check typecheck` and the task's tests; before the final commit `uv run pytest tests/ -q`, `cd apps/web && npx tsc --noEmit && npm run lint`.

---

## File map

| Path | Responsibility | Task |
| :-- | :-- | :-- |
| `tests/evaluation/test_suite_count.json` | recorded passing-test count for the paper | 1 |
| `tests/evaluation/paper_facts.py` | `suite_facts()` reads the recording; live run only verifies green | 1 |
| `src/maljan/core/settings_secrets.py` | Fernet encrypt/decrypt/hint, availability | 2 |
| `src/maljan/core/settings_overrides.py` | dotted↔nested, `build_settings`, flatten, source attribution | 3 |
| `src/maljan/core/settings_catalog.py` | walk `Settings` → leaf entries with type/default/choices/bounds/secret | 4 |
| `src/maljan/core/settings_annotations.py` | `ANNOTATIONS` (title, description, applies, probe) for every core leaf; group rules | 4 |
| `scripts/seed_settings_annotations.py` | one-off generator from `.env.example` comments | 4 |
| `apps/api/alembic/versions/20260902000000_runtime_settings.py` | table | 5 |
| `apps/api/app/models/settings.py` | `RuntimeSetting` ORM | 5 |
| `apps/api/app/services/settings_catalog_api.py` | API-side entries (editable knobs, read-only system) + composed catalog | 6 |
| `apps/api/app/services/settings_service.py` | load/values/save/reset + audit | 6 |
| `apps/api/app/runtime_config.py` | TTL-cached `api.*` reads | 7 |
| `apps/api/app/worker/enrich_worker.py`, `api/v1/samples.py`, `auth/throttle.py`, `api/v1/system.py`, `middleware/rate_limit_middleware.py` | read knobs via `runtime_config` | 7 |
| `apps/api/app/schemas/settings.py`, `apps/api/app/api/v1/settings.py` | request/response models and routes | 8 |
| `apps/api/app/services/settings_probes.py` | connection probes | 9 |
| `apps/api/app/worker/analysis_worker.py` | overrides at job start + snapshot | 10 |
| `apps/web/src/types/settings.ts`, `apps/web/src/lib/api.ts` | DTOs + client methods | 11 |
| `apps/web/src/app/(app)/settings/configuration/*` and `settings/page.tsx` | Configuration tab | 12 |
| `apps/web/e2e/settings-configuration.spec.ts` | route-mocked e2e | 13 |
| `.env.example`, `README.md`, spec status | docs | 14 |

---

### Task 1: Pin the paper's passing-test count to a recorded artefact

**Files:**
- Create: `tests/evaluation/test_suite_count.json`
- Modify: `tests/evaluation/paper_facts.py:366-416` (`suite_facts`) and the artefact list used by `artifact_digest()` (around line 1494)
- Test: `tests/evaluation/test_suite_count_pin.py`

**Interfaces:**
- Produces: `paper_facts.recorded_suite_count() -> int`; `suite_facts()` keeps returning `{"test_count": "2,716"}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/evaluation/test_suite_count_pin.py
"""The manuscript's passing-test count is a recorded fact, not a live one.

Any test added to this tree used to move the number in a paper under
submission (2,716 -> 2,719 on 2026-09-02). The count now describes the suite
at study time and lives in an artefact next to the other paper inputs.
"""
import json
from pathlib import Path

from tests.evaluation import paper_facts

_ART = Path(__file__).with_name("test_suite_count.json")


def test_artifact_exists_and_is_well_formed():
    data = json.loads(_ART.read_text())
    assert data["count"] == 2716
    assert len(data["measured_at_commit"]) >= 7
    assert data["measured_on"] == "2026-09-02"


def test_recorded_count_is_what_the_paper_prints():
    assert paper_facts.recorded_suite_count() == 2716
    assert paper_facts._format_count(2716) == "2,716"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/evaluation/test_suite_count_pin.py -v`
Expected: FAIL (`FileNotFoundError` / `AttributeError: recorded_suite_count`)

- [ ] **Step 3: Create the artefact and change the derivation**

`tests/evaluation/test_suite_count.json`:
```json
{
  "count": 2716,
  "measured_at_commit": "afbb797",
  "measured_on": "2026-09-02",
  "note": "Passing tests at study time, excluding the three paper gates. Recorded because the sentence in the paper is historical; the live suite grows."
}
```

In `paper_facts.py`, add above `suite_facts()`:
```python
_SUITE_COUNT = _HERE / "test_suite_count.json"


def recorded_suite_count() -> int:
    """The passing-test count the paper states, read from its artefact."""
    return int(json.loads(_SUITE_COUNT.read_text())["count"])


def _format_count(n: int) -> str:
    return f"{n:,}"
```
Replace the tail of `suite_facts()` (after the `proc = subprocess.run(...)` block and the red-run `FactError`) so the live count only verifies and warns:
```python
    live = None
    for line in reversed(proc.stdout.splitlines()):
        m = _PASSED.search(line)
        if m:
            live = int(m.group(1))
            break
    if live is None:
        raise FactError("could not read a passing-test count from pytest")
    recorded = recorded_suite_count()
    if live != recorded:
        print(
            f"note: live suite passes {live} tests; the paper states the recorded "
            f"{recorded} (tests/evaluation/test_suite_count.json)",
            file=sys.stderr,
        )
    return {"test_count": _format_count(recorded)}
```
Add `"test_suite_count.json"` to the artefact list hashed by `artifact_digest()` so the paper's input stamp tracks it. Update the `suite_facts` docstring: the number is recorded; the run is the green check.

- [ ] **Step 4: Run tests and the facts gate**

Run: `uv run pytest tests/evaluation/test_suite_count_pin.py -v` → PASS.
Run: `make facts && git diff --exit-code --stat tests/evaluation/paper_facts.json tests/evaluation/cluster_analysis.json` → no diff (2,716 unchanged).

- [ ] **Step 5: Commit**

```bash
git add tests/evaluation/test_suite_count.json tests/evaluation/test_suite_count_pin.py tests/evaluation/paper_facts.py
git commit -m "paper: the passing-test count is a recorded artefact, not a live run"
```

---

### Task 2: Secret box

**Files:**
- Create: `src/maljan/core/settings_secrets.py`
- Test: `tests/unit/core/test_settings_secrets.py`

**Interfaces:**
- Produces: `PREFIX = "enc:v1:"`, `is_available() -> bool`, `encrypt(plain: str) -> str`, `decrypt(stored: str) -> str`, `is_encrypted(value: object) -> bool`, `hint(plain: str) -> str`, `class SecretsUnavailable(RuntimeError)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/test_settings_secrets.py
import pytest
from cryptography.fernet import Fernet

from maljan.core import settings_secrets as box


@pytest.fixture
def key(monkeypatch):
    k = Fernet.generate_key().decode()
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", k)
    return k


def test_round_trip(key):
    stored = box.encrypt("sk-live-1234")
    assert stored.startswith(box.PREFIX)
    assert box.is_encrypted(stored)
    assert box.decrypt(stored) == "sk-live-1234"


def test_hint_is_last_four_and_never_more():
    assert box.hint("sk-live-1234") == "1234"
    assert box.hint("ab") == ""


def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    assert box.is_available() is False
    with pytest.raises(box.SecretsUnavailable):
        box.encrypt("x")


def test_decrypt_rejects_foreign_token(key, monkeypatch):
    stored = box.encrypt("x")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(box.SecretsUnavailable):
        box.decrypt(stored)


def test_plain_values_are_not_encrypted():
    assert box.is_encrypted("http://localhost:8080") is False
    assert box.is_encrypted(42) is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/core/test_settings_secrets.py -v` → FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement**

```python
# src/maljan/core/settings_secrets.py
"""Encryption for secret settings stored in the database.

A secret set from the UI is written as ``enc:v1:<fernet token>`` under the key
in ``SETTINGS_ENCRYPTION_KEY``. The API and the worker share ``.env``, so both
can open it. Without the key, callers get ``SecretsUnavailable`` and the UI
shows secret fields read-only.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"
ENV_VAR = "SETTINGS_ENCRYPTION_KEY"


class SecretsUnavailable(RuntimeError):
    """No usable encryption key, or a token this key cannot open."""


def _fernet() -> Fernet:
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        raise SecretsUnavailable(f"{ENV_VAR} is not set")
    try:
        return Fernet(raw.encode())
    except (ValueError, TypeError) as exc:
        raise SecretsUnavailable(f"{ENV_VAR} is not a valid Fernet key") from exc


def is_available() -> bool:
    try:
        _fernet()
    except SecretsUnavailable:
        return False
    return True


def encrypt(plain: str) -> str:
    return PREFIX + _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt(stored: str) -> str:
    if not is_encrypted(stored):
        raise SecretsUnavailable("value is not an encrypted secret")
    try:
        return _fernet().decrypt(stored[len(PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise SecretsUnavailable("stored secret cannot be opened with the current key") from exc


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def hint(plain: str) -> str:
    """Last four characters, or nothing for a value too short to hint safely."""
    return plain[-4:] if len(plain) >= 8 else ""
```

- [ ] **Step 4: Run tests** → `uv run pytest tests/unit/core/test_settings_secrets.py -v` → PASS

- [ ] **Step 5: Commit**

```bash
git add src/maljan/core/settings_secrets.py tests/unit/core/test_settings_secrets.py
git commit -m "feat(settings): Fernet box for secrets stored in the database"
```

---
### Task 3: Overrides layering (dotted keys, `build_settings`, source attribution)

**Files:**
- Create: `src/maljan/core/settings_overrides.py`
- Test: `tests/unit/core/test_settings_overrides.py`

**Interfaces:**
- Produces:
  - `CORE_NS = "core"`, `API_NS = "api"`; `split_key(key) -> tuple[str, str]` (`"core.llm.provider"` → `("core", "llm.provider")`)
  - `nest(flat: Mapping[str, Any]) -> dict[str, Any]` (dotted paths → nested dict)
  - `flatten(obj: Mapping[str, Any], prefix: str = "") -> dict[str, Any]` (nested → dotted; lists and non-dict values are leaves; a dict whose values are dicts of a model type is still flattened, so `llm.agents` becomes leaves only when the caller passes `model_dump()` — see `flatten_leaves`)
  - `flatten_leaves(model: BaseModel, leaf_keys: Iterable[str]) -> dict[str, Any]` (values for exactly the catalog's keys, JSON mode)
  - `build_settings(core_overrides: Mapping[str, Any]) -> Settings` (keys are dotted paths **without** the `core.` prefix)
  - `effective_source(*, overridden: bool, env_value: Any, default_value: Any) -> Literal["ui","env","default"]`
  - `public_snapshot(settings: Settings, secret_keys: Iterable[str]) -> dict[str, Any]` (flattened, secrets replaced by `"***"` when set)

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/test_settings_overrides.py
import pytest

from maljan.core import settings_overrides as ov
from maljan.core.config import Settings


def test_nest_builds_nested_dict():
    assert ov.nest({"llm.openai.base_url": "http://x", "llm.provider": "openai", "chunking.overlap_tokens": 5}) == {
        "llm": {"openai": {"base_url": "http://x"}, "provider": "openai"},
        "chunking": {"overlap_tokens": 5},
    }


def test_flatten_is_inverse_of_nest_for_scalars():
    flat = {"a.b": 1, "a.c": "x", "d": [1, 2]}
    assert ov.flatten(ov.nest(flat)) == flat


def test_split_key():
    assert ov.split_key("core.llm.provider") == ("core", "llm.provider")
    assert ov.split_key("api.enrichment_enabled") == ("api", "enrichment_enabled")
    with pytest.raises(ValueError):
        ov.split_key("llm.provider")


def test_override_wins_and_env_sibling_survives(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    monkeypatch.setenv("LLM__OPENAI__EXPERT_MODEL", "env-expert")
    s = ov.build_settings({"llm.openai.base_url": "http://ui:1/v1"})
    assert s.llm.openai.base_url == "http://ui:1/v1"
    assert s.llm.openai.api_key.get_secret_value() == "env-key"
    assert s.llm.openai.expert_model == "env-expert"


def test_build_settings_rejects_invalid_value():
    with pytest.raises(Exception):  # pydantic ValidationError
        ov.build_settings({"negotiation.max_iterations": "not-a-number"})


def test_effective_source():
    assert ov.effective_source(overridden=True, env_value=1, default_value=1) == "ui"
    assert ov.effective_source(overridden=False, env_value=2, default_value=1) == "env"
    assert ov.effective_source(overridden=False, env_value=1, default_value=1) == "default"


def test_public_snapshot_masks_secrets(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    snap = ov.public_snapshot(Settings(), secret_keys=["llm.openai.api_key"])
    assert snap["llm.openai.api_key"] == "***"
    assert "llm.provider" in snap


def test_flatten_leaves_reads_only_requested_keys():
    s = Settings()
    out = ov.flatten_leaves(s, ["llm.provider", "negotiation.max_iterations"])
    assert set(out) == {"llm.provider", "negotiation.max_iterations"}
    assert isinstance(out["negotiation.max_iterations"], int)
```

- [ ] **Step 2: Run to verify failure** → `uv run pytest tests/unit/core/test_settings_overrides.py -v` → FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement**

```python
# src/maljan/core/settings_overrides.py
"""Layer database overrides over the environment.

Overrides are dotted paths (``llm.openai.base_url``). ``build_settings`` nests
them and passes them to ``Settings(**nested)``; pydantic-settings deep-merges
init kwargs with the environment and dotenv sources, so an overridden
``llm.openai.base_url`` keeps an ``LLM__OPENAI__API_KEY`` from ``.env``
(verified against the real model on 2026-09-02). Precedence is therefore
``UI > env > default`` with no code of its own.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel

from maljan.core.config import Settings

CORE_NS = "core"
API_NS = "api"
Source = Literal["ui", "env", "default"]


def split_key(key: str) -> tuple[str, str]:
    ns, sep, path = key.partition(".")
    if not sep or ns not in (CORE_NS, API_NS) or not path:
        raise ValueError(f"settings key must be '<core|api>.<path>', got {key!r}")
    return ns, path


def nest(flat: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in flat.items():
        cursor = out
        parts = key.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                raise ValueError(f"{key!r} descends into a non-mapping at {part!r}")
        cursor[parts[-1]] = value
    return out


def flatten(obj: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested mapping -> dotted keys. Every mapping is structure; see flatten_leaves."""
    out: dict[str, Any] = {}
    for k, v in obj.items():
        path = f"{prefix}{k}"
        if isinstance(v, Mapping):
            out.update(flatten(v, path + "."))
        else:
            out[path] = v
    return out


def flatten_leaves(model: BaseModel, leaf_keys: Iterable[str]) -> dict[str, Any]:
    """Values for exactly ``leaf_keys`` from a model instance, JSON-serialisable.

    Nested models are walked attribute by attribute; a leaf that is itself a
    mapping (``llm.agents``, ``react_agent_timeout_overrides``) is returned
    whole, which is what ``flatten`` alone would not do.
    """
    dumped = model.model_dump(mode="json")
    out: dict[str, Any] = {}
    for key in leaf_keys:
        cursor: Any = dumped
        for part in key.split("."):
            cursor = cursor[part]
        out[key] = cursor
    return out


def build_settings(core_overrides: Mapping[str, Any]) -> Settings:
    return Settings(**nest(core_overrides))


def effective_source(*, overridden: bool, env_value: Any, default_value: Any) -> Source:
    if overridden:
        return "ui"
    return "env" if env_value != default_value else "default"


def public_snapshot(settings: Settings, secret_keys: Iterable[str]) -> dict[str, Any]:
    secrets = set(secret_keys)
    snap = flatten(settings.model_dump(mode="json"))
    for key in list(snap):
        if key in secrets:
            snap[key] = "***" if snap[key] else None
    return snap
```

- [ ] **Step 4: Run tests** → PASS. Also `make lint format-check typecheck`.

- [ ] **Step 5: Commit**

```bash
git add src/maljan/core/settings_overrides.py tests/unit/core/test_settings_overrides.py
git commit -m "feat(settings): layer dotted overrides over the environment through Settings(**nested)"
```

---

### Task 4: Catalog and annotations for the core model

**Files:**
- Create: `src/maljan/core/settings_catalog.py`, `src/maljan/core/settings_annotations.py`, `scripts/seed_settings_annotations.py`
- Test: `tests/unit/core/test_settings_catalog.py`

**Interfaces:**
- Produces:
  ```python
  FieldType = Literal["bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"]
  Applies = Literal["next_job", "live", "restart"]

  @dataclass(frozen=True)
  class CatalogEntry:
      key: str            # "core.llm.openai.base_url"
      namespace: str      # "core" | "api"
      path: str           # "llm.openai.base_url"
      type: FieldType
      default: Any
      nullable: bool
      choices: list[str] | None
      minimum: float | None
      maximum: float | None
      secret: bool
      group: str
      title: str
      description: str
      applies: Applies
      editable: bool
      reason: str | None
      probe: str | None

  def core_leaves() -> list[Leaf]                 # Leaf(path, annotation(type), default, field_info)
  def core_catalog() -> list[CatalogEntry]        # leaves joined with ANNOTATIONS
  def group_for(path: str) -> str                 # from GROUP_RULES
  GROUP_ORDER: list[tuple[str, str]]              # (group key, title) in display order
  ANNOTATIONS: dict[str, Annotation]              # Annotation = TypedDict(title, description, applies?, probe?, group?)
  ```

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/test_settings_catalog.py
from maljan.core import settings_catalog as cat
from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER


def test_every_leaf_is_annotated_and_no_annotation_is_orphaned():
    leaves = {leaf.path for leaf in cat.core_leaves()}
    annotated = set(ANNOTATIONS)
    assert leaves - annotated == set(), f"unannotated settings: {sorted(leaves - annotated)}"
    assert annotated - leaves == set(), f"annotations for missing settings: {sorted(annotated - leaves)}"


def test_every_annotation_has_a_title_and_description():
    empty = [k for k, a in ANNOTATIONS.items() if not a["title"].strip() or not a["description"].strip()]
    assert empty == [], empty


def test_types_and_choices():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["llm.openai.api_key"].type == "secret" and by_path["llm.openai.api_key"].secret
    assert by_path["reporting.default_tlp"].type == "enum"
    assert by_path["reporting.default_tlp"].choices == ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]
    assert by_path["negotiation.max_iterations"].type == "int"
    assert by_path["negotiation.consensus_threshold"].type == "float"
    assert by_path["llm.parallel_analysts"].type == "bool"
    assert by_path["llm.frontier.arms"].type == "json"
    assert by_path["react_agent_timeout_overrides"].type == "dict"
    assert by_path["mcp.ghidra.args"].type == "list"
    assert by_path["mcp.ghidra.auth_token"].type == "secret"


def test_groups_cover_every_entry_in_order():
    groups = [g for g, _ in GROUP_ORDER]
    for e in cat.core_catalog():
        assert e.group in groups, e.key
    assert groups.index("llm") < groups.index("providers") < groups.index("frontier")


def test_keys_carry_namespace_and_defaults_are_json_serialisable():
    import json
    for e in cat.core_catalog():
        assert e.key == f"core.{e.path}"
        json.dumps(e.default)
```

- [ ] **Step 2: Run to verify failure** → FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement the catalog walker**

```python
# src/maljan/core/settings_catalog.py
"""Every leaf of the core Settings model, described for a generic UI.

The walk is a pure function of the pydantic models: field names, types,
defaults, Literal choices, numeric bounds and SecretStr-ness come from the
model; titles, descriptions and when a change applies come from
``settings_annotations``. A test refuses a leaf without an annotation, so a
new field cannot be added to config.py without also being explained.
"""
from __future__ import annotations

import types
import typing
from dataclasses import dataclass, asdict
from typing import Any, Literal, get_args, get_origin

from pydantic import BaseModel, SecretStr
from pydantic.fields import FieldInfo

from maljan.core.config import Settings
from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER, group_for

FieldType = Literal["bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"]
Applies = Literal["next_job", "live", "restart"]

# Field names that are secrets although typed as plain str.
_SECRET_NAMES = {"auth_token", "api_key", "cape2_api_token"}


@dataclass(frozen=True)
class Leaf:
    path: str
    annotation: Any
    default: Any
    field: FieldInfo


@dataclass(frozen=True)
class CatalogEntry:
    key: str
    namespace: str
    path: str
    type: FieldType
    default: Any
    nullable: bool
    choices: list[str] | None
    minimum: float | None
    maximum: float | None
    secret: bool
    group: str
    title: str
    description: str
    applies: Applies
    editable: bool
    reason: str | None
    probe: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unwrap_optional(tp: Any) -> tuple[Any, bool]:
    origin = get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in get_args(tp) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return tp, False


def _is_model(tp: Any) -> bool:
    return isinstance(tp, type) and issubclass(tp, BaseModel)


def _walk(model: type[BaseModel], prefix: str, defaults: Any) -> list[Leaf]:
    out: list[Leaf] = []
    for name, field in model.model_fields.items():
        tp, _ = _unwrap_optional(field.annotation)
        path = f"{prefix}{name}"
        default = getattr(defaults, name) if defaults is not None else None
        if _is_model(tp):
            out.extend(_walk(tp, path + ".", default))
        else:
            out.append(Leaf(path=path, annotation=field.annotation, default=default, field=field))
    return out


def core_leaves() -> list[Leaf]:
    """Leaves of ``Settings`` with the *code* defaults (env ignored)."""
    defaults = Settings.model_construct()  # no env, no validation: declared defaults only
    # model_construct leaves nested models unbuilt; build them from their own defaults
    for name, field in Settings.model_fields.items():
        tp, _ = _unwrap_optional(field.annotation)
        if _is_model(tp) and not isinstance(getattr(defaults, name, None), BaseModel):
            object.__setattr__(defaults, name, tp())
    return _walk(Settings, "", defaults)


def _field_type(leaf: Leaf) -> tuple[FieldType, list[str] | None, bool]:
    tp, nullable = _unwrap_optional(leaf.annotation)
    name = leaf.path.rsplit(".", 1)[-1]
    if tp is SecretStr or name in _SECRET_NAMES:
        return "secret", None, nullable
    if get_origin(tp) is Literal:
        return "enum", [str(a) for a in get_args(tp)], nullable
    if tp is bool:
        return "bool", None, nullable
    if tp is int:
        return "int", None, nullable
    if tp is float:
        return "float", None, nullable
    if tp is str:
        return "str", None, nullable
    origin = get_origin(tp)
    if origin in (list, set, tuple):
        return "list", None, nullable
    if origin is dict:
        _, val = get_args(tp) or (None, None)
        return ("json" if _is_model(val) else "dict"), None, nullable
    return "json", None, nullable


def _bounds(field: FieldInfo) -> tuple[float | None, float | None]:
    lo = hi = None
    for meta in field.metadata:
        lo = getattr(meta, "ge", getattr(meta, "gt", lo)) if hasattr(meta, "ge") or hasattr(meta, "gt") else lo
        hi = getattr(meta, "le", getattr(meta, "lt", hi)) if hasattr(meta, "le") or hasattr(meta, "lt") else hi
    return lo, hi


def _json_default(value: Any) -> Any:
    if isinstance(value, SecretStr):
        return None
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: _json_default(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_default(v) for v in value]
    return value


def core_catalog() -> list[CatalogEntry]:
    entries: list[CatalogEntry] = []
    for leaf in core_leaves():
        ann = ANNOTATIONS[leaf.path]
        ftype, choices, nullable = _field_type(leaf)
        lo, hi = _bounds(leaf.field)
        entries.append(
            CatalogEntry(
                key=f"core.{leaf.path}",
                namespace="core",
                path=leaf.path,
                type=ftype,
                default=_json_default(leaf.default),
                nullable=nullable,
                choices=choices,
                minimum=lo,
                maximum=hi,
                secret=ftype == "secret",
                group=ann.get("group") or group_for(leaf.path),
                title=ann["title"],
                description=ann["description"],
                applies=ann.get("applies", "next_job"),
                editable=True,
                reason=None,
                probe=ann.get("probe"),
            )
        )
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    entries.sort(key=lambda e: (order[e.group], e.path))
    return entries
```

- [ ] **Step 4: Implement group rules and generate the annotation skeleton**

```python
# src/maljan/core/settings_annotations.py (top of file)
"""What each setting means, in words a person can act on.

Titles and descriptions were seeded from the comments in ``.env.example`` by
``scripts/seed_settings_annotations.py`` and then edited. Groups come from
the key prefix (``group_for``); an entry may override its group. ``applies``
defaults to ``next_job`` for every core setting. ``probe`` names the
connection test in apps/api/app/services/settings_probes.py that exercises
the field.
"""
from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class Annotation(TypedDict):
    title: str
    description: str
    applies: NotRequired[Literal["next_job", "live", "restart"]]
    probe: NotRequired[str]
    group: NotRequired[str]


GROUP_ORDER: list[tuple[str, str]] = [
    ("llm", "LLM & model"),
    ("providers", "Providers"),
    ("frontier", "Frontier arms"),
    ("sandbox", "Sandbox (CAPE)"),
    ("mcp", "MCP servers (Ghidra, CAPE)"),
    ("memory", "Memory / LTM (Qdrant)"),
    ("analysis", "Analysis layers"),
    ("negotiation", "Negotiation"),
    ("chunking", "Chunking"),
    ("reporting", "Reporting"),
    ("agents", "Agent timeouts and budgets"),
    ("tracing", "Tracing"),
    ("enrichment", "Enrichment / threat intelligence"),
    ("api", "API"),
    ("system", "System (read-only)"),
]

_PREFIX_GROUPS: list[tuple[str, str]] = [
    ("llm.frontier", "frontier"),
    ("llm.openai", "providers"), ("llm.anthropic", "providers"),
    ("llm.gemini", "providers"), ("llm.ollama", "providers"),
    ("llm", "llm"),
    ("negotiation", "negotiation"), ("chunking", "chunking"),
    ("memory", "memory"), ("sandbox", "sandbox"),
    ("analysis", "analysis"), ("preprocessing", "analysis"),
    ("mcp", "mcp"), ("reporting", "reporting"),
    ("react_agent", "agents"), ("max_token_limit", "agents"),
    ("langchain", "tracing"),
    ("openai_api_key", "providers"), ("anthropic_api_key", "providers"), ("google_api_key", "providers"),
]


def group_for(path: str) -> str:
    for prefix, group in _PREFIX_GROUPS:
        if path == prefix or path.startswith(prefix + ".") or path.startswith(prefix + "_"):
            return group
    return "agents"


ANNOTATIONS: dict[str, Annotation] = {
    # generated skeleton is pasted below and then edited by hand
}
```

Generator (run once, paste its output into `ANNOTATIONS`, then edit every entry whose description is empty):
```python
# scripts/seed_settings_annotations.py
"""Draft ANNOTATIONS for settings_annotations.py from .env.example comments.

For each ``KEY=`` line (commented or not) the comment block immediately above
it becomes the description; the key maps to the dotted path
(``LLM__OPENAI__BASE_URL`` -> ``llm.openai.base_url``). Leaves with no key in
.env.example get an empty description, which the catalog test rejects until a
person writes one. Prints Python to paste.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from maljan.core.settings_catalog import core_leaves  # noqa: E402

ENV = Path(__file__).resolve().parents[1] / ".env.example"
KEY = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=")


def harvest() -> dict[str, str]:
    docs: dict[str, str] = {}
    block: list[str] = []
    for raw in ENV.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        m = KEY.match(line)
        if m:
            path = m.group(1).lower().replace("__", ".")
            text = " ".join(b for b in block if b)
            docs.setdefault(path, text)
            block = []
            continue
        if line.startswith("#") and not set(line) <= {"#", "=", " ", "-"}:
            block.append(line.lstrip("# ").strip())
        elif not line.strip():
            block = []
    return docs


def main() -> None:
    docs = harvest()
    print("ANNOTATIONS: dict[str, Annotation] = {")
    for leaf in core_leaves():
        title = leaf.path.rsplit(".", 1)[-1].replace("_", " ").capitalize()
        desc = docs.get(leaf.path, "").replace('"', "'")
        print(f'    "{leaf.path}": {{"title": "{title}", "description": "{desc}"}},')
    print("}")


if __name__ == "__main__":
    main()
```
Run: `uv run python scripts/seed_settings_annotations.py > /tmp/ann.py`, paste into `settings_annotations.py`, then write a description for every entry left empty (the test lists them). Set `"probe": "llm"` on `llm.provider`, `llm.openai.base_url`, `llm.openai.api_key`, `llm.openai.expert_model`, `llm.openai.judge_model`; `"probe": "ghidra"` on `mcp.ghidra.url`, `mcp.ghidra.auth_token`, `mcp.ghidra.enabled`; `"probe": "cape"` on `sandbox.cape2_base_url`, `sandbox.cape2_api_token`; `"probe": "qdrant"` on `memory.qdrant_url`, `memory.qdrant_collection`.

- [ ] **Step 5: Run tests** → `uv run pytest tests/unit/core/test_settings_catalog.py -v` → PASS (after every description is filled). `make lint format-check typecheck`.

- [ ] **Step 6: Commit**

```bash
git add src/maljan/core/settings_catalog.py src/maljan/core/settings_annotations.py scripts/seed_settings_annotations.py tests/unit/core/test_settings_catalog.py
git commit -m "feat(settings): a catalog of every core setting, with a test that refuses an unexplained field"
```

---
### Task 5: `runtime_settings` table and ORM model

**Files:**
- Create: `apps/api/alembic/versions/20260902000000_runtime_settings.py`, `apps/api/app/models/settings.py`
- Modify: `apps/api/app/models/__init__.py` (export `RuntimeSetting`)
- Test: `tests/unit/api/test_runtime_setting_model.py`

**Interfaces:**
- Produces: `class RuntimeSetting(Base)` with columns `key: str (PK)`, `value: dict|list|str|int|float|bool|None (JSONB)`, `is_secret: bool`, `updated_by: uuid|None`, `updated_at: datetime`; `__tablename__ = "runtime_settings"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/api/test_runtime_setting_model.py
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.models import RuntimeSetting  # noqa: E402


def test_table_shape():
    cols = RuntimeSetting.__table__.columns
    assert RuntimeSetting.__tablename__ == "runtime_settings"
    assert cols["key"].primary_key
    assert cols["value"].type.__class__.__name__ == "JSONB"
    assert cols["is_secret"].default.arg is False
    assert cols["updated_by"].nullable is True
```

- [ ] **Step 2: Run** → FAIL (`ImportError: RuntimeSetting`)

- [ ] **Step 3: Implement**

```python
# apps/api/app/models/settings.py
"""Runtime overrides set from the UI. One row per dotted key; no row = no override."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RuntimeSetting(Base):
    __tablename__ = "runtime_settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[object] = mapped_column(JSONB, nullable=False)
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```
Add `from app.models.settings import RuntimeSetting` and `"RuntimeSetting"` to `apps/api/app/models/__init__.py`.

Migration:
```python
# apps/api/alembic/versions/20260902000000_runtime_settings.py
"""Add ``runtime_settings`` — configuration overrides set from the web UI.

Until now every knob lived in ``.env`` and changing one meant editing a file
on the host and restarting processes. Overrides now live here, keyed by the
dotted setting path with a namespace (``core.llm.openai.base_url``,
``api.enrichment_enabled``), and layer over the environment: the worker reads
them at the start of each job, the API through a short-lived cache. Secret
values are stored Fernet-encrypted as ``enc:v1:<token>``; ``is_secret`` marks
them so a reader never has to guess. An empty table is exactly today's system.

Revision ID: 20260902000000
Revises: 20260726020000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260902000000"
down_revision = "20260726020000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_settings",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("is_secret", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("runtime_settings")
```

- [ ] **Step 4: Run test; apply migration locally**

`uv run pytest tests/unit/api/test_runtime_setting_model.py -v` → PASS.
With Postgres up (`cd docker && POSTGRES_PORT=5433 docker compose up -d postgres`): `cd apps/api && PYTHONPATH=.:../../src ../../.venv/bin/alembic upgrade head` → `20260902000000 (head)`; `alembic downgrade -1` then `upgrade head` both succeed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/alembic/versions/20260902000000_runtime_settings.py apps/api/app/models/settings.py apps/api/app/models/__init__.py tests/unit/api/test_runtime_setting_model.py
git commit -m "feat(settings): runtime_settings table for UI-managed overrides"
```

---

### Task 6: API-side catalog and the settings service

**Files:**
- Create: `apps/api/app/services/settings_catalog_api.py`, `apps/api/app/services/settings_service.py`
- Test: `tests/unit/api/test_settings_service.py`

**Interfaces:**
- Consumes: `core_catalog()`, `CatalogEntry`, `GROUP_ORDER` (Task 4); `build_settings`, `nest`, `split_key`, `flatten_leaves`, `effective_source` (Task 3); `settings_secrets` (Task 2); `RuntimeSetting` (Task 5).
- Produces:
  ```python
  # settings_catalog_api.py
  API_EDITABLE: dict[str, dict]      # name -> {title, description, applies:"live", probe?}
  API_READONLY: dict[str, dict]      # name -> {title, description}; applies "restart", editable False, reason
  def api_catalog() -> list[CatalogEntry]
  def full_catalog() -> list[CatalogEntry]          # core + api, ordered by GROUP_ORDER
  def catalog_index() -> dict[str, CatalogEntry]    # key -> entry (cached)

  # settings_service.py
  class SettingsValidationError(Exception): errors: dict[str, str]
  @dataclass class ValueInfo: value: Any|None; is_set: bool|None; hint: str|None; source: str; updated_at: datetime|None; updated_by: uuid|None
  @dataclass class SaveResult: applied: list[str]; applies: dict[str, int]
  class SettingsService:
      def __init__(self, db: AsyncSession) -> None
      async def load_overrides(self) -> dict[str, Any]              # full keys, secrets decrypted
      async def values(self) -> dict[str, ValueInfo]
      async def save(self, changes: dict[str, Any], *, user_id, ip: str|None) -> SaveResult
      async def reset(self, keys: list[str], *, user_id, ip: str|None) -> list[str]
      def validate(self, merged_core: dict, merged_api: dict) -> None    # raises SettingsValidationError
  async def load_core_overrides(db) -> dict[str, Any]                  # convenience for the worker: paths without "core."
  ```

- [ ] **Step 1: Write the failing tests** (pure validation and value shaping; DB via a fake session)

```python
# tests/unit/api/test_settings_service.py
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.models import RuntimeSetting  # noqa: E402
from app.services import settings_service as svc  # noqa: E402
from app.services.settings_catalog_api import catalog_index, full_catalog  # noqa: E402


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))


def make_db(rows):
    db = MagicMock()
    db.execute = AsyncMock(return_value=FakeResult(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())


def test_full_catalog_has_core_and_api_entries():
    keys = {e.key for e in full_catalog()}
    assert "core.llm.provider" in keys
    assert "api.enrichment_enabled" in keys
    assert "api.debug" in keys
    ro = catalog_index()["api.debug"]
    assert ro.editable is False and ro.applies == "restart"
    assert catalog_index()["api.enrichment_enabled"].applies == "live"


def test_validate_rejects_bad_core_and_api_values():
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        s.validate({"negotiation.max_iterations": "x"}, {"enrichment_max_lookups": "y"})
    assert set(ei.value.errors) == {"core.negotiation.max_iterations", "api.enrichment_max_lookups"}


def test_validate_rejects_unknown_and_readonly_keys():
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        s.check_keys({"core.nope": 1, "api.debug": True})
    assert "core.nope" in ei.value.errors and "api.debug" in ei.value.errors


@pytest.mark.asyncio
async def test_save_is_atomic_on_validation_failure():
    db = make_db([])
    s = svc.SettingsService(db)
    with pytest.raises(svc.SettingsValidationError):
        await s.save({"core.llm.provider": "openai", "core.negotiation.max_iterations": "x"}, user_id=uuid.uuid4(), ip=None)
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_save_encrypts_secrets_and_reports_applies(key):
    db = make_db([])
    s = svc.SettingsService(db)
    res = await s.save({"core.llm.openai.api_key": "sk-secret-value-1234", "api.enrichment_enabled": False}, user_id=uuid.uuid4(), ip="127.0.0.1")
    assert sorted(res.applied) == ["api.enrichment_enabled", "core.llm.openai.api_key"]
    assert res.applies == {"next_job": 1, "live": 1}
    added = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], RuntimeSetting)]
    secret_row = next(r for r in added if r.key == "core.llm.openai.api_key")
    assert secret_row.is_secret and str(secret_row.value).startswith("enc:v1:")
    assert "sk-secret" not in str(secret_row.value)


@pytest.mark.asyncio
async def test_values_masks_secrets_and_labels_source(key):
    from maljan.core import settings_secrets as box
    rows = [
        RuntimeSetting(key="core.llm.openai.api_key", value=box.encrypt("sk-secret-value-1234"), is_secret=True),
        RuntimeSetting(key="core.negotiation.max_iterations", value=7, is_secret=False),
    ]
    s = svc.SettingsService(make_db(rows))
    vals = await s.values()
    sec = vals["core.llm.openai.api_key"]
    assert sec.value is None and sec.is_set is True and sec.hint == "1234" and sec.source == "ui"
    assert vals["core.negotiation.max_iterations"].value == 7
    assert vals["core.negotiation.max_iterations"].source == "ui"
    assert vals["core.chunking.overlap_tokens"].source in ("env", "default")


@pytest.mark.asyncio
async def test_save_secret_without_key_is_refused(monkeypatch):
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    s = svc.SettingsService(make_db([]))
    with pytest.raises(svc.SettingsValidationError) as ei:
        await s.save({"core.llm.openai.api_key": "x"}, user_id=None, ip=None)
    assert "SETTINGS_ENCRYPTION_KEY" in ei.value.errors["core.llm.openai.api_key"]
```

- [ ] **Step 2: Run** → FAIL (`ModuleNotFoundError`)

- [ ] **Step 3: Implement the API-side catalog**

```python
# apps/api/app/services/settings_catalog_api.py
"""The API's own knobs, joined with the core catalog.

APISettings is not importable from src/, so its entries are declared here:
an explicit editable list (runtime-safe, ``applies: live``) and an explicit
read-only list (bootstrap and infrastructure, ``applies: restart``). Anything
in APISettings that is in neither list is not shown at all.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import SecretStr

from app.config import APISettings
from maljan.core.settings_annotations import GROUP_ORDER
from maljan.core.settings_catalog import CatalogEntry, core_catalog

API_EDITABLE: dict[str, dict[str, Any]] = {
    "mock_mode_allowed": {"group": "api", "title": "Allow mock mode", "description": "Operator gate for mock analyses. A job still has to ask for mock mode in its own config; both switches must agree."},
    "enrichment_enabled": {"group": "enrichment", "title": "Post-verdict enrichment", "description": "Look up the report's domains and IPs at VirusTotal and AbuseIPDB after every analysis. Providers without a key are skipped."},
    "enrichment_max_lookups": {"group": "enrichment", "title": "Max lookups per kind", "description": "Cap on domains and on IPs sent to each provider per report."},
    "virustotal_api_key": {"group": "enrichment", "title": "VirusTotal API key", "description": "Used by enrichment and by the threat-intel MCP sidecar. Sample hashes, domains and IPs leave the host when this is set.", "probe": "virustotal"},
    "abuseipdb_api_key": {"group": "enrichment", "title": "AbuseIPDB API key", "description": "Used by enrichment and by the threat-intel MCP sidecar. IPs leave the host when this is set.", "probe": "abuseipdb"},
    "upload_max_bytes": {"group": "api", "title": "Upload size limit (bytes)", "description": "Uploads larger than this are rejected with 413 while streaming, before anything is stored."},
    "rate_limit_enabled": {"group": "api", "title": "Rate limiting", "description": "Per client IP and path, counted in Redis. Fails open when Redis is unreachable."},
    "rate_limit_requests": {"group": "api", "title": "Rate limit: requests", "description": "Requests allowed per window per IP and path."},
    "rate_limit_window_seconds": {"group": "api", "title": "Rate limit: window (s)", "description": "Length of the rate-limit window."},
    "login_max_attempts": {"group": "api", "title": "Login attempts before lockout", "description": "Failed logins per e-mail before the account is locked for the lockout period."},
    "login_lockout_seconds": {"group": "api", "title": "Login lockout (s)", "description": "How long a locked account stays locked."},
    "trusted_proxy_ips": {"group": "api", "title": "Trusted proxy IPs", "description": "Peers whose X-Forwarded-For header is believed for rate limiting. Exact IPs, one per entry."},
}

API_READONLY: dict[str, dict[str, Any]] = {
    "debug": {"title": "Debug mode", "description": "Verbose logging and relaxed placeholder checks. Set in .env; needs a restart."},
    "auth_disabled": {"title": "Authentication bypass", "description": "Every request is the seeded dev admin. Local development only. Set in .env."},
    "cors_origins": {"title": "CORS origins", "description": "Browsers allowed to call the API. Set in .env."},
    "database_url": {"title": "Database", "description": "Postgres DSN; credentials are masked here."},
    "redis_url": {"title": "Redis", "description": "Queue, events and rate-limit counters."},
    "minio_endpoint": {"title": "Object store", "description": "MinIO endpoint holding uploaded samples."},
    "qdrant_url": {"title": "Qdrant (API health probe)", "description": "Address the API pings on /health?deep=true."},
    "jwt_access_token_expire_minutes": {"title": "Access token lifetime (min)", "description": "Set in .env."},
    "jwt_refresh_token_expire_days": {"title": "Refresh token lifetime (days)", "description": "Set in .env."},
}

_MASK_URL = ("database_url",)


def _type_of(name: str, default: Any) -> tuple[str, bool]:
    if isinstance(default, SecretStr):
        return "secret", True
    if isinstance(default, bool):
        return "bool", False
    if isinstance(default, int):
        return "int", False
    if isinstance(default, float):
        return "float", False
    if isinstance(default, list):
        return "list", False
    return "str", False


def _masked(name: str, value: Any) -> Any:
    if name in _MASK_URL and isinstance(value, str) and "@" in value:
        head, _, tail = value.rpartition("@")
        scheme, _, _ = head.partition("://")
        return f"{scheme}://***@{tail}"
    return value


def api_catalog() -> list[CatalogEntry]:
    fields = APISettings.model_fields
    entries: list[CatalogEntry] = []
    for name, ann in API_EDITABLE.items():
        default = fields[name].default
        ftype, secret = _type_of(name, default)
        entries.append(CatalogEntry(
            key=f"api.{name}", namespace="api", path=name, type=ftype,
            default=None if secret else default, nullable=False, choices=None, minimum=None, maximum=None,
            secret=secret, group=ann["group"], title=ann["title"], description=ann["description"],
            applies="live", editable=True, reason=None, probe=ann.get("probe"),
        ))
    for name, ann in API_READONLY.items():
        default = fields[name].default
        ftype, secret = _type_of(name, default)
        entries.append(CatalogEntry(
            key=f"api.{name}", namespace="api", path=name, type=ftype,
            default=None if secret else _masked(name, default), nullable=False, choices=None, minimum=None, maximum=None,
            secret=secret, group="system", title=ann["title"], description=ann["description"],
            applies="restart", editable=False, reason="set in .env; restart required", probe=None,
        ))
    return entries


def full_catalog() -> list[CatalogEntry]:
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    return sorted(core_catalog() + api_catalog(), key=lambda e: (order[e.group], e.path))


@lru_cache(maxsize=1)
def catalog_index() -> dict[str, CatalogEntry]:
    return {e.key: e for e in full_catalog()}
```

- [ ] **Step 4: Implement the service**

```python
# apps/api/app/services/settings_service.py
"""Read and write runtime overrides, validating the merged models first."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import APISettings
from app.config import settings as api_settings
from app.database import async_session_factory
from app.models import AuditLog, RuntimeSetting
from app.services.settings_catalog_api import catalog_index
from maljan.core import settings_secrets as box
from maljan.core.config import Settings
from maljan.core.settings_overrides import (
    build_settings, effective_source, flatten_leaves, nest, split_key,
)


class SettingsValidationError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


@dataclass
class ValueInfo:
    value: Any | None
    is_set: bool | None
    hint: str | None
    source: str
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None


@dataclass
class SaveResult:
    applied: list[str] = field(default_factory=list)
    applies: dict[str, int] = field(default_factory=dict)


def _loc_to_key(ns: str, loc: tuple[Any, ...]) -> str:
    return f"{ns}." + ".".join(str(p) for p in loc if not isinstance(p, int))


class SettingsService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ---- reading -------------------------------------------------------
    async def _rows(self) -> list[RuntimeSetting]:
        res = await self.db.execute(select(RuntimeSetting))
        return list(res.scalars().all())

    async def load_overrides(self) -> dict[str, Any]:
        """Full keys -> plain values; secrets decrypted, or dropped if they cannot be."""
        out: dict[str, Any] = {}
        for row in await self._rows():
            if row.is_secret:
                try:
                    out[row.key] = box.decrypt(str(row.value))
                except box.SecretsUnavailable:
                    continue
            else:
                out[row.key] = row.value
        return out

    async def values(self) -> dict[str, ValueInfo]:
        index = catalog_index()
        rows = {r.key: r for r in await self._rows()}
        env_core = Settings()
        core_env = flatten_leaves(env_core, [e.path for e in index.values() if e.namespace == "core"])
        out: dict[str, ValueInfo] = {}
        for key, entry in index.items():
            row = rows.get(key)
            if entry.namespace == "core":
                env_value = core_env[entry.path]
            else:
                raw = getattr(api_settings, entry.path)
                env_value = raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            if entry.secret:
                if row is not None:
                    try:
                        plain = box.decrypt(str(row.value))
                    except box.SecretsUnavailable:
                        plain = ""
                    src = "ui"
                else:
                    plain = env_value or ""
                    src = effective_source(overridden=False, env_value=bool(plain), default_value=False)
                out[key] = ValueInfo(None, bool(plain), box.hint(plain) if plain else None, src,
                                     row.updated_at if row else None, row.updated_by if row else None)
                continue
            if row is not None:
                out[key] = ValueInfo(row.value, None, None, "ui", row.updated_at, row.updated_by)
            else:
                shown = env_value if entry.editable else entry.default if entry.default is not None else env_value
                out[key] = ValueInfo(shown, None, None,
                                     effective_source(overridden=False, env_value=env_value, default_value=entry.default))
        return out

    # ---- validation ----------------------------------------------------
    def check_keys(self, changes: dict[str, Any]) -> None:
        index = catalog_index()
        errors = {}
        for key in changes:
            entry = index.get(key)
            if entry is None:
                errors[key] = "unknown setting"
            elif not entry.editable:
                errors[key] = entry.reason or "read-only"
            elif entry.secret and changes[key] is not None and not box.is_available():
                errors[key] = "secrets cannot be stored: SETTINGS_ENCRYPTION_KEY is not set"
        if errors:
            raise SettingsValidationError(errors)

    def validate(self, merged_core: dict[str, Any], merged_api: dict[str, Any]) -> None:
        errors: dict[str, str] = {}
        try:
            build_settings(merged_core)
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("core", err["loc"])] = err["msg"]
        try:
            APISettings(**nest(merged_api))
        except ValidationError as exc:
            for err in exc.errors():
                errors[_loc_to_key("api", err["loc"])] = err["msg"]
        if errors:
            raise SettingsValidationError(errors)

    # ---- writing -------------------------------------------------------
    async def save(self, changes: dict[str, Any], *, user_id: uuid.UUID | None, ip: str | None) -> SaveResult:
        self.check_keys(changes)
        index = catalog_index()
        current = await self.load_overrides()
        merged = {**current}
        for key, value in changes.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        core = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("core.")}
        api = {split_key(k)[1]: v for k, v in merged.items() if k.startswith("api.")}
        self.validate(core, api)

        rows = {r.key: r for r in await self._rows()}
        before: dict[str, Any] = {}
        after: dict[str, Any] = {}
        result = SaveResult()
        for key, value in changes.items():
            entry = index[key]
            existing = rows.get(key)
            before[key] = ("set" if existing else "unset") if entry.secret else (existing.value if existing else None)
            if value is None:
                if existing is not None:
                    await self.db.delete(existing)
                after[key] = "unset" if entry.secret else None
            else:
                stored = box.encrypt(str(value)) if entry.secret else value
                if existing is None:
                    self.db.add(RuntimeSetting(key=key, value=stored, is_secret=entry.secret, updated_by=user_id))
                else:
                    existing.value = stored
                    existing.is_secret = entry.secret
                    existing.updated_by = user_id
                after[key] = "set" if entry.secret else value
            result.applied.append(key)
            result.applies[entry.applies] = result.applies.get(entry.applies, 0) + 1
        await self.db.commit()
        await _audit(user_id, "settings.update", {"changed": list(changes), "before": before, "after": after}, ip)
        return result

    async def reset(self, keys: list[str], *, user_id: uuid.UUID | None, ip: str | None) -> list[str]:
        rows = {r.key: r for r in await self._rows()}
        removed = []
        for key in keys:
            if key in rows:
                await self.db.delete(rows[key])
                removed.append(key)
        await self.db.commit()
        if removed:
            await _audit(user_id, "settings.reset", {"keys": removed}, ip)
        return removed


async def _audit(user_id: uuid.UUID | None, action: str, details: dict[str, Any], ip: str | None) -> None:
    """Independent transaction, same reasoning as auth._audit; best effort."""
    try:
        async with async_session_factory() as s:
            s.add(AuditLog(user_id=user_id, action=action, resource_type="settings",
                           resource_id=None, details=details, ip_address=ip or None))
            await s.commit()
    except Exception:  # noqa: BLE001 - audit must never turn a save into a 500
        pass


async def load_core_overrides(db: AsyncSession) -> dict[str, Any]:
    """For the worker: core paths without the namespace prefix."""
    overrides = await SettingsService(db).load_overrides()
    return {split_key(k)[1]: v for k, v in overrides.items() if k.startswith("core.")}
```
`values()` ordering note: `flatten_leaves` is called once per request over the whole core model; fine at 136 leaves.

- [ ] **Step 5: Run tests** → `uv run pytest tests/unit/api/test_settings_service.py -v` → PASS; `make lint format-check typecheck`.

- [ ] **Step 6: Commit**

```bash
git add apps/api/app/services/settings_catalog_api.py apps/api/app/services/settings_service.py tests/unit/api/test_settings_service.py
git commit -m "feat(settings): service that validates the merged models before writing a single override"
```

---

### Task 7: `RuntimeConfig` and the read sites that must honour live overrides

**Files:**
- Create: `apps/api/app/runtime_config.py`
- Modify: `apps/api/app/worker/enrich_worker.py:78,104-105,117`, `apps/api/app/api/v1/samples.py:84-88`, `apps/api/app/auth/throttle.py:82,104`, `apps/api/app/api/v1/system.py:53-59`, `apps/api/app/middleware/rate_limit_middleware.py` (where `settings.rate_limit_*` and `trusted_proxy_ips` are read), `apps/api/app/worker/analysis_worker.py:283` (`mock_mode_allowed`)
- Test: `tests/unit/api/test_runtime_config.py`

**Interfaces:**
- Produces:
  ```python
  class RuntimeConfig:
      def __init__(self, session_factory, ttl_seconds: float = 5.0, clock=time.monotonic) -> None
      async def get(self, name: str) -> Any          # override for "api.<name>" if present, else getattr(settings, name) (SecretStr unwrapped)
      async def get_secret(self, name: str) -> str   # "" when unset
      def invalidate(self) -> None
  runtime_config = RuntimeConfig(async_session_factory)
  ```

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_runtime_config.py
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.runtime_config import RuntimeConfig  # noqa: E402


def factory_returning(overrides: dict):
    calls = {"n": 0}

    @asynccontextmanager
    async def _session():
        calls["n"] += 1
        db = MagicMock()
        yield db

    async def _load(_db):
        return dict(overrides)

    return _session, _load, calls


@pytest.mark.asyncio
async def test_override_wins_and_is_cached_within_ttl(monkeypatch):
    now = [100.0]
    session, load, calls = factory_returning({"api.enrichment_enabled": False})
    monkeypatch.setattr("app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db))
    rc = RuntimeConfig(session, ttl_seconds=5, clock=lambda: now[0])
    assert await rc.get("enrichment_enabled") is False
    assert await rc.get("enrichment_enabled") is False
    assert calls["n"] == 1
    now[0] += 6
    await rc.get("enrichment_enabled")
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_falls_back_to_static_settings(monkeypatch):
    session, load, _ = factory_returning({})
    monkeypatch.setattr("app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db))
    rc = RuntimeConfig(session, ttl_seconds=5)
    assert isinstance(await rc.get("upload_max_bytes"), int)
    assert isinstance(await rc.get_secret("virustotal_api_key"), str)


@pytest.mark.asyncio
async def test_db_failure_falls_back_and_does_not_raise(monkeypatch):
    @asynccontextmanager
    async def boom():
        raise RuntimeError("db down")
        yield
    rc = RuntimeConfig(boom, ttl_seconds=5)
    assert isinstance(await rc.get("rate_limit_requests"), int)
```

- [ ] **Step 2: Run** → FAIL

- [ ] **Step 3: Implement**

```python
# apps/api/app/runtime_config.py
"""Live reads of the API's runtime-safe knobs.

``api.*`` overrides saved from the UI are read through here with a short TTL,
so a change is effective on every API process within seconds without a
restart. Anything not overridden falls back to the static APISettings, and so
does everything when the database cannot be reached: a settings read must
never take a request down.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from pydantic import SecretStr

from app.config import settings
from app.database import async_session_factory
from app.services.settings_service import SettingsService

logger = logging.getLogger(__name__)


class RuntimeConfig:
    def __init__(self, session_factory, ttl_seconds: float = 5.0, clock=time.monotonic) -> None:
        self._factory = session_factory
        self._ttl = ttl_seconds
        self._clock = clock
        self._cache: dict[str, Any] = {}
        self._loaded_at: float | None = None

    async def _overrides(self) -> dict[str, Any]:
        now = self._clock()
        if self._loaded_at is not None and now - self._loaded_at < self._ttl:
            return self._cache
        try:
            async with self._factory() as db:
                self._cache = await SettingsService(db).load_overrides()
        except Exception as exc:  # noqa: BLE001 - fall back to static settings
            logger.warning("runtime settings unavailable, using static configuration: %s", exc)
        self._loaded_at = now
        return self._cache

    async def get(self, name: str) -> Any:
        overrides = await self._overrides()
        if f"api.{name}" in overrides:
            return overrides[f"api.{name}"]
        value = getattr(settings, name)
        return value.get_secret_value() if isinstance(value, SecretStr) else value

    async def get_secret(self, name: str) -> str:
        value = await self.get(name)
        return str(value) if value else ""

    def invalidate(self) -> None:
        self._loaded_at = None


runtime_config = RuntimeConfig(async_session_factory)
```

- [ ] **Step 4: Switch the read sites**

Each site keeps its import of `settings` for everything else and reads the listed knobs through `runtime_config` (`from app.runtime_config import runtime_config`):

- `enrich_worker.py`: `if not await runtime_config.get("enrichment_enabled")`; `vt_key = await runtime_config.get_secret("virustotal_api_key") or None`; same for `abuseipdb_api_key`; `max_lookups_per_kind=await runtime_config.get("enrichment_max_lookups")`.
- `samples.py` upload: read `limit = await runtime_config.get("upload_max_bytes")` once at the top of the route handler and pass it into `_streaming_hashes` (add a `max_bytes: int` parameter; replace the two `settings.upload_max_bytes` uses inside it).
- `throttle.py`: `await runtime_config.get("login_lockout_seconds")` and `await runtime_config.get("login_max_attempts")` (both call sites are already `async`).
- `system.py` status: `vt_key = await runtime_config.get_secret("virustotal_api_key")`, `abuse_key = …`, `enrichment_enabled=bool(await runtime_config.get("enrichment_enabled"))`, `mock_mode_allowed=bool(await runtime_config.get("mock_mode_allowed"))`.
- `rate_limit_middleware.py`: in `dispatch`, read `enabled`, `requests`, `window_seconds`, `trusted_proxy_ips` via `await runtime_config.get(...)` before the existing logic; keep the fail-open behaviour.
- `analysis_worker.py:283`: `_mock_active = bool(await runtime_config.get("mock_mode_allowed") and _mock_requested)` and the two log lines that print `settings.mock_mode_allowed` print the fetched value.

Existing tests that patch `settings.<knob>` on these modules (`tests/api/test_system_status.py`, `tests/api/test_enrich_worker.py`) are updated to patch `runtime_config` instead:
```python
from unittest.mock import AsyncMock
with patch("app.api.v1.system.runtime_config.get", AsyncMock(side_effect=lambda n: {"enrichment_enabled": True, "mock_mode_allowed": True}[n])), \
     patch("app.api.v1.system.runtime_config.get_secret", AsyncMock(side_effect=lambda n: {"virustotal_api_key": "vt-secret-key", "abuseipdb_api_key": ""}[n])):
```

- [ ] **Step 5: Run** → `uv run pytest tests/unit/api/test_runtime_config.py tests/api -q` → PASS; `make lint format-check typecheck`.

- [ ] **Step 6: Commit**

```bash
git add apps/api/app/runtime_config.py apps/api/app/worker/enrich_worker.py apps/api/app/api/v1/samples.py apps/api/app/auth/throttle.py apps/api/app/api/v1/system.py apps/api/app/middleware/rate_limit_middleware.py apps/api/app/worker/analysis_worker.py tests/unit/api/test_runtime_config.py tests/api
git commit -m "feat(settings): api knobs read through a five-second runtime cache"
```

---
### Task 8: Schemas and routes

**Files:**
- Create: `apps/api/app/schemas/settings.py`, `apps/api/app/api/v1/settings.py`
- Modify: `apps/api/app/main.py:300-316` (register the router)
- Test: `tests/api/test_settings_routes.py`

**Interfaces:**
- Consumes: `SettingsService`, `SettingsValidationError`, `ValueInfo`, `SaveResult` (Task 6); `full_catalog`, `catalog_index` (Task 6); `GROUP_ORDER` (Task 4); `require_admin`, `get_db`.
- Produces routes under `/api/v1/settings`: `GET /schema`, `GET /`, `PATCH /`, `DELETE /{key}`, `DELETE /?group=`, `GET /export`, and (Task 9) `POST /test/{probe}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_settings_routes.py
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
from app.services.settings_service import SaveResult, SettingsValidationError, ValueInfo  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="00000000-0000-0000-0000-000000000001")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_schema_lists_groups_in_order_and_entries(client):
    r = client.get("/api/v1/settings/schema")
    assert r.status_code == 200
    groups = r.json()["groups"]
    assert groups[0]["key"] == "llm"
    keys = {e["key"] for g in groups for e in g["entries"]}
    assert {"core.llm.provider", "api.enrichment_enabled", "api.debug"} <= keys
    ro = next(e for g in groups for e in g["entries"] if e["key"] == "api.debug")
    assert ro["editable"] is False


def test_values_never_contain_secret_values(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "env"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings")
    assert r.status_code == 200
    body = r.json()["values"]
    assert body["core.llm.openai.api_key"] == {"value": None, "is_set": True, "hint": "1234", "source": "ui", "updated_at": None, "updated_by": None}
    assert body["core.llm.provider"]["value"] == "openai"


def test_patch_returns_applies_summary(client):
    with patch("app.api.v1.settings.SettingsService.save", AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1}))):
        r = client.patch("/api/v1/settings", json={"changes": {"core.llm.provider": "openai"}})
    assert r.status_code == 200
    assert r.json() == {"applied": ["core.llm.provider"], "applies": {"next_job": 1}}


def test_patch_validation_error_is_422_with_field_map(client):
    with patch("app.api.v1.settings.SettingsService.save", AsyncMock(side_effect=SettingsValidationError({"core.negotiation.max_iterations": "Input should be a valid integer"}))):
        r = client.patch("/api/v1/settings", json={"changes": {"core.negotiation.max_iterations": "x"}})
    assert r.status_code == 422
    assert r.json()["errors"] == {"core.negotiation.max_iterations": "Input should be a valid integer"}


def test_reset_one_and_group(client):
    with patch("app.api.v1.settings.SettingsService.reset", AsyncMock(return_value=["core.llm.provider"])) as reset:
        r = client.delete("/api/v1/settings/core.llm.provider")
        assert r.status_code == 200 and r.json() == {"reset": ["core.llm.provider"]}
        r = client.delete("/api/v1/settings?group=llm")
        assert r.status_code == 200
        keys_passed = reset.call_args_list[1].args[0]
        assert all(k.startswith("core.llm.") for k in keys_passed) and "core.llm.provider" in keys_passed


def test_export_is_env_syntax_with_secrets_masked(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "ui"),
        "core.chunking.overlap_tokens": ValueInfo(200, None, None, "default"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "LLM__OPENAI__API_KEY=***" in r.text
    assert "LLM__PROVIDER=openai" in r.text
    assert "CHUNKING__OVERLAP_TOKENS" not in r.text  # only overrides are exported


def test_non_admin_is_rejected():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    r = TestClient(app).get("/api/v1/settings/schema")
    assert r.status_code in (401, 403)
```

- [ ] **Step 2: Run** → FAIL (`ModuleNotFoundError: app.api.v1.settings`)

- [ ] **Step 3: Implement schemas**

```python
# apps/api/app/schemas/settings.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CatalogEntryDTO(BaseModel):
    key: str
    namespace: str
    path: str
    type: str
    default: Any = None
    nullable: bool
    choices: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None
    secret: bool
    group: str
    title: str
    description: str
    applies: str
    editable: bool
    reason: str | None = None
    probe: str | None = None


class GroupDTO(BaseModel):
    key: str
    title: str
    entries: list[CatalogEntryDTO]


class SchemaResponse(BaseModel):
    groups: list[GroupDTO]
    secrets_available: bool


class ValueDTO(BaseModel):
    value: Any = None
    is_set: bool | None = None
    hint: str | None = None
    source: str
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None


class ValuesResponse(BaseModel):
    values: dict[str, ValueDTO]


class PatchRequest(BaseModel):
    changes: dict[str, Any] = Field(min_length=1)


class PatchResponse(BaseModel):
    applied: list[str]
    applies: dict[str, int]


class ResetResponse(BaseModel):
    reset: list[str]


class ProbeRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class ProbeResponse(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None
```

- [ ] **Step 4: Implement routes**

```python
# apps/api/app/api/v1/settings.py
"""Runtime settings: the catalog, the effective values, and the overrides."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import require_admin
from app.models.user import User
from app.schemas.settings import (
    CatalogEntryDTO, GroupDTO, PatchRequest, PatchResponse, ProbeRequest, ProbeResponse,
    ResetResponse, SchemaResponse, ValueDTO, ValuesResponse,
)
from app.services.settings_catalog_api import catalog_index, full_catalog
from app.services.settings_probes import PROBES, run_probe
from app.services.settings_service import SettingsService, SettingsValidationError
from maljan.core import settings_secrets as box
from maljan.core.settings_annotations import GROUP_ORDER

router = APIRouter(prefix="/settings", tags=["Settings"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/schema", response_model=SchemaResponse)
async def get_schema(_: User = Depends(require_admin)) -> SchemaResponse:
    available = box.is_available()
    by_group: dict[str, list[CatalogEntryDTO]] = {}
    for e in full_catalog():
        d = e.to_dict()
        if e.secret and e.editable and not available:
            d["editable"] = False
            d["reason"] = "SETTINGS_ENCRYPTION_KEY is not set; secrets stay in .env"
        by_group.setdefault(e.group, []).append(CatalogEntryDTO(**d))
    groups = [GroupDTO(key=g, title=t, entries=by_group[g]) for g, t in GROUP_ORDER if g in by_group]
    return SchemaResponse(groups=groups, secrets_available=available)


@router.get("", response_model=ValuesResponse)
async def get_values(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)) -> ValuesResponse:
    vals = await SettingsService(db).values()
    return ValuesResponse(values={k: ValueDTO(**vars(v)) for k, v in vals.items()})


@router.patch("", response_model=PatchResponse)
async def patch_values(
    body: PatchRequest, request: Request, user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    try:
        res = await SettingsService(db).save(body.changes, user_id=user.id, ip=_client_ip(request))
    except SettingsValidationError as exc:
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"errors": exc.errors})
    return PatchResponse(applied=res.applied, applies=res.applies)


@router.delete("", response_model=ResetResponse)
async def reset_group(
    request: Request, group: str = Query(...), user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ResetResponse:
    keys = [e.key for e in full_catalog() if e.group == group and e.editable]
    if not keys:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown group: {group}")
    return ResetResponse(reset=await SettingsService(db).reset(keys, user_id=user.id, ip=_client_ip(request)))


@router.delete("/{key}", response_model=ResetResponse)
async def reset_key(
    key: str, request: Request, user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ResetResponse:
    if key not in catalog_index():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown setting: {key}")
    return ResetResponse(reset=await SettingsService(db).reset([key], user_id=user.id, ip=_client_ip(request)))


@router.get("/export", response_class=PlainTextResponse)
async def export_overrides(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)) -> str:
    index = catalog_index()
    lines = ["# Maljan runtime overrides (UI). Secrets are not exported."]
    for key, info in (await SettingsService(db).values()).items():
        if info.source != "ui":
            continue
        entry = index[key]
        env_name = entry.path.upper().replace(".", "__")
        value = "***" if entry.secret else info.value
        lines.append(f"{env_name}={value}")
    return "\n".join(lines) + "\n"


@router.post("/test/{probe}", response_model=ProbeResponse)
async def test_probe(
    probe: str, body: ProbeRequest, _: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
) -> ProbeResponse:
    if probe not in PROBES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown probe: {probe}")
    stored = await SettingsService(db).load_overrides()
    result = await run_probe(probe, body.values, stored)
    return ProbeResponse(**vars(result))
```
Register in `main.py` next to the others: `from app.api.v1.settings import router as settings_router` and `app.include_router(settings_router, prefix=api_prefix)`.

Until Task 9 lands, add a stub `apps/api/app/services/settings_probes.py` with `PROBES: dict[str, object] = {}` and `async def run_probe(name, values, stored): raise KeyError(name)` so the module imports; Task 9 replaces it.

- [ ] **Step 5: Run** → `uv run pytest tests/api/test_settings_routes.py -v` → PASS; `make lint format-check typecheck`.

- [ ] **Step 6: Commit**

```bash
git add apps/api/app/schemas/settings.py apps/api/app/api/v1/settings.py apps/api/app/services/settings_probes.py apps/api/app/main.py tests/api/test_settings_routes.py
git commit -m "feat(settings): admin routes for the catalog, values, overrides and export"
```

---

### Task 9: Connection probes

**Files:**
- Replace: `apps/api/app/services/settings_probes.py`
- Test: `tests/unit/api/test_settings_probes.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass class ProbeResult: ok: bool; latency_ms: int; detail: str; models: list[str] | None = None
  PROBES: dict[str, Callable[[dict[str, Any]], Awaitable[ProbeResult]]]   # "llm","ghidra","cape","qdrant","redis","virustotal","abuseipdb"
  async def run_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult
  ```
  `values` are full keys from the unsaved form; a secret given as `None` means "use the stored override, else the environment". `run_probe` resolves the merged view by building `Settings`/reading `settings`, then calls the probe with plain values.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_settings_probes.py
import sys
from pathlib import Path

import httpx
import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services import settings_probes as probes  # noqa: E402


def transport(handler):
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_llm_probe_lists_models_and_completes(monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path.endswith("/models"):
            assert req.headers["authorization"] == "Bearer k"
            return httpx.Response(200, json={"data": [{"id": "qwen"}, {"id": "other"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10))
    r = await probes.probe_llm({"base_url": "http://llm/v1", "api_key": "k", "expert_model": "qwen"})
    assert r.ok and r.models == ["qwen", "other"] and "qwen" in r.detail


@pytest.mark.asyncio
async def test_ghidra_probe_reports_http_error(monkeypatch):
    monkeypatch.setattr(probes, "_client", lambda: httpx.AsyncClient(transport=transport(lambda r: httpx.Response(401)), timeout=10))
    r = await probes.probe_ghidra({"url": "http://ghidra:8089", "auth_token": "t"})
    assert r.ok is False and "401" in r.detail


@pytest.mark.asyncio
async def test_timeout_is_reported_not_raised(monkeypatch):
    def handler(_r):
        raise httpx.ReadTimeout("slow")
    monkeypatch.setattr(probes, "_client", lambda: httpx.AsyncClient(transport=transport(handler), timeout=10))
    r = await probes.probe_qdrant({"url": "http://q:6333", "collection": "c"})
    assert r.ok is False and "timeout" in r.detail.lower()


@pytest.mark.asyncio
async def test_run_probe_merges_form_over_stored_and_env(monkeypatch):
    seen = {}
    async def fake(values):
        seen.update(values)
        return probes.ProbeResult(True, 1, "x")
    monkeypatch.setitem(probes.PROBES, "llm", fake)
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    await probes.run_probe("llm", {"core.llm.openai.base_url": "http://form/v1", "core.llm.openai.api_key": None}, {"core.llm.openai.expert_model": "stored-model"})
    assert seen == {"base_url": "http://form/v1", "api_key": "env-key", "expert_model": "stored-model", "judge_model": seen["judge_model"], "provider": seen["provider"]}


@pytest.mark.asyncio
async def test_unknown_probe():
    with pytest.raises(KeyError):
        await probes.run_probe("nope", {}, {})
```

- [ ] **Step 2: Run** → FAIL

- [ ] **Step 3: Implement**

```python
# apps/api/app/services/settings_probes.py
"""Connection tests for settings the UI is about to save. Nothing is persisted."""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from redis.asyncio import Redis

from app.config import settings as api_settings
from maljan.core.settings_overrides import build_settings, split_key

TIMEOUT = 10.0


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT)


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


async def _get(url: str, headers: dict[str, str] | None = None) -> tuple[bool, str, httpx.Response | None]:
    try:
        async with _client() as c:
            r = await c.get(url, headers=headers)
        return r.status_code < 400, f"HTTP {r.status_code}", r
    except httpx.TimeoutException:
        return False, f"timeout after {int(TIMEOUT)} s", None
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__}: {exc}", None


async def probe_llm(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    base = (v.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    headers = {"Authorization": f"Bearer {v.get('api_key') or 'none'}"}
    ok, detail, r = await _get(f"{base}/models", headers)
    if not ok or r is None:
        return ProbeResult(False, _ms(t0), f"model list: {detail}")
    models = [m.get("id", "") for m in r.json().get("data", [])]
    model = v.get("expert_model") or (models[0] if models else "")
    try:
        async with _client() as c:
            cr = await c.post(f"{base}/chat/completions", headers=headers,
                              json={"model": model, "max_tokens": 8, "messages": [{"role": "user", "content": "Reply with OK."}]})
    except httpx.TimeoutException:
        return ProbeResult(False, _ms(t0), f"{len(models)} models listed; completion timed out", models)
    except httpx.HTTPError as exc:
        return ProbeResult(False, _ms(t0), f"{len(models)} models listed; completion failed: {exc}", models)
    if cr.status_code >= 400:
        return ProbeResult(False, _ms(t0), f"{len(models)} models listed; completion with {model!r}: HTTP {cr.status_code}", models)
    return ProbeResult(True, _ms(t0), f"{len(models)} models listed; completion with {model!r} succeeded", models)


async def probe_ghidra(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Bearer {v['auth_token']}"} if v.get("auth_token") else None
    ok, detail, _ = await _get(f"{str(v.get('url') or '').rstrip('/')}/check_connection", headers)
    return ProbeResult(ok, _ms(t0), detail)


async def probe_cape(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Token {v['api_token']}"} if v.get("api_token") else None
    ok, detail, _ = await _get(f"{str(v.get('base_url') or '').rstrip('/')}/apiv2/tasks/view/1/", headers)
    return ProbeResult(ok, _ms(t0), detail)


async def probe_qdrant(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    base = str(v.get("url") or "").rstrip("/")
    ok, detail, _ = await _get(f"{base}/readyz")
    if not ok:
        return ProbeResult(False, _ms(t0), f"readyz: {detail}")
    ok2, detail2, _ = await _get(f"{base}/collections/{v.get('collection')}")
    return ProbeResult(True, _ms(t0), f"ready; collection {v.get('collection')!r} {'exists' if ok2 else 'missing (' + detail2 + '), created on first write'}")


async def probe_redis(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    try:
        r = Redis.from_url(str(v.get("url") or api_settings.redis_url), socket_timeout=TIMEOUT)
        pong = await r.ping()
        await r.aclose()
        return ProbeResult(bool(pong), _ms(t0), "PONG" if pong else "no PONG")
    except Exception as exc:  # noqa: BLE001 - reported to the operator
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")


async def probe_virustotal(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    # /ip_addresses/<public ip> validates any key; /users/current needs a user-scoped one.
    ok, detail, _ = await _get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                               {"x-apikey": str(v.get("api_key") or "")})
    return ProbeResult(ok, _ms(t0), detail)


async def probe_abuseipdb(v: dict[str, Any]) -> ProbeResult:
    t0 = time.perf_counter()
    ok, detail, _ = await _get("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
                               {"Key": str(v.get("api_key") or ""), "Accept": "application/json"})
    return ProbeResult(ok, _ms(t0), detail)


PROBES: dict[str, Callable[[dict[str, Any]], Awaitable[ProbeResult]]] = {
    "llm": probe_llm, "ghidra": probe_ghidra, "cape": probe_cape, "qdrant": probe_qdrant,
    "redis": probe_redis, "virustotal": probe_virustotal, "abuseipdb": probe_abuseipdb,
}

# Which settings each probe reads, and the short name it gets them under.
_INPUTS: dict[str, dict[str, str]] = {
    "llm": {"core.llm.provider": "provider", "core.llm.openai.base_url": "base_url", "core.llm.openai.api_key": "api_key",
            "core.llm.openai.expert_model": "expert_model", "core.llm.openai.judge_model": "judge_model"},
    "ghidra": {"core.mcp.ghidra.url": "url", "core.mcp.ghidra.auth_token": "auth_token"},
    "cape": {"core.sandbox.cape2_base_url": "base_url", "core.sandbox.cape2_api_token": "api_token"},
    "qdrant": {"core.memory.qdrant_url": "url", "core.memory.qdrant_collection": "collection"},
    "redis": {},
    "virustotal": {"api.virustotal_api_key": "api_key"},
    "abuseipdb": {"api.abuseipdb_api_key": "api_key"},
}


def _unwrap(value: Any) -> Any:
    return value.get_secret_value() if hasattr(value, "get_secret_value") else value


async def run_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult:
    probe = PROBES[name]
    core_layer = {split_key(k)[1]: v for k, v in stored.items() if k.startswith("core.")}
    core_layer.update({split_key(k)[1]: v for k, v in values.items() if k.startswith("core.") and v is not None})
    core = build_settings(core_layer)
    resolved: dict[str, Any] = {}
    for key, short in _INPUTS[name].items():
        ns, path = split_key(key)
        if key in values and values[key] is not None:
            resolved[short] = values[key]
        elif key in stored:
            resolved[short] = stored[key]
        elif ns == "core":
            cursor: Any = core
            for part in path.split("."):
                cursor = getattr(cursor, part)
            resolved[short] = _unwrap(cursor)
        else:
            resolved[short] = _unwrap(getattr(api_settings, path))
    return await probe(resolved)
```

- [ ] **Step 4: Run** → `uv run pytest tests/unit/api/test_settings_probes.py tests/api/test_settings_routes.py -v` → PASS; quality gate.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/services/settings_probes.py tests/unit/api/test_settings_probes.py
git commit -m "feat(settings): connection probes for the LLM, Ghidra, CAPE, Qdrant, Redis and the intel keys"
```

---

### Task 10: The worker reads overrides at the start of every job

**Files:**
- Modify: `apps/api/app/worker/analysis_worker.py:255-268` and where `run_summary` is passed into the persisted `AnalysisReport` (search `run_summary=` in the same file)
- Test: `tests/unit/api/test_worker_settings_overrides.py`

**Interfaces:**
- Consumes: `load_core_overrides(db)` (Task 6), `build_settings`, `public_snapshot` (Task 3), `core_catalog` (Task 4).
- Produces: `analysis_worker.build_job_settings(overrides: dict, job_config: dict | None) -> Settings`; `run_summary["settings_snapshot"]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/api/test_worker_settings_overrides.py
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import build_job_settings  # noqa: E402


def test_override_applies_and_job_config_still_wins():
    s = build_job_settings({"negotiation.max_iterations": 7, "llm.provider": "ollama"}, None)
    assert s.negotiation.max_iterations == 7 and s.llm.provider == "ollama"
    s2 = build_job_settings({"negotiation.max_iterations": 7}, {"max_iterations": 2, "llm_provider": "openai"})
    assert s2.negotiation.max_iterations == 2 and s2.llm.provider == "openai"


def test_snapshot_masks_secrets(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    from app.worker.analysis_worker import settings_snapshot
    snap = settings_snapshot(build_job_settings({}, None))
    assert snap["llm.openai.api_key"] == "***"
    assert "env-key" not in str(snap)
```

- [ ] **Step 2: Run** → FAIL (`ImportError: build_job_settings`)

- [ ] **Step 3: Implement**

Add near the top of `analysis_worker.py` (after imports):
```python
from maljan.core.settings_catalog import core_catalog
from maljan.core.settings_overrides import build_settings, public_snapshot

_SECRET_PATHS = [e.path for e in core_catalog() if e.secret]


def build_job_settings(overrides: dict, job_config: dict | None):
    """UI overrides layered over the environment, then the job's own config on top."""
    core_settings = build_settings(overrides)
    if job_config:
        if "max_iterations" in job_config:
            core_settings.negotiation.max_iterations = job_config["max_iterations"]
        if "llm_provider" in job_config:
            core_settings.llm.provider = job_config["llm_provider"]
    return core_settings


def settings_snapshot(core_settings) -> dict:
    return public_snapshot(core_settings, _SECRET_PATHS)
```
Replace lines 263-268:
```python
            from app.services.settings_service import load_core_overrides

            overrides = await load_core_overrides(db)
            core_settings = build_job_settings(overrides, job.config)
            if overrides:
                logger.info("Applying %d runtime setting override(s) from the UI.", len(overrides))
```
Where `run_summary` is built for the `AnalysisReport`, add `run_summary["settings_snapshot"] = settings_snapshot(core_settings)` before it is persisted (the dict is JSON; secrets already masked).

- [ ] **Step 4: Run** → `uv run pytest tests/unit/api/test_worker_settings_overrides.py tests/unit/api -q` → PASS; quality gate.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/worker/analysis_worker.py tests/unit/api/test_worker_settings_overrides.py
git commit -m "feat(settings): the worker builds each job's Settings from the UI overrides and records a masked snapshot"
```

---
### Task 11: Frontend types and API client methods

**Files:**
- Create: `apps/web/src/types/settings.ts`
- Modify: `apps/web/src/lib/api.ts` (add six methods next to the System block, around line 426)

**Interfaces:**
- Produces:
  ```ts
  // types/settings.ts
  export type FieldType = "bool" | "int" | "float" | "str" | "secret" | "enum" | "list" | "dict" | "json";
  export type Applies = "next_job" | "live" | "restart";
  export interface CatalogEntry { key: string; namespace: "core" | "api"; path: string; type: FieldType; default: unknown; nullable: boolean; choices: string[] | null; minimum: number | null; maximum: number | null; secret: boolean; group: string; title: string; description: string; applies: Applies; editable: boolean; reason: string | null; probe: string | null; }
  export interface SettingsGroup { key: string; title: string; entries: CatalogEntry[]; }
  export interface SettingsSchema { groups: SettingsGroup[]; secrets_available: boolean; }
  export interface SettingValue { value: unknown; is_set: boolean | null; hint: string | null; source: "default" | "env" | "ui"; updated_at: string | null; updated_by: string | null; }
  export interface SettingsValues { values: Record<string, SettingValue>; }
  export interface PatchResult { applied: string[]; applies: Record<Applies, number>; }
  export interface ProbeResult { ok: boolean; latency_ms: number; detail: string; models: string[] | null; }
  export class SettingsValidationError extends Error { constructor(public errors: Record<string, string>) { super("validation failed"); } }
  ```
  `api.getSettingsSchema(): Promise<SettingsSchema>`, `api.getSettingsValues(): Promise<SettingsValues>`, `api.patchSettings(changes: Record<string, unknown>): Promise<PatchResult>` (throws `SettingsValidationError` on 422), `api.resetSetting(key): Promise<{reset: string[]}>`, `api.resetSettingsGroup(group): Promise<{reset: string[]}>`, `api.testSettingsProbe(probe, values): Promise<ProbeResult>`, `api.exportSettings(): Promise<string>`.

- [ ] **Step 1: Add the types file** with the interfaces above verbatim.

- [ ] **Step 2: Add the client methods**

```ts
  /* ── Runtime settings (admin) ─────────────────────── */
  getSettingsSchema() {
    return this.request<SettingsSchema>("/api/v1/settings/schema");
  }

  getSettingsValues() {
    return this.request<SettingsValues>("/api/v1/settings");
  }

  async patchSettings(changes: Record<string, unknown>): Promise<PatchResult> {
    const token = this.getToken();
    const res = await fetch(`${this.baseUrl}/api/v1/settings`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ changes }),
    });
    if (res.status === 422) {
      const body = (await res.json().catch(() => ({}))) as { errors?: Record<string, string> };
      throw new SettingsValidationError(body.errors ?? {});
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `Request failed: ${res.status}`);
    }
    return res.json();
  }

  resetSetting(key: string) {
    return this.request<{ reset: string[] }>(`/api/v1/settings/${encodeURIComponent(key)}`, { method: "DELETE" });
  }

  resetSettingsGroup(group: string) {
    return this.request<{ reset: string[] }>(`/api/v1/settings?group=${encodeURIComponent(group)}`, { method: "DELETE" });
  }

  testSettingsProbe(probe: string, values: Record<string, unknown>) {
    return this.request<ProbeResult>(`/api/v1/settings/test/${probe}`, { method: "POST", body: JSON.stringify({ values }) });
  }

  exportSettings() {
    return this.textRequest("/api/v1/settings/export");
  }
```
Import the types at the top of `api.ts`: `import { SettingsValidationError } from "@/types/settings"; import type { PatchResult, ProbeResult, SettingsSchema, SettingsValues } from "@/types/settings";`

- [ ] **Step 3: Verify** → `cd apps/web && npx tsc --noEmit && npm run lint` → clean.

- [ ] **Step 4: Commit**

```bash
git add apps/web/src/types/settings.ts apps/web/src/lib/api.ts
git commit -m "feat(web): settings DTOs and client methods"
```

---

### Task 12: The Configuration tab

**Files:**
- Create: `apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx`, `useSettings.ts`, `FieldRow.tsx`, `widgets.tsx`, `GroupHeader.tsx`, `ApplyBar.tsx`
- Modify: `apps/web/src/app/(app)/settings/page.tsx` (third tab)

**Interfaces:**
- Consumes: Task 11 types and methods; `getErrorMessage` from `@/lib/errors`.
- Produces: `<ConfigurationTab />` (self-contained; loads its own data).

- [ ] **Step 1: The hook** — state, loading, pending changes, save, reset, probes

```tsx
// apps/web/src/app/(app)/settings/configuration/useSettings.ts
"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { SettingsValidationError } from "@/types/settings";
import type { CatalogEntry, PatchResult, ProbeResult, SettingValue, SettingsSchema } from "@/types/settings";

export type Pending = Record<string, unknown>; // key -> new value (null = clear secret)

export function useSettings() {
  const [schema, setSchema] = useState<SettingsSchema | null>(null);
  const [values, setValues] = useState<Record<string, SettingValue>>({});
  const [pending, setPending] = useState<Pending>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [lastResult, setLastResult] = useState<PatchResult | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [s, v] = await Promise.all([api.getSettingsSchema(), api.getSettingsValues()]);
      setSchema(s);
      setValues(v.values);
    } catch (e) {
      const msg = getErrorMessage(e);
      if (/403|admin/i.test(msg)) setForbidden(true);
      else setLoadError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const entries = useMemo(() => {
    const m = new Map<string, CatalogEntry>();
    schema?.groups.forEach((g) => g.entries.forEach((e) => m.set(e.key, e)));
    return m;
  }, [schema]);

  const stage = useCallback((key: string, value: unknown) => {
    setPending((p) => ({ ...p, [key]: value }));
    setErrors((e) => { const n = { ...e }; delete n[key]; return n; });
  }, []);

  const unstage = useCallback((key: string) => {
    setPending((p) => { const n = { ...p }; delete n[key]; return n; });
  }, []);

  const apply = useCallback(async () => {
    setSaving(true);
    setErrors({});
    try {
      const res = await api.patchSettings(pending);
      setLastResult(res);
      setPending({});
      await reload();
      return res;
    } catch (e) {
      if (e instanceof SettingsValidationError) setErrors(e.errors);
      else setLoadError(getErrorMessage(e));
      return null;
    } finally {
      setSaving(false);
    }
  }, [pending, reload]);

  const reset = useCallback(async (key: string) => {
    await api.resetSetting(key);
    unstage(key);
    await reload();
  }, [reload, unstage]);

  const resetGroup = useCallback(async (group: string) => {
    await api.resetSettingsGroup(group);
    setPending({});
    await reload();
  }, [reload]);

  const probe = useCallback(async (name: string, keys: string[]): Promise<ProbeResult> => {
    const body: Record<string, unknown> = {};
    for (const k of keys) if (k in pending) body[k] = pending[k];
    return api.testSettingsProbe(name, body);
  }, [pending]);

  return { schema, values, entries, pending, errors, loading, forbidden, loadError, saving, lastResult,
           stage, unstage, apply, reset, resetGroup, probe, reload };
}
```

- [ ] **Step 2: Widgets** — one component per field type

```tsx
// apps/web/src/app/(app)/settings/configuration/widgets.tsx
"use client";
import { useState } from "react";
import type { CatalogEntry, SettingValue } from "@/types/settings";

const input = "w-full bg-bg-secondary border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

export interface WidgetProps {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;          // undefined when nothing staged
  onChange: (value: unknown) => void;
  models?: string[];        // filled by the LLM probe for model fields
}

function shown(p: WidgetProps): unknown {
  return p.staged !== undefined ? p.staged : p.current?.value ?? p.entry.default;
}

export function BoolWidget(p: WidgetProps) {
  const v = Boolean(shown(p));
  return (
    <button type="button" role="switch" aria-checked={v} disabled={!p.entry.editable}
      onClick={() => p.onChange(!v)}
      className={`relative inline-flex h-5 w-9 rounded-full transition-colors ${v ? "bg-accent" : "bg-border"} disabled:opacity-50`}>
      <span className={`inline-block h-4 w-4 mt-0.5 rounded-full bg-white transition-transform ${v ? "translate-x-4" : "translate-x-0.5"}`} />
    </button>
  );
}

export function NumberWidget(p: WidgetProps) {
  const v = shown(p);
  return (
    <input type="number" className={input} disabled={!p.entry.editable}
      step={p.entry.type === "float" ? "any" : 1} min={p.entry.minimum ?? undefined} max={p.entry.maximum ?? undefined}
      value={v === null || v === undefined ? "" : String(v)}
      onChange={(e) => p.onChange(e.target.value === "" ? null : p.entry.type === "float" ? parseFloat(e.target.value) : parseInt(e.target.value, 10))} />
  );
}

export function TextWidget(p: WidgetProps) {
  const v = shown(p);
  const list = p.models && p.models.length > 0 && /model$/.test(p.entry.path) ? `models-${p.entry.key}` : undefined;
  return (
    <>
      <input type="text" className={input} disabled={!p.entry.editable} list={list}
        value={v === null || v === undefined ? "" : String(v)}
        onChange={(e) => p.onChange(e.target.value === "" && p.entry.nullable ? null : e.target.value)} />
      {list && <datalist id={list}>{p.models!.map((m) => <option key={m} value={m} />)}</datalist>}
    </>
  );
}

export function EnumWidget(p: WidgetProps) {
  const v = shown(p);
  return (
    <select className={input} disabled={!p.entry.editable} value={String(v ?? "")} onChange={(e) => p.onChange(e.target.value)}>
      {(p.entry.choices ?? []).map((c) => <option key={c} value={c}>{c}</option>)}
    </select>
  );
}

export function ListWidget(p: WidgetProps) {
  const v = (shown(p) as string[] | null) ?? [];
  return (
    <textarea className={`${input} font-mono`} rows={Math.min(6, Math.max(2, v.length))} disabled={!p.entry.editable}
      placeholder="one entry per line" value={v.join("\n")}
      onChange={(e) => p.onChange(e.target.value.split("\n").map((s) => s.trim()).filter(Boolean))} />
  );
}

export function JsonWidget(p: WidgetProps) {
  const initial = JSON.stringify(shown(p) ?? (p.entry.type === "dict" ? {} : null), null, 2);
  const [text, setText] = useState(initial);
  const [bad, setBad] = useState<string | null>(null);
  return (
    <div>
      <textarea className={`${input} font-mono`} rows={Math.min(14, Math.max(3, text.split("\n").length))} disabled={!p.entry.editable}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          try { p.onChange(JSON.parse(e.target.value)); setBad(null); } catch (err) { setBad((err as Error).message); }
        }} />
      {bad && <div className="text-[11px] text-danger mt-1">Invalid JSON: {bad}</div>}
    </div>
  );
}

export function SecretWidget(p: WidgetProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const isSet = p.staged !== undefined ? p.staged !== null : Boolean(p.current?.is_set);
  const status = p.staged !== undefined
    ? (p.staged === null ? "will be cleared" : "new value staged")
    : p.current?.is_set ? `set · …${p.current.hint ?? ""} · ${p.current.source}` : "not set";
  if (!p.entry.editable) return <div className="text-sm text-text-muted">{status}{p.entry.reason ? ` — ${p.entry.reason}` : ""}</div>;
  return (
    <div className="flex items-center gap-2">
      {editing ? (
        <>
          <input type="password" autoComplete="new-password" className={input} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="paste the new value" />
          <button type="button" className="text-xs text-accent" onClick={() => { p.onChange(draft); setEditing(false); setDraft(""); }}>Stage</button>
          <button type="button" className="text-xs text-text-secondary" onClick={() => { setEditing(false); setDraft(""); }}>Cancel</button>
        </>
      ) : (
        <>
          <span className="text-sm text-text-muted">{status}</span>
          <button type="button" className="text-xs text-accent" onClick={() => setEditing(true)}>Set new value</button>
          {isSet && <button type="button" className="text-xs text-danger" onClick={() => p.onChange(null)}>Clear</button>}
        </>
      )}
    </div>
  );
}

export function Widget(p: WidgetProps) {
  switch (p.entry.type) {
    case "bool": return <BoolWidget {...p} />;
    case "int": case "float": return <NumberWidget {...p} />;
    case "enum": return <EnumWidget {...p} />;
    case "list": return <ListWidget {...p} />;
    case "dict": case "json": return <JsonWidget {...p} />;
    case "secret": return <SecretWidget {...p} />;
    default: return <TextWidget {...p} />;
  }
}
```

- [ ] **Step 3: Field row, group header, apply bar**

```tsx
// FieldRow.tsx
"use client";
import type { CatalogEntry, SettingValue } from "@/types/settings";
import { Widget } from "./widgets";

const APPLIES: Record<string, string> = { next_job: "next analysis", live: "immediately", restart: "restart required" };
const SOURCE: Record<string, string> = { default: "default", env: "env", ui: "ui" };

export default function FieldRow({ entry, current, staged, error, onChange, onUnstage, onReset, models }: {
  entry: CatalogEntry; current?: SettingValue; staged: unknown; error?: string; models?: string[];
  onChange: (v: unknown) => void; onUnstage: () => void; onReset: () => void;
}) {
  const dirty = staged !== undefined;
  const source = current?.source ?? "default";
  return (
    <div id={`setting-${entry.key}`} className={`grid grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-4 py-3 border-b border-border ${dirty ? "bg-accent/5" : ""}`}>
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-text-primary">{entry.title}</span>
          <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${source === "ui" ? "bg-accent/20 text-accent" : source === "env" ? "bg-warning/20 text-warning" : "bg-border text-text-muted"}`}>{SOURCE[source]}</span>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">{APPLIES[entry.applies]}</span>
          {dirty && <span className="text-[10px] uppercase tracking-wider text-accent">modified</span>}
        </div>
        <button type="button" className="text-[11px] font-mono text-text-muted hover:text-text-secondary" title="copy key"
          onClick={() => navigator.clipboard?.writeText(entry.key)}>{entry.key}</button>
        <p className="text-xs text-text-secondary mt-1">{entry.description}</p>
        {!entry.editable && entry.reason && <p className="text-[11px] text-text-muted mt-1">{entry.reason}</p>}
      </div>
      <div>
        <Widget entry={entry} current={current} staged={staged} onChange={onChange} models={models} />
        {error && <div className="text-[11px] text-danger mt-1" role="alert">{error}</div>}
        <div className="flex gap-3 mt-1">
          {dirty && <button type="button" className="text-[11px] text-text-secondary" onClick={onUnstage}>Discard change</button>}
          {source === "ui" && entry.editable && <button type="button" className="text-[11px] text-text-secondary" onClick={onReset}>Reset to env</button>}
        </div>
      </div>
    </div>
  );
}
```

```tsx
// GroupHeader.tsx
"use client";
import { useState } from "react";
import type { ProbeResult, SettingsGroup } from "@/types/settings";

export default function GroupHeader({ group, probes, onProbe, onResetGroup }: {
  group: SettingsGroup; probes: string[];
  onProbe: (name: string) => Promise<ProbeResult>; onResetGroup: () => Promise<void>;
}) {
  const [results, setResults] = useState<Record<string, ProbeResult | "running" | undefined>>({});
  const overridden = group.entries.some((e) => e.editable);
  return (
    <div className="flex items-center justify-between mb-2">
      <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">{group.title}</h2>
      <div className="flex items-center gap-3">
        {probes.map((name) => {
          const r = results[name];
          return (
            <span key={name} className="flex items-center gap-2">
              <button type="button" className="text-xs text-accent" disabled={r === "running"}
                onClick={async () => { setResults((s) => ({ ...s, [name]: "running" })); const res = await onProbe(name).catch((e) => ({ ok: false, latency_ms: 0, detail: String(e), models: null })); setResults((s) => ({ ...s, [name]: res })); }}>
                {name === "llm" ? "Test connection & fetch models" : `Test ${name}`}
              </button>
              {r && r !== "running" && <span className={`text-[11px] ${r.ok ? "text-success" : "text-danger"}`} role="status">{r.ok ? "ok" : "failed"} · {r.latency_ms} ms · {r.detail}</span>}
              {r === "running" && <span className="text-[11px] text-text-muted">testing…</span>}
            </span>
          );
        })}
        {overridden && <button type="button" className="text-[11px] text-text-secondary" onClick={() => void onResetGroup()}>Reset group to env</button>}
      </div>
    </div>
  );
}
```

```tsx
// ApplyBar.tsx
"use client";
import type { CatalogEntry } from "@/types/settings";

const APPLIES: Record<string, string> = { next_job: "takes effect on the next analysis", live: "takes effect immediately", restart: "needs a restart" };

export default function ApplyBar({ pending, entries, saving, onApply, onDiscard, confirming, setConfirming }: {
  pending: Record<string, unknown>; entries: Map<string, CatalogEntry>; saving: boolean;
  onApply: () => void; onDiscard: () => void; confirming: boolean; setConfirming: (b: boolean) => void;
}) {
  const keys = Object.keys(pending);
  if (keys.length === 0) return null;
  return (
    <div className="sticky bottom-0 mt-6 border-t border-border bg-bg-primary/95 backdrop-blur px-4 py-3">
      {confirming && (
        <ul className="text-xs text-text-secondary mb-3 space-y-1 max-h-40 overflow-auto">
          {keys.map((k) => {
            const e = entries.get(k);
            const v = pending[k];
            return <li key={k}><span className="font-mono">{k}</span> → {e?.secret ? (v === null ? "cleared" : "new secret") : JSON.stringify(v)} <span className="text-text-muted">({APPLIES[e?.applies ?? "next_job"]})</span></li>;
          })}
        </ul>
      )}
      <div className="flex items-center gap-4">
        <span className="text-sm text-text-primary">{keys.length} change{keys.length === 1 ? "" : "s"} pending</span>
        {!confirming ? (
          <button type="button" className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded" onClick={() => setConfirming(true)}>Apply</button>
        ) : (
          <button type="button" disabled={saving} className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded disabled:opacity-50" onClick={onApply}>{saving ? "Saving…" : "Confirm and apply"}</button>
        )}
        <button type="button" className="text-xs text-text-secondary" onClick={() => { setConfirming(false); onDiscard(); }}>Discard</button>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: The tab container**

```tsx
// ConfigurationTab.tsx
"use client";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import ApplyBar from "./ApplyBar";
import FieldRow from "./FieldRow";
import GroupHeader from "./GroupHeader";
import { useSettings } from "./useSettings";

export default function ConfigurationTab() {
  const s = useSettings();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    const dirty = Object.keys(s.pending).length > 0;
    const handler = (e: BeforeUnloadEvent) => { if (dirty) { e.preventDefault(); } };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [s.pending]);

  const visibleGroups = useMemo(() => {
    if (!s.schema) return [];
    const q = query.trim().toLowerCase();
    return s.schema.groups
      .map((g) => ({ ...g, entries: q ? g.entries.filter((e) => [e.key, e.title, e.description].some((t) => t.toLowerCase().includes(q))) : g.entries }))
      .filter((g) => g.entries.length > 0 && (q || !active || g.key === active));
  }, [s.schema, query, active]);

  if (s.loading) return <div className="text-sm text-text-secondary">Loading configuration…</div>;
  if (s.forbidden) return <div className="text-sm text-text-secondary" role="alert">Configuration is available to administrators only (admin role required).</div>;
  if (s.loadError) return <div className="text-sm text-danger" role="alert">{s.loadError}</div>;
  if (!s.schema) return null;

  const groupKey = active ?? s.schema.groups[0]?.key ?? null;

  return (
    <div>
      <div className="flex items-center justify-between gap-4 mb-4">
        <input type="search" placeholder="Search settings (key, title, description)" value={query} onChange={(e) => setQuery(e.target.value)}
          className="flex-1 bg-bg-secondary border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent" />
        {!s.schema.secrets_available && <span className="text-[11px] text-warning">SETTINGS_ENCRYPTION_KEY is not set: secrets are read-only</span>}
        <button type="button" className="text-xs text-accent" onClick={async () => { const text = await api.exportSettings(); await navigator.clipboard?.writeText(text); setToast("Overrides copied as .env lines"); setTimeout(() => setToast(null), 2500); }}>Export overrides (.env)</button>
      </div>
      {s.lastResult && (
        <div className="text-xs text-success mb-3" role="status">
          Applied {s.lastResult.applied.length} setting{s.lastResult.applied.length === 1 ? "" : "s"}
          {s.lastResult.applies.next_job ? ` · ${s.lastResult.applies.next_job} on the next analysis` : ""}
          {s.lastResult.applies.live ? ` · ${s.lastResult.applies.live} immediately` : ""}
        </div>
      )}
      {toast && <div className="text-xs text-text-secondary mb-3" role="status">{toast}</div>}
      <div className="grid grid-cols-[200px_minmax(0,1fr)] gap-6">
        <nav aria-label="Setting groups" className="space-y-1">
          {s.schema.groups.map((g) => {
            const dirty = g.entries.some((e) => e.key in s.pending);
            return (
              <button key={g.key} type="button" onClick={() => { setActive(g.key); setQuery(""); }}
                className={`w-full text-left px-2 py-1.5 text-xs rounded ${(!query && groupKey === g.key) ? "bg-bg-secondary text-text-primary" : "text-text-secondary hover:text-text-primary"}`}>
                {g.title}{dirty ? " •" : ""}
              </button>
            );
          })}
        </nav>
        <div>
          {visibleGroups.map((g) => {
            const probes = Array.from(new Set(g.entries.map((e) => e.probe).filter((p): p is string => Boolean(p))));
            return (
              <section key={g.key} className="mb-8">
                <GroupHeader group={g} probes={probes}
                  onProbe={async (name) => {
                    const keys = g.entries.filter((e) => e.probe === name).map((e) => e.key);
                    const r = await s.probe(name, keys);
                    if (r.models) setModels(r.models);
                    return r;
                  }}
                  onResetGroup={() => s.resetGroup(g.key)} />
                {g.entries.map((e) => (
                  <FieldRow key={e.key} entry={e} current={s.values[e.key]} staged={s.pending[e.key]} error={s.errors[e.key]}
                    models={e.probe === "llm" ? models : undefined}
                    onChange={(v) => s.stage(e.key, v)} onUnstage={() => s.unstage(e.key)} onReset={() => void s.reset(e.key)} />
                ))}
              </section>
            );
          })}
        </div>
      </div>
      <ApplyBar pending={s.pending} entries={s.entries} saving={s.saving} confirming={confirming} setConfirming={setConfirming}
        onApply={async () => { const r = await s.apply(); if (r) setConfirming(false); }}
        onDiscard={() => Object.keys(s.pending).forEach((k) => s.unstage(k))} />
    </div>
  );
}
```

- [ ] **Step 5: Wire the tab into `page.tsx`**

Change the tab state type to `"general" | "apikeys" | "configuration"`, add `{ key: "configuration" as const, label: "Configuration" }` to `tabs`, import `ConfigurationTab from "./configuration/ConfigurationTab"`, and render `{activeTab === "configuration" && <ConfigurationTab />}` after the API keys block.

- [ ] **Step 6: Verify against the running API** (infra + API up as in the observation recipe; log in as an admin user): open `/settings` → Configuration; change `Negotiation → Max iterations`, Apply, confirm; reload and see the `ui` badge; Reset to env; test LLM connection and see the model list populate the model fields; set and clear a secret; a non-admin account sees the locked message. `cd apps/web && npx tsc --noEmit && npm run lint && npm run build` → clean.

- [ ] **Step 7: Commit**

```bash
git add "apps/web/src/app/(app)/settings"
git commit -m "feat(web): schema-driven Configuration tab with sources, apply summary, probes and secrets"
```

---

### Task 13: Playwright spec (route-mocked)

**Files:**
- Create: `apps/web/e2e/settings-configuration.spec.ts`
- Modify: `apps/web/e2e/mocks.ts` (add the settings routes to the mocked surface so the catch-all does not fail them)

- [ ] **Step 1: Add mocks**

In `mocks.ts`, add exported fixtures and register them inside `installApiMocks` alongside the existing routes (follow the file's pattern of `page.route("**/api/v1/...", ...)`):
```ts
export const MOCK_SETTINGS_SCHEMA = {
  secrets_available: true,
  groups: [
    { key: "negotiation", title: "Negotiation", entries: [
      { key: "core.negotiation.max_iterations", namespace: "core", path: "negotiation.max_iterations", type: "int", default: 5, nullable: false, choices: null, minimum: null, maximum: null, secret: false, group: "negotiation", title: "Max iterations", description: "Hard ceiling on negotiation rounds.", applies: "next_job", editable: true, reason: null, probe: null },
    ]},
    { key: "providers", title: "Providers", entries: [
      { key: "core.llm.openai.api_key", namespace: "core", path: "llm.openai.api_key", type: "secret", default: null, nullable: true, choices: null, minimum: null, maximum: null, secret: true, group: "providers", title: "OpenAI-compatible API key", description: "Bearer token for the OpenAI-compatible endpoint.", applies: "next_job", editable: true, reason: null, probe: "llm" },
    ]},
  ],
};
export const MOCK_SETTINGS_VALUES = {
  values: {
    "core.negotiation.max_iterations": { value: 5, is_set: null, hint: null, source: "default", updated_at: null, updated_by: null },
    "core.llm.openai.api_key": { value: null, is_set: true, hint: "1234", source: "env", updated_at: null, updated_by: null },
  },
};
```
and in `installApiMocks`:
```ts
  await page.route("**/api/v1/settings/schema", (r) => r.fulfill({ json: MOCK_SETTINGS_SCHEMA }));
  await page.route("**/api/v1/settings", (r) =>
    r.request().method() === "PATCH"
      ? r.fulfill({ json: { applied: Object.keys(r.request().postDataJSON().changes), applies: { next_job: 1 } } })
      : r.fulfill({ json: MOCK_SETTINGS_VALUES }));
```

- [ ] **Step 2: The spec**

```ts
// apps/web/e2e/settings-configuration.spec.ts
import { expect } from "@playwright/test";
import { test } from "./fixtures";

test.describe("Settings → Configuration", () => {
  test("stages a change, shows the apply summary and sends one PATCH", async ({ authenticatedPage: page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.negotiation.max_iterations"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });

    const field = page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]");
    await field.fill("7");
    await expect(page.getByText("1 change pending")).toBeVisible();
    await page.getByRole("button", { name: "Apply" }).click();
    await expect(page.getByText("takes effect on the next analysis")).toBeVisible();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(page.getByRole("status")).toContainText("Applied 1 setting");
    expect(patches).toEqual([{ changes: { "core.negotiation.max_iterations": 7 } }]);
  });

  test("secrets show state, never the value", async ({ authenticatedPage: page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Providers" }).click();
    await expect(page.getByText("set · …1234 · env")).toBeVisible();
    await expect(page.locator("input[type=password]")).toHaveCount(0);
  });

  test("a 422 lands under the field", async ({ authenticatedPage: page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.route("**/api/v1/settings", (r) =>
      r.request().method() === "PATCH"
        ? r.fulfill({ status: 422, json: { errors: { "core.negotiation.max_iterations": "Input should be greater than 0" } } })
        : r.fallback());
    await page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]").fill("0");
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByRole("alert")).toContainText("greater than 0");
  });
});
```

- [ ] **Step 3: Run only this spec** (never the whole suite unprompted): `cd apps/web && npx playwright test e2e/settings-configuration.spec.ts` → 3 passed.

- [ ] **Step 4: Commit**

```bash
git add apps/web/e2e/settings-configuration.spec.ts apps/web/e2e/mocks.ts
git commit -m "test(web): route-mocked e2e for the Configuration tab"
```

---

### Task 14: Documentation and template

**Files:**
- Modify: `.env.example` (new key near the JWT/secrets block), `README.md` (Configuration section), `docs/specs/2026-09-02-runtime-settings-design.md` (status line)

- [ ] **Step 1: `.env.example`**

```
# Encryption key for secrets saved from the web UI (Settings → Configuration).
# Secrets are stored Fernet-encrypted in Postgres under this key; without it the
# UI shows secret fields read-only and everything else still works. Generate:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# SETTINGS_ENCRYPTION_KEY=
```

- [ ] **Step 2: README** — under "Configuration", add:

> **From the UI.** Administrators can change every pipeline setting and the API's runtime knobs from Settings → Configuration. Values saved there are stored in Postgres and take precedence over `.env`; the worker reads them at the start of each analysis and the API within five seconds. Secrets are encrypted with `SETTINGS_ENCRYPTION_KEY` and are never shown back. Each field shows where its current value comes from (default, env or UI), and "Test connection" checks the LLM endpoint, Ghidra, CAPE, Qdrant, Redis and the intelligence keys before you save. Infrastructure settings (database, Redis, MinIO, JWT, `AUTH_DISABLED`, `DEBUG`) stay in `.env`.

- [ ] **Step 3: Spec status** → change the status line to `Status: implemented (see docs/plans/2026-09-02-runtime-settings.md).`

- [ ] **Step 4: Final gates**

`make lint format-check typecheck && uv run pytest tests/ -q` (all green); `make facts && git diff --exit-code --stat tests/evaluation/paper_facts.json tests/evaluation/cluster_analysis.json` (byte-identical); `cd apps/web && npx tsc --noEmit && npm run lint && npm run build`.

- [ ] **Step 5: Commit**

```bash
git add .env.example README.md docs/specs/2026-09-02-runtime-settings-design.md
git commit -m "docs: configuration from the web UI, and the encryption key it needs"
```

---

## Self-review

- **Spec coverage:** persistence & precedence (T3, T5, T6), scope (T4 all core leaves; T6 `API_EDITABLE`/`API_READONLY`), secrets (T2, T6, T8 schema flag), schema-driven UI with completeness test (T4, T12), endpoints incl. export and probes (T8, T9), apply semantics (T7 `RuntimeConfig`, T10 worker + snapshot), audit (T6), UI behaviours (T12: rail, search, badges, applies chip, reset, probes + model list, sticky apply with confirmation, unload guard, 422 mapping, secret set/clear, export), tests (T1–T13), paper pin (T1), migration/docs (T5, T14). No gap found.
- **Placeholders:** none.
- **Type consistency:** `CatalogEntry` fields match `CatalogEntryDTO` and the TS `CatalogEntry`; `ValueInfo` ↔ `ValueDTO` ↔ `SettingValue`; `SaveResult(applied, applies)` ↔ `PatchResponse` ↔ `PatchResult`; `ProbeResult(ok, latency_ms, detail, models)` identical on both sides; `split_key`, `nest`, `build_settings`, `flatten_leaves`, `effective_source`, `public_snapshot` used with the signatures defined in T3; `load_core_overrides(db)` (T6) consumed in T10; `run_probe(name, values, stored)` (T9) consumed in T8.
