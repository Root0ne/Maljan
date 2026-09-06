# Agent composition implementation plan (sub-project C)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator declare analysts as *agent definitions*, group them into named *profiles*, build the graph from the active profile and pick one per job — from the settings UI, without editing Python — while the `default` profile under default settings stays today's system byte for byte: the same three analyst classes under the same names, the same prompts, the same tool sets, the same node and edge set, the same `run_summary` keys.

**Architecture:** Eighteen sequential tasks on one branch, one commit each. Task 1 pins what must not move (the compiled graph's nodes and edges for both `parallel_analysts` settings, the exact message list `NetworkAnalyst.revise`/`revise_isr` sends, and a grep gate over the topology sources) before a line of production code changes — the same opening move sub-projects A and B made. `src/maljan/agents/composition.py` is the single place that answers "what prompt, what tools, what LLM, what static provider does agent `<key>` get": the graph, the container, the worker's mirror step and the settings probe all call `resolve_agent`, so a probe cannot report one answer and a job get another. `ConfigurableAnalyst` is one class parametrised by a `ResolvedAgent`; the four built-in roles keep their existing classes, because those classes carry the provider-specific ISR extraction the goldens pin. `AgentRegistry` stays the class registry for built-in roles and stops being a topology source. The settings surface mirrors B's `mcp.servers` exactly — one JSON leaf per map, one composite editor per leaf, one per-key validation module (`agent_map.py` beside `server_map.py`) — so A's staging, hidden-dirty, reset and export behaviour is unchanged.

**Tech Stack:** Python 3.13, pydantic / pydantic-settings, LangChain + LangGraph, MCP (stdio + streamable-http), FastAPI, SQLAlchemy async + alembic, MinIO, arq; Next.js 16 / React 19 / TypeScript; Playwright; Docker Compose.

**Spec:** docs/specs/2026-09-05-agent-composition-design.md

## Global Constraints

From the spec (§2, §3.2, §8, §11):

- The graph skeleton is fixed: N analysts → negotiation ↔ revision → judge → report. No free-form DAG, no second judge, no custom negotiation logic.
- Built-in definitions (`static`, `dynamic`, `network`, `judge`) and the `default` profile are seeded in code and read-only; `enabled: false` on a built-in *analyst* definition is the one permitted edit. An operator clones a built-in to change it.
- `prompt: null` on a built-in role means the built-in prompt (HEAD + provider fragment + TAIL); `role == "generic"` requires a non-empty prompt.
- Per-agent LLM lives at `llm.agents.<key>.*` and nowhere else; the definition never stores it.
- `static_provider: str | null` per agent (null = the global `static.provider`); there is no per-agent sandbox provider.
- `ToolRef.kind` is `mcp` or `provider` only.
- `MCPServerConfig.agents` entries are definition keys; `choices_from: agent_roles` resolves to effective definition keys.
- A custom analyst never fails a job: a failed tool server or provider adds a degradation reason and the agent runs with what remains.
- The agent probe never calls the LLM. It is admin-only and opens servers on B's probe budget.
- A `ToolRef.name` outside a server's allow-list is rejected at save, so a definition cannot widen a server's exposure.
- Prompts are operator text, not secrets: exported as-is, rendered as plain text, never as HTML.

Project constraints, verbatim:

- Default profile byte-identity: prompts, tool sets, graph node/edge set, run_summary keys unchanged under default settings.
- `tests/evaluation/**` never modified; `make facts` byte-identical; the pinned test-count artefact is never re-pinned.
- No AI self-attribution in commits, comments or docs. No question sentences in headings, comments or docs.
- Every new settings leaf needs an annotation in settings_annotations.py (an existing test enforces it).
- Built-in definitions/profile are read-only except `enabled` on built-in analysts.
- API keys/tokens never printed or logged; tests build credentials at runtime.
- Web: `tsc --noEmit`, `npm run lint` (no new warnings), `npm run build`; Playwright only the spec named by the task, chromium only during tasks.
- Controller sweep after every task: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`.

Working rules carried over from B: branch `feat/agent-composition` stacked on `feat/tool-servers`, one commit per task, imperative lowercase messages with a `feat:`/`test:`/`fix:`/`docs:` prefix; TDD (failing test first) then `uv run ruff check <files>`, `uv run ruff format --check <files>`, `uv run mypy src/ apps/api/`; run only the modules a task names mid-task; no `git checkout`, `git stash` or `git reset`, and `git add` explicit paths only; implementers do not spawn subagents.

## Names fixed by this plan

The spec leaves these internal names open. They are chosen once here and used identically in every task below.

| Name | Where | Meaning |
| :-- | :-- | :-- |
| `AnalystRole` | `src/maljan/core/config.py` | `Literal["static", "dynamic", "network", "judge", "generic"]` |
| `AGENT_KEY_PATTERN` | `src/maljan/core/config.py` | the same string as `SERVER_KEY_PATTERN` |
| `BUILTIN_AGENTS` / `BUILTIN_PROFILES` | `src/maljan/core/config.py` | `("static", "dynamic", "network", "judge")` / `("default",)` |
| `ToolRef`, `AgentDefinition`, `ProfileDefinition`, `AgentsConfig` | `src/maljan/core/config.py` | the four new models |
| `_builtin_definitions()` / `_builtin_profiles()` | `src/maljan/core/config.py` | default factories, shaped like `_builtin_servers()` |
| `ResolvedAgent` | `src/maljan/agents/composition.py` | frozen dataclass: what one agent actually gets |
| `builtin_prompt` / `resolve_agent` / `aresolve_agent` | `src/maljan/agents/composition.py` | prompt assembly / full resolution / its awaited twin |
| `analyst_keys` / `current_analyst_keys` / `active_profile` | `src/maljan/agents/composition.py` | ordered analyst keys of a `Settings` / of `get_settings()` / the active `ProfileDefinition` |
| `AGENT_TOOL_UNAVAILABLE_REASON` | `src/maljan/providers/servers.py` | `"agent tool '{server}.{name}' unavailable"` |
| `ServerRegistry.tools_for_ref` / `.atools_for_ref` | `src/maljan/providers/servers.py` | one `ToolRef`'s tools, sync / async |
| `prompt_to_messages` / `revision_messages` | `src/maljan/agents/base_agent.py` | `(role, text)` pairs to LangChain messages / the shared revision framing |
| `_REVISION_ISR_FRAMING` | `src/maljan/agents/base_agent.py` | the negotiation-round suffix `revise_isr` appends to its system prompt |
| `_NETWORK_REVISE_SYSTEM` | `src/maljan/agents/network_analyst.py` | the bespoke system prompt `revise` has always sent |
| `JUDGE_VERDICT_SYSTEM` | `src/maljan/agents/judge_agent.py` | the verdict system prompt, extracted to a module constant |
| `ConfigurableAnalyst` | `src/maljan/agents/configurable_analyst.py` | the one class every `generic` definition runs as |
| `ServiceContainer.active_profile` / `.analyst_keys` / `.agent_role` | `src/maljan/core/container.py` | the job's profile / its ordered keys / one key's role |
| `validate_agent_map` / `AgentMapError` | `apps/api/app/services/agent_map.py` | PATCH-time validation of the two agent maps |
| `AGENT_DEFINITIONS_KEY` / `AGENT_PROFILES_KEY` / `AGENT_PROFILE_KEY` | `apps/api/app/services/agent_map.py` | `"core.agents.definitions"` / `"core.agents.profiles"` / `"core.agents.profile"` |
| `effective_profiles` / `effective_definitions` | `apps/api/app/services/agent_map.py` | stored map layered over the built-in seeds |
| `probe_agent` / `run_agent_probe` | `apps/api/app/services/settings_probes.py` | the dry resolution probe / its staged-values wrapper |
| `POST /api/v1/settings/test/agent?name=<key>` | API | the agent probe route |
| `AgentDefinitionsEditor.tsx` / `ProfilesEditor.tsx` | `apps/web/src/app/(app)/settings/configuration/` | the two new composite editors |
| `capture_graph_golden.py` / `capture_revision_prompt_golden.py` | `scripts/` | the two Task 1 capture scripts |

## File structure

**Create**

| Path | Responsibility |
| :-- | :-- |
| `scripts/capture_graph_golden.py` | Write `graph_default.json` from a compiled graph, both `parallel_analysts` settings. |
| `scripts/capture_revision_prompt_golden.py` | Write `revision_prompt_network.json` from `NetworkAnalyst.revise`/`revise_isr` with a recording fake LLM. |
| `tests/fixtures/golden/graph_default.json` | The node set, edge set, conditional path map and analyst order the default profile must produce. |
| `tests/fixtures/golden/revision_prompt_network.json` | The exact message list both network revision paths send. |
| `tests/pipeline/test_graph_snapshot.py` | `build_graph` against the graph golden, and a custom-profile snapshot. |
| `tests/agents/test_revision_prompt_golden.py` | Byte identity of the network revision messages across the `revision_messages` extraction. |
| `tests/unit/test_topology_sources.py` | Grep gate: where `list_agents()` may appear and that no agent branches on its own name. |
| `src/maljan/agents/composition.py` | `ResolvedAgent`, `builtin_prompt`, `resolve_agent`, `aresolve_agent`, `analyst_keys`, `active_profile`. |
| `src/maljan/agents/configurable_analyst.py` | `ConfigurableAnalyst`: one `BaseAnalyst` driven by a `ResolvedAgent`. |
| `tests/unit/test_agents_config.py` | One accepting and one rejecting case per §3.2 rule, plus the pinned default dump. |
| `tests/agents/test_composition.py` | Resolution unit tests: clone on r2, tool-less generic, provider ref, dedupe, missing tool. |
| `tests/agents/test_configurable_analyst.py` | `ConfigurableAnalyst` against a fake LLM. |
| `tests/unit/test_container_composition.py` | Container profile wiring and the per-id static provider cache. |
| `tests/unit/test_analyst_set_consumers.py` | `run_summary`, `ttp_cascade` and the judge derive their analyst set from the profile. |
| `tests/api/test_worker_profile_mirror.py` | One mirror per distinct provider that needs one. |
| `tests/api/test_job_profile.py` | Per-job `profile`: 422 on unknown, folded into `agents.profile`. |
| `apps/api/app/services/agent_map.py` | Per-key validation of `core.agents.definitions` / `.profiles` / `.profile`. |
| `tests/api/test_settings_agents.py` | The API's save validation and the two new `choices_from` sources. |
| `tests/api/test_agent_probe.py` | The agent probe resolves without an LLM call. |
| `tests/servers/test_agent_parity.py` | Built-in keys vs the class registry; `agent_roles`; job-schema profile parity. |
| `apps/web/src/app/(app)/settings/configuration/AgentDefinitionsEditor.tsx` | The `agent_definitions` composite editor. |
| `apps/web/src/app/(app)/settings/configuration/ProfilesEditor.tsx` | The `profiles` composite editor. |
| `apps/web/e2e/settings-agents.spec.ts` | End-to-end coverage of both editors and the job profile select. |

**Modify**

| Path | Change |
| :-- | :-- |
| `src/maljan/core/config.py` | The four models, the seeds, `AgentsConfig`, `Settings.agents`, the cross-model validator, `AgentRole` becomes a deprecated `str` alias. |
| `src/maljan/core/settings_annotations.py` | Three new annotations, `"agents"` group label, `ChoicesFrom`/`Editor` literals. |
| `src/maljan/core/settings_catalog.py` | `ChoicesFrom` gains `"profiles"`; `Editor` gains the two new editors. |
| `src/maljan/providers/servers.py` | `tools_for_ref` / `atools_for_ref` and their degradation reason. |
| `src/maljan/agents/base_agent.py` | `prompt_to_messages`, `revision_messages`, `_REVISION_ISR_FRAMING`. |
| `src/maljan/agents/network_analyst.py` | `revise` / `revise_isr` call `revision_messages`; `_NETWORK_REVISE_SYSTEM` extracted. |
| `src/maljan/agents/judge_agent.py` | `JUDGE_VERDICT_SYSTEM` extracted; the analyst-set literal derives from the profile. |
| `src/maljan/agents/static_analyst.py` | `_provider()` reads the agent's resolved static provider id. |
| `src/maljan/core/container.py` | `active_profile`, `analyst_keys`, `agent_role`, profile-driven `get_agent`, per-id `get_static_provider`. |
| `src/maljan/pipeline/builder.py` | Analyst order from the profile. |
| `src/maljan/pipeline/nodes.py` | Four topology reads and the static-role branches move onto the profile. |
| `src/maljan/pipeline/state.py` | `static_sample_paths` (per static-provider mirror paths). |
| `src/maljan/app.py` | `run`/`arun` carry `static_sample_paths`; the roster log reads the profile. |
| `src/maljan/cli.py` | The agent listing reads the profile. |
| `src/maljan/analysis/run_summary.py` | `profile` field, `set_profile`, `to_dict` key, profile-driven layer order. |
| `src/maljan/analysis/ttp_cascade.py` | `is_consensus` reads the configured analyst layers. |
| `apps/api/app/schemas/job.py` | `_KnownJobConfig.profile`. |
| `apps/api/app/schemas/settings.py` | `ProbeResponse.details`. |
| `apps/api/app/services/server_map.py` | `_ROLES` reads effective definition keys. |
| `apps/api/app/services/settings_service.py` | `save` validates the agent maps. |
| `apps/api/app/services/settings_probes.py` | `ProbeResult.details`, `probe_agent`, `run_agent_probe`, `PROBES["agent"]`. |
| `apps/api/app/services/settings_catalog_api.py` | `profiles` and effective `agent_roles` choice sources. |
| `apps/api/app/api/v1/settings.py` | `POST /settings/test/agent`. |
| `apps/api/app/api/v1/jobs.py` | Submit-time profile validation. |
| `apps/api/app/worker/analysis_worker.py` | `build_job_settings` folds `profile`; the mirror step runs once per distinct provider. |
| `apps/web/src/types/settings.ts` | `Editor`, `ChoicesFrom`, `AgentDefinitionEntry`, `ToolRefEntry`, `ProfileEntry`, `ProbeResult.details`. |
| `apps/web/src/lib/api.ts` | `probeAgent`. |
| `apps/web/src/app/(app)/settings/configuration/FieldRow.tsx` | Dispatch to the two new editors. |
| `apps/web/src/app/(app)/samples/page.tsx` | The Profile select. |
| `apps/web/src/app/(app)/samples/useProviderChoices.ts` | Also return `profiles`. |
| `apps/web/src/app/(app)/analysis/[id]/pipeline/PipelinePanel.tsx` | Steps from `run_summary.profile.analysts`. |
| `apps/web/src/components/TranscriptPanel.tsx` | Deterministic fallback palette. |
| `apps/web/e2e/mocks.ts` | The two agent leaves, their values and the agent probe route. |
| `apps/web/e2e/job-submit-providers.spec.ts` | The profile case. |
| `tests/agents/test_prompt_byte_identity.py` | Four `resolve_agent` prompts and the static tool set. |
| `tests/servers/test_server_security.py` | The composition security invariants. |
| `README.md`, `.env.example`, `docs/specs/2026-09-05-agent-composition-design.md` | Operator documentation and the spec status line. |

---

### Task 1: Pin the graph, the revision prompt and the topology sources before anything moves

**Files:**
- Create: `scripts/capture_graph_golden.py`, `scripts/capture_revision_prompt_golden.py`, `tests/fixtures/golden/graph_default.json`, `tests/fixtures/golden/revision_prompt_network.json`, `tests/pipeline/test_graph_snapshot.py`, `tests/agents/test_revision_prompt_golden.py`, `tests/unit/test_topology_sources.py`
- Modify: nothing. This task must not touch `src/` or `apps/`.
- Test: the three new test modules.

**Interfaces:**
- Consumes: `maljan.pipeline.builder.build_graph`, `maljan.core.container.ServiceContainer` (mock mode), `maljan.agents.network_analyst.NetworkAnalyst`, `CompiledStateGraph.get_graph()` (`.nodes`, `.edges`) and `CompiledStateGraph.builder.branches` (the conditional edge's `ends` map).
- Produces:
  ```python
  # scripts/capture_graph_golden.py
  def graph_shape(parallel: bool) -> dict[str, Any]          # {"analysts", "nodes", "edges", "conditional"}
  # scripts/capture_revision_prompt_golden.py
  class RecordingLLM(BaseChatModel)                          # records .invoke's messages, answers with a fixed string
  def revision_shape() -> dict[str, Any]                     # {"revise": [...], "revise_isr": [...], "inputs": {...}}
  # tests/pipeline/test_graph_snapshot.py
  def compiled_shape(container: ServiceContainer) -> dict[str, Any]   # read by Task 7's custom-profile test
  # tests/unit/test_topology_sources.py
  TOPOLOGY_SOURCES: set[str]                                 # repo-relative paths allowed to call list_agents()
  NAME_BRANCHES: set[str]                                    # repo-relative paths allowed to branch on an agent name
  ```
  `tests/fixtures/golden/graph_default.json` and `tests/fixtures/golden/revision_prompt_network.json` are the single source of truth for tasks 4, 5 and 7.

- [ ] **Step 1: Write the capture scripts**

```python
# scripts/capture_graph_golden.py
"""Pin the compiled graph of the default profile, before the profile exists.

Sub-project C replaces ``AgentRegistry.list_agents()`` as the builder's
topology source. The replacement is only free if the graph it produces is the
graph it produced before, so the node names, the edge set, the conditional
edge's path map and the analyst order are captured here from a live
``build_graph`` — for both values of ``llm.parallel_analysts``, because the
two topologies are different graphs and only one of them is the default.

Run: ``uv run python scripts/capture_graph_golden.py``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "graph_default.json"


def graph_shape(parallel: bool) -> dict[str, Any]:
    """The node set, edge set, conditional path map and analyst order."""
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer
    from maljan.pipeline.builder import build_graph

    cfg = Settings(_env_file=None)
    cfg.llm.parallel_analysts = parallel
    container = ServiceContainer(cfg, mock=True)
    compiled = build_graph(container)
    drawn = compiled.get_graph()
    conditional: dict[str, dict[str, str]] = {}
    for source, branches in compiled.builder.branches.items():
        for spec in branches.values():
            conditional[source] = dict(spec.ends or {})
    analysts = [
        node[: -len("_analyst")] for node in drawn.nodes if node.endswith("_analyst")
    ]
    return {
        # The analyst order is the sequential chain order, which is the order
        # the builder received; recovered from the edges rather than from the
        # node dict so the parallel capture records the same list.
        "analysts": _analyst_order(drawn, analysts, parallel),
        "nodes": sorted(drawn.nodes),
        "edges": sorted(f"{e.source}->{e.target}" for e in drawn.edges),
        "conditional": conditional,
    }


def _analyst_order(drawn: Any, analysts: list[str], parallel: bool) -> list[str]:
    """Analyst order: the chain in sequential mode, the node order in parallel."""
    if parallel:
        # Every analyst hangs off START, so the graph carries no order; the
        # builder's own iteration order is what the node dict preserves.
        return [n[: -len("_analyst")] for n in drawn.nodes if n.endswith("_analyst")]
    nxt = {e.source: e.target for e in drawn.edges if not e.conditional}
    node = nxt.get("__start__", "")
    order: list[str] = []
    while node.endswith("_analyst"):
        order.append(node[: -len("_analyst")])
        node = nxt.get(node, "")
    assert len(order) == len(analysts), f"chain {order} misses one of {analysts}"
    return order


def main() -> None:
    payload = {
        "sequential": graph_shape(parallel=False),
        "parallel": graph_shape(parallel=True),
    }
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
```

```python
# scripts/capture_revision_prompt_golden.py
"""Pin the exact messages the network analyst's two revision paths send.

Task 4 extracts the revision framing out of ``NetworkAnalyst`` into
``BaseAnalyst.revision_messages`` so ``ConfigurableAnalyst`` can call the same
function. That extraction is a refactor only if the model receives the same
bytes afterwards, so the bytes are recorded here first, from a fake LLM that
answers nothing and remembers everything.

Run: ``uv run python scripts/capture_revision_prompt_golden.py``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "revision_prompt_network.json"

# Deliberately boring inputs: the point is the framing around them, and a value
# with a brace or a newline in it would only test the template engine.
INPUTS = {
    "original_data": "RAW-DATA-MARKER",
    "own_report": "OWN-REPORT-MARKER",
    "peer_reports": {"static": "STATIC-MARKER", "dynamic": "DYNAMIC-MARKER"},
    "mediator_feedback": "MEDIATOR-MARKER",
}


class RecordingLLM(FakeMessagesListChatModel):
    """A chat model that answers a constant and keeps every message it saw."""

    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append(
            [{"type": m.type, "content": str(m.content)} for m in messages]
        )
        return super()._generate(messages, stop, run_manager, **kwargs)


def revision_shape() -> dict[str, Any]:
    from maljan.agents.network_analyst import NetworkAnalyst

    llm = RecordingLLM(responses=[AIMessage(content="CLAIM: x\nEVIDENCE: y\n---\n")])
    agent = NetworkAnalyst(llm=llm, name="network")

    RecordingLLM.seen = []
    agent.revise(
        INPUTS["original_data"],
        INPUTS["own_report"],
        INPUTS["peer_reports"],
        INPUTS["mediator_feedback"],
    )
    revise = RecordingLLM.seen[-1]

    RecordingLLM.seen = []
    agent.revise_isr(
        INPUTS["original_data"],
        INPUTS["own_report"],
        INPUTS["peer_reports"],
        INPUTS["mediator_feedback"],
        revision_round=2,
    )
    revise_isr = RecordingLLM.seen[-1]

    return {"inputs": INPUTS, "revise": revise, "revise_isr": revise_isr}


def main() -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(
        json.dumps(revision_shape(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Capture both goldens**

```bash
uv run python scripts/capture_graph_golden.py
uv run python scripts/capture_revision_prompt_golden.py
git add tests/fixtures/golden/graph_default.json tests/fixtures/golden/revision_prompt_network.json
```

Expected: `graph_default.json` carries `sequential.analysts == ["static", "dynamic", "network"]`, nine nodes (`__start__`, `__end__`, the three analysts, `negotiation`, `revision`, `judge`, `report`) and `conditional.negotiation == {"revision": "revision", "judge": "judge"}`; `revision_prompt_network.json` carries two two-message lists.

- [ ] **Step 3: Write the three gate tests**

```python
# tests/pipeline/test_graph_snapshot.py
"""The compiled graph of the default profile is the graph on ``dev``.

Sub-project C moves the builder's topology source from the class registry to
the active profile. Node names, the edge set, the conditional edge's path map
and the analyst order are what "the same graph" means, and they are compared
here against a fixture captured before the move
(``scripts/capture_graph_golden.py``). Both values of
``llm.parallel_analysts`` are covered: they are two different graphs and only
one of them is the default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.builder import build_graph

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "graph_default.json"


def compiled_shape(container: ServiceContainer) -> dict[str, Any]:
    """The node set, edge set and conditional path map of a built graph."""
    compiled = build_graph(container)
    drawn = compiled.get_graph()
    conditional: dict[str, dict[str, str]] = {}
    for source, branches in compiled.builder.branches.items():
        for spec in branches.values():
            conditional[source] = dict(spec.ends or {})
    nxt = {e.source: e.target for e in drawn.edges if not e.conditional}
    order: list[str] = []
    node = nxt.get("__start__", "")
    while node.endswith("_analyst"):
        order.append(node[: -len("_analyst")])
        node = nxt.get(node, "")
    return {
        "analysts": order,
        "nodes": sorted(drawn.nodes),
        "edges": sorted(f"{e.source}->{e.target}" for e in drawn.edges),
        "conditional": conditional,
    }


def _container(parallel: bool) -> ServiceContainer:
    cfg = Settings(_env_file=None)
    cfg.llm.parallel_analysts = parallel
    return ServiceContainer(cfg, mock=True)


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_the_sequential_graph_is_unchanged(golden):
    shape = compiled_shape(_container(parallel=False))
    expected = golden["sequential"]
    assert shape["nodes"] == expected["nodes"]
    assert shape["edges"] == expected["edges"]
    assert shape["conditional"] == expected["conditional"]
    assert shape["analysts"] == expected["analysts"]


def test_the_parallel_graph_is_unchanged(golden):
    shape = compiled_shape(_container(parallel=True))
    expected = golden["parallel"]
    assert shape["nodes"] == expected["nodes"]
    assert shape["edges"] == expected["edges"]
    assert shape["conditional"] == expected["conditional"]


def test_the_default_analyst_order_is_the_paper_triple(golden):
    """The order is a property of the system, not an accident of the fixture."""
    assert golden["sequential"]["analysts"] == ["static", "dynamic", "network"]


def test_the_negotiation_branch_still_has_exactly_two_destinations(golden):
    assert golden["sequential"]["conditional"] == {
        "negotiation": {"revision": "revision", "judge": "judge"}
    }
```

```python
# tests/agents/test_revision_prompt_golden.py
"""The network analyst's revision messages are frozen.

Both revision paths are about to be re-expressed through one shared helper
(``BaseAnalyst.revision_messages``, Task 4) so the configurable analyst can
send the same framing. The helper is a refactor only if the model receives
identical bytes, which is what this compares — against a fixture captured
from the pre-extraction code by ``scripts/capture_revision_prompt_golden.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage

GOLDEN = (
    Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "revision_prompt_network.json"
)


class _Recording(FakeMessagesListChatModel):
    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


def _agent() -> tuple:
    from maljan.agents.network_analyst import NetworkAnalyst

    llm = _Recording(responses=[AIMessage(content="CLAIM: x\nEVIDENCE: y\n---\n")])
    return NetworkAnalyst(llm=llm, name="network"), json.loads(
        GOLDEN.read_text(encoding="utf-8")
    )


def test_revise_sends_the_captured_messages():
    agent, golden = _agent()
    inputs = golden["inputs"]
    _Recording.seen = []
    agent.revise(
        inputs["original_data"],
        inputs["own_report"],
        inputs["peer_reports"],
        inputs["mediator_feedback"],
    )
    assert _Recording.seen[-1] == golden["revise"]


def test_revise_isr_sends_the_captured_messages():
    agent, golden = _agent()
    inputs = golden["inputs"]
    _Recording.seen = []
    agent.revise_isr(
        inputs["original_data"],
        inputs["own_report"],
        inputs["peer_reports"],
        inputs["mediator_feedback"],
        revision_round=2,
    )
    assert _Recording.seen[-1] == golden["revise_isr"]


def test_the_two_paths_are_genuinely_different_prompts():
    """A golden that accidentally captured one path twice would prove nothing."""
    _, golden = _agent()
    assert golden["revise"] != golden["revise_isr"]
    assert len(golden["revise"]) == 2 and len(golden["revise_isr"]) == 2
    assert golden["revise"][0]["type"] == "system"
    assert golden["revise"][1]["type"] == "human"


def test_every_input_marker_reaches_the_model():
    _, golden = _agent()
    body = golden["revise"][1]["content"] + golden["revise_isr"][1]["content"]
    for marker in ("RAW-DATA-MARKER", "OWN-REPORT-MARKER", "MEDIATOR-MARKER"):
        assert marker in body
    assert "STATIC-MARKER" in body and "DYNAMIC-MARKER" in body
```

```python
# tests/unit/test_topology_sources.py
"""Only one thing may decide which analysts exist, and no agent may know its own name.

Risk R1 in the spec: five call sites read ``AgentRegistry.list_agents()``
today, and missing one leaves a node set that disagrees with the active
profile. Risk R2: a built-in class running under a clone's name diverges the
moment anything branches on ``self.name == "static"``.

This test is written against today's code and passes unchanged: the
allow-lists below name every current call site. Task 7 shrinks
``TOPOLOGY_SOURCES`` to the registry and the parity test, and removes the two
name branches ``NAME_BRANCHES`` records, editing this file to match. It is a
ratchet, so it only ever gets smaller.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCHED = [ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app"]

# Where "which analysts exist" may be answered from. Task 7 reduces this to
# the registry itself plus the parity test that compares it with the seeds.
TOPOLOGY_SOURCES: set[str] = {
    "src/maljan/agents/registry.py",
    "src/maljan/pipeline/builder.py",
    "src/maljan/pipeline/nodes.py",
    "src/maljan/core/container.py",
    "src/maljan/app.py",
    "src/maljan/cli.py",
    "apps/api/app/worker/analysis_worker.py",
}

# Where an agent's *key* may be compared against a literal built-in name.
# Every one of these is a static-role branch that must become a role check
# once a clone of ``static`` can run under another key (Task 7).
NAME_BRANCHES: set[str] = {
    "src/maljan/pipeline/nodes.py",
}

_LIST_AGENTS = re.compile(r"\blist_agents\s*\(")
_NAME_EQ = re.compile(
    r"""(?:self\.name|agent_name|\bname)\s*==\s*["'](?:static|dynamic|network)["']"""
)


def _python_files() -> list[Path]:
    return [p for root in SEARCHED for p in root.rglob("*.py") if "__pycache__" not in p.parts]


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_list_agents_is_called_only_where_the_allow_list_says():
    offenders = sorted(
        _rel(p)
        for p in _python_files()
        if _LIST_AGENTS.search(p.read_text(encoding="utf-8"))
        and _rel(p) not in TOPOLOGY_SOURCES
    )
    assert offenders == [], (
        "a new topology source appeared: read the active profile "
        "(container.analyst_keys()) instead of the class registry"
    )


def test_the_allow_list_names_no_file_that_stopped_calling_it():
    """A ratchet only ratchets if it is trimmed when a call site goes away."""
    calling = {
        _rel(p) for p in _python_files() if _LIST_AGENTS.search(p.read_text(encoding="utf-8"))
    }
    stale = sorted(TOPOLOGY_SOURCES - calling - {"tests/servers/test_agent_parity.py"})
    assert stale == [], f"remove these from TOPOLOGY_SOURCES: {stale}"


def test_no_new_module_branches_on_a_built_in_agent_name():
    offenders = sorted(
        _rel(p)
        for p in _python_files()
        if _NAME_EQ.search(p.read_text(encoding="utf-8")) and _rel(p) not in NAME_BRANCHES
    )
    assert offenders == [], (
        "an agent's key is not its role: a clone of 'static' runs under its own "
        "key, so branch on container.agent_role(key) instead"
    )


def test_the_recorded_name_branches_are_the_ones_that_exist_today():
    """Names the debt explicitly so Task 7 can prove it paid it off."""
    branching = {
        _rel(p) for p in _python_files() if _NAME_EQ.search(p.read_text(encoding="utf-8"))
    }
    assert branching == NAME_BRANCHES
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_revision_prompt_golden.py tests/unit/test_topology_sources.py -q`
Expected: PASS — all of it describes today's code, so a failure here means the capture scripts and the repository already disagree.

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check scripts tests/pipeline/test_graph_snapshot.py tests/agents/test_revision_prompt_golden.py tests/unit/test_topology_sources.py && \
uv run ruff format --check scripts tests/pipeline/test_graph_snapshot.py tests/agents/test_revision_prompt_golden.py tests/unit/test_topology_sources.py
git add scripts/capture_graph_golden.py scripts/capture_revision_prompt_golden.py \
  tests/fixtures/golden/graph_default.json tests/fixtures/golden/revision_prompt_network.json \
  tests/pipeline/test_graph_snapshot.py tests/agents/test_revision_prompt_golden.py \
  tests/unit/test_topology_sources.py
git commit -m "test: pin the default graph, the network revision prompt and the topology sources"
```

- [ ] **Step 6: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 2: The settings shape — agent definitions, profiles and the rules that bind them

**Files:**
- Modify: `src/maljan/core/config.py:680` (`AgentRole` becomes a deprecated alias), `:730` (`MCPServerConfig.agents`), and a new section after `MCPConfig` (~`:828`); `Settings` (`:1316` field list, `:1544` after-validator); `src/maljan/core/settings_annotations.py:26-27` (`ChoicesFrom`, `Editor`), `:41` (the `agents` group label), the `ANNOTATIONS.update({...})` block at `:1335`; `src/maljan/core/settings_catalog.py:25-26` (`ChoicesFrom`, `Editor`); `apps/api/app/services/server_map.py:29,43` (`_ROLES`)
- Test: `tests/unit/test_agents_config.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/config.py
  AnalystRole = Literal["static", "dynamic", "network", "judge", "generic"]
  AGENT_KEY_PATTERN = SERVER_KEY_PATTERN
  BUILTIN_AGENTS: tuple[str, ...] = ("static", "dynamic", "network", "judge")
  BUILTIN_PROFILES: tuple[str, ...] = ("default",)
  AgentRole = str                       # deprecated alias, kept so B's imports compile

  class ToolRef(BaseModel):
      kind: Literal["mcp", "provider"]
      server: str | None = None
      name: str | None = None

  class AgentDefinition(BaseModel):
      role: AnalystRole
      label: str = ""
      prompt: str | None = None
      tools: list[ToolRef] = []
      static_provider: str | None = None
      enabled: bool = True

  class ProfileDefinition(BaseModel):
      label: str = ""
      analysts: list[str]

  class AgentsConfig(BaseModel):
      profile: str = "default"
      profiles: dict[str, ProfileDefinition]
      definitions: dict[str, AgentDefinition]

  def _builtin_definitions() -> dict[str, AgentDefinition]
  def _builtin_profiles() -> dict[str, ProfileDefinition]
  Settings.agents: AgentsConfig
  Settings._validate_agent_composition(self) -> "Settings"     # model_validator(mode="after")
  # apps/api/app/services/server_map.py
  def _definition_keys(stored: dict[str, Any] | None) -> set[str]
  ```
- Consumes: `maljan.providers.registry.static_provider_ids`, `MCPServerConfig`, `SERVER_KEY_PATTERN`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_agents_config.py
"""What an operator may write into ``agents.definitions`` and ``agents.profiles``.

Every rule in spec §3.2 gets an accepting case and a rejecting one. The
accepting cases matter as much as the rejections: a validator that refuses
everything would also keep the default profile byte-identical.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.config import (
    AGENT_KEY_PATTERN,
    BUILTIN_AGENTS,
    BUILTIN_PROFILES,
    SERVER_KEY_PATTERN,
    AgentDefinition,
    AgentsConfig,
    ProfileDefinition,
    Settings,
    ToolRef,
)

DEFAULT_AGENTS = {
    "profile": "default",
    "profiles": {
        "default": {"label": "Default", "analysts": ["static", "dynamic", "network"]},
    },
    "definitions": {
        "static": {
            "role": "static", "label": "Static analyst", "prompt": None,
            "tools": [], "static_provider": None, "enabled": True,
        },
        "dynamic": {
            "role": "dynamic", "label": "Dynamic analyst", "prompt": None,
            "tools": [], "static_provider": None, "enabled": True,
        },
        "network": {
            "role": "network", "label": "Network analyst", "prompt": None,
            "tools": [], "static_provider": None, "enabled": True,
        },
        "judge": {
            "role": "judge", "label": "Judge", "prompt": None,
            "tools": [], "static_provider": None, "enabled": True,
        },
    },
}


def _settings(**agents) -> Settings:
    return Settings(_env_file=None, agents=agents)


# ── seeding and the pinned default ─────────────────────────────────────


def test_the_key_pattern_is_the_one_the_server_map_already_uses():
    assert AGENT_KEY_PATTERN == SERVER_KEY_PATTERN


def test_the_default_settings_dump_is_exactly_the_pinned_dict():
    assert Settings(_env_file=None).agents.model_dump() == DEFAULT_AGENTS


def test_a_stored_map_holding_only_a_custom_agent_gets_the_built_ins_back():
    cfg = _settings(
        definitions={"strings": {"role": "generic", "prompt": "look at strings"}}
    )
    assert set(cfg.agents.definitions) == {*BUILTIN_AGENTS, "strings"}
    assert set(cfg.agents.profiles) == set(BUILTIN_PROFILES)
    assert cfg.agents.definitions["static"].role == "static"


def test_disabling_a_built_in_analyst_is_kept_not_reseeded_away():
    cfg = _settings(
        definitions={"dynamic": {"role": "dynamic", "enabled": False}},
        profiles={"lean": {"analysts": ["static", "network"]}},
        profile="lean",
    )
    assert cfg.agents.definitions["dynamic"].enabled is False


# ── keys ───────────────────────────────────────────────────────────────


def test_a_slug_key_is_accepted():
    cfg = _settings(definitions={"static_r2": {"role": "static"}})
    assert "static_r2" in cfg.agents.definitions


@pytest.mark.parametrize("key", ["Static", "9lives", "a" * 33, "has space"])
def test_a_non_slug_key_is_refused(key):
    with pytest.raises(ValidationError, match="lowercase"):
        _settings(definitions={key: {"role": "generic", "prompt": "p"}})


# ── the active profile ─────────────────────────────────────────────────


def test_naming_an_existing_profile_is_accepted():
    cfg = _settings(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    assert cfg.agents.profile == "lean"


def test_naming_a_profile_that_does_not_exist_is_refused():
    with pytest.raises(ValidationError, match="unknown profile 'ghost'"):
        _settings(profile="ghost")


# ── built-ins are read-only except ``enabled`` ─────────────────────────


def test_a_built_in_may_be_disabled():
    cfg = _settings(
        definitions={"network": {"role": "network", "enabled": False}},
        profiles={"lean": {"analysts": ["static"]}},
        profile="lean",
    )
    assert cfg.agents.definitions["network"].enabled is False


def test_a_built_in_with_an_edited_prompt_is_refused():
    with pytest.raises(ValidationError, match="'static' is built in; clone it to change it"):
        _settings(definitions={"static": {"role": "static", "prompt": "mine"}})


def test_the_default_profile_may_not_be_edited():
    with pytest.raises(ValidationError, match="'default' is built in; clone it to change it"):
        _settings(profiles={"default": {"analysts": ["network"]}})


def test_a_clone_of_a_built_in_may_carry_its_own_prompt():
    cfg = _settings(
        definitions={"static_r2": {"role": "static", "prompt": "mine", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    assert cfg.agents.definitions["static_r2"].prompt == "mine"


# ── the analyst list ───────────────────────────────────────────────────


def test_a_profile_of_enabled_non_judge_analysts_is_accepted():
    cfg = _settings(profiles={"two": {"analysts": ["static", "network"]}}, profile="two")
    assert cfg.agents.profiles["two"].analysts == ["static", "network"]


def test_a_profile_naming_an_unknown_definition_is_refused():
    with pytest.raises(ValidationError, match="'two' lists unknown analyst 'ghost'"):
        _settings(profiles={"two": {"analysts": ["static", "ghost"]}})


def test_a_profile_naming_a_disabled_definition_is_refused():
    with pytest.raises(ValidationError, match="'two' lists disabled analyst 'dynamic'"):
        _settings(
            definitions={"dynamic": {"role": "dynamic", "enabled": False}},
            profiles={"two": {"analysts": ["static", "dynamic"]}},
        )


def test_a_profile_naming_the_judge_is_refused():
    with pytest.raises(ValidationError, match="the judge cannot be an analyst"):
        _settings(profiles={"two": {"analysts": ["static", "judge"]}})


def test_a_profile_repeating_an_analyst_is_refused():
    with pytest.raises(ValidationError, match="lists 'static' twice"):
        _settings(profiles={"two": {"analysts": ["static", "static"]}})


def test_an_empty_profile_is_refused():
    with pytest.raises(ValidationError, match="needs at least one analyst"):
        _settings(profiles={"empty": {"analysts": []}})


# ── prompts ────────────────────────────────────────────────────────────


def test_a_generic_agent_with_a_prompt_is_accepted():
    cfg = _settings(definitions={"strings": {"role": "generic", "prompt": "read strings"}})
    assert cfg.agents.definitions["strings"].prompt == "read strings"


@pytest.mark.parametrize("prompt", [None, "", "   "])
def test_a_generic_agent_without_a_prompt_is_refused(prompt):
    with pytest.raises(ValidationError, match="a generic agent needs a prompt"):
        _settings(definitions={"strings": {"role": "generic", "prompt": prompt}})


# ── tool references ────────────────────────────────────────────────────


def test_a_reference_to_a_whole_server_is_accepted():
    cfg = _settings(
        definitions={
            "strings": {
                "role": "generic", "prompt": "p",
                "tools": [{"kind": "mcp", "server": "network"}],
            }
        }
    )
    assert cfg.agents.definitions["strings"].tools[0].server == "network"


def test_a_reference_to_an_unknown_server_is_refused():
    with pytest.raises(ValidationError, match="'strings' references unknown mcp server 'ghost'"):
        _settings(
            definitions={
                "strings": {
                    "role": "generic", "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "ghost"}],
                }
            }
        )


def test_a_named_tool_outside_the_servers_allow_list_is_refused():
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["narrow"].tools  # noqa: B018 - documents the shape read below
    with pytest.raises(ValidationError, match="'read_pcap' is not allowed on server 'narrow'"):
        Settings(
            _env_file=None,
            mcp={"servers": {"narrow": {"enabled": True, "command": "x", "tools": ["extract_dns"]}}},
            agents={
                "definitions": {
                    "strings": {
                        "role": "generic", "prompt": "p",
                        "tools": [{"kind": "mcp", "server": "narrow", "name": "read_pcap"}],
                    }
                }
            },
        )


def test_a_named_tool_on_a_server_that_exposes_everything_is_left_to_resolution():
    """``tools: null`` means "the whole manifest", which is not known at save time."""
    cfg = _settings(
        definitions={
            "strings": {
                "role": "generic", "prompt": "p",
                "tools": [{"kind": "mcp", "server": "network", "name": "whatever_it_offers"}],
            }
        }
    )
    assert cfg.agents.definitions["strings"].tools[0].name == "whatever_it_offers"


def test_an_mcp_reference_without_a_server_is_refused():
    with pytest.raises(ValidationError, match="an mcp tool reference needs a server"):
        ToolRef(kind="mcp")


def test_a_provider_reference_carrying_a_server_is_refused():
    with pytest.raises(ValidationError, match="a provider tool reference names no server"):
        ToolRef(kind="provider", server="network")


def test_a_bare_provider_reference_is_accepted():
    assert ToolRef(kind="provider").server is None


# ── static providers ───────────────────────────────────────────────────


def test_a_registered_static_provider_is_accepted():
    cfg = _settings(definitions={"static_r2": {"role": "static", "static_provider": "r2"}})
    assert cfg.agents.definitions["static_r2"].static_provider == "r2"


def test_an_unregistered_static_provider_is_refused():
    with pytest.raises(ValidationError, match="unknown static provider 'idapro'"):
        _settings(definitions={"static_r2": {"role": "static", "static_provider": "idapro"}})


# ── the server binding vocabulary ──────────────────────────────────────


def test_a_server_may_be_bound_to_a_custom_definition_key():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["strings"]}}},
        agents={"definitions": {"strings": {"role": "generic", "prompt": "p"}}},
    )
    assert cfg.mcp.servers["mine"].agents == ["strings"]


def test_a_server_bound_to_a_definition_that_does_not_exist_is_refused():
    with pytest.raises(ValidationError, match="server 'mine' is bound to unknown agent 'ghost'"):
        Settings(
            _env_file=None,
            mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["ghost"]}}},
        )


def test_the_deprecated_agent_role_alias_is_still_a_type():
    """Sub-project B imports ``AgentRole``; it must keep importing."""
    from maljan.core.config import AgentRole

    assert AgentRole is str


# ── annotations ────────────────────────────────────────────────────────


def test_every_new_leaf_is_annotated_and_grouped():
    from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER

    for key in ("agents.profile", "agents.profiles", "agents.definitions"):
        assert key in ANNOTATIONS, key
    assert ANNOTATIONS["agents.profile"]["choices_from"] == "profiles"
    assert ANNOTATIONS["agents.profile"]["order"] == -1
    assert ANNOTATIONS["agents.profiles"]["editor"] == "profiles"
    assert ANNOTATIONS["agents.definitions"]["editor"] == "agent_definitions"
    assert dict(GROUP_ORDER)["agents"] == "Agents"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_agents_config.py -q`
Expected: FAIL — `ImportError: cannot import name 'AGENT_KEY_PATTERN' from 'maljan.core.config'`.

- [ ] **Step 3: Add the models and the seeds to `config.py`**

Replace line 680 with the new vocabulary, keeping the old name alive:

```python
# The role a definition plays in the fixed skeleton. ``generic`` is the one
# role with no class of its own: it runs as ``ConfigurableAnalyst``.
AnalystRole = Literal["static", "dynamic", "network", "judge", "generic"]

# Deprecated since sub-project C. ``MCPServerConfig.agents`` used to be a
# Literal of the four built-in roles; an operator can now bind a server to any
# definition key, so the field is a plain ``str`` validated against the
# definition map in ``Settings``. The name stays because sub-project B's
# modules import it, and it stays a type so an annotation using it still
# type-checks.
AgentRole = str
```

`MCPServerConfig.agents` (line 730) becomes:

```python
    # Which agents receive this server's tools. Definition keys since
    # sub-project C — the four built-in roles are simply the four built-in
    # keys — validated against ``agents.definitions`` in ``Settings``.
    agents: list[str] = Field(default_factory=list)
```

After `MCPConfig` (following the `cape` property at line 827), add the whole composition block:

```python
# ---------------------------------------------------------------------------
# Agent composition (sub-project C)
# ---------------------------------------------------------------------------

# A definition key is a slug, exactly like a server key: it names a graph node
# (``f"{key}_analyst"``), a path segment in the probe URL, and a key in
# ``llm.agents``. Sharing the pattern rather than re-declaring it keeps the two
# maps' rules from drifting apart.
AGENT_KEY_PATTERN = SERVER_KEY_PATTERN
BUILTIN_AGENTS: tuple[str, ...] = ("static", "dynamic", "network", "judge")
BUILTIN_PROFILES: tuple[str, ...] = ("default",)

_AGENT_KEY_RE = re.compile(AGENT_KEY_PATTERN)
_KEY_RULE = (
    "an agent name is lowercase, starts with a letter, and is at most 32 "
    "characters of letters, digits, '-' or '_'"
)


class ToolRef(BaseModel):
    """One tool source an agent definition asks for by name.

    ``kind="mcp"`` names an entry of ``mcp.servers``; ``name=None`` means that
    server's whole allow-listed set, and a name means one tool of it.
    ``kind="provider"`` means "the tools of this agent's static provider" and
    carries nothing else — the provider is already chosen by
    ``AgentDefinition.static_provider``, so naming it twice could disagree.

    ``builtin`` is deliberately not a kind: no in-process tool exists in this
    project, every tool comes from an MCP server or a provider, and the literal
    grows on the day one does.
    """

    kind: Literal["mcp", "provider"]
    server: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def _shape_matches_the_kind(self) -> "ToolRef":
        if self.kind == "mcp":
            if not self.server:
                raise ValueError("an mcp tool reference needs a server")
        elif self.server is not None or self.name is not None:
            raise ValueError("a provider tool reference names no server and no tool")
        return self


class AgentDefinition(BaseModel):
    """One agent, as configuration rather than as a class.

    ``prompt=None`` on a built-in role means the built-in prompt assembled from
    the agent's own providers (see ``agents.composition.builtin_prompt``), which
    is what keeps a clone honest: change the provider, keep the prompt null,
    and the middle of the prompt changes with it.

    The LLM is *not* here. It lives at ``llm.agents.<key>.*``, the location
    sub-project A froze; two copies of one setting drift.
    """

    role: AnalystRole
    label: str = ""
    prompt: str | None = None
    tools: list[ToolRef] = Field(default_factory=list)
    static_provider: str | None = None
    enabled: bool = True


class ProfileDefinition(BaseModel):
    """An ordered set of analyst keys. The order is the sequential run order."""

    label: str = ""
    analysts: list[str]


def _builtin_definitions() -> dict[str, AgentDefinition]:
    """The four agents the pipeline has always had, as settings.

    Every field is the neutral value, because "the built-in behaviour" is what
    a null prompt, an empty tool list and a null static provider *mean*. The
    judge is here so that its LLM and its tool servers have the same editing
    surface as the analysts; it can never appear in a profile.
    """
    return {
        "static": AgentDefinition(role="static", label="Static analyst"),
        "dynamic": AgentDefinition(role="dynamic", label="Dynamic analyst"),
        "network": AgentDefinition(role="network", label="Network analyst"),
        "judge": AgentDefinition(role="judge", label="Judge"),
    }


def _builtin_profiles() -> dict[str, ProfileDefinition]:
    """The paper's architecture, named. The order is the order the graph ran in."""
    return {
        "default": ProfileDefinition(
            label="Default", analysts=["static", "dynamic", "network"]
        ),
    }


class AgentsConfig(BaseModel):
    """The agent definitions, the profiles, and which profile is active."""

    profile: str = "default"
    profiles: dict[str, ProfileDefinition] = Field(default_factory=_builtin_profiles)
    definitions: dict[str, AgentDefinition] = Field(default_factory=_builtin_definitions)

    @model_validator(mode="after")
    def _seed_and_check(self) -> "AgentsConfig":
        """Re-seed the built-ins, then apply every rule that needs only this model.

        Seeding is ``MCPConfig._reseed_builtins`` again: a stored map holds only
        what the operator added or disabled, so a missing built-in comes back
        and a present one is kept. What "kept" may differ by is the next rule.
        """
        for key, default in _builtin_definitions().items():
            self.definitions.setdefault(key, default)
        for key, default in _builtin_profiles().items():
            self.profiles.setdefault(key, default)

        for key in self.definitions:
            if not _AGENT_KEY_RE.match(str(key)):
                raise ValueError(f"{key!r}: {_KEY_RULE}")
        for key in self.profiles:
            if not _AGENT_KEY_RE.match(str(key)):
                raise ValueError(f"{key!r}: {_KEY_RULE}")

        # A built-in is compared field by field against its seed. ``enabled`` is
        # excluded for an analyst — that is the operator's one lever — and not
        # for the judge, which the skeleton always runs.
        for key, seed in _builtin_definitions().items():
            current = self.definitions[key].model_dump()
            expected = seed.model_dump()
            if key != "judge":
                current.pop("enabled", None)
                expected.pop("enabled", None)
            if current != expected:
                raise ValueError(f"{key!r} is built in; clone it to change it")
        for key, seed in _builtin_profiles().items():
            if self.profiles[key].model_dump() != seed.model_dump():
                raise ValueError(f"{key!r} is built in; clone it to change it")

        for key, definition in self.definitions.items():
            if definition.role == "generic" and not (definition.prompt or "").strip():
                raise ValueError(f"{key!r}: a generic agent needs a prompt")

        for name, profile in self.profiles.items():
            if not profile.analysts:
                raise ValueError(f"profile {name!r} needs at least one analyst")
            seen: set[str] = set()
            for analyst in profile.analysts:
                if analyst in seen:
                    raise ValueError(f"profile {name!r} lists {analyst!r} twice")
                seen.add(analyst)
                definition = self.definitions.get(analyst)
                if definition is None:
                    raise ValueError(f"profile {name!r} lists unknown analyst {analyst!r}")
                if definition.role == "judge":
                    raise ValueError(
                        f"profile {name!r} lists {analyst!r}: the judge cannot be an analyst"
                    )
                if not definition.enabled:
                    raise ValueError(f"profile {name!r} lists disabled analyst {analyst!r}")

        if self.profile not in self.profiles:
            available = ", ".join(sorted(self.profiles))
            raise ValueError(f"unknown profile {self.profile!r}. Available: {available}")
        return self
```

`import re` is already at the top of `config.py`; confirm it before adding, and add it beside `import sys` if it is not.

- [ ] **Step 4: Add the field and the cross-model validator to `Settings`**

Add the field beside `mcp` in the sub-config block (line ~1343):

```python
    # Which analysts exist, in what order, and what each one gets. The
    # ``default`` profile is the architecture this project measured itself on.
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
```

Add the validator immediately after `_populate_deprecated_mcp_view` (line 1544), because it reads `mcp.servers` and `static.provider` and therefore needs both sub-configs built:

```python
    @model_validator(mode="after")
    def _validate_agent_composition(self) -> "Settings":
        """The agent rules that need more than ``AgentsConfig`` to check.

        Three references leave the model that owns them: a ``ToolRef`` names a
        server in ``mcp.servers``, a definition may name a static provider in
        the provider registry, and a server names the agents it is bound to.
        Checking them here rather than in ``AgentsConfig`` is what lets a single
        PATCH that adds a server *and* an agent that uses it validate as one
        unit instead of failing on whichever half pydantic built first.
        """
        from maljan.providers.registry import static_provider_ids

        provider_ids = set(static_provider_ids())
        for key, definition in self.agents.definitions.items():
            if definition.static_provider is not None:
                if definition.static_provider not in provider_ids:
                    available = ", ".join(sorted(provider_ids))
                    raise ValueError(
                        f"{key!r}: unknown static provider "
                        f"{definition.static_provider!r}. Available: {available}"
                    )
            for ref in definition.tools:
                if ref.kind != "mcp":
                    continue
                server = self.mcp.servers.get(str(ref.server))
                if server is None:
                    raise ValueError(
                        f"{key!r} references unknown mcp server {ref.server!r}"
                    )
                # ``tools=None`` is "every tool this server advertises", which
                # is only knowable from a live handshake. A name against such a
                # server is checked at resolution and a miss degrades there;
                # refusing it here would make a built-in sidecar unreferenceable.
                if ref.name is not None and server.tools is not None:
                    if ref.name not in server.tools:
                        raise ValueError(
                            f"{key!r}: {ref.name!r} is not allowed on server {ref.server!r}"
                        )

        known = set(self.agents.definitions)
        for name, server in self.mcp.servers.items():
            for agent in server.agents:
                if agent not in known:
                    available = ", ".join(sorted(known))
                    raise ValueError(
                        f"server {name!r} is bound to unknown agent {agent!r}. "
                        f"Available: {available}"
                    )
        return self
```

- [ ] **Step 5: Annotate the three new leaves**

In `settings_annotations.py`, widen the two literals (lines 26-27):

```python
    choices_from: NotRequired[
        Literal["static_providers", "sandbox_providers", "mcp_servers", "agent_roles", "profiles"]
    ]
    editor: NotRequired[Literal["server_map", "rest_sandbox", "agent_definitions", "profiles"]]
```

Rename the group label (line 41) — the group now holds the two editors as well as the timeouts:

```python
    ("agents", "Agents"),
```

Add the three annotations to the `ANNOTATIONS.update({...})` block that already carries `mcp.servers` (line ~1335):

```python
        "agents.profile": {
            "title": "Active profile",
            "description": (
                "Which profile a job runs unless it names one of its own. A "
                "profile is an ordered set of analysts; 'default' is the "
                "three-analyst architecture this project was measured on."
            ),
            "group": "agents",
            "choices_from": "profiles",
            "order": -1,
        },
        "agents.profiles": {
            "title": "Profiles",
            "description": (
                "Named ensembles, each an ordered list of enabled analyst "
                "definitions. The order is the order the analysts run in when "
                "analysts run sequentially. 'default' is read-only; clone it."
            ),
            "group": "agents",
            "editor": "profiles",
            "order": -1,
        },
        "agents.definitions": {
            "title": "Agent definitions",
            "description": (
                "Every agent Maljan can run, keyed by a short name: its role, "
                "its prompt, the tool servers it receives and the static "
                "provider it reads. The four built-ins are read-only apart from "
                "their enabled switch; clone one to change it."
            ),
            "group": "agents",
            "editor": "agent_definitions",
            "order": -1,
        },
```

In `settings_catalog.py`, widen the two exported literals (lines 25-26) to exactly the same members:

```python
ChoicesFrom = Literal[
    "static_providers", "sandbox_providers", "mcp_servers", "agent_roles", "profiles"
]
Editor = Literal["server_map", "rest_sandbox", "agent_definitions", "profiles"]
```

- [ ] **Step 6: Point the server map's role check at the definition keys**

In `apps/api/app/services/server_map.py`, replace the `AgentRole` import and the `_ROLES` constant (lines 29, 43) with a function over the staged settings, and use it inside `validate_server_map`:

```python
from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    MCPServerConfig,
    _builtin_definitions,
)
```

(`get_args` and the `AgentRole` import go; `typing.Any` stays.)

```python
def _definition_keys(stored: dict[str, Any] | None) -> set[str]:
    """Every agent a server may be bound to, from the map the operator has.

    A server's ``agents`` list used to be a Literal of four roles; it is now a
    list of definition keys, so what is valid depends on settings the operator
    can change in the same session. The stored ``core.agents.definitions``
    override wins where it exists, and the built-in seeds supply the rest —
    the same layering ``AgentsConfig`` itself does on load.
    """
    keys = set(_builtin_definitions())
    definitions = (stored or {}).get("core.agents.definitions")
    if isinstance(definitions, dict):
        keys |= {str(k) for k in definitions}
    return keys
```

Inside `validate_server_map`, replace the `_ROLES` loop with:

```python
        roles = _definition_keys(stored_settings)
        for role in entry.get("agents") or []:
            if role not in roles:
                errors[f"{key}.agents"] = (
                    f"{role!r} is not a known agent; expected one of {', '.join(sorted(roles))}"
                )
```

`validate_server_map` and `split_server_secrets` each gain a keyword-only `stored_settings: dict[str, Any] | None = None` (the whole override mapping, distinct from the existing `stored`, which is the server map alone), and `SettingsService.save` passes `stored=stored_map, stored_settings=current` at line 278.

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/unit/test_agents_config.py tests/unit/core/test_settings_catalog.py tests/unit/api/test_server_map_validation.py tests/api/test_settings_schema_choices.py -q`
Expected: PASS.

- [ ] **Step 8: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core apps/api/app/services tests/unit/test_agents_config.py && \
uv run ruff format --check src/maljan/core apps/api/app/services tests/unit/test_agents_config.py && \
uv run mypy src/ apps/api/
git add src/maljan/core/config.py src/maljan/core/settings_annotations.py \
  src/maljan/core/settings_catalog.py apps/api/app/services/server_map.py \
  apps/api/app/services/settings_service.py tests/unit/test_agents_config.py
git commit -m "feat(config): agent definitions and profiles as settings, with the rules that bind them"
```

- [ ] **Step 9: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 3: `resolve_agent` — one answer to "what does this agent get"

**Files:**
- Create: `src/maljan/agents/composition.py`, `tests/agents/test_composition.py`
- Modify: `src/maljan/providers/servers.py:37` (a second reason template), `:790-833` (`tools_for_ref` beside `tools_for`), `:834-873` (`atools_for_ref`); `src/maljan/agents/judge_agent.py:535` (`JUDGE_VERDICT_SYSTEM` extracted to module scope); `tests/agents/test_prompt_byte_identity.py` (four new tests)
- Test: `tests/agents/test_composition.py`, `tests/agents/test_prompt_byte_identity.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/agents/composition.py
  @dataclass(frozen=True)
  class ResolvedAgent:
      key: str
      role: str
      prompt: str
      tools: list[BaseTool]
      static_provider_id: str
      llm: Any | None
      degradation_reasons: tuple[str, ...] = ()

  def builtin_prompt(role: str, container: Any, static_provider_id: str) -> str
  def _agent_llm(container: Any, key: str) -> Any  # None on a mock container
  def resolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent
  async def aresolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent
  def active_profile(settings: Settings) -> ProfileDefinition
  def analyst_keys(settings: Settings) -> list[str]
  def current_analyst_keys() -> list[str]
  def static_provider_id_for(settings: Settings, key: str) -> str
  # src/maljan/providers/servers.py
  AGENT_TOOL_UNAVAILABLE_REASON = "agent tool '{server}.{name}' unavailable"
  def ServerRegistry.tools_for_ref(self, ref, job_id, **context) -> tuple[list[BaseTool], list[str]]
  async def ServerRegistry.atools_for_ref(self, ref, job_id, **context) -> tuple[list[BaseTool], list[str]]
  # src/maljan/agents/judge_agent.py
  JUDGE_VERDICT_SYSTEM: str
  ```
- Consumes: `ServiceContainer.get_agent_llm`, `.get_static_provider`, `.get_server_registry`; `static_analyst._ISR_HEAD/_ISR_TAIL`, `dynamic_analyst._ISR_SYSTEM`, `network_analyst._ISR_SYSTEM`; `maljan.core.config.AgentDefinition`, `ToolRef`, `ProfileDefinition`.

- [ ] **Step 1: Write the failing test**

```python
# tests/agents/test_composition.py
"""What ``resolve_agent`` hands one agent, and where each piece came from.

The four built-in resolutions are pinned in ``test_prompt_byte_identity.py``
because they are byte-identity statements. These are the composition rules:
a clone follows its own provider, a generic agent starts tool-less, an
explicit provider reference is the only way a generic agent gets provider
tools, duplicates collapse by name, and a tool a server does not have is a
degradation rather than a crash.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.composition import (
    ResolvedAgent,
    analyst_keys,
    builtin_prompt,
    resolve_agent,
)
from maljan.core.config import Settings, ToolRef


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: name, name=name, description=name)


class _Provider:
    """A static provider that offers two tools and a recognisable fragment."""

    id = "r2"

    class capabilities:  # noqa: N801 - mirrors the provider attribute shape
        provides_tools = True
        needs_sample_mirror = True

    def prompt_fragment(self) -> str:
        return "R2-FRAGMENT "

    def open(self, job: Any) -> None:
        self.opened = True

    def get_tools(self) -> list[Any]:
        return [_tool("r2_open"), _tool("r2_analyze")]

    def select_tools(self, pool: list[Any], categories: Any) -> list[Any]:
        return list(pool)


class _Registry:
    """A stand-in ``ServerRegistry`` with a scripted answer per call."""

    def __init__(self, bound: dict[str, list[Any]], by_ref: dict[str, Any]) -> None:
        self.bound = bound
        self.by_ref = by_ref
        self.degradation_reasons: list[str] = []

    def tools_for(self, role, job_id, *, exclude="", **context):  # type: ignore[no-untyped-def]
        return list(self.bound.get(role, [])), []

    def tools_for_ref(self, ref, job_id, **context):  # type: ignore[no-untyped-def]
        key = f"{ref.server}.{ref.name}"
        answer = self.by_ref.get(key)
        if answer is None:
            reason = f"agent tool '{key}' unavailable"
            self.degradation_reasons.append(reason)
            return [], [reason]
        return list(answer), []


class _Container:
    def __init__(self, cfg: Settings, **over: Any) -> None:
        self.config = cfg
        self._provider = over.get("provider", _Provider())
        self._registry = over.get("registry", _Registry({}, {}))
        self.llm = object()

    def get_agent_llm(self, name: str) -> Any:
        return self.llm

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self._provider

    def get_server_registry(self) -> Any:
        return self._registry


def test_a_clone_on_r2_gets_the_r2_fragment_in_the_built_in_assembly():
    from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL

    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"static_r2": {"role": "static", "static_provider": "r2"}},
            "profiles": {"two": {"analysts": ["static", "static_r2"]}},
            "profile": "two",
        },
    )
    resolved = resolve_agent("static_r2", _Container(cfg))
    assert resolved.prompt == _ISR_HEAD + "R2-FRAGMENT " + _ISR_TAIL
    assert resolved.static_provider_id == "r2"
    assert resolved.role == "static"


def test_an_explicit_prompt_wins_over_the_built_in_assembly():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"static_r2": {"role": "static", "prompt": "MINE"}},
            "profiles": {"two": {"analysts": ["static", "static_r2"]}},
            "profile": "two",
        },
    )
    assert resolve_agent("static_r2", _Container(cfg)).prompt == "MINE"


def test_a_generic_agent_with_no_references_and_no_bound_servers_is_tool_less():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"strings": {"role": "generic", "prompt": "read strings"}},
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg))
    assert resolved.tools == []
    assert resolved.prompt == "read strings"


def test_a_provider_reference_is_the_only_way_a_generic_agent_gets_provider_tools():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {
                "strings": {
                    "role": "generic", "prompt": "p", "static_provider": "r2",
                    "tools": [{"kind": "provider"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg))
    assert [t.name for t in resolved.tools] == ["r2_open", "r2_analyze"]


def test_a_bound_server_and_an_explicit_reference_to_it_produce_one_copy_of_each_tool():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["strings"]}}},
        agents={
            "definitions": {
                "strings": {
                    "role": "generic", "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "grep"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    registry = _Registry(
        bound={"strings": [_tool("grep"), _tool("head")]},
        by_ref={"mine.grep": [_tool("grep")]},
    )
    resolved = resolve_agent("strings", _Container(cfg, registry=registry))
    assert [t.name for t in resolved.tools] == ["grep", "head"]


def test_a_tool_the_server_does_not_offer_is_a_degradation_not_an_error():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x"}}},
        agents={
            "definitions": {
                "strings": {
                    "role": "generic", "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "nope"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg, registry=_Registry({}, {})))
    assert resolved.tools == []
    assert resolved.degradation_reasons == ("agent tool 'mine.nope' unavailable",)


def test_the_llm_comes_from_the_agents_own_key():
    cfg = Settings(_env_file=None)
    seen: list[str] = []

    class _C(_Container):
        def get_agent_llm(self, name: str) -> Any:
            seen.append(name)
            return self.llm

    resolve_agent("static", _C(cfg))
    assert seen == ["static"]


def test_analyst_keys_is_the_active_profiles_order():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"rev": {"analysts": ["network", "static"]}}, "profile": "rev"},
    )
    assert analyst_keys(cfg) == ["network", "static"]


def test_the_default_settings_give_the_paper_triple():
    assert analyst_keys(Settings(_env_file=None)) == ["static", "dynamic", "network"]


def test_builtin_prompt_refuses_a_role_it_has_no_prompt_for():
    with pytest.raises(ValueError, match="no built-in prompt for role 'generic'"):
        builtin_prompt("generic", _Container(Settings(_env_file=None)), "ghidra")


def test_the_resolved_agent_is_frozen():
    resolved = resolve_agent("network", _Container(Settings(_env_file=None)))
    assert isinstance(resolved, ResolvedAgent)
    with pytest.raises(Exception):
        resolved.key = "other"  # type: ignore[misc]


def test_a_tool_ref_for_a_whole_server_asks_the_registry_for_the_whole_set():
    ref = ToolRef(kind="mcp", server="mine")
    registry = _Registry({}, {"mine.None": [_tool("a"), _tool("b")]})
    tools, reasons = registry.tools_for_ref(ref, "job")
    assert [t.name for t in tools] == ["a", "b"] and reasons == []
```

Add to `tests/agents/test_prompt_byte_identity.py`:

```python
def _mock_container():
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    return ServiceContainer(Settings(_env_file=None), mock=True)


def test_the_resolved_static_prompt_is_the_golden():
    from maljan.agents.composition import resolve_agent

    assert resolve_agent("static", _mock_container()).prompt == _golden(
        "static_isr_system_ghidra.txt"
    )


def test_the_resolved_dynamic_prompt_is_the_golden():
    """Pinned to CAPE2, exactly as ``dynamic_analyst._ISR_SYSTEM`` always was.

    The dynamic analyst has never assembled its prompt from the *configured*
    sandbox (that field defaults to ``mock``, whose fragment is empty); it
    sends this frozen constant on every run. Resolution says the same thing,
    or the default profile would change the day this landed.
    """
    from maljan.agents.composition import resolve_agent
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM

    assert resolve_agent("dynamic", _mock_container()).prompt == _ISR_SYSTEM
    assert _ISR_SYSTEM == _golden("dynamic_system_cape2.txt")


def test_the_resolved_network_and_judge_prompts_are_their_constants():
    from maljan.agents.composition import resolve_agent
    from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM
    from maljan.agents.network_analyst import _ISR_SYSTEM as NETWORK_SYSTEM

    container = _mock_container()
    assert resolve_agent("network", container).prompt == NETWORK_SYSTEM
    assert resolve_agent("judge", container).prompt == JUDGE_VERDICT_SYSTEM


def test_the_resolved_static_tool_set_is_todays_registry_tool_set():
    """Under the default profile nothing is bound to ``static``, and that is the point.

    ``resolve_agent`` composes the *registry* half of an agent's tools; the
    provider half stays where it has always been, inside
    ``StaticAnalyst._initialize_mcp_client``, so the Ghidra attach is not
    pulled forward into resolution. Both halves are unchanged; this pins the
    half resolution owns.
    """
    from maljan.agents.composition import resolve_agent
    from maljan.core.config import Settings
    from maljan.providers.servers import ServerRegistry

    container = _mock_container()
    expected, _ = ServerRegistry(Settings(_env_file=None)).tools_for("static", "job")
    assert [t.name for t in resolve_agent("static", container).tools] == [
        t.name for t in expected
    ]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/agents/test_composition.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.agents.composition'`.

- [ ] **Step 3: Add `tools_for_ref` to the server registry**

In `src/maljan/providers/servers.py`, beside `UNAVAILABLE_REASON` (line 37):

```python
# A server that answered but does not offer the tool a definition asked for by
# name. Distinct from ``UNAVAILABLE_REASON``: the server is fine, the
# *reference* is stale, and an operator fixes those two things differently.
AGENT_TOOL_UNAVAILABLE_REASON = "agent tool '{server}.{name}' unavailable"
```

Add the two methods after `atools_for` (line 873):

```python
    def _ref_tools(self, handle: "ServerHandle", ref: Any) -> tuple[list[BaseTool], list[str]]:
        """The tools one open handle contributes for ``ref``, and any reason it did not.

        ``ref.name is None`` is the whole allow-listed set — the same list
        ``tools_for`` would have merged had the server been bound by ``agents``.
        A name is one tool of it, matched after B's collision prefixing, so a
        renamed tool is still findable under the name the model actually sees.
        """
        available = handle.tools()
        if ref.name is None:
            return list(available), []
        wanted = str(ref.name)
        picked = [
            tool
            for tool in available
            if str(getattr(tool, "name", "")) in (wanted, f"{handle.name}__{wanted}")
        ]
        if not picked:
            return [], [
                AGENT_TOOL_UNAVAILABLE_REASON.format(server=handle.name, name=wanted)
            ]
        return picked, []

    def _record(self, reasons: list[str]) -> None:
        for reason in reasons:
            if reason not in self.degradation_reasons:
                self.degradation_reasons.append(reason)

    def tools_for_ref(
        self, ref: Any, job_id: str, **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """One ``ToolRef(kind="mcp")``'s tools, opened on the shared agent loop.

        The reference half of an agent's tool set. Never raises, for the same
        reason ``tools_for`` never does: a definition that points at a server
        which is down costs the agent depth, not the job.
        """
        from maljan.agents.base_agent import _get_agent_loop

        try:
            handle = self._handle_for(self.get(str(ref.server)), _get_agent_loop())
        except ProviderConfigurationError:
            reasons = [
                AGENT_TOOL_UNAVAILABLE_REASON.format(server=ref.server, name=ref.name or "*")
            ]
            self._record(reasons)
            return [], reasons
        try:
            handle.open(job_id, **context)
        except Exception as exc:  # noqa: BLE001 — a referenced server always degrades
            logger.warning("mcp server '%s' could not be attached: %s", handle.name, exc)
            reasons = [UNAVAILABLE_REASON.format(name=handle.name)]
            self._record(reasons)
            return [], reasons
        tools, reasons = self._ref_tools(handle, ref)
        self._record(reasons)
        return tools, reasons

    async def atools_for_ref(
        self, ref: Any, job_id: str, **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """``tools_for_ref``, awaited on the caller's own loop."""
        loop = asyncio.get_running_loop()
        try:
            handle = self._handle_for(self.get(str(ref.server)), loop)
        except ProviderConfigurationError:
            reasons = [
                AGENT_TOOL_UNAVAILABLE_REASON.format(server=ref.server, name=ref.name or "*")
            ]
            self._record(reasons)
            return [], reasons
        try:
            await handle.aopen(job_id, **context)
        except Exception as exc:  # noqa: BLE001 — a referenced server always degrades
            logger.warning("mcp server '%s' could not be attached: %s", handle.name, exc)
            reasons = [UNAVAILABLE_REASON.format(name=handle.name)]
            self._record(reasons)
            return [], reasons
        tools, reasons = self._ref_tools(handle, ref)
        self._record(reasons)
        return tools, reasons
```

- [ ] **Step 4: Extract the judge's verdict prompt to a module constant**

In `src/maljan/agents/judge_agent.py`, move the `verdict_system = (...)` literal at line 535 to module scope, unchanged byte for byte, directly above `class JudgeAgent`:

```python
# The judge's system prompt. A module constant since sub-project C so that
# ``composition.builtin_prompt("judge")`` and ``give_verdict`` cannot disagree
# about what the judge is told; the text is unchanged from the inline literal
# it replaces, and ``tests/agents/test_prompt_byte_identity.py`` says so.
JUDGE_VERDICT_SYSTEM = (
    "You are the Chief Malware Judge. Based on the expert reports below, "
    "provide a final verdict: Malware, Benign, or Suspicious.\n\n"
    "RULES:\n"
    "- Map findings to MITRE ATT&CK using AttackPattern objects (valid IDs: T#### or T####.###).\n"
    "- Omit technique ID if unsure.\n"
    "- On every Relationship, set x_maljan_confidence (0.0-1.0), "
    "x_maljan_evidence_basis (static|dynamic|network|all|unknown), "
    "and x_maljan_contributing_agents list.\n"
    "- ALL STIX object IDs MUST be ``<type>--<random uuid4>`` "
    "(spec-compliant 8-4-4-4-12 hex). NEVER reuse example UUIDs from "
    "the schema description. NEVER use ``<type>--T####`` (non-UUID).\n"
    "- DO NOT emit Indicator objects whose pattern values are inferred, "
    "hypothetical, or example. Every Indicator's pattern value MUST "
    "appear verbatim in the deterministic evidence (static strings, "
    "sandbox observations, or network IOCs). When in doubt, emit zero "
    "Indicators — the deterministic renderer will fill them in.\n"
    "- Return ONLY a valid JSON STIX 2.1 Bundle. No markdown wrappers."
)
```

and replace the assignment at line 535 with `verdict_system = JUDGE_VERDICT_SYSTEM`.

- [ ] **Step 5: Write `composition.py`**

```python
# src/maljan/agents/composition.py
"""What one agent definition actually resolves to, for a given job.

One function answers "what prompt, what tools, what LLM, what static provider
does agent ``<key>`` get" — the graph, the container, the worker's mirror step
and the settings probe all call it, so a probe cannot report one answer and a
run produce another. That is the whole point of the module: before this, the
answer was spread across three analyst classes and could only be discovered by
running a job.

Two halves of an agent's tools live in two places on purpose:

* the *registry* half — servers bound by ``MCPServerConfig.agents`` and the
  explicit ``ToolRef``s of the definition — is composed here, because nothing
  else knows about ``ToolRef``;
* the *provider* half of a built-in role stays inside that role's class
  (``StaticAnalyst._initialize_mcp_client`` and friends), because opening
  Ghidra is a per-sample act with a job context, and pulling it into
  resolution would make the settings probe launch a decompiler.

A ``generic`` agent has no class of its own to open a provider, so an explicit
``ToolRef(kind="provider")`` is the one way it gets provider tools, and that
path *is* resolved here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from maljan.core.config import AgentDefinition, ProfileDefinition, Settings, ToolRef
from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


@dataclass(frozen=True)
class ResolvedAgent:
    """Everything an agent needs, decided once per job and never re-derived.

    ``degradation_reasons`` are this agent's own — a referenced tool that is
    not there, a server that would not open. They are additive: the run
    summary reads ``container.server_degradation_reasons()``, which is the
    registry's union across every agent in the job.
    """

    key: str
    role: str
    prompt: str
    tools: list["BaseTool"]
    static_provider_id: str
    llm: Any | None
    degradation_reasons: tuple[str, ...] = ()


def active_profile(settings: Settings) -> ProfileDefinition:
    """The profile this job runs. ``AgentsConfig`` guarantees it exists."""
    return settings.agents.profiles[settings.agents.profile]


def analyst_keys(settings: Settings) -> list[str]:
    """The ordered analyst keys of the active profile.

    The single topology source: the builder, the negotiation and revision
    nodes, the judge node and the run summary all read this list, so a profile
    change moves all of them together or none of them.
    """
    return list(active_profile(settings).analysts)


def current_analyst_keys() -> list[str]:
    """``analyst_keys`` for the process-wide settings.

    For the two consumers that have no container to ask — ``ttp_cascade``'s
    ``is_consensus`` and ``run_summary``'s per-layer ordering — both of which
    run inside a job whose settings the worker has already installed.
    """
    from maljan.core.config import get_settings

    return analyst_keys(get_settings())


def static_provider_id_for(settings: Settings, key: str) -> str:
    """The static provider id agent ``key`` reads, falling back to the global one."""
    definition = settings.agents.definitions.get(key)
    if definition is not None and definition.static_provider:
        return str(definition.static_provider)
    return str(settings.static.provider)


def builtin_prompt(role: str, container: Any, static_provider_id: str) -> str:
    """The prompt a built-in role has always sent.

    ``static`` is assembled — HEAD + the *agent's own* static provider's
    fragment + TAIL — which is what makes a clone on radare2 meaningful: the
    same assembly, a different middle.

    ``dynamic`` is the frozen CAPE2 assembly, not the configured sandbox's.
    This analyst has never read the configured provider for its prompt (the
    default is ``mock``, whose fragment is empty), there is no per-agent
    sandbox provider to vary, and assembling from the configured one here
    would change the default profile's dynamic prompt on the day this landed.
    """
    if role == "static":
        from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL

        provider = container.get_static_provider(static_provider_id)
        return _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL
    if role == "dynamic":
        from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_SYSTEM

        return DYNAMIC_SYSTEM
    if role == "network":
        from maljan.agents.network_analyst import _ISR_SYSTEM as NETWORK_SYSTEM

        return NETWORK_SYSTEM
    if role == "judge":
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM

        return JUDGE_VERDICT_SYSTEM
    raise ValueError(f"no built-in prompt for role {role!r}: give the definition a prompt")


def _definition(settings: Settings, key: str) -> AgentDefinition:
    definition = settings.agents.definitions.get(key)
    if definition is None:
        available = ", ".join(sorted(settings.agents.definitions)) or "(none)"
        raise KeyError(f"No agent definition named {key!r}. Available: {available}")
    return definition


def _dedupe(tools: list["BaseTool"]) -> list["BaseTool"]:
    """First occurrence of each tool name wins, order preserved.

    B's collision prefixing has already run by the time a tool reaches here, so
    two tools with the same name really are the same tool arriving twice — a
    server both bound by ``agents`` and named by a ``ToolRef``.
    """
    seen: set[str] = set()
    out: list["BaseTool"] = []
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        if name in seen:
            continue
        seen.add(name)
        out.append(tool)
    return out


def _provider_tools(container: Any, definition: AgentDefinition, provider_id: str) -> list[Any]:
    """The agent's static provider's tools, for a definition that asked for them."""
    if not any(ref.kind == "provider" for ref in definition.tools):
        return []
    from maljan.providers.base import StaticJobContext

    provider = container.get_static_provider(provider_id)
    if not provider.capabilities.provides_tools:
        logger.info("Static provider '%s' exposes no tools.", provider.id)
        return []
    provider.open(StaticJobContext())
    return list(provider.select_tools(provider.get_tools(), None))


def _mcp_refs(definition: AgentDefinition) -> list[ToolRef]:
    return [ref for ref in definition.tools if ref.kind == "mcp"]


def _agent_llm(container: Any, key: str) -> Any:
    """The agent's model, or None on a mock container.

    A mock container (``ServiceContainer(settings, mock=True)``) builds no LLM
    registry and ``get_agent_llm`` raises there; the agent probe resolves on
    such a container on purpose, so resolution never asks it for a model.
    """
    if getattr(container, "mock", False):
        return None
    return container.get_agent_llm(key)


def resolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent:
    """Everything agent ``key`` gets under this container's settings."""
    settings: Settings = container.config
    definition = _definition(settings, key)
    provider_id = static_provider_id_for(settings, key)
    prompt = definition.prompt
    if prompt is None:
        prompt = builtin_prompt(definition.role, container, provider_id)

    reasons: list[str] = []
    tools: list[Any] = list(_provider_tools(container, definition, provider_id))
    registry = container.get_server_registry()
    bound, bound_reasons = registry.tools_for(key, job_key)
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(definition):
        referenced, ref_reasons = registry.tools_for_ref(ref, job_key)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=_dedupe(tools),
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
    )


async def aresolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent:
    """``resolve_agent``, attaching on the caller's own loop.

    For a caller already inside an event loop — the judge's node and the
    settings probe — where handing the attach to the shared agent loop would
    bind a transport to a loop other than the one that awaits its tool calls.
    """
    settings: Settings = container.config
    definition = _definition(settings, key)
    provider_id = static_provider_id_for(settings, key)
    prompt = definition.prompt
    if prompt is None:
        prompt = builtin_prompt(definition.role, container, provider_id)

    reasons: list[str] = []
    tools: list[Any] = list(_provider_tools(container, definition, provider_id))
    registry = container.get_server_registry()
    bound, bound_reasons = await registry.atools_for(key, job_key)
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(definition):
        referenced, ref_reasons = await registry.atools_for_ref(ref, job_key)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=_dedupe(tools),
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
    )
```

`container.get_static_provider(provider_id)` takes its argument from Task 6; until that task lands, `ServiceContainer.get_static_provider` still takes none. Add the optional parameter in Task 6 — this task's tests use the fake container above and `tests/agents/test_prompt_byte_identity.py` calls `resolve_agent` with a real one, so add the one-line signature change (`def get_static_provider(self, provider_id: str | None = None)` ignoring the argument for now) in this task and give it its caching behaviour in Task 6.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/agents/test_composition.py tests/agents/test_prompt_byte_identity.py tests/servers -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/agents src/maljan/providers/servers.py tests/agents && \
uv run ruff format --check src/maljan/agents src/maljan/providers/servers.py tests/agents && \
uv run mypy src/ apps/api/
git add src/maljan/agents/composition.py src/maljan/agents/judge_agent.py \
  src/maljan/providers/servers.py src/maljan/core/container.py \
  tests/agents/test_composition.py tests/agents/test_prompt_byte_identity.py
git commit -m "feat(agents): resolve an agent definition into its prompt, tools, llm and static provider"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 4: One revision framing, shared by the network analyst and every custom one

**Files:**
- Modify: `src/maljan/agents/base_agent.py` (module scope, beside the other prompt helpers: `prompt_to_messages`, `_REVISION_ISR_FRAMING`, `revision_messages`); `src/maljan/agents/network_analyst.py:160-206` (`revise`), `:316-382` (`revise_isr`), plus `_NETWORK_REVISE_SYSTEM` at module scope
- Test: `tests/agents/test_revision_prompt_golden.py` (Task 1, unchanged), `tests/agents/test_revision_messages.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/agents/base_agent.py
  _REVISION_ISR_FRAMING: str
  def prompt_to_messages(prompt_messages: list[tuple[str, str]]) -> list[BaseMessage]
  def revision_messages(
      system_prompt: str,
      original_data: str,
      own_report: str,
      peer_reports: dict[str, str],
      mediator_feedback: str,
      *,
      isr: bool = False,
      revision_round: int = 1,
  ) -> list[tuple[str, str]]
  # src/maljan/agents/network_analyst.py
  _NETWORK_REVISE_SYSTEM: str
  ```
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test**

```python
# tests/agents/test_revision_messages.py
"""The shared revision framing, examined directly.

``test_revision_prompt_golden.py`` proves the network analyst still sends the
same bytes. This proves the helper it now sends them through behaves the way
``ConfigurableAnalyst`` will rely on: the system prompt passes through
untouched on the text path and gains the negotiation framing on the ISR path,
the peer section is labelled differently on each, and an agent with no peers
says so rather than sending an empty block.
"""

from __future__ import annotations

from maljan.agents.base_agent import (
    _REVISION_ISR_FRAMING,
    prompt_to_messages,
    revision_messages,
)

PEERS = {"static": "S-TEXT", "dynamic": "D-TEXT"}


def _one(isr: bool) -> tuple[str, str]:
    messages = revision_messages(
        "SYSTEM-TEXT", "RAW", "OWN", PEERS, "FEEDBACK", isr=isr, revision_round=3
    )
    assert [role for role, _ in messages] == ["system", "human"]
    return messages[0][1], messages[1][1]


def test_the_text_path_passes_the_system_prompt_through_untouched():
    system, _ = _one(isr=False)
    assert system == "SYSTEM-TEXT"


def test_the_isr_path_appends_the_negotiation_framing():
    system, _ = _one(isr=True)
    assert system == "SYSTEM-TEXT" + "\n\n" + _REVISION_ISR_FRAMING
    assert "DISPUTES: NONE" in _REVISION_ISR_FRAMING


def test_the_text_path_labels_peers_as_analyst_reports():
    _, human = _one(isr=False)
    assert "STATIC ANALYST REPORT:\nS-TEXT" in human
    assert "DYNAMIC ANALYST REPORT:\nD-TEXT" in human
    assert "PEER ANALYST REPORTS:" in human
    assert "MEDIATOR CONTRADICTIONS:\nFEEDBACK" in human
    assert human.endswith("Revise your analysis addressing the contradictions above.")


def test_the_isr_path_labels_peers_as_reports_and_asks_for_disputes():
    _, human = _one(isr=True)
    assert "STATIC REPORT:\nS-TEXT" in human
    assert "PEER REPORTS:" in human
    assert "MEDIATOR FEEDBACK:\nFEEDBACK" in human
    assert "DISPUTES:" in human


def test_both_paths_carry_the_raw_data_and_the_agents_own_report():
    for isr in (False, True):
        _, human = _one(isr)
        assert "OWN" in human and "RAW" in human


def test_an_agent_with_no_peers_is_told_so():
    for isr in (False, True):
        messages = revision_messages("S", "RAW", "OWN", {}, "F", isr=isr)
        assert "No peer reports available." in messages[1][1]


def test_prompt_to_messages_builds_the_two_message_types_without_a_template():
    """Braces in the *content* must not be read as template variables."""
    messages = prompt_to_messages([("system", "S {json}"), ("human", 'H {"a": 1}')])
    assert [m.type for m in messages] == ["system", "human"]
    assert messages[0].content == "S {json}"
    assert messages[1].content == 'H {"a": 1}'


def test_prompt_to_messages_ignores_a_role_it_does_not_know():
    assert prompt_to_messages([("assistant", "x"), ("human", "y")]) == prompt_to_messages(
        [("human", "y")]
    )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/agents/test_revision_messages.py -q`
Expected: FAIL — `ImportError: cannot import name 'revision_messages' from 'maljan.agents.base_agent'`.

- [ ] **Step 3: Add the helpers to `base_agent.py`**

At module scope, above `class BaseAnalyst`:

```python
# The negotiation-round instructions the ISR revision path appends to whatever
# system prompt its agent carries. Lifted verbatim out of
# ``NetworkAnalyst.revise_isr``; ``tests/agents/test_revision_prompt_golden.py``
# holds it to the byte.
_REVISION_ISR_FRAMING = (
    "You are in a negotiation round. You MUST:\n"
    "1. List any peer claims you still DISPUTE in a DISPUTES section.\n"
    "2. Revise your own claims based on new evidence.\n"
    "3. If you have NO disputes, write 'DISPUTES: NONE' to signal convergence."
)


def prompt_to_messages(prompt_messages: list[tuple[str, str]]) -> list["BaseMessage"]:
    """``(role, text)`` pairs as LangChain messages, with no templating step.

    The same construction ``execute_tool_loop`` does inline, and for the same
    reason: a ``ChatPromptTemplate`` would read a literal ``{...}`` inside a
    report — JSON, a decompiled struct — as an f-string variable and raise on
    content the pipeline routinely produces. An unknown role is dropped rather
    than guessed at.
    """
    from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

    built: list[BaseMessage] = []
    for role, content in prompt_messages:
        if role == "system":
            built.append(SystemMessage(content=content))
        elif role == "human":
            built.append(HumanMessage(content=content))
    return built


def revision_messages(
    system_prompt: str,
    original_data: str,
    own_report: str,
    peer_reports: dict[str, str],
    mediator_feedback: str,
    *,
    isr: bool = False,
    revision_round: int = 1,
) -> list[tuple[str, str]]:
    """The revision prompt every analyst sends, as ``(role, text)`` pairs.

    Extracted from ``NetworkAnalyst`` so the configurable analyst sends the
    same framing rather than a second copy of it that drifts. The two paths it
    covers are the two that exist: ``isr=False`` is the plain text revision,
    which passes ``system_prompt`` through untouched; ``isr=True`` is the
    negotiation round, which appends ``_REVISION_ISR_FRAMING`` and asks for the
    CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE plus DISPUTES shape the ISR parsers
    read. Everything here — the labels, the order of the blocks, the closing
    sentence — is byte-for-byte what the network analyst sent before.

    ``revision_round`` is not interpolated into the prompt (it never was); it
    is carried so a caller's log line and the returned ISR agree about which
    round produced which text.
    """
    logger.debug(
        "Building revision prompt (isr=%s, round=%d, peers=%d).",
        isr,
        revision_round,
        len(peer_reports),
    )
    if isr:
        peer_section = (
            "\n\n".join(f"{name.upper()} REPORT:\n{report}" for name, report in peer_reports.items())
            or "No peer reports available."
        )
        return [
            ("system", system_prompt + "\n\n" + _REVISION_ISR_FRAMING),
            (
                "human",
                f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                f"PEER REPORTS:\n{peer_section}\n\n"
                f"MEDIATOR FEEDBACK:\n{mediator_feedback}\n\n"
                f"RAW DATA:\n{original_data}\n\n"
                "Format your response as structured claims (CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
                "followed by a DISPUTES section listing peer claims you reject.\n"
                "Example:\n"
                "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
                "DISPUTES:\n- Static analyst says no C2 strings but PCAP shows beaconing.\n",
            ),
        ]

    peer_section = (
        "\n\n".join(
            f"{name.upper()} ANALYST REPORT:\n{report}" for name, report in peer_reports.items()
        )
        or "No peer reports available."
    )
    return [
        ("system", system_prompt),
        (
            "human",
            f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
            f"PEER ANALYST REPORTS:\n{peer_section}\n\n"
            f"MEDIATOR CONTRADICTIONS:\n{mediator_feedback}\n\n"
            f"ORIGINAL RAW DATA:\n{original_data}\n\n"
            "Revise your analysis addressing the contradictions above.",
        ),
    ]
```

- [ ] **Step 4: Point the network analyst at the helper**

Add the extracted system prompt at module scope in `network_analyst.py`, under `_ISR_SYSTEM`:

```python
# The text revision path's own system prompt. It is not ``_ISR_SYSTEM`` plus a
# suffix — it is a different prompt, and it was inline in ``revise`` until the
# revision framing moved to ``BaseAnalyst``. Byte-for-byte unchanged.
_NETWORK_REVISE_SYSTEM = (
    "You are an expert Network Analyst participating in a collaborative "
    "multi-agent malware analysis. The mediator has identified contradictions "
    "between your report and other experts. Review the peer reports and mediator "
    "feedback, then revise your analysis. Correlate network traffic with any "
    "hardcoded C2 URLs or HTTP API calls raised by peers. "
    "Focus on MITRE ATT&CK: T1071, T1571."
)
```

`revise` becomes, in full:

```python
    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise network analysis based on peer findings and mediator feedback.

        The framing moved to ``BaseAnalyst.revision_messages`` so a custom
        analyst sends the same one. The messages that reach the model are
        identical, which is what ``tests/agents/test_revision_prompt_golden.py``
        compares against a fixture captured before the move; the
        ``ChatPromptTemplate`` round trip is gone with it, because the template
        only ever substituted these same four values and could not survive a
        brace inside one of them.
        """
        self.logger.info("Revising network analysis based on peer feedback...")

        messages = revision_messages(
            _NETWORK_REVISE_SYSTEM,
            original_data,
            own_report,
            peer_reports,
            mediator_feedback,
            isr=False,
        )
        response = self.llm.invoke(prompt_to_messages(messages))
        return str(response.content)
```

`revise_isr` becomes, in full:

```python
    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Return (revised_text, AgentISR) with dissent_items populated."""
        self.logger.info("Executing network ISR revision (round %d)...", revision_round)

        messages = revision_messages(
            _ISR_SYSTEM,
            original_data,
            own_report,
            peer_reports,
            mediator_feedback,
            isr=True,
            revision_round=revision_round,
        )
        response = self.llm.invoke(prompt_to_messages(messages))
        content = str(response.content)

        claims = _parse_claim_blocks(content)
        dissent = _parse_disputes(content)

        if not claims:
            return content, self._text_to_isr(content, revision_round=revision_round)

        isr = AgentISR(
            agent_id=self.name,
            domain="network",
            claims=claims,
            dissent_items=dissent,
            revision_round=revision_round,
        )
        return content, isr
```

Update the import line at the top of `network_analyst.py`:

```python
from maljan.agents.base_agent import BaseAnalyst, prompt_to_messages, revision_messages
```

`ChatPromptTemplate` is still used by `analyze` and `analyze_isr`, so its import stays.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/agents/test_revision_messages.py tests/agents/test_revision_prompt_golden.py tests/agents -q`
Expected: PASS — in particular the Task 1 golden, unchanged, against the refactored code.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/agents tests/agents && \
uv run ruff format --check src/maljan/agents tests/agents && \
uv run mypy src/ apps/api/
git add src/maljan/agents/base_agent.py src/maljan/agents/network_analyst.py \
  tests/agents/test_revision_messages.py
git commit -m "fix: one revision framing behind the network analyst's two revision paths"
```

- [ ] **Step 7: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 5: `ConfigurableAnalyst` — one class for every custom agent

**Files:**
- Create: `src/maljan/agents/configurable_analyst.py`, `tests/agents/test_configurable_analyst.py`
- Modify: `src/maljan/agents/base_agent.py:1842` (`_infer_domain` returns `str`)
- Test: `tests/agents/test_configurable_analyst.py`

**Interfaces:**
- Produces:
  ```python
  # src/maljan/agents/configurable_analyst.py
  class ConfigurableAnalyst(BaseAnalyst):
      def __init__(self, definition_key: str, resolved: ResolvedAgent, llm: BaseChatModel) -> None
      def analyze(self, data: str) -> str
      def revise(self, original_data, own_report, peer_reports, mediator_feedback) -> str
      def analyze_isr(self, data: str) -> AgentISR
      def revise_isr(self, original_data, own_report, peer_reports, mediator_feedback,
                     revision_round: int = 1) -> tuple[str, AgentISR]
      def _infer_domain(self) -> str
      def _initialize_mcp_client(self) -> None
  ```
- Consumes: `BaseAnalyst.execute_tool_loop`, `._text_to_isr`, `.revision_messages`, `maljan.agents.composition.ResolvedAgent`.

- [ ] **Step 1: Write the failing test**

```python
# tests/agents/test_configurable_analyst.py
"""The generic analyst, against a fake LLM.

Four properties, and they are the whole class: it sends its resolved prompt,
it revises through the shared framing, its ISRs carry its own key as the
domain, and a broken tool never costs the job an analyst.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst


class _Recording(FakeMessagesListChatModel):
    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


def _llm(text: str = "CLAIM: found it\nEVIDENCE: string at 0x40\nCONFIDENCE: 0.7\nTECHNIQUE: T1027\n---\n") -> _Recording:
    _Recording.seen = []
    return _Recording(responses=[AIMessage(content=text)])


def _resolved(llm: Any, tools: list[Any] | None = None, reasons: tuple[str, ...] = ()) -> ResolvedAgent:
    return ResolvedAgent(
        key="strings",
        role="generic",
        prompt="PROMPT-MARKER",
        tools=tools or [],
        static_provider_id="ghidra",
        llm=llm,
        degradation_reasons=reasons,
    )


def _agent(**over: Any) -> ConfigurableAnalyst:
    llm = over.pop("llm", None) or _llm()
    resolved = over.pop("resolved", None) or _resolved(llm, **over)
    return ConfigurableAnalyst("strings", resolved, llm)


def test_analyze_sends_the_resolved_prompt_and_the_data():
    agent = _agent()
    text = agent.analyze("EVIDENCE-BLOB")
    assert "found it" in text
    system, human = _Recording.seen[-1]
    assert system["content"] == "PROMPT-MARKER"
    assert human["content"] == "EVIDENCE-BLOB"


def test_revise_uses_the_shared_revision_framing():
    from maljan.agents.base_agent import revision_messages

    agent = _agent()
    agent.revise("RAW", "OWN", {"static": "S"}, "FEEDBACK")
    expected = revision_messages("PROMPT-MARKER", "RAW", "OWN", {"static": "S"}, "FEEDBACK")
    assert [m["content"] for m in _Recording.seen[-1]] == [text for _, text in expected]


def test_the_isr_domain_is_the_definition_key_not_a_guessed_role():
    agent = _agent()
    isr = agent.analyze_isr("EVIDENCE-BLOB")
    assert isr.domain == "strings"
    assert isr.agent_id == "strings"
    assert isr.claims and isr.claims[0].technique_id == "T1027"


def test_revise_isr_returns_the_text_and_an_isr_of_the_right_round():
    agent = _agent()
    text, isr = agent.revise_isr("RAW", "OWN", {}, "F", revision_round=2)
    assert "found it" in text
    assert isr.revision_round == 2 and isr.domain == "strings"


def test_the_isr_path_asks_for_the_structured_shape():
    agent = _agent()
    agent.analyze_isr("EVIDENCE-BLOB")
    human = _Recording.seen[-1][1]["content"]
    assert "CLAIM:" in human and "EVIDENCE:" in human and "TECHNIQUE:" in human
    assert "EVIDENCE-BLOB" in human


def test_a_resolution_degradation_is_carried_and_never_raised():
    agent = _agent(reasons=("agent tool 'mine.nope' unavailable",))
    assert agent.degradation_reasons == ["agent tool 'mine.nope' unavailable"]
    assert agent.analyze("data")


def test_a_tool_that_explodes_is_recorded_and_the_loop_still_answers(monkeypatch):
    """A custom analyst never fails a job — the rule B applies to custom servers."""

    def _boom() -> str:
        raise RuntimeError("tool is broken")

    tool = StructuredTool.from_function(func=_boom, name="boom", description="boom")
    agent = _agent(tools=[tool])

    def _explode(prompt_messages: list) -> str:
        raise RuntimeError("tool is broken")

    monkeypatch.setattr(agent, "execute_tool_loop", _explode)
    text = agent.analyze("data")
    assert text.startswith("[WARN]")
    assert any("tool is broken" in r for r in agent.degradation_reasons)


def test_a_tool_failure_still_produces_a_zero_claim_isr_rather_than_an_exception(monkeypatch):
    agent = _agent()

    def _explode(prompt_messages: list) -> str:
        raise RuntimeError("llm is down")

    monkeypatch.setattr(agent, "execute_tool_loop", _explode)
    isr = agent.analyze_isr("data")
    assert isr.domain == "strings" and isr.claims == []


def test_the_agent_reports_its_resolved_tools_without_re_resolving(monkeypatch):
    tool = StructuredTool.from_function(func=lambda: "x", name="grep", description="grep")
    agent = _agent(tools=[tool])
    assert [t.name for t in agent.tools] == ["grep"]
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["grep"]


def test_the_name_is_the_definition_key():
    assert _agent().name == "strings"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/agents/test_configurable_analyst.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'maljan.agents.configurable_analyst'`.

- [ ] **Step 3: Write the class**

```python
# src/maljan/agents/configurable_analyst.py
"""The analyst an operator declares rather than writes.

One class, parametrised by a ``ResolvedAgent``. Deliberately thin: the three
built-in analysts carry provider-specific ISR extraction that goldens pin —
Ghidra program info, CAPE signature shapes, PCAP heuristics — and reproducing
any of that generically would be a guess. What is left is the part that is the
same for every analyst: send the prompt, run the ReAct loop when there are
tools and a plain call when there are none, and wrap whatever comes back into
an ISR under the agent's own key.

The degradation policy is the one sub-project B applies to custom servers: a
custom analyst never fails a job. A tool server that would not attach, a tool
that is not there, an LLM call that raises — each becomes a reason on
``degradation_reasons`` and a ``[WARN]`` report, so the run summary says the
ensemble was thinner rather than the job dying on an agent the operator added
this morning.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.base_agent import BaseAnalyst, revision_messages
from maljan.agents.composition import ResolvedAgent
from maljan.agents.base_agent import describe_exception
from maljan.schemas.isr_models import AgentISR

# Appended to the agent's own prompt on the ISR paths. The operator writes what
# their agent is *for*; this is the shape the ISR parsers read, and asking them
# to reproduce it by hand would make a working definition a matter of luck.
_ISR_FORMAT_INSTRUCTION = (
    "Return a structured list of findings. For each finding state: the claim, "
    "the exact artifact reference, your confidence (0.0-1.0), and the MITRE "
    "ATT&CK technique ID.\n\n"
    "Format each finding as:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference>\n"
    "CONFIDENCE: <float>\n"
    "TECHNIQUE: <T-ID or NONE>\n"
    "---\n\n"
)


class ConfigurableAnalyst(BaseAnalyst):
    """A ``BaseAnalyst`` whose prompt, tools and LLM come from configuration."""

    def __init__(
        self, definition_key: str, resolved: ResolvedAgent, llm: BaseChatModel
    ) -> None:
        super().__init__(llm=llm, name=definition_key, tools=list(resolved.tools))
        self._resolved = resolved
        # Reasons resolution already produced (a referenced tool that is not
        # there) start the list; the analyst appends its own as it runs.
        self.degradation_reasons = list(resolved.degradation_reasons)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _initialize_mcp_client(self) -> None:
        """Nothing to attach: resolution already did it.

        Present because ``BaseAnalyst._try_initialize_mcp`` calls it. A custom
        analyst has no provider lifecycle of its own — its tools arrived in the
        ``ResolvedAgent`` — so this is deliberately a no-op rather than a
        second attachment path that could disagree with the first.
        """
        return None

    def _infer_domain(self) -> str:
        """The definition key. A custom agent's domain is its own name."""
        return self.name

    # ------------------------------------------------------------------
    # Text interface
    # ------------------------------------------------------------------

    def _run(self, prompt_messages: list[tuple[str, str]], what: str) -> str:
        """Run the loop and turn any failure into a report the pipeline can read."""
        try:
            return str(self.execute_tool_loop(prompt_messages))
        except Exception as exc:  # noqa: BLE001 — a custom analyst never fails a job
            reason = f"agent '{self.name}': {describe_exception(exc)}"
            self.logger.warning("%s failed during %s: %s", self.name, what, reason)
            if reason not in self.degradation_reasons:
                self.degradation_reasons.append(reason)
            return f"[WARN] {reason}"

    def analyze(self, data: str) -> str:
        self.logger.info("Executing '%s' analysis (%d tools).", self.name, len(self.tools))
        return self._run([("system", self._resolved.prompt), ("human", data)], "analysis")

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        self.logger.info("Revising '%s' analysis based on peer feedback...", self.name)
        return self._run(
            revision_messages(
                self._resolved.prompt,
                original_data,
                own_report,
                peer_reports,
                mediator_feedback,
                isr=False,
            ),
            "revision",
        )

    # ------------------------------------------------------------------
    # ISR interface
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        self.logger.info("Executing '%s' ISR analysis...", self.name)
        text = self._run(
            [
                ("system", self._resolved.prompt),
                ("human", _ISR_FORMAT_INSTRUCTION + data),
            ],
            "ISR analysis",
        )
        return self._text_to_isr(text, revision_round=0)

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        self.logger.info("Executing '%s' ISR revision (round %d)...", self.name, revision_round)
        text = self._run(
            revision_messages(
                self._resolved.prompt,
                original_data,
                own_report,
                peer_reports,
                mediator_feedback,
                isr=True,
                revision_round=revision_round,
            ),
            "ISR revision",
        )
        return text, self._text_to_isr(text, revision_round=revision_round)
```

In `base_agent.py`, widen `_infer_domain`'s return type (line 1842) so the override above is not a narrowing violation. The body is unchanged:

```python
    def _infer_domain(self) -> str:
        """Infer the ISR domain from the agent's registered name.

        Returns ``str`` rather than the three-way Literal since sub-project C:
        a custom analyst's domain is its own definition key, and ``AgentISR``
        has always accepted a free string there.
        """
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/agents/test_configurable_analyst.py tests/agents -q`
Expected: PASS.

- [ ] **Step 5: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/agents tests/agents && \
uv run ruff format --check src/maljan/agents tests/agents && \
uv run mypy src/ apps/api/
git add src/maljan/agents/configurable_analyst.py src/maljan/agents/base_agent.py \
  tests/agents/test_configurable_analyst.py
git commit -m "feat(agents): a configurable analyst driven by its resolved definition"
```

- [ ] **Step 6: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 6: The container builds agents from definitions

**Files:**
- Modify: `src/maljan/core/container.py:118` (a second static-provider cache), `:146-152` (the init log), `:267-274` (`get_static_provider`), `:322-337` (`get_agent`), plus the three new accessors
- Test: `tests/unit/test_container_composition.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/core/container.py
  def ServiceContainer.active_profile(self) -> ProfileDefinition
  def ServiceContainer.analyst_keys(self) -> list[str]
  def ServiceContainer.agent_role(self, key: str) -> str
  def ServiceContainer.get_agent(self, name: str) -> BaseAnalyst          # profile-aware
  def ServiceContainer.get_static_provider(self, provider_id: str | None = None) -> StaticProvider
  ```
- Consumes: `maljan.agents.composition.resolve_agent`, `.active_profile`, `.analyst_keys`; `AgentRegistry.create`; `ConfigurableAnalyst`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_container_composition.py
"""The container answers "which analysts" and "which class" from the profile.

The first test is the byte-identity one: with the default profile the
container hands back the same three classes under the same three names it
always did. The rest are the new capability — a clone runs its built-in class
under its own key, a generic definition runs ``ConfigurableAnalyst``, and two
static providers in one profile really are two provider objects.
"""

from __future__ import annotations

import pytest

from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.network_analyst import NetworkAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


def _container(**agents) -> ServiceContainer:
    cfg = Settings(_env_file=None, agents=agents) if agents else Settings(_env_file=None)
    return ServiceContainer(cfg, mock=True)


def test_the_default_profile_gives_todays_three_agents_unchanged():
    container = _container()
    assert container.analyst_keys() == ["static", "dynamic", "network"]
    assert [type(container.get_agent(k)) for k in container.analyst_keys()] == [
        StaticAnalyst,
        DynamicAnalyst,
        NetworkAnalyst,
    ]
    assert [container.get_agent(k).name for k in container.analyst_keys()] == [
        "static",
        "dynamic",
        "network",
    ]


def test_the_active_profile_is_the_object_not_its_name():
    container = _container()
    assert container.active_profile().analysts == ["static", "dynamic", "network"]


def test_a_clone_runs_its_built_in_class_under_its_own_key():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    agent = container.get_agent("static_r2")
    assert isinstance(agent, StaticAnalyst)
    assert agent.name == "static_r2"
    assert agent._resolved.static_provider_id == "r2"
    assert container.agent_role("static_r2") == "static"


def test_a_generic_definition_runs_the_configurable_analyst():
    container = _container(
        definitions={"strings": {"role": "generic", "prompt": "read strings"}},
        profiles={"one": {"analysts": ["strings"]}},
        profile="one",
    )
    agent = container.get_agent("strings")
    assert isinstance(agent, ConfigurableAnalyst)
    assert agent.name == "strings"
    assert agent._resolved.prompt == "read strings"
    assert container.agent_role("strings") == "generic"


def test_two_provider_ids_give_two_provider_instances_and_each_is_cached():
    container = _container()
    ghidra_a = container.get_static_provider("ghidra")
    ghidra_b = container.get_static_provider("ghidra")
    r2 = container.get_static_provider("r2")
    assert ghidra_a is ghidra_b
    assert ghidra_a is not r2
    assert r2.id == "r2"


def test_the_no_argument_call_still_returns_the_globally_configured_provider():
    container = _container()
    assert container.get_static_provider() is container.get_static_provider("ghidra")
    assert container.get_static_provider().id == "ghidra"


def test_every_agent_gets_the_ledgers_and_a_way_back_to_the_container():
    container = _container(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"one": {"analysts": ["strings"]}},
        profile="one",
    )
    for key in ("static", "strings"):
        agent = container.get_agent(key)
        assert agent._container is container
        assert agent.token_ledger is container.get_token_ledger()
        assert agent.truncation_ledger is container.get_truncation_ledger()


def test_an_agent_is_built_once_and_cached():
    container = _container()
    assert container.get_agent("static") is container.get_agent("static")


def test_an_unknown_key_says_what_is_available():
    container = _container()
    with pytest.raises(KeyError, match="No agent definition named 'ghost'"):
        container.get_agent("ghost")


def test_a_reduced_profile_is_the_only_thing_the_container_reports():
    container = _container(
        profiles={"lean": {"analysts": ["network"]}}, profile="lean"
    )
    assert container.analyst_keys() == ["network"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_container_composition.py -q`
Expected: FAIL — `AttributeError: 'ServiceContainer' object has no attribute 'analyst_keys'`.

- [ ] **Step 3: Cache static providers by id**

In `__init__` (line 118), replace the single-slot cache with a map, keeping the old attribute name gone rather than stale:

```python
        self._static_provider_cache: dict[str, StaticProvider] = {}
```

and replace the init log's registry read (lines 146-152) with the profile:

```python
        from maljan.agents.composition import analyst_keys

        logger.info(
            "ServiceContainer initialized (mock=%s, profile=%s, analysts=%s, parsers=%s)",
            mock,
            config.agents.profile,
            analyst_keys(config),
            self.parser_registry.list_parsers(),
        )
```

`get_static_provider` (line 267) becomes, in full:

```python
    def get_static_provider(self, provider_id: str | None = None) -> StaticProvider:
        """The static provider for ``provider_id``, or the globally configured one.

        Cached per id rather than once, because a profile may hold two static
        analysts on two providers and each needs its own object: the providers
        are stateful (an open decompiler session, a loaded program), and
        sharing one between two analysts would have them fighting over which
        binary is loaded. ``get_static_provider()`` with no argument is the
        pre-existing call and returns exactly what it always did.
        """
        wanted = str(provider_id or self.config.static.provider)
        with self._lock:
            cached = self._static_provider_cache.get(wanted)
            if cached is None:
                from maljan.providers.registry import get_static_provider as build

                cfg = self.config
                if wanted != str(cfg.static.provider):
                    # The registry builds from ``cfg.static.provider``; a
                    # per-agent provider is that same construction against a
                    # copy, so no provider needs to learn a second entry point.
                    cfg = cfg.model_copy(deep=True)
                    cfg.static.provider = wanted  # type: ignore[assignment]
                cached = build(cfg)
                logger.info("Static provider: %s.", cached.id)
                self._static_provider_cache[wanted] = cached
            return cached
```

`aclose` closes every static provider it built; find the `get_static_provider().close()` call inside `aclose` (line ~365 onward) and replace it with a loop over `self._static_provider_cache.values()`, keeping the surrounding try/except exactly as it is:

```python
        for provider in list(self._static_provider_cache.values()):
            try:
                provider.close()
            except Exception as exc:  # noqa: BLE001 — teardown never raises
                logger.warning("Static provider '%s' did not close cleanly: %s", provider.id, exc)
```

- [ ] **Step 4: Build agents from definitions**

Add the three accessors above `get_agent`:

```python
    # ------------------------------------------------------------------
    # Composition accessors
    # ------------------------------------------------------------------

    def active_profile(self) -> Any:
        """The ``ProfileDefinition`` this job runs."""
        from maljan.agents.composition import active_profile

        return active_profile(self.config)

    def analyst_keys(self) -> list[str]:
        """The ordered analyst keys of the active profile.

        The topology source for the builder, the negotiation and revision
        nodes, the judge node and the worker's roster announcement. It replaced
        ``agent_registry.list_agents()`` in all of them at once, because a
        profile that half the pipeline believes in is worse than no profile.
        """
        from maljan.agents.composition import analyst_keys

        return analyst_keys(self.config)

    def agent_role(self, key: str) -> str:
        """The role definition ``key`` plays: what the code may branch on.

        A clone of the static analyst runs under its own key, so ``key ==
        "static"`` stopped being the question anything should ask; this is the
        question they meant.
        """
        definition = self.config.agents.definitions.get(key)
        if definition is None:
            available = ", ".join(sorted(self.config.agents.definitions)) or "(none)"
            raise KeyError(f"No agent definition named {key!r}. Available: {available}")
        return str(definition.role)
```

`get_agent` becomes, in full:

```python
    def get_agent(self, name: str) -> BaseAnalyst:
        """The agent definition ``name`` names, instantiated and wired.

        A built-in role runs its own class under the definition's key — a clone
        ``static_r2`` is a ``StaticAnalyst`` named ``static_r2`` — because
        those classes carry the provider-specific ISR extraction the goldens
        pin. A ``generic`` role runs ``ConfigurableAnalyst``. Both get the
        per-run ledgers, a way back to this container, and their
        ``ResolvedAgent``, so nothing below re-derives a prompt or a tool set.
        """
        with self._lock:
            cached = self._agent_cache.get(name)
            if cached is not None:
                return cached

            from maljan.agents.composition import resolve_agent
            from maljan.agents.configurable_analyst import ConfigurableAnalyst

            role = self.agent_role(name)
            resolved = resolve_agent(name, self)
            if role == "generic":
                agent: BaseAnalyst = ConfigurableAnalyst(name, resolved, resolved.llm)
            else:
                agent = self.agent_registry.create(role, resolved.llm)
                # The class is chosen by role; the *identity* is the key. Every
                # per-agent lookup downstream — timeout overrides, LLM
                # overrides, ISR agent_id, the graph node name — reads
                # ``agent.name``, so this one assignment is what makes a clone
                # a separate participant rather than a second copy of its source.
                agent.name = name
                agent.logger = agent.logger.getChild(name.lower())
            agent.token_ledger = getattr(self, "_token_ledger", None)
            agent.truncation_ledger = getattr(self, "_truncation_ledger", None)
            # Hand the agent a way back to this container. The static analyst
            # used to construct a *whole new* ServiceContainer on every failed
            # MCP init — per chunk, so up to ten of them per run.
            agent._container = self
            agent._resolved = resolved
            self._agent_cache[name] = agent
            return agent
```

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/unit/test_container_composition.py tests/unit/test_container.py tests/agents -q`
Expected: PASS.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check src/maljan/core/container.py tests/unit/test_container_composition.py && \
uv run ruff format --check src/maljan/core/container.py tests/unit/test_container_composition.py && \
uv run mypy src/ apps/api/
git add src/maljan/core/container.py tests/unit/test_container_composition.py
git commit -m "feat(core): the container builds agents and static providers from the active profile"
```

- [ ] **Step 7: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 7: The graph is built from the profile

**Files:**
- Modify: `src/maljan/pipeline/builder.py:63`; `src/maljan/pipeline/nodes.py:102`, `:335`, `:437`, `:656`, `:803`, `:959`; `src/maljan/app.py:286`; `src/maljan/cli.py:276`; `apps/api/app/worker/analysis_worker.py:527`; `tests/unit/test_topology_sources.py` (shrink both allow-lists)
- Test: `tests/pipeline/test_graph_snapshot.py` (a custom-profile case), `tests/unit/test_topology_sources.py`
- Not modified: `src/maljan/pipeline/state.py` — the graph's state shape does not change with the profile.

**Interfaces:**
- Consumes: `ServiceContainer.analyst_keys()`, `.agent_role(key)`.
- Produces: no new names; four topology reads and two name branches move.

- [ ] **Step 1: Write the failing test**

Append to `tests/pipeline/test_graph_snapshot.py`:

```python
def test_a_custom_profile_produces_its_own_nodes_and_chain():
    """Four analysts, one of them generic, in the order the profile lists them."""
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {
                "static_r2": {"role": "static", "static_provider": "r2"},
                "strings": {"role": "generic", "prompt": "read strings"},
            },
            "profiles": {
                "wide": {"analysts": ["static", "static_r2", "network", "strings"]}
            },
            "profile": "wide",
        },
    )
    cfg.llm.parallel_analysts = False
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert shape["analysts"] == ["static", "static_r2", "network", "strings"]
    assert shape["nodes"] == sorted(
        [
            "__start__",
            "__end__",
            "static_analyst",
            "static_r2_analyst",
            "network_analyst",
            "strings_analyst",
            "negotiation",
            "revision",
            "judge",
            "report",
        ]
    )
    assert "static_r2_analyst->network_analyst" in shape["edges"]
    assert "strings_analyst->negotiation" in shape["edges"]
    assert shape["conditional"] == {"negotiation": {"revision": "revision", "judge": "judge"}}


def test_a_custom_profile_fans_out_from_start_in_parallel_mode():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"lean": {"analysts": ["network", "static"]}}, "profile": "lean"},
    )
    cfg.llm.parallel_analysts = True
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert "__start__->network_analyst" in shape["edges"]
    assert "__start__->static_analyst" in shape["edges"]
    assert "network_analyst->negotiation" in shape["edges"]
    assert "dynamic_analyst" not in " ".join(shape["nodes"])


def test_a_profile_of_one_analyst_still_reaches_negotiation():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"solo": {"analysts": ["network"]}}, "profile": "solo"},
    )
    cfg.llm.parallel_analysts = False
    shape = compiled_shape(ServiceContainer(cfg, mock=True))
    assert shape["analysts"] == ["network"]
    assert "__start__->network_analyst" in shape["edges"]
    assert "network_analyst->negotiation" in shape["edges"]
```

Shrink the two allow-lists in `tests/unit/test_topology_sources.py` to what this task leaves behind:

```python
TOPOLOGY_SOURCES: set[str] = {
    "src/maljan/agents/registry.py",
}

NAME_BRANCHES: set[str] = set()
```

and drop `test_the_recorded_name_branches_are_the_ones_that_exist_today`'s tolerance by leaving it exactly as written — with an empty `NAME_BRANCHES` it now asserts that nothing branches on a built-in agent name at all.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/pipeline/test_graph_snapshot.py tests/unit/test_topology_sources.py -q`
Expected: FAIL — the custom-profile cases build the default three nodes, and the grep gate names `builder.py`, `nodes.py`, `container.py`, `app.py`, `cli.py` and `analysis_worker.py`.

- [ ] **Step 3: Read the profile in the builder**

`src/maljan/pipeline/builder.py`, line 63, becomes:

```python
    # 1. The analysts of the active profile, in the order it lists them. The
    #    class registry is still what turns a role into a class; it stopped
    #    being what decides which agents exist (spec §5), because that answer
    #    now has to survive a per-job override.
    agent_names = container.analyst_keys()

    if not agent_names:
        raise RuntimeError(
            f"Profile {container.config.agents.profile!r} has no analysts. "
            "Cannot build pipeline."
        )
```

The module docstring's "The chain is built in registry order" becomes "The chain is built in profile order".

- [ ] **Step 4: Read the profile in the nodes**

`nodes.py:656` (negotiation) and `nodes.py:803` (revision) each become:

```python
        agent_names = container.analyst_keys()
```

`nodes.py:959` (judge) becomes:

```python
            reports = {
                name: revised.get(name) or original.get(name, "")
                for name in container.analyst_keys()
            }
```

The three static-role branches become role reads. `nodes.py:102` is inside `_augment_static_chunks_with_path(chunks, state, static=...)`, which receives the agent name from its caller; give it the role instead. Its signature and guard become:

```python
def _augment_static_chunks_with_path(
    chunks: list, state: AnalysisState, *, static: StaticAnalysis | None = None, role: str = ""
) -> list:
    ...
    if role == "static" or len(chunks) != 1:
```

and the two branches inside `make_analyst_node` become:

```python
            role = container.agent_role(agent_name)
```

computed once directly after `agent = container.get_agent(agent_name)`, then `if agent_name == "static":` at line 335 becomes `if role == "static":`, its `_augment_static_chunks_with_path(chunks, state, static=_st)` call becomes `_augment_static_chunks_with_path(chunks, state, static=_st, role=role)`, and `if agent_name == "static":` at line 437 becomes `if role == "static":`.

Inside the line-335 block, the sample path the agent is pinned to becomes the agent's own provider's mirror (the per-provider dict Task 9 fills in; until then the fallback is the only entry):

```python
                agent._analysis_file_path = (  # type: ignore[attr-defined]
                    (state.get("static_sample_paths") or {}).get(
                        agent._resolved.static_provider_id
                    )
                    or state.get("static_sample_path")
                    or None
                )
```

- [ ] **Step 5: Read the profile in the three informational call sites**

`src/maljan/app.py:286`:

```python
        logger.info("Analysts: %s", self.container.analyst_keys())
```

`src/maljan/cli.py:276`:

```python
    typer.echo(f"\nActive profile: {container.config.agents.profile}")
    typer.echo(f"Analysts: {container.analyst_keys()}")
```

(the surrounding command already builds a container; if it holds only an `AgentRegistry`, build the container it needs from `get_settings()` with `mock=True` the way the rest of that command does.)

`apps/api/app/worker/analysis_worker.py:527`:

```python
            # Announce which analysts are about to run so the frontend can show
            # them. The active profile, not the class registry: a job that runs
            # four analysts must not announce three.
            registered_agents = app.container.analyst_keys()
```

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/pipeline tests/unit/test_topology_sources.py tests/unit/test_container_composition.py -q`
Expected: PASS — including the Task 1 default-graph snapshot, unchanged.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan apps/api/app tests/pipeline tests/unit/test_topology_sources.py && \
uv run ruff format --check src/maljan apps/api/app tests/pipeline tests/unit/test_topology_sources.py && \
uv run mypy src/ apps/api/
git add src/maljan/pipeline/builder.py src/maljan/pipeline/nodes.py src/maljan/app.py \
  src/maljan/cli.py apps/api/app/worker/analysis_worker.py \
  tests/pipeline/test_graph_snapshot.py tests/unit/test_topology_sources.py
git commit -m "feat(pipeline): build the graph from the active profile instead of the class registry"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 8: Every consumer of "the analyst set" reads the profile

**Files:**
- Modify: `src/maljan/analysis/run_summary.py:166-213` (`RunSummary.profile`), `:314,319` (the per-layer order), `:397-434` (`to_dict`), `:589` (a `set_profile` beside `set_failed_analysts`); `src/maljan/analysis/ttp_cascade.py:143` (`is_consensus`); `src/maljan/agents/judge_agent.py:1010` (the layer set in `_build_confidence_instruction`); `src/maljan/pipeline/nodes.py:1322` (`_ANALYST_AGENTS`), `:1430-1448` (the builder chain)
- Test: `tests/unit/test_analyst_set_consumers.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/analysis/run_summary.py
  RunSummary.profile: dict[str, Any] | None = None
  def RunSummaryBuilder.set_profile(self, name: str, analysts: list[str], custom: list[str]) -> RunSummaryBuilder
  # run_summary["profile"] == {"name": str, "analysts": [str], "custom": [str]}
  ```
- Consumes: `maljan.agents.composition.current_analyst_keys`, `ServiceContainer.analyst_keys`, `.agent_role`, `.config.agents`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_analyst_set_consumers.py
"""Four places used to spell the analyst set out as a literal.

They spelled the same three names, so nothing noticed. A profile with four
analysts, or with one, makes each of them wrong in a different way: the judge
reports a missing analyst that was never asked for, the cascade never declares
consensus, the run summary attributes techniques to layers nobody ran.
"""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.analysis.ttp_cascade import TechniqueScore
from maljan.core.config import Settings, install_settings, reset_settings_cache


def _install(**agents) -> Settings:
    cfg = Settings(_env_file=None, agents=agents) if agents else Settings(_env_file=None)
    install_settings(cfg)
    return cfg


def teardown_function() -> None:
    reset_settings_cache()


def _score(layers: list[str]) -> TechniqueScore:
    return TechniqueScore(
        technique_id="T1027",
        contributing_layers=layers,
        layer_contributions=[],
        layer_confidences={},
        raw_weighted_confidence=0.5,
        cross_layer_multiplier=1.0,
        weighted_confidence=0.5,
        total_evidence_count=1,
    )


def test_the_default_profile_still_means_the_three_standard_layers():
    _install()
    assert _score(["static", "dynamic", "network"]).is_consensus is True
    assert _score(["static", "network"]).is_consensus is False


def test_a_reduced_profile_reaches_consensus_on_the_layers_it_actually_runs():
    _install(profiles={"lean": {"analysts": ["static", "network"]}}, profile="lean")
    assert _score(["static", "network"]).is_consensus is True


def test_a_wide_profile_needs_every_one_of_its_analysts_for_consensus():
    _install(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"wide": {"analysts": ["static", "network", "strings"]}},
        profile="wide",
    )
    assert _score(["static", "network"]).is_consensus is False
    assert _score(["static", "network", "strings"]).is_consensus is True


def test_the_run_summary_records_the_default_triple_and_no_custom_agents():
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("default", ["static", "dynamic", "network"], [])
        .build()
    )
    assert summary.to_dict()["profile"] == {
        "name": "default",
        "analysts": ["static", "dynamic", "network"],
        "custom": [],
    }


def test_the_run_summary_records_a_custom_profiles_own_list():
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("wide", ["static", "static_r2", "strings"], ["static_r2", "strings"])
        .build()
    )
    assert summary.to_dict()["profile"]["custom"] == ["static_r2", "strings"]


def test_a_run_summary_built_without_a_profile_still_serialises():
    """Old reports have no profile, and the panel that reads it has a fallback."""
    summary = (
        RunSummaryBuilder(start_time=0.0).set_sample("abc", None).set_verdict("Benign", 0).build()
    )
    assert summary.to_dict()["profile"] is None


def test_every_other_run_summary_key_is_unchanged():
    _install()
    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 3)
        .set_profile("default", ["static", "dynamic", "network"], [])
        .build()
    )
    keys = set(summary.to_dict())
    assert keys == {
        "file_hash", "file_name", "final_decision", "stix_object_count", "elapsed_seconds",
        "timestamp", "negotiation", "agent_stats", "cascade", "validation", "tokens",
        "degraded_mode", "degradation_reasons", "failed_analysts", "techniques_by_layer",
        "profile",
    }


def test_the_per_layer_attribution_lists_the_profiles_analysts_then_the_rule_layers():
    _install(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"wide": {"analysts": ["network", "strings"]}},
        profile="wide",
    )
    from maljan.analysis.run_summary import _attribution_layers

    assert _attribution_layers() == ["network", "strings", "yara", "sigma"]


def test_the_judges_empty_analyst_check_covers_exactly_the_profile():
    _install(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    from maljan.agents.composition import current_analyst_keys

    assert current_analyst_keys() == ["network"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_analyst_set_consumers.py -q`
Expected: FAIL — `AttributeError: 'RunSummaryBuilder' object has no attribute 'set_profile'`.

- [ ] **Step 3: Give the run summary a profile**

In `run_summary.py`, add the field to `RunSummary` beside `techniques_by_layer` (line 212), documented in the class docstring's attribute list as "profile: which profile ran, the analysts it named, and which of them are not built in":

```python
    profile: dict[str, Any] | None = None
```

Add the helper the per-layer attribution reads, at module scope:

```python
def _attribution_layers() -> list[str]:
    """The layer order the per-layer breakdown renders, profile first.

    Was the literal ``("static", "dynamic", "network", "yara", "sigma")``,
    which named three analysts that a custom profile may not run and missed
    every analyst it does. The two rule layers stay appended: they are
    deterministic passes, not analysts, and they run whatever the profile says.
    """
    from maljan.agents.composition import current_analyst_keys

    try:
        analysts = current_analyst_keys()
    except Exception:  # noqa: BLE001 — a report renders even without settings
        analysts = ["static", "dynamic", "network"]
    return [*analysts, "yara", "sigma"]
```

Replace the two literals at lines 314 and 319 with it:

```python
                layers_in_order = _attribution_layers()
                for layer in layers_in_order:
                    count = self.techniques_by_layer.get(layer, 0)
                    lines.append(f"- `{layer}`: {count}")
                # Surface any other layers we didn't enumerate above.
                for layer, count in sorted(self.techniques_by_layer.items()):
                    if layer not in set(layers_in_order):
                        lines.append(f"- `{layer}`: {count}")
```

Add the key to `to_dict` (after `"techniques_by_layer"`):

```python
            "profile": dict(self.profile) if self.profile else None,
```

Add the builder setter beside `set_failed_analysts` (line 589), and `self._profile: dict[str, Any] | None = None` to `RunSummaryBuilder.__init__`, and `profile=self._profile` to the `RunSummary(...)` construction inside `build()`:

```python
    def set_profile(
        self, name: str, analysts: list[str], custom: list[str]
    ) -> RunSummaryBuilder:
        """Record which ensemble ran (spec §5).

        ``custom`` is the subset of ``analysts`` that is not one of the four
        built-in definitions — what the report and the pipeline panel badge, so
        a reader can tell a measured run from an operator's own arrangement.
        """
        self._profile = {
            "name": name,
            "analysts": list(analysts),
            "custom": list(custom),
        }
        return self
```

- [ ] **Step 4: Derive the cascade's consensus from the profile**

`ttp_cascade.py`, `TechniqueScore.is_consensus` (line 143) becomes:

```python
    @property
    def is_consensus(self) -> bool:
        """True when every analyst layer of the active profile provided evidence.

        Was the literal triple, which is right for the default profile and
        wrong for every other: a two-analyst profile could never reach
        consensus, and a four-analyst one reached it while one analyst was
        silent.
        """
        from maljan.agents.composition import current_analyst_keys

        try:
            layers = current_analyst_keys()
        except Exception:  # noqa: BLE001 — a score is computed even without settings
            layers = ["static", "dynamic", "network"]
        return bool(layers) and all(d in self.contributing_layers for d in layers)
```

- [ ] **Step 5: Derive the judge's two literals from the profile**

`judge_agent.py`, inside `_build_confidence_instruction` (line ~1010), the evidence-basis mapping becomes:

```python
                from maljan.agents.composition import current_analyst_keys

                analysts = set(current_analyst_keys())
                layers = r.contributing_layers
                # Map layer set → evidence_basis controlled vocab
                if analysts and set(layers) == analysts:
                    basis = "all"
                elif len(layers) == 2:  # noqa: PLR2004
                    basis = "+".join(sorted(layers))
                elif len(layers) == 1:
                    basis = layers[0]
                else:
                    basis = "unknown"
```

Hoist `analysts = set(current_analyst_keys())` above the `for r in top:` loop so it is read once per verdict rather than once per technique.

`nodes.py:1322`, inside the judge node, becomes:

```python
            _analyst_keys = container.analyst_keys()
            _empty_analysts = [
                name
                for name in _analyst_keys
                if name in isr_reports and not getattr(isr_reports.get(name), "claims", None)
            ]
```

and the `RunSummaryBuilder` chain at line ~1430 gains one link, directly after `.set_failed_analysts(_failed_analysts)`:

```python
                    .set_profile(
                        container.config.agents.profile,
                        _analyst_keys,
                        [k for k in _analyst_keys if container.agent_role(k) == "generic"
                         or k not in BUILTIN_AGENTS],
                    )
```

with `from maljan.core.config import BUILTIN_AGENTS` added to `nodes.py`'s imports. A key is "custom" when it is not one of the four seeded definitions, which is exactly what the badge in the pipeline panel means.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/unit/test_analyst_set_consumers.py tests/unit tests/pipeline -q`
Expected: PASS, including the existing run-summary fixture tests.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan tests/unit/test_analyst_set_consumers.py && \
uv run ruff format --check src/maljan tests/unit/test_analyst_set_consumers.py && \
uv run mypy src/ apps/api/
git add src/maljan/analysis/run_summary.py src/maljan/analysis/ttp_cascade.py \
  src/maljan/agents/judge_agent.py src/maljan/pipeline/nodes.py \
  tests/unit/test_analyst_set_consumers.py
git commit -m "feat(analysis): the judge, the cascade and the run summary read the profile's analyst set"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 9: Two static analysts, two providers, two mirrors

**Files:**
- Modify: `src/maljan/agents/static_analyst.py:116-124` (`_provider`); `src/maljan/pipeline/state.py:70` (a second path field); `src/maljan/app.py:77-97`, `:253-259`, `:319-344` (`static_sample_paths` through `run`/`arun` into the initial state); `apps/api/app/worker/analysis_worker.py:553` (the declaration), `:632-660` (the mirror step), `:729` (the call)
- Test: `tests/api/test_worker_profile_mirror.py` (create), `tests/agents/test_static_provider_per_agent.py` (create)

**Interfaces:**
- Produces:
  ```python
  # src/maljan/pipeline/state.py
  AnalysisState.static_sample_paths: dict[str, str]      # provider id -> container-visible path
  # src/maljan/app.py
  def MaljanApp.run(..., static_sample_paths: dict[str, str] | None = None) -> dict[str, Any]
  async def MaljanApp.arun(..., static_sample_paths: dict[str, str] | None = None) -> dict[str, Any]
  # apps/api/app/worker/analysis_worker.py
  def profile_static_providers(container) -> list[str]   # distinct provider ids, global one first
  ```
- Consumes: `mirror_target_for` (unchanged), `ServiceContainer.get_static_provider(id)`, `.analyst_keys()`, `maljan.agents.composition.static_provider_id_for`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/agents/test_static_provider_per_agent.py
"""A static analyst reads the provider its definition names, not the global one."""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


def _container(**agents) -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None, agents=agents), mock=True)


def test_the_built_in_static_analyst_reads_the_globally_configured_provider():
    container = _container()
    agent = container.get_agent("static")
    assert agent._provider() is container.get_static_provider()
    assert agent._provider().id == "ghidra"


def test_a_clone_reads_its_own_provider():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    clone = container.get_agent("static_r2")
    assert clone._provider().id == "r2"
    assert clone._provider() is not container.get_agent("static")._provider()


def test_an_analyst_without_a_container_still_falls_back_to_the_global_provider():
    """Standalone use (tests, scripts) keeps working with no container at all."""
    from maljan.agents.static_analyst import StaticAnalyst

    agent = StaticAnalyst(llm=None, name="static")  # type: ignore[arg-type]
    assert agent._provider().id == "ghidra"
```

```python
# tests/api/test_worker_profile_mirror.py
"""The sample is mirrored once per static provider that needs a copy.

Today the worker asks the one configured provider. A profile with two static
analysts on two providers needs two mirrors, or the second analyst opens a
path that is not there; a profile with none needs zero, and the existing
single-provider path must produce exactly the bytes and the state key it
always did (sub-project A's contract).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import mirror_target_for, profile_static_providers  # noqa: E402

from maljan.core.config import Settings  # noqa: E402
from maljan.core.container import ServiceContainer  # noqa: E402


def _container(**agents) -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None, agents=agents), mock=True)


def test_the_default_profile_names_one_provider():
    assert profile_static_providers(_container()) == ["ghidra"]


def test_two_static_analysts_on_two_providers_name_both_global_first():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    assert profile_static_providers(container) == ["ghidra", "r2"]


def test_two_static_analysts_on_the_same_provider_name_it_once():
    container = _container(
        definitions={"static_b": {"role": "static", "static_provider": "ghidra"}},
        profiles={"two": {"analysts": ["static", "static_b"]}},
        profile="two",
    )
    assert profile_static_providers(container) == ["ghidra"]


def test_a_profile_with_no_static_analyst_still_names_the_global_provider():
    """The global provider backs ``state['static_sample_path']``, which A froze."""
    container = _container(
        profiles={"lean": {"analysts": ["network"]}}, profile="lean"
    )
    assert profile_static_providers(container) == ["ghidra"]


def test_a_provider_that_reads_in_place_produces_no_mirror_target():
    container = _container()
    assert (
        mirror_target_for(
            container.get_static_provider("capa_yara"), sha256="ab" * 32, extension=".exe"
        )
        is None
    )


def test_each_provider_gets_its_own_container_visible_path():
    container = _container()
    ghidra = mirror_target_for(
        container.get_static_provider("ghidra"), sha256="ab" * 32, extension=".exe"
    )
    r2 = mirror_target_for(
        container.get_static_provider("r2"), sha256="ab" * 32, extension=".exe"
    )
    assert ghidra is not None and r2 is not None
    # Same host file, two answers about how a tool reaches it: Ghidra sees the
    # container mount, a co-located r2mcp sees the host path itself.
    assert ghidra[0] == r2[0]
    assert ghidra[1] != r2[1]


def test_the_state_carries_a_path_per_provider_and_keeps_the_global_key():
    from maljan.pipeline.state import AnalysisState

    assert "static_sample_paths" in AnalysisState.__annotations__
    assert "static_sample_path" in AnalysisState.__annotations__
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/agents/test_static_provider_per_agent.py tests/api/test_worker_profile_mirror.py -q`
Expected: FAIL — `ImportError: cannot import name 'profile_static_providers'`, and the clone reads `ghidra`.

- [ ] **Step 3: The static analyst reads its own provider**

`static_analyst.py`, `_provider` becomes, in full:

```python
    def _provider(self) -> Any:
        """The static provider for *this agent*: its own, the container's, or an ad hoc one.

        A definition may name a static provider (a clone of ``static`` on
        radare2), in which case that is the one this analyst reads; the
        container caches one object per id, so two static analysts on two
        providers are two providers and not one with two opinions. Without a
        resolution — a bare analyst in a test or a script — this is exactly the
        globally configured provider it always was.
        """
        container = getattr(self, "_container", None)
        resolved = getattr(self, "_resolved", None)
        if container is not None:
            if resolved is not None:
                return container.get_static_provider(resolved.static_provider_id)
            return container.get_static_provider()
        from maljan.core.config import get_settings
        from maljan.providers.registry import get_static_provider

        return get_static_provider(get_settings())
```

- [ ] **Step 4: Carry a path per provider through the state**

`state.py`, directly under `static_sample_path` (line 70):

```python
    # Sub-project C: one container-visible path per static provider a profile
    # uses, keyed by provider id. ``static_sample_path`` above stays exactly
    # what it was — the *globally configured* provider's path, which is what
    # sub-project A's contract promises and what every single-provider run
    # reads — and this is the second and later entries a profile with two
    # static analysts needs. Empty on every default-profile run.
    static_sample_paths: dict[str, str]
```

`app.py`: `run` and `arun` each take `static_sample_paths: dict[str, str] | None = None` after `static_sample_path`, `run` forwards it (`asyncio.run(self.arun(file_hash, file_name, sample_path, static_sample_path, static_sample_paths))`), and the initial state gains one line after `"static_sample_path": static_sample_path,`:

```python
            "static_sample_paths": dict(static_sample_paths or {}),
```

Document the new argument in both docstrings as "one container-visible path per static provider this job's profile uses, keyed by provider id; the globally configured provider's entry is also ``static_sample_path``".

- [ ] **Step 5: Mirror once per provider in the worker**

Add the helper beside `mirror_target_for` in `analysis_worker.py`:

```python
def profile_static_providers(container: Any) -> list[str]:
    """The distinct static provider ids this job needs, the global one first.

    "First" matters: the first entry backs ``state["static_sample_path"]``,
    which is the key sub-project A froze and every single-provider reader still
    uses. The globally configured provider is always in the list even when no
    analyst names it, because that key must exist for a profile that runs no
    static analyst at all.
    """
    from maljan.agents.composition import static_provider_id_for

    settings = container.config
    ids = [str(settings.static.provider)]
    for key in container.analyst_keys():
        if container.agent_role(key) != "static":
            continue
        provider_id = static_provider_id_for(settings, key)
        if provider_id not in ids:
            ids.append(provider_id)
    return ids
```

Replace the declaration at line 553 with both:

```python
            static_sample_path: str | None = None
            static_sample_paths: dict[str, str] = {}
```

and the mirror block (lines 632-660) becomes:

```python
                _mirror_target_path: Path | str = sample_files.work_dir()
                try:
                    for _provider_id in profile_static_providers(app.container):
                        target = mirror_target_for(
                            app.container.get_static_provider(_provider_id),
                            sha256=sample.sha256,
                            extension=_orig_ext,
                        )
                        if target is None:
                            logger.info(
                                "Static provider '%s' needs no sample mirror; skipping the copy.",
                                _provider_id,
                                extra={"job_id": job_id, "component": "sample-mirror"},
                            )
                            continue
                        host_mirror, container_path = target
                        _mirror_target_path = host_mirror
                        sample_files.private_copy(Path(temp_path), host_mirror)
                        static_sample_paths[_provider_id] = container_path
                        if static_sample_path is None:
                            # The first id is the globally configured provider,
                            # so this is the same value this variable has always
                            # carried on a single-provider run.
                            static_sample_path = container_path
                        logger.info(
                            "Mirrored sample to %s for static provider '%s' (%s).",
                            host_mirror,
                            _provider_id,
                            container_path,
                            extra={"job_id": job_id, "component": "sample-mirror"},
                        )
                except Exception as mirror_exc:
                    logger.warning(
                        "Failed to mirror sample to %s for the static provider: %s. "
                        "Static analyst will fall back to metadata-only prompt.",
                        _mirror_target_path,
                        mirror_exc,
                        extra={"job_id": job_id, "component": "sample-mirror"},
                    )
```

The host file is the same for two providers that share `work_dir()` and a sha256, so `private_copy` writes the same bytes twice at most; it is idempotent and this keeps the loop free of a special case. The pipeline call at line 729 gains one argument:

```python
                        static_sample_path=static_sample_path,
                        static_sample_paths=static_sample_paths,
```

The function-hash path elsewhere in the worker reads `static_sample_path` and is untouched: it is the global provider's path, which is what it always was.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/agents/test_static_provider_per_agent.py tests/api/test_worker_profile_mirror.py tests/unit/api/test_worker_mirror.py tests/pipeline -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check src/maljan apps/api/app tests/agents tests/api && \
uv run ruff format --check src/maljan apps/api/app tests/agents tests/api && \
uv run mypy src/ apps/api/
git add src/maljan/agents/static_analyst.py src/maljan/pipeline/state.py src/maljan/app.py \
  apps/api/app/worker/analysis_worker.py tests/agents/test_static_provider_per_agent.py \
  tests/api/test_worker_profile_mirror.py
git commit -m "feat(worker): mirror the sample once per static provider the profile uses"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 10: A job can name its profile

**Files:**
- Modify: `apps/api/app/schemas/job.py:12-37` (`_KnownJobConfig.profile`); `apps/api/app/api/v1/jobs.py:28-65` (submit-time validation); `apps/api/app/worker/analysis_worker.py:43-69` (`build_job_settings`)
- Test: `tests/api/test_job_profile.py` (create)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/schemas/job.py
  _KnownJobConfig.profile: str | None = None
  # apps/api/app/api/v1/jobs.py
  async def _known_profiles(db: AsyncSession) -> set[str]
  ```
- Consumes: `agent_map.effective_profiles` (Task 11 formalises it; this task adds it), `SettingsService.load_overrides`, `build_settings`.

- [ ] **Step 1: Write the failing test**

```python
# tests/api/test_job_profile.py
"""A job may name a profile; an unknown one is a 422 at submit time."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.jobs import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import get_current_user  # noqa: E402
from app.schemas.job import JobCreateRequest, _KnownJobConfig  # noqa: E402
from app.worker.analysis_worker import build_job_settings  # noqa: E402


def test_the_field_is_a_free_string_not_a_literal():
    """Profiles are operator-invented names; a Literal could never hold them."""
    assert _KnownJobConfig.model_fields["profile"].annotation == (str | None)


def test_a_profile_folds_into_the_agents_setting():
    cfg = build_job_settings(
        {
            "agents.profiles": {"lean": {"analysts": ["network"]}},
        },
        {"profile": "lean"},
    )
    assert cfg.agents.profile == "lean"
    assert cfg.agents.profiles["lean"].analysts == ["network"]


def test_a_job_without_a_profile_changes_nothing():
    assert build_job_settings({}, {"llm_provider": "ollama"}).agents.profile == "default"
    assert build_job_settings({}, None).agents.profile == "default"


def test_an_explicit_null_profile_is_refused_like_every_other_known_key():
    with pytest.raises(ValueError, match="explicit null is not allowed for: profile"):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"profile": None})


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _submit(client: TestClient, config: dict) -> object:
    created = MagicMock(id=uuid.uuid4(), status="pending")
    with patch("app.api.v1.jobs.AnalysisService.create_job", AsyncMock(return_value=created)):
        return client.post(
            "/api/v1/jobs", json={"sample_id": str(uuid.uuid4()), "config": config}
        )


def test_a_known_profile_is_accepted(client):
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = _submit(client, {"profile": "default"})
    assert response.status_code == 201


def test_an_unknown_profile_is_a_422_naming_it(client):
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = _submit(client, {"profile": "ghost"})
    assert response.status_code == 422
    assert "unknown profile 'ghost'" in response.text


def test_a_profile_an_operator_saved_is_accepted(client):
    stored = {"core.agents.profiles": {"lean": {"analysts": ["network"]}}}
    with patch(
        "app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value=stored)
    ):
        response = _submit(client, {"profile": "lean"})
    assert response.status_code == 201
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/api/test_job_profile.py -q`
Expected: FAIL — `KeyError: 'profile'` in the model-fields assertion.

- [ ] **Step 3: Add the field**

`apps/api/app/schemas/job.py`, after `sandbox_provider`:

```python
    # The agent profile for this job. A free string rather than a Literal
    # because the valid values are settings an operator writes, not a registry
    # the code owns; the route checks it against the effective profile map at
    # submit time, which is where "known" can actually be answered.
    profile: str | None = None
```

- [ ] **Step 4: Check it at submit time**

In `apps/api/app/api/v1/jobs.py`, add the lookup and call it inside `create_job` before `svc.create_job`:

```python
async def _known_profiles(db: AsyncSession) -> set[str]:
    """Every profile name a job may pick, stored map layered over the seeds."""
    from app.services.agent_map import effective_profiles
    from app.services.settings_service import SettingsService

    return set(effective_profiles(await SettingsService(db).load_overrides()))
```

and inside `create_job`, after the opening `logger.info`:

```python
    profile = (body.config or {}).get("profile")
    if profile is not None:
        known = await _known_profiles(db)
        if str(profile) not in known:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unknown profile {str(profile)!r}. Available: {', '.join(sorted(known))}",
            )
```

`create_job` gains `db: AsyncSession = Depends(get_db)` as a parameter so the route can read the overrides; `_get_service` already depends on the same session, so this adds no second connection.

Add the loader `agent_map.effective_profiles` now (Task 11 adds the rest of that module around it):

```python
# apps/api/app/services/agent_map.py  (first version; Task 11 completes it)
"""What an admin may write into the two agent maps, and what a job may pick.

Shaped after ``server_map.py``: one leaf holds a whole map, so the settings
service's per-key checks cannot see inside it, and these are the checks that
belong inside. No secrets live here — a prompt is operator text, not a
credential — so there is no split/merge half, which is the one way this module
is simpler than its sibling.
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import _builtin_definitions, _builtin_profiles

AGENT_DEFINITIONS_KEY = "core.agents.definitions"
AGENT_PROFILES_KEY = "core.agents.profiles"
AGENT_PROFILE_KEY = "core.agents.profile"


def effective_profiles(overrides: dict[str, Any]) -> dict[str, Any]:
    """The profile map as it stands: the stored one over the built-in seeds."""
    out = {name: p.model_dump(mode="json") for name, p in _builtin_profiles().items()}
    stored = overrides.get(AGENT_PROFILES_KEY)
    if isinstance(stored, dict):
        out.update({str(k): v for k, v in stored.items()})
    return out


def effective_definitions(overrides: dict[str, Any]) -> dict[str, Any]:
    """The definition map as it stands: the stored one over the built-in seeds."""
    out = {name: d.model_dump(mode="json") for name, d in _builtin_definitions().items()}
    stored = overrides.get(AGENT_DEFINITIONS_KEY)
    if isinstance(stored, dict):
        out.update({str(k): v for k, v in stored.items()})
    return out
```

- [ ] **Step 5: Fold it into the job's settings**

`build_job_settings`, after the `sandbox_provider` branch and before the `sandbox_report_id` one:

```python
        if job_config.get("profile") is not None:
            merged["agents.profile"] = job_config["profile"]
```

`settings_snapshot` needs no change: `public_snapshot` walks the whole `Settings` model, so `agents.profile`, `agents.profiles` and `agents.definitions` are already in it.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/api/test_job_profile.py tests/api/test_job_provider_overrides.py tests/unit/api/test_worker_settings_overrides.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app tests/api && \
uv run ruff format --check apps/api/app tests/api && \
uv run mypy src/ apps/api/
git add apps/api/app/schemas/job.py apps/api/app/api/v1/jobs.py \
  apps/api/app/services/agent_map.py apps/api/app/worker/analysis_worker.py \
  tests/api/test_job_profile.py
git commit -m "feat(api): a job may name its agent profile, checked at submit time"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 11: The API validates the two agent maps per key

**Files:**
- Modify: `apps/api/app/services/agent_map.py` (complete the module Task 10 started); `apps/api/app/services/settings_service.py:255-300` (`save` calls it); `apps/api/app/services/settings_catalog_api.py:296-310` (two choice sources)
- Test: `tests/api/test_settings_agents.py` (create)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/services/agent_map.py
  class AgentMapError(Exception):
      errors: dict[str, str]
  def validate_definitions(value: Any, *, servers: dict[str, Any] | None = None) -> dict[str, Any]
  def validate_profiles(value: Any, *, definitions: dict[str, Any]) -> dict[str, Any]
  def validate_agent_map(changes: dict[str, Any], stored: dict[str, Any]) -> dict[str, Any]
  ```
- Consumes: `AgentsConfig`, `AgentDefinition`, `ProfileDefinition`, `_builtin_definitions`, `_builtin_profiles`, `static_provider_ids`, `SettingsService.load_overrides`.

- [ ] **Step 1: Write the failing test**

```python
# tests/api/test_settings_agents.py
"""PATCH-time validation of the agent maps, keyed per definition and per profile.

The model validates too — that is what stops a bad value from ever reaching a
job — but a model error is one message about a whole map. The editor draws a
card per definition, so it needs an error per definition, which is what this
layer produces, exactly as ``server_map.py`` does for servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.agent_map import (  # noqa: E402
    AGENT_DEFINITIONS_KEY,
    AGENT_PROFILE_KEY,
    AGENT_PROFILES_KEY,
    AgentMapError,
    effective_definitions,
    effective_profiles,
    validate_agent_map,
)

BUILTIN_STATIC = {
    "role": "static", "label": "Static analyst", "prompt": None,
    "tools": [], "static_provider": None, "enabled": True,
}


def _defs(**extra):
    return {AGENT_DEFINITIONS_KEY: {**extra}}


def test_a_valid_definition_round_trips_with_the_built_ins_reseeded():
    out = validate_agent_map(
        _defs(strings={"role": "generic", "prompt": "read strings"}), stored={}
    )
    definitions = out[AGENT_DEFINITIONS_KEY]
    assert set(definitions) == {"static", "dynamic", "network", "judge", "strings"}
    assert definitions["strings"]["role"] == "generic"


def test_a_bad_key_is_reported_under_that_key():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(**{"Bad Name": {"role": "generic", "prompt": "p"}}), stored={})
    assert "Bad Name" in exc.value.errors
    assert "lowercase" in exc.value.errors["Bad Name"]


def test_a_generic_agent_without_a_prompt_is_reported_on_its_prompt_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(strings={"role": "generic", "prompt": ""}), stored={})
    assert exc.value.errors["strings.prompt"] == "a generic agent needs a prompt"


def test_an_edited_built_in_says_to_clone_it():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(static={**BUILTIN_STATIC, "prompt": "mine"}), stored={})
    assert exc.value.errors["static"] == "'static' is built in; clone it to change it"


def test_a_disabled_built_in_analyst_is_allowed():
    out = validate_agent_map(
        {
            AGENT_DEFINITIONS_KEY: {"dynamic": {"role": "dynamic", "enabled": False}},
            AGENT_PROFILES_KEY: {"lean": {"analysts": ["static", "network"]}},
            AGENT_PROFILE_KEY: "lean",
        },
        stored={},
    )
    assert out[AGENT_DEFINITIONS_KEY]["dynamic"]["enabled"] is False


def test_an_unknown_static_provider_is_reported_on_its_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(static_r2={"role": "static", "static_provider": "idapro"}), stored={}
        )
    assert "idapro" in exc.value.errors["static_r2.static_provider"]


def test_a_tool_reference_to_an_unknown_server_is_reported_on_its_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(
                strings={
                    "role": "generic", "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "ghost"}],
                }
            ),
            stored={},
        )
    assert "ghost" in exc.value.errors["strings.tools"]


def test_a_named_tool_outside_the_servers_allow_list_is_refused():
    stored = {
        "core.mcp.servers": {
            "mine": {"enabled": True, "transport": "stdio", "command": "x", "tools": ["grep"]}
        }
    }
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(
                strings={
                    "role": "generic", "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "rm"}],
                }
            ),
            stored=stored,
        )
    assert "'rm' is not allowed on server 'mine'" in exc.value.errors["strings.tools"]


def test_a_profile_naming_a_missing_analyst_is_reported_under_the_profile():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILES_KEY: {"two": {"analysts": ["static", "ghost"]}}}, stored={})
    assert "ghost" in exc.value.errors["two"]


def test_the_default_profile_may_not_be_edited():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILES_KEY: {"default": {"analysts": ["network"]}}}, stored={})
    assert exc.value.errors["default"] == "'default' is built in; clone it to change it"


def test_the_active_profile_must_exist_in_the_map_being_saved():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILE_KEY: "ghost"}, stored={})
    assert "ghost" in exc.value.errors[AGENT_PROFILE_KEY]


def test_a_profile_and_the_definition_it_uses_may_be_saved_in_one_patch():
    out = validate_agent_map(
        {
            AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}},
            AGENT_PROFILES_KEY: {"wide": {"analysts": ["static", "strings"]}},
            AGENT_PROFILE_KEY: "wide",
        },
        stored={},
    )
    assert out[AGENT_PROFILE_KEY] == "wide"


def test_a_definition_stored_earlier_still_counts_when_only_a_profile_is_patched():
    stored = {AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}}}
    out = validate_agent_map(
        {AGENT_PROFILES_KEY: {"wide": {"analysts": ["strings"]}}}, stored=stored
    )
    assert out[AGENT_PROFILES_KEY]["wide"]["analysts"] == ["strings"]


def test_an_explicit_null_clears_a_map_back_to_the_built_ins():
    """Identical to sub-project B's null semantics for the server map."""
    stored = {AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}}}
    out = validate_agent_map({AGENT_DEFINITIONS_KEY: None}, stored=stored)
    assert out[AGENT_DEFINITIONS_KEY] is None
    assert set(effective_definitions({})) == {"static", "dynamic", "network", "judge"}


def test_clearing_the_definitions_that_a_stored_profile_uses_is_refused():
    stored = {
        AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}},
        AGENT_PROFILES_KEY: {"wide": {"analysts": ["strings"]}},
    }
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_DEFINITIONS_KEY: None}, stored=stored)
    assert "strings" in exc.value.errors["wide"]


def test_the_effective_maps_layer_stored_over_seeded():
    assert set(effective_profiles({})) == {"default"}
    assert set(
        effective_profiles({AGENT_PROFILES_KEY: {"lean": {"analysts": ["network"]}}})
    ) == {"default", "lean"}


def test_the_catalog_resolves_the_two_new_choice_sources():
    from app.services.settings_catalog_api import resolved_catalog

    entries = {e.key: e for e in resolved_catalog(["network"], profiles=["default", "lean"], agents=["static", "strings"])}
    assert entries["core.agents.profile"].choices == ["default", "lean"]
    assert entries["core.mcp.servers"].editor == "server_map"
    assert entries["core.agents.definitions"].editor == "agent_definitions"
    assert entries["core.agents.profiles"].editor == "profiles"


def test_a_server_binding_offers_the_effective_definition_keys():
    from app.services.settings_catalog_api import resolved_catalog

    entries = {e.key: e for e in resolved_catalog([], profiles=["default"], agents=["static", "strings"])}
    catalog_entry = entries["core.static.generic.server"]
    assert catalog_entry.choices_from == "mcp_servers"
    # ``agent_roles`` is consumed by the definitions editor rather than by a
    # leaf, so the source is asserted through the resolver's own table.
    from app.services.settings_catalog_api import _choice_sources

    assert _choice_sources([], ["default"], ["static", "strings"])["agent_roles"] == [
        "static",
        "strings",
    ]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/api/test_settings_agents.py -q`
Expected: FAIL — `ImportError: cannot import name 'AgentMapError' from 'app.services.agent_map'`.

- [ ] **Step 3: Complete `agent_map.py`**

Append to the module Task 10 created:

```python
import re

from maljan.core.config import (
    AGENT_KEY_PATTERN,
    AgentDefinition,
    ProfileDefinition,
    Settings,
)
from pydantic import ValidationError

_KEY_RE = re.compile(AGENT_KEY_PATTERN)
_KEY_RULE = (
    "an agent name is lowercase, starts with a letter, and is at most 32 "
    "characters of letters, digits, '-' or '_'"
)


class AgentMapError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def _server_allow_lists(overrides: dict[str, Any]) -> dict[str, list[str] | None]:
    """Each effective server's allow-list, so a tool reference can be checked.

    ``None`` for a server that exposes its whole manifest: a name against one of
    those is checked at resolution and degrades there, because what it offers is
    only knowable from a live handshake.
    """
    servers = Settings(_env_file=None).mcp.servers
    out: dict[str, list[str] | None] = {
        name: (list(cfg.tools) if cfg.tools is not None else None)
        for name, cfg in servers.items()
    }
    stored = overrides.get("core.mcp.servers")
    if isinstance(stored, dict):
        for name, entry in stored.items():
            if isinstance(entry, dict):
                tools = entry.get("tools")
                out[str(name)] = list(tools) if isinstance(tools, list) else None
    return out


def validate_definitions(
    value: Any, *, servers: dict[str, list[str] | None] | None = None
) -> dict[str, Any]:
    """Return the definition map to store, or raise with one message per offender."""
    from maljan.providers.registry import static_provider_ids

    if not isinstance(value, dict):
        raise AgentMapError({"": "the definition map must be an object keyed by agent name"})

    allow_lists = servers if servers is not None else {}
    provider_ids = set(static_provider_ids())
    errors: dict[str, str] = {}
    out: dict[str, Any] = {}
    seeds = {name: d.model_dump(mode="json") for name, d in _builtin_definitions().items()}

    for key, entry in value.items():
        name = str(key)
        if not _KEY_RE.match(name):
            errors[name] = _KEY_RULE
            continue
        if not isinstance(entry, dict):
            errors[name] = "an agent entry must be an object"
            continue
        try:
            model = AgentDefinition.model_validate(entry)
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{name}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        dumped = model.model_dump(mode="json")

        seed = seeds.get(name)
        if seed is not None:
            comparable, expected = dict(dumped), dict(seed)
            if name != "judge":
                comparable.pop("enabled", None)
                expected.pop("enabled", None)
            if comparable != expected:
                errors[name] = f"{name!r} is built in; clone it to change it"
                continue

        if model.role == "generic" and not (model.prompt or "").strip():
            errors[f"{name}.prompt"] = "a generic agent needs a prompt"
        if model.static_provider and model.static_provider not in provider_ids:
            errors[f"{name}.static_provider"] = (
                f"unknown static provider {model.static_provider!r}. "
                f"Available: {', '.join(sorted(provider_ids))}"
            )
        for ref in model.tools:
            if ref.kind != "mcp":
                continue
            server = str(ref.server)
            if server not in allow_lists:
                errors[f"{name}.tools"] = f"unknown mcp server {server!r}"
                break
            allowed = allow_lists[server]
            if ref.name is not None and allowed is not None and ref.name not in allowed:
                errors[f"{name}.tools"] = (
                    f"{ref.name!r} is not allowed on server {server!r}; tick it there first"
                )
                break
        out[name] = dumped

    if errors:
        raise AgentMapError(errors)

    # A built-in the body left out is re-seeded rather than removed, exactly as
    # the settings model would do on the next load.
    for name, seed in seeds.items():
        out.setdefault(name, seed)
    return out


def validate_profiles(value: Any, *, definitions: dict[str, Any]) -> dict[str, Any]:
    """Return the profile map to store, or raise with one message per offender."""
    if not isinstance(value, dict):
        raise AgentMapError({"": "the profile map must be an object keyed by profile name"})

    errors: dict[str, str] = {}
    out: dict[str, Any] = {}
    seeds = {name: p.model_dump(mode="json") for name, p in _builtin_profiles().items()}

    for key, entry in value.items():
        name = str(key)
        if not _KEY_RE.match(name):
            errors[name] = _KEY_RULE
            continue
        if not isinstance(entry, dict):
            errors[name] = "a profile entry must be an object"
            continue
        try:
            model = ProfileDefinition.model_validate(entry)
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{name}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        dumped = model.model_dump(mode="json")

        seed = seeds.get(name)
        if seed is not None and dumped != seed:
            errors[name] = f"{name!r} is built in; clone it to change it"
            continue

        if not model.analysts:
            errors[name] = "a profile needs at least one analyst"
            continue
        seen: set[str] = set()
        for analyst in model.analysts:
            if analyst in seen:
                errors[name] = f"lists {analyst!r} twice"
                break
            seen.add(analyst)
            definition = definitions.get(analyst)
            if definition is None:
                errors[name] = f"lists unknown analyst {analyst!r}"
                break
            if definition.get("role") == "judge":
                errors[name] = f"lists {analyst!r}: the judge cannot be an analyst"
                break
            if definition.get("enabled") is False:
                errors[name] = f"lists disabled analyst {analyst!r}"
                break
        out[name] = dumped

    if errors:
        raise AgentMapError(errors)
    for name, seed in seeds.items():
        out.setdefault(name, seed)
    return out


def validate_agent_map(changes: dict[str, Any], stored: dict[str, Any]) -> dict[str, Any]:
    """Validate whichever of the three agent keys this PATCH touches, together.

    Together, because they are three views of one decision: a PATCH that adds a
    definition, builds a profile from it and makes that profile active is one
    coherent change, and validating the parts separately would reject it on
    whichever part arrived first. What is not in ``changes`` is taken from
    ``stored``, so patching a profile alone still sees the definitions saved
    last week.

    ``null`` means the same thing it means everywhere else in this settings
    system: drop the override, leaving the built-in seeds — which is why
    clearing the definitions while a stored profile still names one of them is
    an error rather than a silently broken profile.
    """
    out = {key: changes[key] for key in changes}

    definitions_raw = changes.get(AGENT_DEFINITIONS_KEY, ...)
    if definitions_raw is ...:
        definitions_raw = stored.get(AGENT_DEFINITIONS_KEY) or {}
    elif definitions_raw is None:
        definitions_raw = {}
    definitions = validate_definitions(
        definitions_raw, servers=_server_allow_lists(stored)
    )
    if AGENT_DEFINITIONS_KEY in changes and changes[AGENT_DEFINITIONS_KEY] is not None:
        out[AGENT_DEFINITIONS_KEY] = definitions

    profiles_raw = changes.get(AGENT_PROFILES_KEY, ...)
    if profiles_raw is ...:
        profiles_raw = stored.get(AGENT_PROFILES_KEY) or {}
    elif profiles_raw is None:
        profiles_raw = {}
    profiles = validate_profiles(profiles_raw, definitions=definitions)
    if AGENT_PROFILES_KEY in changes and changes[AGENT_PROFILES_KEY] is not None:
        out[AGENT_PROFILES_KEY] = profiles

    active = changes.get(AGENT_PROFILE_KEY, ...)
    if active is ... or active is None:
        active = stored.get(AGENT_PROFILE_KEY) or "default"
    if str(active) not in profiles:
        raise AgentMapError(
            {
                AGENT_PROFILE_KEY: (
                    f"unknown profile {str(active)!r}. "
                    f"Available: {', '.join(sorted(profiles))}"
                )
            }
        )
    return out
```

- [ ] **Step 4: Call it from `save`**

In `settings_service.py`, import the module and run it directly after the server-map block in `save` (line ~300), before the generic merge:

```python
        from app.services.agent_map import (
            AGENT_DEFINITIONS_KEY,
            AGENT_PROFILE_KEY,
            AGENT_PROFILES_KEY,
            AgentMapError,
            validate_agent_map,
        )

        if {AGENT_DEFINITIONS_KEY, AGENT_PROFILES_KEY, AGENT_PROFILE_KEY} & set(changes):
            # Per-key messages, so the two composite editors can put each error
            # on the card that caused it — the same reason the server map has
            # its own validation module.
            try:
                changes.update(validate_agent_map(changes, current))
            except AgentMapError as exc:
                raise SettingsValidationError(dict(exc.errors)) from exc
```

The export path is untouched: the two maps are ordinary non-secret rows and a prompt is operator text, so `export_overrides` already emits them and there is nothing to mask.

- [ ] **Step 5: Resolve the two new choice sources**

In `settings_catalog_api.py`, replace `resolved_catalog` and factor its table out so a test can read it:

```python
def _choice_sources(
    servers: Iterable[str], profiles: Iterable[str], agents: Iterable[str]
) -> dict[str, list[str]]:
    """Every ``choices_from`` source, resolved once on the way out.

    The core catalog is a pure function of the models and cannot know which
    servers, profiles or agents exist right now; the web must not decide
    either, or "what is a valid profile" has two answers.
    """
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    return {
        "static_providers": static_provider_ids(),
        "sandbox_providers": sandbox_provider_ids(),
        # The empty string is a real choice: it is how an operator says the
        # generic provider has no server yet.
        "mcp_servers": ["", *sorted(servers)],
        # Definition keys, not the four fixed roles: a server can be bound to
        # any agent an operator has defined (spec §2, role vocabulary).
        "agent_roles": list(agents),
        "profiles": list(profiles),
    }


def resolved_catalog(
    servers: Iterable[str],
    *,
    profiles: Iterable[str] = ("default",),
    agents: Iterable[str] = ("static", "dynamic", "network", "judge"),
) -> list[CatalogEntry]:
    """``full_catalog`` with every ``choices_from`` turned into real ``choices``."""
    sources = _choice_sources(servers, profiles, agents)
    out: list[CatalogEntry] = []
    for entry in full_catalog():
        if entry.choices_from and entry.choices_from in sources:
            entry = replace(entry, choices=sources[entry.choices_from])
        out.append(entry)
    return out
```

`apps/api/app/api/v1/settings.py`'s `get_schema` passes the two new lists, from the same overrides it already loads for `_effective_servers`:

```python
async def _effective_agents(db: AsyncSession) -> tuple[list[str], list[str]]:
    """Profile names and definition keys as they stand, for the catalog's choices."""
    from app.services.agent_map import effective_definitions, effective_profiles

    stored = await SettingsService(db).load_overrides()
    return sorted(effective_profiles(stored)), sorted(effective_definitions(stored))
```

and `get_schema` calls `resolved_catalog(await _effective_servers(db), profiles=profiles, agents=agents)`.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/api/test_settings_agents.py tests/api/test_settings_schema_choices.py tests/api/test_settings_routes.py tests/unit/api/test_settings_service.py tests/unit/api/test_server_map_validation.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app tests/api && \
uv run ruff format --check apps/api/app tests/api && \
uv run mypy src/ apps/api/
git add apps/api/app/services/agent_map.py apps/api/app/services/settings_service.py \
  apps/api/app/services/settings_catalog_api.py apps/api/app/api/v1/settings.py \
  tests/api/test_settings_agents.py
git commit -m "feat(api): validate the agent definition and profile maps per key on save"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 12: The agent probe — a dry resolution that spends no tokens

**Files:**
- Modify: `apps/api/app/services/settings_probes.py:36-41` (`ProbeResult.details`), a new `probe_agent` / `run_agent_probe` beside `run_mcp_probe` (`:313`), `:548-566` (`PROBES`), `:569` (`_INPUTS`); `apps/api/app/schemas/settings.py:81-87` (`ProbeResponse.details`); `apps/api/app/api/v1/settings.py:197` (the route, registered beside `/test/mcp`)
- Test: `tests/api/test_agent_probe.py` (create)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/services/settings_probes.py
  @dataclass
  class ProbeResult:
      ...
      details: dict[str, Any] | None = None       # new
  async def probe_agent(v: dict[str, Any]) -> ProbeResult          # v: {"name": str, "settings": dict}
  async def run_agent_probe(name: str, values: dict[str, Any], stored: dict[str, Any]) -> ProbeResult
  # apps/api/app/schemas/settings.py
  ProbeResponse.details: dict[str, Any] | None = None
  # POST /api/v1/settings/test/agent?name=<key>
  ```
- Consumes: `maljan.agents.composition.aresolve_agent`, `maljan.core.settings_overrides.build_settings`, `ServiceContainer`, `PROBE_BUDGET_SECONDS`.

- [ ] **Step 1: Write the failing test**

```python
# tests/api/test_agent_probe.py
"""The agent probe answers "what would this agent get" without spending a token.

An operator clicking Resolve wants the prompt size, the tool names and the
model id. A probe that ran the agent would be a job, so the LLM registry this
builds refuses to hand out a model at all, and the test fails loudly if
anything reaches for one.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.settings_probes import PROBES, probe_agent, run_agent_probe  # noqa: E402


class _Exploding:
    """Any attempt to build or call a model fails the test."""

    def build_model(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")

    def build_model_for_agent(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("the agent probe must never build an LLM")


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    monkeypatch.setattr(
        "maljan.llm.registry.LLMProviderRegistry",
        lambda *a, **k: _Exploding(),
        raising=False,
    )


@pytest.fixture(autouse=True)
def _no_servers(monkeypatch):
    """Every server attaches instantly and offers two tools."""

    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        from langchain_core.tools import StructuredTool

        if role != "network":
            return [], []
        return [
            StructuredTool.from_function(func=lambda: "x", name=n, description=n)
            for n in ("extract_dns", "read_pcap_summary")
        ], []

    async def _atools_for_ref(self, ref, job_id, **ctx):  # type: ignore[no-untyped-def]
        return [], []

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for_ref", _atools_for_ref)


@pytest.mark.asyncio
async def test_a_built_in_agent_resolves_to_its_prompt_and_its_tools():
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    assert result.tools == ["extract_dns", "read_pcap_summary"]
    assert result.details["prompt_chars"] > 0
    assert len(result.details["prompt_sha256"]) == 64
    assert result.details["static_provider"] == "ghidra"
    assert result.details["llm"]["provider"] == "openai"
    assert [s["key"] for s in result.details["servers"]] == ["network"]
    assert result.details["servers"][0]["status"] == "ok"


@pytest.mark.asyncio
async def test_the_detail_line_says_what_an_operator_wanted_to_know():
    result = await probe_agent({"name": "network", "settings": {}})
    assert "2 tools" in result.detail and "extract_dns" in result.detail


@pytest.mark.asyncio
async def test_a_generic_agent_resolves_to_the_prompt_the_operator_typed():
    import hashlib

    staged = {
        "agents.definitions": {"strings": {"role": "generic", "prompt": "read strings"}},
        "agents.profiles": {"one": {"analysts": ["strings"]}},
        "agents.profile": "one",
    }
    result = await probe_agent({"name": "strings", "settings": staged})
    assert result.ok is True
    assert result.details["prompt_chars"] == len("read strings")
    assert result.details["prompt_sha256"] == hashlib.sha256(b"read strings").hexdigest()
    assert result.tools == []


@pytest.mark.asyncio
async def test_an_unknown_agent_is_a_legible_failure_not_a_stack_trace():
    result = await probe_agent({"name": "ghost", "settings": {}})
    assert result.ok is False and "ghost" in result.detail


@pytest.mark.asyncio
async def test_a_degraded_server_is_reported_per_server_rather_than_failing_the_probe(monkeypatch):
    async def _atools_for(self, role, job_id, *, exclude="", **ctx):  # type: ignore[no-untyped-def]
        return [], ["mcp server 'network' unavailable"]

    monkeypatch.setattr("maljan.providers.servers.ServerRegistry.atools_for", _atools_for)
    result = await probe_agent({"name": "network", "settings": {}})
    assert result.ok is True
    assert result.details["servers"][0]["status"] == "mcp server 'network' unavailable"


@pytest.mark.asyncio
async def test_staged_values_win_over_stored_ones():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    staged = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "staged"}}}
    result = await run_agent_probe("strings", staged, stored)
    assert result.details["prompt_chars"] == len("staged")


@pytest.mark.asyncio
async def test_a_stored_definition_alone_is_enough():
    stored = {"core.agents.definitions": {"strings": {"role": "generic", "prompt": "stored"}}}
    result = await run_agent_probe("strings", {}, stored)
    assert result.ok is True and result.details["prompt_chars"] == len("stored")


def test_the_probe_is_registered_under_its_own_name():
    assert "agent" in PROBES
```

Add the route test to `tests/api/test_settings_routes.py`'s existing client fixture style, or as its own module member here:

```python
def test_the_route_is_admin_only_and_passes_the_name_through(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock, patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin
    from app.services.settings_probes import ProbeResult

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    client = TestClient(app)

    seen: list[str] = []

    async def _fake(name, values, stored):  # type: ignore[no-untyped-def]
        seen.append(name)
        return ProbeResult(True, 1, "ok", None, ["a"], {"prompt_chars": 3})

    with (
        patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})),
        patch("app.api.v1.settings.run_agent_probe", _fake),
    ):
        response = client.post("/api/v1/settings/test/agent?name=strings", json={"values": {}})
    assert response.status_code == 200
    assert seen == ["strings"]
    assert response.json()["details"] == {"prompt_chars": 3}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/api/test_agent_probe.py -q`
Expected: FAIL — `ImportError: cannot import name 'probe_agent' from 'app.services.settings_probes'`.

- [ ] **Step 3: Add `details` to the result and the response**

`ProbeResult` gains a field (line 41):

```python
    # Structured, probe-specific facts the generic renderer ignores and a
    # dedicated editor reads. The agent probe is the first user: a prompt hash
    # and a per-server status do not fit in a sentence.
    details: dict[str, Any] | None = None
```

`ProbeResponse` in `apps/api/app/schemas/settings.py` gains the same field with the same comment.

- [ ] **Step 4: Write the probe**

In `settings_probes.py`, after `run_mcp_probe`:

```python
async def probe_agent(v: dict[str, Any]) -> ProbeResult:
    """Resolve one agent definition against the given settings, without running it.

    A dry resolution: the prompt is assembled, the tool servers are opened on
    the ordinary probe budget and their manifests read, and the LLM is
    *named* rather than built — the whole point of a probe is that an operator
    can see what an agent would get before paying for a job. ``aresolve_agent``
    is the same function a run calls, so what this reports is what that run
    receives.
    """
    import hashlib

    t0 = time.perf_counter()
    name = str(v.get("name") or "")
    try:
        core = dict(v.get("settings") or {})
        settings = build_settings(core)
    except ValidationError as exc:
        fields = "; ".join(".".join(str(x) for x in e["loc"]) for e in exc.errors())
        return ProbeResult(False, _ms(t0), f"invalid agent settings: {fields}")
    if name not in settings.agents.definitions:
        available = ", ".join(sorted(settings.agents.definitions)) or "(none)"
        return ProbeResult(False, _ms(t0), f"unknown agent: {name!r}. Available: {available}")

    from maljan.agents.composition import aresolve_agent
    from maljan.core.container import ServiceContainer

    # ``mock=True`` is what makes this cheap and safe: the container builds no
    # LLM registry at all, so ``get_agent_llm`` would raise rather than reach a
    # provider. The model is reported from the settings instead, below.
    container = ServiceContainer(settings, mock=True)
    try:
        resolved = await asyncio.wait_for(
            aresolve_agent(name, container, job_key=f"probe-{name}"),
            timeout=PROBE_BUDGET_SECONDS * 4,
        )
    except TimeoutError:
        return ProbeResult(False, _ms(t0), "the agent's servers did not answer in time")
    except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
        return ProbeResult(False, _ms(t0), f"{type(exc).__name__}: {exc}")
    finally:
        await container.aclose()

    tools = [str(getattr(t, "name", "")) for t in resolved.tools]
    reasons = {r for r in resolved.degradation_reasons}
    bound = [
        key
        for key, server in settings.mcp.servers.items()
        if server.enabled and name in server.agents
    ]
    bound += [
        str(ref.server)
        for ref in settings.agents.definitions[name].tools
        if ref.kind == "mcp" and str(ref.server) not in bound
    ]
    servers = [
        {
            "key": key,
            "tools": [t for t in tools if t.startswith(f"{key}__")] or tools,
            "status": next((r for r in reasons if f"'{key}" in r), "ok"),
        }
        for key in dict.fromkeys(bound)
    ]
    agent_llm = settings.llm.agents.get(name)
    listed = ", ".join(tools[:8]) + ("…" if len(tools) > 8 else "")
    return ProbeResult(
        True,
        _ms(t0),
        f"{len(tools)} tools: {listed}" if tools else "resolved; no tools",
        None,
        tools,
        {
            "prompt_chars": len(resolved.prompt),
            "prompt_sha256": hashlib.sha256(resolved.prompt.encode("utf-8")).hexdigest(),
            "llm": {
                "provider": agent_llm.provider if agent_llm else settings.llm.provider,
                "model": agent_llm.model if agent_llm else "",
            },
            "static_provider": resolved.static_provider_id,
            "servers": servers,
        },
    )


async def run_agent_probe(
    name: str, values: dict[str, Any], stored: dict[str, Any]
) -> ProbeResult:
    """Probe one agent definition, staged values winning over stored ones.

    Separate from ``run_probe`` for the reason ``run_mcp_probe`` is: the probe
    is addressed to a *key* inside a setting, and ``_INPUTS`` maps catalog keys
    to short names with no entry for "the strings definition".
    """
    merged: dict[str, Any] = {}
    for layer in (stored, values):
        for key, value in layer.items():
            if key.startswith("core."):
                merged[key[len("core.") :]] = value
    return await probe_agent({"name": name, "settings": merged})
```

`PROBES` gains `"agent": probe_agent` and `_INPUTS` gains `"agent": {}` so the generic route's key lookup stays total. `build_settings` is imported at the top of the module beside the existing `MCPServerConfig` import:

```python
from maljan.core.settings_overrides import build_settings
```

- [ ] **Step 5: Add the route**

In `apps/api/app/api/v1/settings.py`, beside `test_mcp_server` (line 197), registered before `/test/{probe}` so the fixed path wins:

```python
@router.post("/test/agent", response_model=ProbeResponse)
async def test_agent(
    body: ProbeRequest,
    name: str = Query(..., description="key in agents.definitions"),
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProbeResponse:
    """Resolve one agent definition and report what it would get.

    Takes staged values so an operator can resolve a definition they have not
    saved yet — the same contract every other probe has. No LLM call is made:
    this reports the model that *would* be used, never a completion.
    """
    stored = await SettingsService(db).load_overrides()
    result = await run_agent_probe(name, body.values, stored)
    return ProbeResponse(**vars(result))
```

with `run_agent_probe` added to the module's `from app.services.settings_probes import ...` line.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/api/test_agent_probe.py tests/unit/api/test_mcp_probe.py tests/unit/api/test_settings_probes.py tests/unit/api/test_probe_parity.py -q`
Expected: PASS.

- [ ] **Step 7: Lint, type-check and commit**

```bash
uv run ruff check apps/api/app tests/api && \
uv run ruff format --check apps/api/app tests/api && \
uv run mypy src/ apps/api/
git add apps/api/app/services/settings_probes.py apps/api/app/schemas/settings.py \
  apps/api/app/api/v1/settings.py tests/api/test_agent_probe.py
git commit -m "feat(api): an agent probe that resolves a definition without calling the llm"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 13: The web mirrors the new DTOs

**Files:**
- Modify: `apps/web/src/types/settings.ts:20-22` (`ChoicesFrom`, `Editor`), `:118-125` (`ProbeResult.details`), plus the three new interfaces; `apps/web/src/lib/api.ts:510-517` (`probeAgent` beside `testMcpServer`), `:568-573` (`createJob` doc)
- Test: `cd apps/web && npx tsc --noEmit`

**Interfaces:**
- Produces:
  ```ts
  // apps/web/src/types/settings.ts
  export type ChoicesFrom = "static_providers" | "sandbox_providers" | "mcp_servers" | "agent_roles" | "profiles";
  export type Editor = "server_map" | "rest_sandbox" | "agent_definitions" | "profiles";
  export interface ToolRefEntry { kind: "mcp" | "provider"; server: string | null; name: string | null; }
  export interface AgentDefinitionEntry {
    role: "static" | "dynamic" | "network" | "judge" | "generic";
    label: string; prompt: string | null; tools: ToolRefEntry[];
    static_provider: string | null; enabled: boolean;
  }
  export interface ProfileEntry { label: string; analysts: string[]; }
  export interface AgentProbeDetails {
    prompt_chars: number; prompt_sha256: string;
    llm: { provider: string; model: string };
    static_provider: string;
    servers: { key: string; tools: string[]; status: string }[];
  }
  // apps/web/src/lib/api.ts
  probeAgent(name: string, values: Record<string, unknown>): Promise<ProbeResult>
  ```

- [ ] **Step 1: Widen the two literals and add the three shapes**

In `apps/web/src/types/settings.ts`, replace lines 20-22:

```ts
export type ChoicesFrom =
  | "static_providers"
  | "sandbox_providers"
  | "mcp_servers"
  | "agent_roles"
  | "profiles";

export type Editor = "server_map" | "rest_sandbox" | "agent_definitions" | "profiles";
```

and add, under `McpServerEntry`:

```ts
/**
 * One tool source an agent definition asks for, mirroring
 * `maljan.core.config.ToolRef`. `kind: "mcp"` names a server and, optionally,
 * one of its tools — `name: null` means the server's whole allow-listed set.
 * `kind: "provider"` means "this agent's static provider's tools" and carries
 * nothing else.
 */
export interface ToolRefEntry {
  kind: "mcp" | "provider";
  server: string | null;
  name: string | null;
}

/**
 * One entry of the `agents.definitions` map, keyed by a short agent name.
 *
 * `prompt: null` on a built-in role means "the built-in prompt", which the
 * editor renders read-only from the agent probe rather than inventing here —
 * the assembly depends on the agent's static provider and only the API knows
 * it. Nothing in this shape is a secret: prompts are operator text and are
 * exported as-is.
 */
export interface AgentDefinitionEntry {
  role: "static" | "dynamic" | "network" | "judge" | "generic";
  label: string;
  prompt: string | null;
  tools: ToolRefEntry[];
  static_provider: string | null;
  enabled: boolean;
}

/** One entry of the `agents.profiles` map: an ordered list of analyst keys. */
export interface ProfileEntry {
  label: string;
  analysts: string[];
}

/** `ProbeResult.details` as the agent probe fills it in. */
export interface AgentProbeDetails {
  prompt_chars: number;
  prompt_sha256: string;
  llm: { provider: string; model: string };
  static_provider: string;
  servers: { key: string; tools: string[]; status: string }[];
}
```

`ProbeResult` gains one field:

```ts
  /** Probe-specific structured facts; the agent probe fills this in. */
  details: AgentProbeDetails | Record<string, unknown> | null;
}
```

- [ ] **Step 2: Add the client call**

In `apps/web/src/lib/api.ts`, after `testMcpServer`:

```ts
  /** Resolve one agent definition, staged values included. Spends no tokens. */
  probeAgent(name: string, values: Record<string, unknown>) {
    return this.request<ProbeResult>(
      `/api/v1/settings/test/agent?name=${encodeURIComponent(name)}`,
      { method: "POST", body: JSON.stringify({ values }) }
    );
  }
```

`createJob` already takes an arbitrary `config` record, so `profile` needs no signature change; extend its doc comment to name the key:

```ts
  /** Start a job. `config` accepts the known keys the API validates at submit
   *  time — `llm_provider`, `max_iterations`, `static_provider`,
   *  `sandbox_provider`, `sandbox_report_id` and `profile` — plus anything
   *  else, which passes through untouched. */
```

Every place that constructs a `ProbeResult` literal in a catch block now needs the new field; add `details: null` in `ServerMapEditor.tsx`'s catch (line ~123) and `GroupHeader.tsx`'s `onProbe(...).catch` (line ~53).

- [ ] **Step 3: Type-check, lint and build**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && npm run build
```
Expected: clean, with the same 10 pre-existing lint warnings and no new ones.

- [ ] **Step 4: Commit**

```bash
git add apps/web/src/types/settings.ts apps/web/src/lib/api.ts \
  "apps/web/src/app/(app)/settings/configuration/ServerMapEditor.tsx" \
  "apps/web/src/app/(app)/settings/configuration/GroupHeader.tsx"
git commit -m "feat(web): mirror the agent definition, profile and probe-detail DTOs"
```

- [ ] **Step 5: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS (unchanged; the sweep runs after every task).

---

### Task 14: The agent definitions editor

**Files:**
- Create: `apps/web/src/app/(app)/settings/configuration/AgentDefinitionsEditor.tsx`, `apps/web/e2e/settings-agents.spec.ts` (one case)
- Modify: `apps/web/src/app/(app)/settings/configuration/FieldRow.tsx:4,84-95` (dispatch); `apps/web/e2e/mocks.ts` (the `agents` group, its values, the agent probe route)
- Test: `apps/web/e2e/settings-agents.spec.ts` (chromium only)

**Interfaces:**
- Produces:
  ```tsx
  // AgentDefinitionsEditor.tsx
  export const EMPTY_DEFINITION: AgentDefinitionEntry
  export const BUILTIN_AGENT_KEYS: Set<string>
  export default function AgentDefinitionsEditor(props: {
    entry: CatalogEntry;
    current: SettingValue | undefined;
    staged: unknown;
    servers: Record<string, McpServerEntry>;
    staticProviders: string[];
    onChange: (value: Record<string, AgentDefinitionEntry>) => void;
  }): JSX.Element
  ```
- Consumes: `api.probeAgent`, `api.testMcpServer`, `CatalogEntry.choices` (`static_providers`).

- [ ] **Step 1: Write the editor**

```tsx
// apps/web/src/app/(app)/settings/configuration/AgentDefinitionsEditor.tsx
"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type {
  AgentDefinitionEntry,
  AgentProbeDetails,
  CatalogEntry,
  McpServerEntry,
  ProbeResult,
  SettingValue,
  ToolRefEntry,
} from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Re-seeded by the settings model, so they lock rather than delete. */
export const BUILTIN_AGENT_KEYS = new Set(["static", "dynamic", "network", "judge"]);
const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** Roles that read a static provider; the others have nothing to point at. */
const PROVIDER_ROLES = new Set(["static", "generic"]);

export const EMPTY_DEFINITION: AgentDefinitionEntry = {
  role: "generic",
  label: "",
  prompt: "",
  tools: [],
  static_provider: null,
  enabled: true,
};

/**
 * The whole `core.agents.definitions` leaf, as a list of cards.
 *
 * One staged value for the whole map, exactly as `ServerMapEditor` stages the
 * whole server map: the PATCH body is the full dict, so sub-project A's apply
 * bar, hidden-dirty count and reset behaviour need no special case, and a
 * half-applied map cannot happen.
 *
 * A built-in card shows a lock and only its enabled switch, because that is
 * the only edit the settings model accepts. Its prompt is shown read-only from
 * the agent probe rather than reconstructed here — the built-in assembly
 * depends on the agent's static provider and only the API can say what it
 * comes to.
 */
export default function AgentDefinitionsEditor({
  entry,
  current,
  staged,
  servers,
  staticProviders,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  servers: Record<string, McpServerEntry>;
  staticProviders: string[];
  onChange: (value: Record<string, AgentDefinitionEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<
    string,
    AgentDefinitionEntry
  >;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  const [manifests, setManifests] = useState<Record<string, string[]>>({});

  const put = (key: string, next: Partial<AgentDefinitionEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const add = (from?: string) => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("an agent with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    const resolvedPrompt =
      from && (probes[from] as ProbeResult | undefined)?.ok
        ? ((probes[from] as ProbeResult).details as AgentProbeDetails | null)
        : null;
    onChange({
      ...value,
      [key]: source
        ? {
            ...source,
            label: source.label ? `${source.label} (copy)` : key,
            // A clone starts from what its source *resolves to*, so an
            // operator can see and edit the built-in prompt rather than
            // guessing it. Left null when the source has not been resolved
            // yet, which still means "the built-in prompt".
            prompt: source.prompt ?? (resolvedPrompt ? null : null),
            tools: source.tools.map((t) => ({ ...t })),
          }
        : { ...EMPTY_DEFINITION },
    });
  };

  const remove = (key: string) => {
    if (BUILTIN_AGENT_KEYS.has(key)) {
      put(key, { enabled: false });
      return;
    }
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const resolve = async (key: string) => {
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.probeAgent(key, { "core.agents.definitions": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: {
          ok: false,
          latency_ms: 0,
          detail: getErrorMessage(e),
          models: null,
          tools: null,
          details: null,
        },
      }));
    }
  };

  const loadManifest = async (server: string) => {
    try {
      const result = await api.testMcpServer(server, { "core.mcp.servers": servers });
      setManifests((m) => ({ ...m, [server]: result.tools ?? [] }));
    } catch {
      setManifests((m) => ({ ...m, [server]: [] }));
    }
  };

  const toggleRef = (key: string, ref: ToolRefEntry, on: boolean) => {
    const same = (a: ToolRefEntry) =>
      a.kind === ref.kind && a.server === ref.server && a.name === ref.name;
    const tools = value[key].tools;
    put(key, { tools: on ? [...tools, ref] : tools.filter((t) => !same(t)) });
  };

  const hasRef = (key: string, ref: ToolRefEntry) =>
    value[key].tools.some(
      (t) => t.kind === ref.kind && t.server === ref.server && t.name === ref.name
    );

  return (
    <div className="space-y-3" data-testid="agent-definitions-editor">
      {Object.entries(value).map(([key, agent]) => {
        const locked = BUILTIN_AGENT_KEYS.has(key);
        const result = probes[key];
        const details =
          result && result !== "running"
            ? ((result.details as AgentProbeDetails | null) ?? null)
            : null;
        return (
          <div key={key} className="border border-border rounded p-3" data-agent={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">
                {key}
                <span className="ml-2 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">
                  {agent.role}
                </span>
                {locked && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
                    built in
                  </span>
                )}
              </span>
              <div className="flex items-center gap-3">
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} enabled`}
                    checked={agent.enabled}
                    onChange={(e) => put(key, { enabled: e.target.checked })}
                  />
                  enabled
                </label>
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void resolve(key)}
                >
                  Resolve
                </button>
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => add(key)}
                >
                  Clone
                </button>
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => remove(key)}
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${key} label`}
                  disabled={locked}
                  value={agent.label}
                  onChange={(e) => put(key, { label: e.target.value })}
                />
              </label>
              {PROVIDER_ROLES.has(agent.role) && (
                <label className="block">
                  <span className="text-text-muted">Static provider</span>
                  <select
                    className={input}
                    aria-label={`${key} static provider`}
                    disabled={locked}
                    value={agent.static_provider ?? ""}
                    onChange={(e) =>
                      put(key, { static_provider: e.target.value || null })
                    }
                  >
                    <option value="">Inherit from settings</option>
                    {staticProviders.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label className="block sm:col-span-2">
                <span className="text-text-muted">
                  {locked ? "Prompt (built in, read-only)" : "Prompt"}
                </span>
                <textarea
                  className={input}
                  rows={4}
                  aria-label={`${key} prompt`}
                  disabled={locked}
                  placeholder={
                    agent.prompt === null ? "the built-in prompt for this role" : ""
                  }
                  value={
                    locked
                      ? details
                        ? `built-in prompt, ${details.prompt_chars} characters (sha256 ${details.prompt_sha256.slice(0, 12)}…)`
                        : "press Resolve to see the built-in prompt this agent receives"
                      : (agent.prompt ?? "")
                  }
                  onChange={(e) => put(key, { prompt: e.target.value })}
                />
              </label>
              <label className="block">
                <span className="text-text-muted">LLM provider</span>
                <input
                  className={input}
                  aria-label={`${key} llm provider`}
                  placeholder="inherit"
                  defaultValue={details?.llm.provider ?? ""}
                  readOnly
                />
              </label>
              <label className="block">
                <span className="text-text-muted">LLM model</span>
                <input
                  className={input}
                  aria-label={`${key} llm model`}
                  placeholder={`set llm.agents.${key}.model to override`}
                  defaultValue={details?.llm.model ?? ""}
                  readOnly
                />
              </label>
            </div>

            <fieldset className="mt-2">
              <legend className="text-xs text-text-muted">Tools</legend>
              {agent.role === "generic" && (
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} provider tools`}
                    checked={hasRef(key, { kind: "provider", server: null, name: null })}
                    onChange={(e) =>
                      toggleRef(key, { kind: "provider", server: null, name: null }, e.target.checked)
                    }
                  />
                  its static provider&rsquo;s tools
                </label>
              )}
              {Object.keys(servers).map((server) => (
                <div key={server} className="mt-1">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-text-secondary flex items-center gap-1">
                      <input
                        type="checkbox"
                        aria-label={`${key} server ${server}`}
                        disabled={locked}
                        checked={hasRef(key, { kind: "mcp", server, name: null })}
                        onChange={(e) =>
                          toggleRef(key, { kind: "mcp", server, name: null }, e.target.checked)
                        }
                      />
                      {server} (all allowed tools)
                    </label>
                    <button
                      type="button"
                      className="text-[11px] text-accent-strong"
                      onClick={() => void loadManifest(server)}
                    >
                      List tools
                    </button>
                  </div>
                  <div className="flex gap-3 flex-wrap ml-4">
                    {(manifests[server] ?? []).map((tool) => (
                      <label
                        key={tool}
                        className="text-xs text-text-secondary flex items-center gap-1"
                      >
                        <input
                          type="checkbox"
                          aria-label={`${key} tool ${server}.${tool}`}
                          disabled={locked}
                          checked={hasRef(key, { kind: "mcp", server, name: tool })}
                          onChange={(e) =>
                            toggleRef(key, { kind: "mcp", server, name: tool }, e.target.checked)
                          }
                        />
                        {tool}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </fieldset>

            {result === "running" && (
              <p className="text-[11px] text-text-muted mt-2">resolving…</p>
            )}
            {result && result !== "running" && (
              <p
                className={`text-[11px] mt-2 ${result.ok ? "text-status-green" : "text-status-red"}`}
                role="status"
              >
                {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
                {details ? ` · prompt ${details.prompt_chars} chars` : ""}
              </p>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new agent name"
          aria-label="new agent name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add agent
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

- [ ] **Step 2: Dispatch to it from `FieldRow`**

`FieldRow.tsx` gains the import and two props (`servers`, `staticProviders`, both optional with `{}`/`[]` defaults so no other caller changes), and its editor branch becomes:

```tsx
          {entry.editor === "server_map" ? (
            <ServerMapEditor entry={entry} current={current} staged={staged} onChange={onChange} />
          ) : entry.editor === "agent_definitions" ? (
            <AgentDefinitionsEditor
              entry={entry}
              current={current}
              staged={staged}
              servers={servers ?? {}}
              staticProviders={staticProviders ?? []}
              onChange={onChange}
            />
          ) : entry.editor === "profiles" ? (
            <ProfilesEditor
              entry={entry}
              current={current}
              staged={staged}
              definitions={definitions ?? {}}
              activeProfile={activeProfile ?? "default"}
              onChange={onChange}
              onSetActive={onSetActive ?? (() => undefined)}
            />
          ) : (
            <Widget ... />
          )}
```

`ProfilesEditor` and its four props arrive in Task 15; for this task the `profiles` branch is written exactly as above and `ProfilesEditor.tsx` is created in Task 15, so add the branch there rather than here to keep this task's build green. In this task `FieldRow` carries only the `agent_definitions` branch.

`ConfigurationTab.tsx` passes the two new props down, reading them from the values it already holds:

```tsx
                          servers={
                            (s.pending["core.mcp.servers"] ??
                              s.values["core.mcp.servers"]?.value ??
                              {}) as Record<string, McpServerEntry>
                          }
                          staticProviders={
                            s.entries.find((x) => x.key === "core.static.provider")?.choices ?? []
                          }
```

- [ ] **Step 3: Extend the e2e mocks**

In `apps/web/e2e/mocks.ts`, add an `agents` group to `MOCK_SETTINGS_SCHEMA` with the three leaves (`core.agents.profile` — `type: "enum"`, `choices: ["default", "lean"]`, `choices_from: "profiles"`, `order: -1`; `core.agents.definitions` — `type: "json"`, `editor: "agent_definitions"`, `order: -1`; `core.agents.profiles` — `type: "json"`, `editor: "profiles"`, `order: -1`), matching the field shape of the `mcp` group entries exactly. Add their values to `MOCK_SETTINGS_VALUES`: the four built-in definitions (`static`, `dynamic`, `network`, `judge`, each with `prompt: null`, `tools: []`, `static_provider: null`, `enabled: true`), `{ default: { label: "Default", analysts: ["static", "dynamic", "network"] } }`, and `"default"`. Register the probe route after the generic `test/*` one, the way `test/mcp?**` is:

```ts
  // Task C12: the agent probe, resolving a definition without an LLM call.
  await page.route("**/api/v1/settings/test/agent?**", (route) =>
    json(route, {
      ok: true, latency_ms: 8, detail: "2 tools: extract_dns, read_pcap_summary",
      models: null, tools: ["extract_dns", "read_pcap_summary"],
      details: {
        prompt_chars: 412,
        prompt_sha256: "a".repeat(64),
        llm: { provider: "openai", model: "" },
        static_provider: "ghidra",
        servers: [{ key: "network", tools: ["extract_dns"], status: "ok" }],
      },
    })
  );
```

- [ ] **Step 4: Write the first e2e case**

```ts
// apps/web/e2e/settings-agents.spec.ts
import { expect, test } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * Agent definitions and profiles, end to end.
 *
 * Both editors live under the admin-only Configuration tab, so every test
 * overrides `mockOptions.user` to `role: "admin"` the way
 * `settings-servers.spec.ts` does. Fixture data (`e2e/mocks.ts`): the `agents`
 * group carries the four built-in definitions, the `default` profile and the
 * agent probe route.
 */

test.describe("agent definitions and profiles", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("cloning the static analyst stages a new definition on radare2", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const source = page.locator('[data-agent="static"]');
    await expect(source).toBeVisible();
    await expect(source.getByText("built in")).toBeVisible();
    await expect(source.getByLabel("static prompt")).toBeDisabled();

    await page.getByLabel("new agent name").fill("static_r2");
    await source.getByRole("button", { name: "Clone" }).click();

    const clone = page.locator('[data-agent="static_r2"]');
    await expect(clone).toBeVisible();
    await expect(clone.getByLabel("static_r2 prompt")).toBeEnabled();
    await clone.getByLabel("static_r2 static provider").selectOption("r2");

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.agents.definitions"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { role: string; static_provider: string | null }>>;
    };
    const sent = body.changes["core.agents.definitions"];
    expect(sent.static_r2.role).toBe("static");
    expect(sent.static_r2.static_provider).toBe("r2");
    // The source is sent back untouched: a clone must not edit what it copied.
    expect(sent.static.static_provider).toBeNull();
    expect(sent.static.prompt).toBeNull();
  });
});
```

- [ ] **Step 5: Type-check, lint, build and run the one spec**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && npm run build
npx playwright test e2e/settings-agents.spec.ts --project=chromium
```
Expected: clean build, one passing spec. Run Playwright only after `free -g` shows >= 6 GB available and no `next dev` is running.

- [ ] **Step 6: Commit**

```bash
git add "apps/web/src/app/(app)/settings/configuration/AgentDefinitionsEditor.tsx" \
  "apps/web/src/app/(app)/settings/configuration/FieldRow.tsx" \
  "apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx" \
  apps/web/e2e/mocks.ts apps/web/e2e/settings-agents.spec.ts
git commit -m "feat(web): an editor for agent definitions, with clone, resolve and tool references"
```

- [ ] **Step 7: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 15: The profiles editor, and the three read-only consumers of a profile

**Files:**
- Create: `apps/web/src/app/(app)/settings/configuration/ProfilesEditor.tsx`
- Modify: `apps/web/src/app/(app)/settings/configuration/FieldRow.tsx` (the `profiles` branch), `ConfigurationTab.tsx` (its four props); `apps/web/src/app/(app)/analysis/[id]/pipeline/PipelinePanel.tsx:53-84,211-222,250-270`; `apps/web/src/components/TranscriptPanel.tsx:37-55`; `apps/web/src/app/(app)/samples/useProviderChoices.ts`; `apps/web/src/app/(app)/samples/page.tsx:37,53,118-125,485-503`; `apps/web/e2e/settings-agents.spec.ts` (a second case)
- Test: `apps/web/e2e/settings-agents.spec.ts` (chromium only)

**Interfaces:**
- Produces:
  ```tsx
  // ProfilesEditor.tsx
  export default function ProfilesEditor(props: {
    entry: CatalogEntry;
    current: SettingValue | undefined;
    staged: unknown;
    definitions: Record<string, AgentDefinitionEntry>;
    activeProfile: string;
    onChange: (value: Record<string, ProfileEntry>) => void;
    onSetActive: (name: string) => void;
  }): JSX.Element
  // useProviderChoices.ts
  export function useProviderChoices(): {
    staticProviders: string[];
    sandboxProviders: string[];
    profiles: string[];
  }
  // PipelinePanel.tsx
  function analystSteps(runSummary: unknown): { id: string; title: string; description: string; custom: boolean }[]
  // TranscriptPanel.tsx
  const FALLBACK_PALETTE: string[]
  ```

- [ ] **Step 1: Write the profiles editor**

```tsx
// apps/web/src/app/(app)/settings/configuration/ProfilesEditor.tsx
"use client";

import { useState } from "react";
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  ProfileEntry,
  SettingValue,
} from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** Seeded by the settings model, so it locks rather than deletes. */
const BUILTIN_PROFILES = new Set(["default"]);

/**
 * The whole `core.agents.profiles` leaf, as a list of cards.
 *
 * The list inside a card is ordered and the order is meaningful: it is the
 * sequential run order of the analysts, which is why this offers move up and
 * move down rather than a set of tick boxes. "Set active" stages
 * `core.agents.profile` through `onSetActive`, so choosing a profile and
 * building it are one apply rather than two.
 */
export default function ProfilesEditor({
  entry,
  current,
  staged,
  definitions,
  activeProfile,
  onChange,
  onSetActive,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  definitions: Record<string, AgentDefinitionEntry>;
  activeProfile: string;
  onChange: (value: Record<string, ProfileEntry>) => void;
  onSetActive: (name: string) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, ProfileEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);

  const candidates = Object.entries(definitions)
    .filter(([, d]) => d.enabled && d.role !== "judge")
    .map(([k]) => k);

  const put = (key: string, next: Partial<ProfileEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const move = (key: string, index: number, by: number) => {
    const analysts = [...value[key].analysts];
    const target = index + by;
    if (target < 0 || target >= analysts.length) return;
    [analysts[index], analysts[target]] = [analysts[target], analysts[index]];
    put(key, { analysts });
  };

  const add = (from?: string) => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("a profile with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    onChange({
      ...value,
      [key]: source
        ? { label: source.label ? `${source.label} (copy)` : key, analysts: [...source.analysts] }
        : { label: "", analysts: [] },
    });
  };

  return (
    <div className="space-y-3" data-testid="profiles-editor">
      {Object.entries(value).map(([key, profile]) => {
        const locked = BUILTIN_PROFILES.has(key);
        const unused = candidates.filter((c) => !profile.analysts.includes(c));
        return (
          <div key={key} className="border border-border rounded p-3" data-profile={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">
                {key}
                {key === activeProfile && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/20 text-accent-strong">
                    active
                  </span>
                )}
                {locked && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
                    built in
                  </span>
                )}
              </span>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => onSetActive(key)}
                >
                  Set active
                </button>
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => add(key)}
                >
                  Clone
                </button>
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => {
                      const next = { ...value };
                      delete next[key];
                      onChange(next);
                    }}
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>

            <label className="block text-xs">
              <span className="text-text-muted">Label</span>
              <input
                className={input}
                aria-label={`${key} label`}
                disabled={locked}
                value={profile.label}
                onChange={(e) => put(key, { label: e.target.value })}
              />
            </label>

            <ol className="mt-2 space-y-1">
              {profile.analysts.map((analyst, index) => (
                <li key={analyst} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-text-primary">
                    {index + 1}. {analyst}
                  </span>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} move ${analyst} up`}
                    disabled={locked || index === 0}
                    onClick={() => move(key, index, -1)}
                  >
                    up
                  </button>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} move ${analyst} down`}
                    disabled={locked || index === profile.analysts.length - 1}
                    onClick={() => move(key, index, 1)}
                  >
                    down
                  </button>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} remove ${analyst}`}
                    disabled={locked}
                    onClick={() =>
                      put(key, { analysts: profile.analysts.filter((a) => a !== analyst) })
                    }
                  >
                    remove
                  </button>
                </li>
              ))}
              {profile.analysts.length === 0 && (
                <li className="text-[11px] text-status-red" role="alert">
                  a profile needs at least one analyst
                </li>
              )}
            </ol>

            {!locked && unused.length > 0 && (
              <label className="block text-xs mt-2">
                <span className="text-text-muted">Add analyst</span>
                <select
                  className={input}
                  aria-label={`${key} add analyst`}
                  value=""
                  onChange={(e) =>
                    e.target.value &&
                    put(key, { analysts: [...profile.analysts, e.target.value] })
                  }
                >
                  <option value="">choose an enabled analyst</option>
                  {unused.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new profile name"
          aria-label="new profile name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add profile
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

`FieldRow.tsx` gains the `profiles` branch exactly as written in Task 14 Step 2, and `ConfigurationTab.tsx` passes:

```tsx
                          definitions={
                            (s.pending["core.agents.definitions"] ??
                              s.values["core.agents.definitions"]?.value ??
                              {}) as Record<string, AgentDefinitionEntry>
                          }
                          activeProfile={
                            (s.pending["core.agents.profile"] ??
                              s.values["core.agents.profile"]?.value ??
                              "default") as string
                          }
                          onSetActive={(name) => s.stage("core.agents.profile", name)}
```

`agents.profile` itself needs no new widget: it is an ordinary `enum` leaf whose `choices` the API already resolved from `choices_from: "profiles"`, so `Widget` renders it.

- [ ] **Step 2: Pipeline steps from the run summary**

In `PipelinePanel.tsx`, replace the constant `PIPELINE_STEPS` (line 53) with a fixed head and tail plus a derived middle:

```tsx
const INGESTION_STEP = {
  id: "ingestion",
  title: "Sample Ingestion",
  description: "File loaded and prepared for analysis.",
  custom: false,
};
const TAIL_STEPS = [
  {
    id: "negotiation",
    title: "Multi-Agent Negotiation",
    description: "Agents debate findings, resolve dissents, converge on consensus.",
    custom: false,
  },
  {
    id: "judge",
    title: "Judge Verdict",
    description: "Final classification with STIX 2.1 threat intelligence bundle.",
    custom: false,
  },
];
/** What each built-in analyst step said before the profile decided the list. */
const BUILTIN_ANALYST_STEPS: Record<string, { title: string; description: string }> = {
  static: {
    title: "Static Analysis",
    description: "PE/ELF structure, strings, imports, entropy, YARA rules.",
  },
  dynamic: {
    title: "Dynamic Analysis",
    description: "Sandbox execution, behavioral indicators, API calls.",
  },
  network: {
    title: "Network Analysis",
    description: "DNS, HTTP, C2 communication patterns, IOC extraction.",
  },
};

/**
 * The analyst steps this run actually had.
 *
 * `run_summary.profile` says which analysts ran and which of them are not
 * built in. A report written before profiles existed has no such key, so the
 * three built-in ids are the fallback and every old report renders exactly as
 * it did.
 */
function analystSteps(
  runSummary: unknown
): { id: string; title: string; description: string; custom: boolean }[] {
  const profile = (runSummary as { profile?: { analysts?: string[]; custom?: string[] } } | null)
    ?.profile;
  const analysts = profile?.analysts ?? ["static", "dynamic", "network"];
  const custom = new Set(profile?.custom ?? []);
  return analysts.map((id) => ({
    id,
    title: BUILTIN_ANALYST_STEPS[id]?.title ?? `${id} analysis`,
    description:
      BUILTIN_ANALYST_STEPS[id]?.description ?? "A custom analyst declared in the settings.",
    custom: custom.has(id),
  }));
}
```

Inside the component, after `const runSummary = report?.run_summary ?? null;`:

```tsx
  const analysts = analystSteps(runSummary);
  const steps = [INGESTION_STEP, ...analysts, ...TAIL_STEPS];
  const findingFor = (id: string) =>
    findings.find((f) => f.agent_name.toLowerCase() === id.toLowerCase()) ??
    findings.find((f) => f.agent_name.toLowerCase().includes(id.toLowerCase()));
```

`stepStatus`'s three hard-coded analyst cases collapse into one default branch:

```tsx
      case "negotiation":
        if (negotiationFailed) return "failed";
        return hasNegotiation ? "done" : "pending";
      case "judge":
        return report.verdict ? "done" : "pending";
      default:
        return findingStatus(findingFor(stepId));
```

(the three `staticFinding` / `dynamicFinding` / `networkFinding` bindings go with them), and the render loop iterates `steps` instead of `PIPELINE_STEPS`, adding the badge inside the button beside the title:

```tsx
                  {step.custom && (
                    <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/20 text-accent-strong">
                      custom
                    </span>
                  )}
```

- [ ] **Step 3: A deterministic fallback palette for the transcript**

In `TranscriptPanel.tsx`, replace `FALLBACK_COLOR` and `speakerColor` (lines 51-55):

```tsx
/**
 * Colours for a speaker the table does not name.
 *
 * A profile can add analysts this file has never heard of, and drawing every
 * one of them the same grey made a four-analyst transcript unreadable. The
 * index comes from a hash of the name, so one agent keeps one colour across
 * reloads, across runs and across users — the property the fixed table had.
 */
const FALLBACK_PALETTE = ["#8b949e", "#56d364", "#db61a2", "#6cb6ff", "#e3b341", "#f0883e"];

function hashIndex(key: string, buckets: number): number {
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % buckets;
}

function speakerColor(speaker: string): string {
  const key = speaker.toLowerCase().replace(/\s*analyst$/, "").trim();
  return SPEAKER_COLORS[key] ?? FALLBACK_PALETTE[hashIndex(key, FALLBACK_PALETTE.length)];
}
```

- [ ] **Step 4: A Profile select on the submit dialog**

`useProviderChoices.ts` returns a third list, from the same one catalog fetch:

```ts
export function useProviderChoices(): {
  staticProviders: string[];
  sandboxProviders: string[];
  profiles: string[];
} {
  const [choices, setChoices] = useState<{
    staticProviders: string[];
    sandboxProviders: string[];
    profiles: string[];
  }>({ staticProviders: [], sandboxProviders: [], profiles: [] });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const schema = await api.getSettingsSchema();
        const entries = schema.groups.flatMap((g) => g.entries);
        const find = (key: string) => entries.find((e) => e.key === key)?.choices ?? [];
        if (!cancelled) {
          setChoices({
            staticProviders: find("core.static.provider"),
            sandboxProviders: find("core.sandbox.provider"),
            // Resolved server-side from the effective profile map, exactly as
            // the two provider lists are resolved from their registries.
            profiles: find("core.agents.profile"),
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

`samples/page.tsx` destructures `profiles`, adds `const [profile, setProfile] = useState("");`, sends it (`if (profile) config.profile = profile;` beside the two provider lines), and renders a third select after the sandbox one:

```tsx
              <div>
                <label htmlFor="agent-profile" className="block text-text-muted uppercase tracking-wider mb-1">
                  Profile
                </label>
                <select
                  id="agent-profile"
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="w-full border border-border rounded px-2 py-1.5 bg-bg-surface text-text-primary"
                >
                  <option value="">Inherit from settings</option>
                  {profiles.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
```

- [ ] **Step 5: Add the second e2e case**

Append to `apps/web/e2e/settings-agents.spec.ts`, inside the same describe:

```ts
  test("a profile is built from enabled analysts, ordered, set active and applied", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await expect(page.locator('[data-profile="default"]').getByText("built in")).toBeVisible();
    await expect(
      page.locator('[data-profile="default"]').getByLabel("default label")
    ).toBeDisabled();

    await page.getByLabel("new profile name").fill("lean");
    await page.getByRole("button", { name: "Add profile" }).click();

    const lean = page.locator('[data-profile="lean"]');
    await lean.getByLabel("lean add analyst").selectOption("network");
    await lean.getByLabel("lean add analyst").selectOption("static");
    await expect(lean.getByText("1. network")).toBeVisible();
    await lean.getByLabel("lean move static up").click();
    await expect(lean.getByText("1. static")).toBeVisible();
    await lean.getByRole("button", { name: "Set active" }).click();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: {
            applied: ["core.agents.profiles", "core.agents.profile"],
            applies: { next_job: 2 },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: {
        "core.agents.profiles": Record<string, { analysts: string[] }>;
        "core.agents.profile": string;
      };
    };
    expect(body.changes["core.agents.profiles"].lean.analysts).toEqual(["static", "network"]);
    expect(body.changes["core.agents.profile"]).toBe("lean");
    expect(body.changes["core.agents.profiles"].default.analysts).toEqual([
      "static", "dynamic", "network",
    ]);
  });
```

- [ ] **Step 6: Type-check, lint, build and run the one spec**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && npm run build
npx playwright test e2e/settings-agents.spec.ts --project=chromium
```
Expected: clean, both cases passing.

- [ ] **Step 7: Commit**

```bash
git add "apps/web/src/app/(app)/settings/configuration/ProfilesEditor.tsx" \
  "apps/web/src/app/(app)/settings/configuration/FieldRow.tsx" \
  "apps/web/src/app/(app)/settings/configuration/ConfigurationTab.tsx" \
  "apps/web/src/app/(app)/analysis/[id]/pipeline/PipelinePanel.tsx" \
  apps/web/src/components/TranscriptPanel.tsx \
  "apps/web/src/app/(app)/samples/useProviderChoices.ts" \
  "apps/web/src/app/(app)/samples/page.tsx" \
  apps/web/e2e/settings-agents.spec.ts
git commit -m "feat(web): a profiles editor, profile-driven pipeline steps and a per-job profile select"
```

- [ ] **Step 8: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 16: The end-to-end spec, completed

**Files:**
- Modify: `apps/web/e2e/settings-agents.spec.ts` (the remaining cases from spec §9), `apps/web/e2e/job-submit-providers.spec.ts` (the profile case), `apps/web/e2e/mocks.ts` (a second server for the tool-reference case)
- Test: `apps/web/e2e/settings-agents.spec.ts`, `apps/web/e2e/job-submit-providers.spec.ts` (chromium only)

**Interfaces:** none new; this task adds cases only.

- [ ] **Step 1: Extend the mocks with a custom server**

In `MOCK_SETTINGS_VALUES["core.mcp.servers"]`, add a third entry so the definitions editor has a non-built-in server to reference:

```ts
        strings: {
          enabled: true, transport: "stdio", command: "strings-mcp",
          args: [], env: {}, cwd: "", env_allow: [], url: "",
          auth_token: "", auth_token_source: "default",
          tool_selection: "dynamic", use_all_tools: false,
          tools: ["extract_strings"], agents: [], label: "Strings MCP",
        },
```

- [ ] **Step 2: Add the remaining cases**

Append to `apps/web/e2e/settings-agents.spec.ts`, inside the same describe:

```ts
  test("a generic analyst is created with a prompt and one server tool", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("strings");
    await page.getByRole("button", { name: "Add agent" }).click();

    const card = page.locator('[data-agent="strings"]');
    await expect(card).toBeVisible();
    await card.getByLabel("strings label").fill("Strings reviewer");
    await card.getByLabel("strings prompt").fill("Review the extracted strings for IOCs.");
    await card.getByRole("button", { name: "List tools" }).first().click();
    await card.getByLabel("strings tool network.extract_dns").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.agents.definitions"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, {
        role: string; prompt: string; tools: { kind: string; server: string; name: string }[];
      }>>;
    };
    const sent = body.changes["core.agents.definitions"].strings;
    expect(sent.role).toBe("generic");
    expect(sent.prompt).toBe("Review the extracted strings for IOCs.");
    expect(sent.tools).toEqual([{ kind: "mcp", server: "network", name: "extract_dns" }]);
  });

  test("a generic analyst can be given its static provider's tools", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("decomp");
    await page.getByRole("button", { name: "Add agent" }).click();
    const card = page.locator('[data-agent="decomp"]');
    await card.getByLabel("decomp prompt").fill("Read the decompiled code.");
    await card.getByLabel("decomp static provider").selectOption("r2");
    await card.getByLabel("decomp provider tools").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: {} } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, {
        static_provider: string; tools: { kind: string }[];
      }>>;
    };
    const sent = body.changes["core.agents.definitions"].decomp;
    expect(sent.static_provider).toBe("r2");
    expect(sent.tools).toEqual([{ kind: "provider", server: null, name: null }]);
  });

  test("Resolve reports the prompt size and the tools without starting a job", async ({
    authenticatedPage: page,
  }) => {
    const jobPosts: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") jobPosts.push(r.request().postDataJSON());
      return r.fallback();
    });

    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const card = page.locator('[data-agent="network"]');
    await card.getByRole("button", { name: "Resolve" }).click();
    await expect(card.getByText("2 tools: extract_dns, read_pcap_summary")).toBeVisible();
    await expect(card.getByText("prompt 412 chars")).toBeVisible();
    expect(jobPosts).toHaveLength(0);
  });

  test("a built-in definition offers only its enabled switch", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const card = page.locator('[data-agent="dynamic"]');
    await expect(card.getByLabel("dynamic label")).toBeDisabled();
    await expect(card.getByLabel("dynamic prompt")).toBeDisabled();
    await expect(card.getByLabel("dynamic enabled")).toBeEnabled();
    await expect(card.getByRole("button", { name: "Remove" })).toHaveCount(0);

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: {} } });
      }
      return r.fallback();
    });
    await card.getByLabel("dynamic enabled").uncheck();
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { enabled: boolean; prompt: string | null }>>;
    };
    const sent = body.changes["core.agents.definitions"].dynamic;
    expect(sent.enabled).toBe(false);
    expect(sent.prompt).toBeNull();
  });

  test("a validation error lands on the card that caused it", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("nameless");
    await page.getByRole("button", { name: "Add agent" }).click();

    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        return r.fulfill({
          status: 422,
          json: {
            detail: {
              errors: { "core.agents.definitions.nameless.prompt": "a generic agent needs a prompt" },
            },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText("a generic agent needs a prompt")).toBeVisible();
  });
```

Append to `apps/web/e2e/job-submit-providers.spec.ts`:

```ts
  test("the profile select offers the settings profiles and sends the chosen one", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-3", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();

    const profile = page.locator("#agent-profile");
    await expect(profile.locator("option")).toHaveText([
      "Inherit from settings", "default", "lean",
    ]);
    await profile.selectOption("lean");
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ config: { profile: "lean" } });
  });

  test("leaving the profile alone sends no profile key at all", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-4", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Static provider").selectOption("capa_yara");
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies[0]).toMatchObject({ config: { static_provider: "capa_yara" } });
    expect((bodies[0] as { config: Record<string, unknown> }).config).not.toHaveProperty(
      "profile"
    );
  });
```

- [ ] **Step 3: Run both specs**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && npm run build
npx playwright test e2e/settings-agents.spec.ts e2e/job-submit-providers.spec.ts --project=chromium
```
Expected: every case passes, with zero page errors (the fixture asserts that).

- [ ] **Step 4: Commit**

```bash
git add apps/web/e2e/settings-agents.spec.ts apps/web/e2e/job-submit-providers.spec.ts \
  apps/web/e2e/mocks.ts
git commit -m "test(web): end-to-end coverage of the agent editors and the per-job profile"
```

- [ ] **Step 5: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 17: The documentation an operator reads, and the invariants stated as tests

**Files:**
- Create: `tests/servers/test_agent_parity.py`
- Modify: `README.md` (a section after "Connecting your own tool servers", line ~250); `.env.example` (an `AGENTS` block after the MCP servers block, line ~310); `docs/specs/2026-09-05-agent-composition-design.md:3` (status line); `tests/servers/test_server_security.py` (three composition invariants); `docs/specs/2026-09-04-tool-servers-design.md:31` (unchanged — verified, not edited)
- Test: `tests/servers/test_agent_parity.py`, `tests/servers/test_server_security.py`

**Interfaces:** none new.

- [ ] **Step 1: Write the parity and security tests**

```python
# tests/servers/test_agent_parity.py
"""The four ways "which agents exist" is answered must give one answer.

Spec §8 item 4. The class registry, the seeded definitions, the catalog's
``agent_roles`` choices and the job schema's profile validation each hold a
piece of the same fact; a drift between any two of them is a wrong dropdown or
a job that fails minutes after it was accepted.
"""

from __future__ import annotations

import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from maljan.agents.registry import AgentRegistry  # noqa: E402
from maljan.core.config import BUILTIN_AGENTS, BUILTIN_PROFILES, Settings  # noqa: E402


def test_the_built_in_definitions_are_the_registered_classes_plus_the_judge():
    registered = set(AgentRegistry().list_agents(include_disabled=True))
    assert set(BUILTIN_AGENTS) == registered | {"judge"}


def test_every_built_in_definition_names_its_own_role():
    definitions = Settings(_env_file=None).agents.definitions
    for key in BUILTIN_AGENTS:
        assert definitions[key].role == key


def test_the_default_profile_is_every_built_in_analyst_and_not_the_judge():
    profile = Settings(_env_file=None).agents.profiles["default"]
    assert set(profile.analysts) == set(BUILTIN_AGENTS) - {"judge"}
    assert profile.analysts == ["static", "dynamic", "network"]
    assert BUILTIN_PROFILES == ("default",)


def test_agent_roles_resolves_to_the_effective_definition_keys():
    from app.services.settings_catalog_api import _choice_sources

    sources = _choice_sources([], ["default"], ["static", "dynamic", "network", "judge", "x"])
    assert sources["agent_roles"] == ["static", "dynamic", "network", "judge", "x"]
    assert sources["profiles"] == ["default"]


def test_the_job_schemas_profile_accepts_exactly_the_effective_profile_keys():
    from app.services.agent_map import AGENT_PROFILES_KEY, effective_profiles

    assert set(effective_profiles({})) == set(BUILTIN_PROFILES)
    stored = {AGENT_PROFILES_KEY: {"lean": {"analysts": ["network"]}}}
    assert set(effective_profiles(stored)) == {"default", "lean"}


def test_a_definition_key_and_a_server_key_obey_the_same_rule():
    from maljan.core.config import AGENT_KEY_PATTERN, SERVER_KEY_PATTERN

    assert AGENT_KEY_PATTERN == SERVER_KEY_PATTERN
```

Append to `tests/servers/test_server_security.py`:

```python
def test_a_definition_cannot_widen_a_servers_exposure():
    """A ``ToolRef.name`` outside the allow-list is refused at save (spec §11)."""
    import sys
    from pathlib import Path

    _api = Path(__file__).resolve().parents[2] / "apps" / "api"
    if str(_api) not in sys.path:
        sys.path.insert(0, str(_api))
    from app.services.agent_map import AGENT_DEFINITIONS_KEY, AgentMapError, validate_agent_map

    stored = {
        "core.mcp.servers": {
            "mine": {"enabled": True, "transport": "stdio", "command": "x", "tools": ["grep"]}
        }
    }
    with pytest.raises(AgentMapError):
        validate_agent_map(
            {
                AGENT_DEFINITIONS_KEY: {
                    "x": {
                        "role": "generic", "prompt": "p",
                        "tools": [{"kind": "mcp", "server": "mine", "name": "rm_rf"}],
                    }
                }
            },
            stored=stored,
        )


def test_a_prompt_is_operator_text_and_reaches_the_snapshot_unmasked():
    """Prompts are not secrets; a masked prompt would make a report unreadable."""
    from app.worker.analysis_worker import settings_snapshot

    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"x": {"role": "generic", "prompt": "look for PROMPT-MARKER"}},
            "profiles": {"one": {"analysts": ["x"]}},
            "profile": "one",
        },
    )
    snap = json.dumps(settings_snapshot(cfg))
    assert "PROMPT-MARKER" in snap


def test_a_job_cannot_inline_an_agent_definition():
    """Per-job selection picks among operator-defined profiles only (spec §11)."""
    import sys
    from pathlib import Path

    _api = Path(__file__).resolve().parents[2] / "apps" / "api"
    if str(_api) not in sys.path:
        sys.path.insert(0, str(_api))
    from app.schemas.job import _KnownJobConfig

    assert "profile" in _KnownJobConfig.model_fields
    assert "definitions" not in _KnownJobConfig.model_fields
    assert "profiles" not in _KnownJobConfig.model_fields
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/servers -q`
Expected: PASS.

- [ ] **Step 3: Write the README section**

After "Connecting your own tool servers" (README line ~250), add:

```markdown
### Agents and profiles

The three analysts and the judge are configuration, not code. Settings →
Agents holds two maps:

**Agent definitions** — every agent Maljan can run, keyed by a short name.
Each carries a role (`static`, `dynamic`, `network`, `judge` or `generic`), a
prompt, the tool servers it receives and, for the static-flavoured roles, the
static provider it reads. The four built-ins are read-only apart from their
enabled switch; to change one, clone it. A clone keeps its source's class and
its ISR extraction, so a `static` clone pointed at radare2 is a real static
analyst reading r2 — the prompt is reassembled with radare2's fragment in the
middle and nothing else moves. A `generic` definition runs a plain ReAct
analyst with the prompt you write and the tools you tick.

**Profiles** — named, ordered sets of analysts. The order is the order they
run in on a single-slot local model. `default` is the three-analyst
architecture this project was measured on and is read-only; clone it to build
your own. A job may name a profile at submit time; without one it uses the
profile in the settings.

Two things to know before you build one. An agent's model is set at
`llm.agents.<name>.provider` / `.model`, not on the definition — one location,
so two copies cannot drift. And a definition can only narrow what a tool
server exposes: a tool outside that server's allow-list is refused when you
save, so adding an agent never widens the trust boundary the server section
above describes.

The **Resolve** button on a definition card shows exactly what that agent
would get — the assembled prompt's size and hash, the resolved tool names, the
model id and the static provider — without running a job or spending a token.
```

- [ ] **Step 4: Write the `.env.example` block**

After the `MCP__SERVERS__CUSTOM__AUTH_TOKEN` line (~line 309):

```bash
# =============================================================================
# AGENTS AND PROFILES
# =============================================================================
#
# Which analysts run, in what order. "default" is the three-analyst
# architecture this project was measured on: static, dynamic, network, then one
# judge. Profiles and agent definitions are ordinarily edited in the UI
# (Settings -> Agents) and stored as JSON; these variables are the way to set
# them without one.

AGENTS__PROFILE=default

# The two maps, as JSON. Built-in entries are re-seeded on load, so a map here
# only needs what you add. A built-in may only be disabled, never edited.
# AGENTS__PROFILES={"lean": {"label": "Lean", "analysts": ["static", "network"]}}
# AGENTS__DEFINITIONS={"static_r2": {"role": "static", "label": "Static (r2)", "static_provider": "r2"}}
#
# A generic agent needs a prompt; a built-in role leaves it null to keep the
# built-in one. Its model is set separately, at LLM__AGENTS__* — never here.
# AGENTS__DEFINITIONS={"strings": {"role": "generic", "prompt": "Review the strings for IOCs.", "tools": [{"kind": "mcp", "server": "strings", "name": null}]}}
```

- [ ] **Step 5: Update the spec status line and verify B's**

`docs/specs/2026-09-05-agent-composition-design.md`, line 3, first sentence becomes:

```markdown
Status: implemented on `feat/agent-composition` (companion plan: `docs/plans/2026-09-05-agent-composition.md`).
```

Verify that `docs/specs/2026-09-04-tool-servers-design.md:31` still reads correctly now that C has landed — it says C "reads this list as the default `tools` of its agent definitions and generalises it without replacing it", which is what `MCPServerConfig.agents` holding definition keys does. It needs no edit; confirm with `grep -n "sub-project C" docs/specs/2026-09-04-tool-servers-design.md` and leave the file untouched.

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check tests/servers && uv run ruff format --check tests/servers
git add README.md .env.example docs/specs/2026-09-05-agent-composition-design.md \
  tests/servers/test_agent_parity.py tests/servers/test_server_security.py
git commit -m "docs: how an operator composes agents and profiles, with the parity tests behind it"
```

- [ ] **Step 7: Controller sweep**

Run: `uv run pytest tests/unit tests/providers tests/agents tests/api tests/servers tests/integration tests/pipeline -q`
Expected: PASS.

---

### Task 18: The final gate

**Files:** none created or modified except a fix for whatever this task finds. A finding is fixed in place and the gate is re-run from the top; it is not deferred.

**Interfaces:** none new.

#### Mechanical gate

- [ ] **Step 1: Lint, format and types across the repository**

```bash
make lint format-check typecheck
```
Expected: clean.

- [ ] **Step 2: The whole Python suite**

```bash
uv run pytest tests/ -q
```
Expected: PASS, with the pinned test count unchanged from `dev` unless this branch genuinely added tests — in which case the count moves and `tests/evaluation/test_suite_count.json` is **not** re-pinned; the plan-wide constraint forbids re-measuring it.

- [ ] **Step 3: The evaluation corpus is untouched**

```bash
make facts && git status --short tests/evaluation/
git diff dev -- tests/evaluation/
```
Expected: both empty. `make facts` reads committed per-sample artifacts only — no LLM, no network — so a non-empty diff means a source change leaked into the measured corpus.

- [ ] **Step 4: The goldens still hold**

```bash
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS. These are the six files that say "the default profile is what it was".

- [ ] **Step 5: The web**

```bash
cd apps/web && npx tsc --noEmit && npm run lint && npm run build
```
Expected: clean, with the 10 pre-existing lint warnings and no new ones.

- [ ] **Step 6: Playwright on two browsers**

```bash
cd apps/web && npx playwright test e2e/settings-agents.spec.ts \
  e2e/settings-configuration.spec.ts e2e/job-submit-providers.spec.ts \
  --project=chromium --project=firefox
```
Expected: PASS on both. Run after `free -g` shows >= 6 GB available and with no `next dev` running (kill it by pidfile, never by `pkill -f`).

- [ ] **Step 7: Static application security**

```bash
make semgrep
```
Expected: no new findings.

#### Live scenarios (spec §12)

Recipe, unchanged from sub-project B: mock sandbox (`SANDBOX__PROVIDER=mock`), the local llama-server, and the CPU cap applied *before* the model starts. The report goes to the SDD workspace, not into this repository.

```bash
# Thermal + memory preconditions, in this order.
sudo cpupower frequency-set -u 2.4GHz
echo 1 | sudo tee /sys/devices/system/cpu/cpufreq/boost   # 0 = boost off
free -g                                                    # >= 6 GB available
scripts/llm_server.sh start && scripts/llm_server.sh wait
make dev-up
```

- [ ] **Step 8: (a) The default profile is today's run**

Submit one sample through the UI with every select left on "Inherit from settings". Confirm: the job completes; `run_summary.profile == {"name": "default", "analysts": ["static", "dynamic", "network"], "custom": []}`; the pipeline panel shows six steps with no custom badge; the report's static, dynamic and network sections read as they did before this branch. Compare the graph and the prompts against the goldens with the Step 4 command while the run is in flight — they are pure functions of the settings and need no job.

- [ ] **Step 9: (b) Four analysts, two providers, one custom agent**

In Settings → Agents: clone `static` to `static_r2` with static provider `r2`; create a generic `strings` agent with a prompt and one tool from a server bound to it; build a profile `wide` with `static`, `static_r2`, `network`, `strings`; set it active; apply. Submit a job. Confirm: all four analysts run in that order (the transcript's speaker order, and the worker log's roster event); the two custom ISRs reach the judge (`isr_reports` carries `static_r2` and `strings`) and the findings table shows rows with those domains; the pipeline panel shows four analyst steps with two custom badges; the worker logged two mirrors, one per provider, and the r2 analyst opened the r2 path.

- [ ] **Step 10: (c) The two refusals**

Disable the built-in `dynamic` definition, then try to save a profile that still lists it: the apply is refused with the message on the profile's own card. Then `POST /api/v1/jobs` with `config.profile = "ghost"`: 422, body naming `unknown profile 'ghost'` and listing the ones that exist.

```bash
curl -sS -X POST localhost:8000/api/v1/jobs \
  -H "Content-Type: application/json" -b "$COOKIE_JAR" \
  -d '{"sample_id": "'"$SAMPLE_ID"'", "config": {"profile": "ghost"}}' | head -5
```

- [ ] **Step 11: (d) The probe spends nothing**

With the llama-server request log open, press Resolve on the `strings` card. Confirm: the tool names and the prompt size appear; the llama-server log gains no request; no job row is created.

```bash
scripts/llm_server.sh status      # note the request count before
# press Resolve in the UI
scripts/llm_server.sh status      # unchanged
```

- [ ] **Step 12: (e) A reduced profile degrades legibly**

Set a profile of `network` alone and run a job. Confirm: the job completes; the graph has one analyst node; `run_summary.degradation_reasons` and the report's degraded-run banner say which analysts were absent rather than the report merely being thinner; the cascade reaches consensus on `network` alone (Task 8's rule), and the judge's confidence table shows `network` rather than `unknown`.

- [ ] **Step 13: Restore the box and write the report**

```bash
make dev-down
scripts/llm_server.sh stop
sudo cpupower frequency-set -u 5.0GHz   # or this host's stock maximum
echo 1 | sudo tee /sys/devices/system/cpu/cpufreq/boost
```

Write the live-verification report to the SDD workspace (not this repository), naming for each scenario: what was run, the job id, the observed `run_summary.profile`, and any deviation. A scenario that could not be run is recorded as not run, never as passed.

- [ ] **Step 14: Open the pull request**

```bash
git log --oneline dev..feat/agent-composition   # 17 commits, one per task
gh pr create --base dev --title "Agent composition: analysts as definitions, ensembles as profiles" \
  --body-file <the PR body written from this plan's Goal and the live report's findings>
```

The PR targets `dev` (the branch workflow since 2026-09-03) and is stacked on `feat/tool-servers`; retarget to `dev` once PR #6 merges. No AI attribution in the title, the body, or any commit.

---

## Verification of this plan

Every name a later task uses is defined in an earlier one:

| Name | Defined in | First used by |
| :-- | :-- | :-- |
| `graph_default.json`, `revision_prompt_network.json` | 1 | 7, 4 |
| `compiled_shape` | 1 | 7 |
| `TOPOLOGY_SOURCES`, `NAME_BRANCHES` | 1 | 7 |
| `AgentsConfig`, `AgentDefinition`, `ProfileDefinition`, `ToolRef` | 2 | 3, 6, 10, 11 |
| `AGENT_KEY_PATTERN`, `BUILTIN_AGENTS`, `BUILTIN_PROFILES` | 2 | 8, 11, 14, 17 |
| `_builtin_definitions`, `_builtin_profiles` | 2 | 10, 11 |
| `Settings.agents` | 2 | 3, 6, 8, 9, 10, 11, 12 |
| `ResolvedAgent`, `resolve_agent`, `aresolve_agent`, `builtin_prompt` | 3 | 5, 6, 9, 12 |
| `analyst_keys`, `current_analyst_keys`, `active_profile`, `static_provider_id_for` | 3 | 6, 7, 8, 9 |
| `tools_for_ref`, `atools_for_ref`, `AGENT_TOOL_UNAVAILABLE_REASON` | 3 | 3, 12 |
| `JUDGE_VERDICT_SYSTEM` | 3 | 3 |
| `get_static_provider(provider_id)` | 3 (signature), 6 (behaviour) | 3, 6, 9 |
| `prompt_to_messages`, `revision_messages`, `_REVISION_ISR_FRAMING` | 4 | 5 |
| `_NETWORK_REVISE_SYSTEM` | 4 | 4 |
| `ConfigurableAnalyst` | 5 | 6 |
| `ServiceContainer.analyst_keys`, `.active_profile`, `.agent_role` | 6 | 7, 8, 9 |
| `state["static_sample_paths"]` | 9 | 7 (reader), 9 (writer) |
| `profile_static_providers` | 9 | 9 |
| `effective_profiles`, `effective_definitions` | 10 | 11, 17 |
| `AGENT_DEFINITIONS_KEY`, `AGENT_PROFILES_KEY`, `AGENT_PROFILE_KEY` | 10 | 11, 12, 17 |
| `AgentMapError`, `validate_agent_map` | 11 | 17 |
| `_choice_sources`, `resolved_catalog(profiles=, agents=)` | 11 | 17 |
| `ProbeResult.details`, `probe_agent`, `run_agent_probe` | 12 | 12, 14 |
| `AgentDefinitionEntry`, `ProfileEntry`, `ToolRefEntry`, `AgentProbeDetails` | 13 | 14, 15 |
| `api.probeAgent` | 13 | 14 |
| `AgentDefinitionsEditor`, `BUILTIN_AGENT_KEYS`, `EMPTY_DEFINITION` | 14 | 15 (FieldRow), 16 |
| `settings-agents.spec.ts` | 14 | 15, 16 |
| `ProfilesEditor`, `analystSteps`, `FALLBACK_PALETTE`, `useProviderChoices().profiles` | 15 | 16 |

Task 7 reads `state["static_sample_paths"]` before Task 9 writes it; the read is written with `(state.get("static_sample_paths") or {})` and falls through to `static_sample_path`, so Task 7 is green on its own and Task 9 fills the dict in.
