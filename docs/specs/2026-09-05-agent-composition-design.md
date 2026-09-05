# Agent composition design — Maljan sub-project C

Status: approved design, not yet implemented. Builds on sub-project A (`docs/specs/2026-09-03-provider-layer-design.md`, PR #5 into `dev`) and sub-project B (`docs/specs/2026-09-04-tool-servers-design.md`, PR #6). Branch `feat/agent-composition` is stacked on `feat/tool-servers` until #5 and #6 merge. Companion plan: `docs/plans/2026-09-05-agent-composition.md` (written after this spec is reviewed).

## 1. Problem

After A and B an operator can choose a static provider and a sandbox provider, connect any number of MCP tool servers and bind each one to the analysts that should receive it. The set of analysts itself is still fixed in code: `AgentRegistry.discover_agents()` imports exactly three analyst modules (`src/maljan/agents/registry.py:61-63`), the graph is built from that registry (`src/maljan/pipeline/builder.py:63`), the judge computes its degradation set from a literal tuple (`src/maljan/pipeline/nodes.py:1322`), and the web pipeline panel hard-codes four step ids. An operator who wants a fourth analyst (a strings analyst on an r2 server, a YARA-focused reviewer, a second static analyst on a different provider) or who wants to run a reduced ensemble has to edit Python.

Sub-project C closes that gap: analysts are declared as agent definitions, named profiles pick an ordered set of them, the graph is built from the active profile, and both are edited from the settings UI and selectable per job. The default profile is today's architecture byte for byte.

## 2. Decisions

| Question | Decision | Reason |
| :-- | :-- | :-- |
| How far can composition go | N analysts plus one fixed judge; the graph skeleton (analysts → negotiation ↔ revision → judge → report) is fixed | The negotiation loop is the paper's contribution; a free-form DAG makes the default-profile conformance argument unverifiable |
| Representation | `agents.definitions` (name → definition) and `agents.profiles` (name → ordered analyst list), `agents.profile` selects the active one | The interface frozen in A §13; mirrors B's `mcp.servers` map so its validation, editor and storage patterns are reused |
| Built-ins | Definitions `static`, `dynamic`, `network`, `judge` and profile `default` are seeded in code and read-only; an operator clones them | Byte-identity of the default profile is a property of unmodifiable built-ins, the same rule B applies to built-in servers |
| Custom analyst behaviour | One `ConfigurableAnalyst` class parametrised by its definition; built-in roles keep their classes | Built-in classes carry provider-specific ISR extraction the goldens pin; a generic class carries none of that risk |
| Prompt model | `prompt: str | null`; null on a built-in role means the built-in prompt (HEAD + provider fragment + TAIL), required on `generic` | Byte-identity for built-ins, full ownership for custom agents |
| LLM per agent | Not stored on the definition; the editor binds to `llm.agents.<name>.*` | A froze that location; two copies of the same setting would drift |
| Providers per agent | `static_provider: str | null` only (null = global `static.provider`); no per-agent sandbox | The sandbox stage is one detonation per job owned by `MaljanApp`; two static analysts on two providers is the real use case |
| `ToolRef.kind` | `mcp` and `provider` only; A's sketch listed `builtin` too | No in-process tool exists today: every tool comes from an MCP server or a provider. Recording the deviation here keeps A §13 honest |
| Role vocabulary for server binding | `MCPServerConfig.agents` entries are definition keys; `choices_from: agent_roles` resolves to definition keys | B's spec said C "reads this list as the default tools of its agent definitions and generalises it without replacing it" |
| Per-job selection | `profile` in the job config, validated at submit against known profiles | Same shape as A's `static_provider` / `sandbox_provider` job overrides |
| Agent probe | Dry resolution (prompt, tools, LLM id), no LLM call | An operator sees what an agent would get before running a job; a probe that spends tokens is a job, not a probe |

## 3. Settings shape

### 3.1 `AgentsConfig` at `Settings.agents`

```python
AnalystRole = Literal["static", "dynamic", "network", "generic"]
AGENT_KEY_PATTERN = SERVER_KEY_PATTERN            # ^[a-z][a-z0-9_-]{0,31}$, shared with B
BUILTIN_AGENTS = ("static", "dynamic", "network", "judge")
BUILTIN_PROFILES = ("default",)

class ToolRef(BaseModel):
    kind: Literal["mcp", "provider"]
    server: str | None = None     # mcp: key in mcp.servers (required)
    name: str | None = None       # mcp: one tool of that server; None = the server's allow-listed set
                                  # provider: None (the agent's static provider's tool set)

class AgentDefinition(BaseModel):
    role: Literal["static", "dynamic", "network", "judge", "generic"]
    label: str = ""
    prompt: str | None = None
    tools: list[ToolRef] = []
    static_provider: str | None = None
    enabled: bool = True

class ProfileDefinition(BaseModel):
    label: str = ""
    analysts: list[str]           # ordered definition keys; order is the sequential run order

class AgentsConfig(BaseModel):
    profile: str = "default"
    profiles: dict[str, ProfileDefinition]      # seeded with "default"
    definitions: dict[str, AgentDefinition]     # seeded with the four built-ins
```

Seeding follows B's `_builtin_servers()`: a `model_validator(mode="after")` inserts every missing built-in key with its built-in value, so an operator's stored map only ever contains what they added or disabled. Built-in values:

| key | role | prompt | tools | static_provider |
| :-- | :-- | :-- | :-- | :-- |
| `static` | static | null | `[]` | null |
| `dynamic` | dynamic | null | `[]` | null |
| `network` | network | null | `[]` | null |
| `judge` | judge | null | `[]` | null |
| profile `default` | | | `analysts: ["static", "dynamic", "network"]` | |

The built-in analyst order is the order `AgentRegistry.list_agents()` returns today (the graph snapshot in §8 pins it).

`judge` is a definition so that the judge's LLM and tool servers keep one editing surface with the analysts; it can never appear in a profile's `analysts` list and cannot be cloned (a `generic` definition cannot take the judge's place; the skeleton has exactly one judge).

### 3.2 Validation (in `Settings`, repeated by the API's `save`)

- Keys match `AGENT_KEY_PATTERN`; `agents.profile` names an existing profile.
- Built-in definitions and the `default` profile are compared field by field against their seeds; any difference is rejected with `"'<key>' is built in; clone it to change it"`. `enabled: false` is the one permitted edit on a built-in analyst definition. A profile that lists a disabled analyst is rejected, with one exception: a built-in profile (immutable, so it cannot drop the member) is tolerated while it is not the active `agents.profile`; a per-job `profile` override naming such a profile is refused at submit.
- Every `analysts` entry names an existing, enabled definition whose role is not `judge`; no duplicates; at least one analyst.
- `role == "generic"` requires a non-empty `prompt`; built-in roles accept a prompt (that is how a clone differs from its source).
- `ToolRef(kind="mcp")` requires `server` present in `mcp.servers`; when `name` is set and the server carries an allow-list (`tools` not null), `name` must be in it, and when the server exposes all tools (`tools` null, built-ins only) the name is checked at resolution and a miss is a degradation reason, not a save error; `ToolRef(kind="provider")` requires `server is None and name is None`.
- `static_provider`, when set, is a registered static provider id.
- `MCPServerConfig.agents` entries must be definition keys (replacing B's `AgentRole` literal, which becomes `str` validated against the map).
- The active profile of a job must resolve to at least one analyst with a usable configuration, otherwise the job fails at start with a legible error in `run_summary` (not silently with zero analysts).

### 3.3 Legacy names

None are renamed. `llm.agents.<name>.*` and the top-level `react_agent_*_overrides` dicts keep their keys; they simply accept custom definition names now. No alembic data migration is needed; a schema migration is not needed either (definitions live in the existing settings-override rows as one JSON value per map, like `core.mcp.servers`).

## 4. Effective tool set and prompt of an agent

`resolve_agent(definition_key, container) -> ResolvedAgent` in `src/maljan/agents/composition.py`:

```
prompt      = definition.prompt if not None else builtin_prompt(role)      # role in built-ins
tools       = registry.tools_for(definition_key, job_key)                     # registry half; built-in roles keep opening
                                                                              # their provider's tools lazily in the analyst
            + provider_tools(static_provider)  # generic only, when a ToolRef(kind=provider) exists                    # servers whose agents list names this key (B)
            + [tool for ref in definition.tools if ref.kind == "mcp"
               for tool in registry.tools_for_ref(ref, job_key)]             # explicit references
llm         = container.get_agent_llm(definition_key)                        # llm.agents.<key> or the global expert LLM
static_prov = definition.static_provider or settings.static.provider
```

Rules:

- `builtin_prompt("static")` is `_ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL` with the agent's resolved static provider; `builtin_prompt("dynamic")` returns the frozen `dynamic_analyst._ISR_SYSTEM` (the analyst has always used that constant, never the configured sandbox's fragment, and there is no per-agent sandbox); `network` uses its constant and `judge` uses `JUDGE_VERDICT_SYSTEM`, extracted byte for byte from the inline literal in `give_verdict`. A clone of `static` with `static_provider: r2` and `prompt: null` therefore gets the r2 fragment: the same assembly, a different middle.
- Duplicate tools (a server both bound by `agents` and referenced by a `ToolRef`) are de-duplicated by name; the collision prefixing from B applies before de-duplication.
- `ResolvedAgent.tools` is the registry half (bound servers plus explicit references). Built-in roles keep opening their provider's tools lazily inside the analyst node, as today, so resolution (and the probe) never launches Ghidra or opens a provider on the graph loop. Provider tools for a `generic` agent come only through an explicit `ToolRef(kind="provider")`, resolved there; a generic agent with no references and no bound servers runs tool-less (the no-tools path in `BaseAnalyst.execute_tool_loop` already exists).
- Resolution is per job and per agent; opening servers still goes through B's `ServerRegistry` on the agent's loop, so the loop-binding rules of B hold unchanged.

## 5. Graph construction

`build_graph(container)`:

- Analyst order comes from `container.active_profile().analysts` (the job's `agents.profile` after per-job overrides), not from `AgentRegistry.list_agents()`. `AgentRegistry` stays as the class registry for built-in roles; its `list_agents()` is no longer a topology source, and the two other call sites (`nodes.py:656`, `nodes.py:803`, `nodes.py:959`, `container.py:147`) read the profile too.
- Node names stay `f"{key}_analyst"`; `llm.parallel_analysts` keeps its two meanings (fan-out shape in the builder, gather versus loop in the revision node).
- `container.get_agent(key)` looks up the definition: built-in role → `AgentRegistry.create(role, llm)` with the definition's key as the agent `name` (so a clone `static_r2` runs `StaticAnalyst` under the name `static_r2`), `generic` → `ConfigurableAnalyst(definition, llm, name=key)`. Both receive `_container`, ledgers and, new, their `ResolvedAgent`.
- `StaticAnalyst._provider()` and the mirror step in the worker use the agent's resolved static provider; with two static analysts on two providers the worker mirrors the sample once per provider that `needs_sample_mirror`, keyed by provider id (`state["static_sample_path"]` becomes a per-provider dict internally with the existing key preserved for the global provider, so A's contract holds).
- The judge's `_ANALYST_AGENTS`, `run_summary.py:314,319`, `ttp_cascade.py:143` and `judge_agent.py:1010` derive their analyst set from the profile via one helper `analyst_keys(container)`; the `yara`/`sigma` synthetic domains stay appended where they are today.
- `run_summary` gains `profile: {name, analysts: [...], custom: [...]}`; `settings_snapshot` already includes `agents.*` through `public_snapshot`.

## 6. `ConfigurableAnalyst`

`src/maljan/agents/configurable_analyst.py`, `class ConfigurableAnalyst(BaseAnalyst)`:

- `analyze(data)` runs the ReAct loop with `[("system", prompt), ("human", data)]`, `revise(...)` with the same system prompt plus the shared revision framing that `NetworkAnalyst.revise` uses (extracted to `base_agent.py` as `revision_messages(...)` so both call one function; `NetworkAnalyst`'s output stays byte-identical, pinned by a new golden built from a captured revision prompt).
- `analyze_isr` / `revise_isr` use the base-class `_text_to_isr` wrapping, with `domain = self.name`; `AgentISR.domain` already accepts `str`.
- Tools, prompt and LLM come from its `ResolvedAgent`; it does not read `mcp.servers` or providers itself.
- Degradation policy: a custom analyst never fails a job. A failed tool server or provider adds `agent '<key>': <reason>` to `degradation_reasons` and the agent runs with what remains, the same rule B applies to custom servers.
- Chunked, view and tiered paths from `BaseAnalyst` work unchanged because they call `analyze_isr`.

## 7. Consumers

- Deterministic report sections (`reporting/builder.py` static/dynamic/network) are built from extractors and stay as they are.
- `AgentFinding.domain` already takes the ISR domain or the agent name; custom analysts appear as rows with their key.
- Web `PipelinePanel` builds its analyst steps from `run_summary.profile.analysts` (fallback to the four ids when absent, so old reports render as before); `TranscriptPanel.AGENT_COLORS` gains a deterministic fallback palette keyed by name hash. `analysis/[id]/pipeline` shows a "custom" badge on non-built-in analysts.
- WebSocket `agent_progress` events are already keyed by agent name.

## 8. Invariants and tests

The default profile with the default settings is today's system:

1. **Graph snapshot golden** (`tests/pipeline/test_graph_snapshot.py`, fixture `tests/fixtures/golden/graph_default.json`): node names, edges (including the conditional edge's path map) and the analyst order for `parallel_analysts` false and true, captured on `dev`, compared against `build_graph` output on this branch.
2. **Prompt byte-identity** (`tests/agents/test_prompt_byte_identity.py`) extended: `resolve_agent("static")`, `("dynamic")`, `("network")`, `("judge")` under `Settings(_env_file=None)` return the pinned prompts; `resolve_agent("static").tools` under the mock container equals today's registry half (`ServerRegistry.tools_for("static", ...)`), the provider half being unchanged code.
3. **Revision prompt golden**: `NetworkAnalyst.revise` message list before and after the extraction of `revision_messages` is identical (captured fixture).
4. **Parity**: built-in definition keys == `AgentRegistry.list_agents(include_disabled=True)` ∪ `{"judge"}`; `choices_from` `agent_roles` returns the effective definition keys; job-schema `profile` accepts exactly the effective profile keys at submit time.
5. **Consumers**: with the default profile `run_summary.profile == {"name": "default", "analysts": ["static", "dynamic", "network"], "custom": []}` and every other `run_summary` key is unchanged against a captured run (the existing run-summary fixture).
6. `tests/evaluation/**` byte-identical to `dev` (CI gate); `make facts` byte-identical; the pinned test-count artefact is untouched.

Unit coverage: validators (each rule in §3.2 has a rejecting and an accepting case), `resolve_agent` (de-duplication, provider fragment with a clone on r2, generic without tools), `ConfigurableAnalyst` with a fake LLM (analyze, revise, ISR domain, degradation), worker mirror per provider, per-job `profile` override folding.

## 9. Settings UI

- Group `agents` (renamed from "Agent timeouts and budgets" to "Agents"; the existing `react_agent_*` leaves stay in it, after the two editors).
- `agents.profile`: an enum widget with `choices_from: "profiles"`, `order: -1`.
- `agents.definitions`: `editor: "agent_definitions"`. Cards per definition: role badge, label, enabled switch, prompt textarea (disabled on built-ins with the resolved built-in prompt shown read-only), LLM fields bound to `llm.agents.<key>.{provider, model, temperature}`, static provider select (`choices_from: static_providers`, hidden for dynamic/network/judge), tool references (servers from `mcp.servers` with their manifest checkboxes as in B's editor, plus a "provider tools" toggle for generic), and a Clone button that stages a copy under a new key with the source's resolved prompt filled in. Built-ins show a lock and only the enabled switch.
- `agents.profiles`: `editor: "profiles"`. Cards per profile: label, ordered analyst list (move up/down, add from enabled analyst definitions, remove), "Set active" which stages `agents.profile`, Clone. `default` is locked.
- Probe button per definition card: "Resolve" → `POST /settings/test/agent?name=<key>` (§10).
- Job submission: a "Profile" select next to the provider selects, default "from settings" (key absent → payload unchanged).
- e2e `settings-agents.spec.ts`: clone static to `static_r2` with provider r2, create a generic analyst with a prompt and one server tool, build a profile with the four, set it active, apply; built-in lock; submit a job with a profile.

## 10. API

- `PATCH /settings` accepts `core.agents.definitions`, `core.agents.profiles`, `core.agents.profile` as JSON leaves; validation errors are keyed per definition/profile as B keys server errors.
- `POST /settings/test/agent?name=<key>` (admin): builds a container from the staged settings, runs `resolve_agent` with servers opened in probe mode (5 s budget, B's probe path), and returns `ProbeResponse` with `tools` = resolved tool names, `details` = `{prompt_chars, prompt_sha256, llm: {provider, model}, static_provider, servers: [{key, tools, status}]}`. Never calls the LLM.
- `POST /jobs` `config.profile: str | None`; unknown profile → 422 `"unknown profile '<name>'"`; folded into `agents.profile` by `build_job_settings`.
- `GET /settings/catalog` `choices_from` gains `profiles`; `agent_roles` now returns effective definition keys.

## 11. Security

- Prompts are operator-authored text stored in settings rows; they are not secrets and are exported as is. They are rendered in the UI as plain text, never as HTML.
- The agent probe runs no LLM call and opens servers with B's probe budget and child reaping; it is admin-only like the other probes.
- A custom analyst's tool access is bounded by B's allow-lists; a `ToolRef.name` outside the server's allow-list is rejected at save, so a definition cannot widen a server's exposure.
- Per-job `profile` selects among operator-defined profiles only; a job cannot inline a definition.

## 12. Live verification (final gate)

On this branch with the mock sandbox, local llama and the CPU cap: (a) default profile: the job completes, `run_summary.profile` is the default triple, graph and prompts byte-identical, report sections as before; (b) a profile with `static`, `static_r2` (clone on r2), `network` and a `generic` "strings reviewer" bound to the r2 server: all four analysts run in order, the custom ISRs reach the judge and the findings table, the pipeline panel shows four steps with two custom badges; (c) a profile naming a disabled definition is refused at save, a job naming an unknown profile is refused with 422; (d) the agent probe on the generic analyst lists its resolved tools without spending tokens (llama request log empty); (e) a reduced profile with only `network` runs and the judge's degradation reasons name the missing built-ins.

## 13. Out of scope

- Free-form graph topologies, a second judge, or custom negotiation logic.
- Per-agent sandbox providers.
- In-process (`builtin`) tools; the `ToolRef.kind` literal grows when one exists.
- Profile import/export as files (the settings export already carries them as JSON).
- Migrating the raw-CAPE consumers to `SandboxReport` (unchanged since A; tracked separately).

## 14. Risks

- **Topology sources**: five call sites read `list_agents()` today; missing one leaves a node set that disagrees with the profile. The graph snapshot golden and a grep gate (`list_agents()` allowed only in the registry and the parity test) close this.
- **Byte identity through clones**: a built-in run under a different name changes only `name`; any code that branches on `self.name == "static"` would diverge. A grep for `name ==` in `agents/` and `pipeline/` is part of the first task.
- **Two static providers per job**: mirror and function-hash paths were written for one provider; the per-provider dict in §5 keeps the single-provider path identical and adds the second only when a profile asks for it.
- **UI size**: two composite editors plus job-form changes; the e2e spec is the gate, run once per task as B did.
- **Memory and thermal**: the live gate runs four analysts on one llama slot sequentially; the same recipe as B (32k context, 6 GB floor, 2.4 GHz cap).
