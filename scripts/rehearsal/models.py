"""What the stub knows about each model it serves: the facts the real APIs state.

* A model whose Anthropic Models API description is stored here
  (``model_descriptions/<id>.json``, the API's own answer as recorded for
  Claude Haiku 5.5) is described with exactly that answer: its window, its
  output cap, the effort levels and thinking types it takes.
* Any other model takes its window and output cap from the repository's
  vendored model table (``data/model_context_windows_v1.json``), the figures
  its vendor documents, matched by the longest family prefix; a model the
  table does not name gets 200,000 / 64,000 and no capability statement, and
  the Models API answers 404 for it, as the real one does for an id it does
  not know. A window nothing documents is marked so (``window_documented``):
  the gate refuses to guess one and asks for ``--window``.
* Sampling: a model in the table's ``fixed_sampling`` rows refuses
  ``temperature``, ``top_p`` and ``top_k``; thinking blocks of a model in its
  ``prefix_bound_thinking`` rows are bound to everything before them.

Nothing here reads the product's code: the facts are data, so a product that
reads them wrongly is a request the stub refuses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_TABLE = _HERE.parents[1] / "data" / "model_context_windows_v1.json"
_DESCRIPTIONS = _HERE / "model_descriptions"

DEFAULT_WINDOW = 200_000
DEFAULT_OUTPUT = 64_000

# The shortest prompt prefix each family caches, in tokens, longest prefix
# first, from the vendors' own pages: Anthropic's prompt-caching page
# (https://platform.claude.com/docs/en/build-with-claude/prompt-caching,
# "Cache limitations") gives 4,096 for Claude Opus 4.5 and Haiku 4.5, 2,048
# for the Haiku 3 family and 1,024 for the other Claude models; DeepSeek's
# context-caching page caches in 64-token units; OpenAI's caches from 1,024.
# Claude Haiku 5.5's figure is in neither the page as recorded nor its stored
# Models API answer; it is taken as its line's latest documented one, 4,096.
MIN_CACHEABLE: dict[str, int] = {
    "claude-haiku-5": 4096,
    "claude-haiku-4-5": 4096,
    "claude-opus-4-5": 4096,
    "claude-3-haiku": 2048,
    "claude-3-5-haiku": 2048,
    "claude-": 1024,
    "deepseek": 64,
    "": 1024,
}


@dataclass
class ModelFacts:
    """One model as the stub serves it."""

    id: str
    window: int = DEFAULT_WINDOW
    max_output: int = DEFAULT_OUTPUT
    description: dict[str, Any] | None = None
    fixed_sampling: bool = False
    prefix_bound: bool = False
    slots: int = 1
    min_cacheable: int = 1024
    # Whether a vendor documents the model: a stored description or a row of
    # the vendored table. An id nothing documents is answered 404.
    known: bool = False
    # Whether the window is a documented one (a stored description, a window
    # row of the table, or one the run named) rather than the stub's default.
    window_documented: bool = False
    # Effort levels the description says the model takes; ``None`` states nothing.
    effort_levels: tuple[str, ...] | None = None
    thinking_types: dict[str, bool] = field(default_factory=dict)

    def takes_effort(self, level: str) -> bool:
        return self.effort_levels is None or level in self.effort_levels

    def models_api_answer(self) -> dict[str, Any] | None:
        """The Models API's answer for this model, or ``None`` for an id it does not know."""
        return dict(self.description) if self.description is not None else None


@lru_cache(maxsize=1)
def _table() -> dict[str, Any]:
    try:
        return dict(json.loads(_TABLE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def _longest_prefix(model: str, keys: Any) -> str:
    matches = [str(k) for k in keys if not str(k).startswith("_") and model.startswith(str(k))]
    return max(matches, key=len) if matches else ""


def _description(model: str) -> dict[str, Any] | None:
    path = _DESCRIPTIONS / f"{model}.json"
    if not path.is_file():
        return None
    return dict(json.loads(path.read_text(encoding="utf-8")))


def facts_for(model: str, *, window: int | None = None, slots: int = 1) -> ModelFacts:
    """The facts the stub serves ``model`` with; ``window`` overrides the documented one."""
    name = str(model or "").strip().lower()
    table = _table()
    facts = ModelFacts(id=name, slots=slots)
    facts.min_cacheable = MIN_CACHEABLE[
        max((k for k in MIN_CACHEABLE if name.startswith(k)), key=len)
    ]
    windows = table.get("windows") or {}
    key = _longest_prefix(name, windows)
    if key:
        facts.window = int(windows[key])
        facts.window_documented = True
    outputs = table.get("max_output") or {}
    key = _longest_prefix(name, outputs)
    if key and isinstance(outputs[key], dict):
        facts.max_output = int(outputs[key].get("tokens") or DEFAULT_OUTPUT)
    facts.fixed_sampling = bool(_longest_prefix(name, table.get("fixed_sampling") or {}))
    facts.prefix_bound = bool(_longest_prefix(name, table.get("prefix_bound_thinking") or {}))
    facts.known = any(
        _longest_prefix(name, table.get(section) or {})
        for section in (
            "windows",
            "max_output",
            "prices",
            "fixed_sampling",
            "prefix_bound_thinking",
        )
    )
    described = _description(name)
    if described is not None:
        facts.known = True
        facts.description = described
        if described.get("max_input_tokens"):
            facts.window = int(described["max_input_tokens"])
            facts.window_documented = True
        facts.max_output = int(described.get("max_tokens") or facts.max_output)
        capabilities = described.get("capabilities") or {}
        effort = capabilities.get("effort") or {}
        if isinstance(effort, dict) and "supported" in effort:
            facts.effort_levels = (
                tuple(k for k, v in effort.items() if isinstance(v, dict) and v.get("supported"))
                if effort.get("supported")
                else ()
            )
        types = ((capabilities.get("thinking") or {}).get("types")) or {}
        facts.thinking_types = {
            str(k): bool(v.get("supported")) for k, v in types.items() if isinstance(v, dict)
        }
    if window:
        facts.window = int(window)
        facts.window_documented = True
        if facts.description is not None:
            facts.description = {**facts.description, "max_input_tokens": int(window)}
    return facts


def undocumented_windows(models: Any, window: int | None = None) -> list[str]:
    """The models among ``models`` whose window nothing documents, ``window`` named or not."""
    if window:
        return []
    names = sorted({str(m).strip() for m in models if str(m or "").strip()})
    return [name for name in names if not facts_for(name).window_documented]
