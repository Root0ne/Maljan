"""No module outside an LLM provider's own adapter decides anything by a provider's name.

Every fact the platform needs about a provider is declared on its adapter
(``maljan.llm.provider_base``) and asked through ``facts_of``. A comparison, a
membership test or a table keyed by a provider's name anywhere else is a
behaviour a provider registered tomorrow would not get, so this test reads
every module of the core and the API and refuses one.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app")

# The names of the shipped providers and the chat-model types their clients report.
PROVIDER_NAMES = frozenset(
    {
        "openai",
        "anthropic",
        "ollama",
        "gemini",
        "openai-chat",
        "anthropic-chat",
        "chat-ollama",
        "chat-google-generative-ai",
    }
)

# A provider's own adapter answers for itself by its own name. The answered-tool
# map in ``tool_replies`` is keyed by request wire format, and each adapter
# names the format it speaks when it builds its client.
OWN_MODULES = frozenset(
    {
        "src/maljan/llm/openai_provider.py",
        "src/maljan/llm/anthropic_provider.py",
        "src/maljan/llm/ollama_provider.py",
        "src/maljan/llm/gemini_provider.py",
        "src/maljan/llm/tool_replies.py",
    }
)


def _names(node: ast.AST) -> list[str]:
    """The provider names a literal holds: a string, or a tuple, list or set of them."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value] if node.value in PROVIDER_NAMES else []
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return [name for element in node.elts for name in _names(element)]
    return []


def _decisions(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                found.extend((node.lineno, name) for name in _names(side))
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if key is not None:
                    found.extend((node.lineno, name) for name in _names(key))
    return found


def test_no_shared_module_compares_or_tables_a_provider_name():
    offenders: list[str] = []
    for source in SOURCES:
        for path in sorted(source.rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative in OWN_MODULES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            offenders.extend(f"{relative}:{line} {name!r}" for line, name in _decisions(tree))
    assert offenders == [], "\n".join(offenders)


def test_the_guard_sees_a_comparison_and_a_table():
    tree = ast.parse('x = provider == "ollama"\ny = {"gemini": 1}\nz = p in ("openai",)')
    assert [name for _line, name in _decisions(tree)] == ["ollama", "gemini", "openai"]
