"""I5: ``settings.mcp.ghidra`` / ``settings.mcp.cape`` are a read-only view.

``tests/evaluation/eval_dynamic_vs_static.py``, ``eval_sink_hint_ablation.py``,
``eval_function_hash_attribution.py`` and ``eval_sink_hint_frequency.py`` all
read ``cfg.mcp.ghidra.*`` — they predate the provider layer and the plan-wide
constraint forbids editing ``tests/evaluation/**``, so the fix lives entirely
on the ``Settings``/``MCPConfig`` side: a deprecated compatibility view,
populated by a ``model_validator(mode="after")`` on ``Settings``, that hands
back the *same* ``MCPServerConfig`` objects as ``settings.static.ghidra`` and
``settings.sandbox.cape2.mcp`` rather than copies.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from maljan.core.config import Settings


def test_the_ghidra_view_is_the_same_object_as_static_ghidra():
    settings = Settings(_env_file=None)
    assert settings.mcp.ghidra is settings.static.ghidra


def test_the_cape_view_is_the_same_object_as_sandbox_cape2_mcp():
    settings = Settings(_env_file=None)
    assert settings.mcp.cape is settings.sandbox.cape2.mcp


def test_a_mutation_through_either_name_is_visible_through_the_other():
    settings = Settings(_env_file=None)
    settings.static.ghidra.url = "http://ghidra.example:8089"
    assert settings.mcp.ghidra.url == "http://ghidra.example:8089"

    settings.mcp.cape.url = "http://cape-mcp.example:9004/mcp/"
    assert settings.sandbox.cape2.mcp.url == "http://cape-mcp.example:9004/mcp/"


def test_two_of_the_scripts_import_clean_without_an_attributeerror():
    """The regression this whole finding is about, for the two scripts where
    ``cfg.mcp.ghidra`` is read inside a function body: before the fix this
    raised ``AttributeError: 'MCPConfig' object has no attribute 'ghidra'``
    the first time that function ran; nothing else in the repo calls it, so
    importing the module (which does not call it) plus the identity tests
    above is the coverage available without executing the sweep itself.
    Both modules guard their real work behind ``if __name__ == "__main__":``,
    so a plain import is side-effect free.
    """
    for name in ("eval_dynamic_vs_static", "eval_sink_hint_ablation"):
        importlib.import_module(f"tests.evaluation.{name}")


def test_the_other_two_scripts_read_cfg_mcp_ghidra_at_module_scope():
    """``eval_function_hash_attribution.py`` and ``eval_sink_hint_frequency.py``
    have no ``__main__`` guard: importing them unconditionally runs their
    whole measurement sweep at import time, including a real ``docker
    restart maljan-ghidra-mcp`` and network calls against a live Ghidra MCP
    server before the module body even finishes executing. That is by
    design for a script meant to be invoked as ``python eval_x.py N`` from a
    shell, never imported — but it means this test must not actually import
    them, on this machine or in CI, without restarting real infrastructure.

    Both read the exact expression ``get_settings().mcp.ghidra`` (one via a
    ``CFG = get_settings(); G = CFG.mcp.ghidra`` alias) at module scope,
    which is exactly what the identity tests above already exercise; this
    test additionally confirms — by source inspection, not execution — that
    the expression these two scripts evaluate is still ``mcp.ghidra`` and
    not something the fix silently missed.
    """
    import ast

    root = Path(__file__).resolve().parents[3] / "tests" / "evaluation"
    for name in ("eval_function_hash_attribution.py", "eval_sink_hint_frequency.py"):
        source = (root / name).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=name)
        attrs = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "ghidra"
        }
        assert "ghidra" in attrs, f"{name} no longer reads .ghidra; re-check this finding"

    # And directly exercise the exact expression both scripts evaluate,
    # without their side-effecting module bodies.
    settings = Settings(_env_file=None)
    assert settings.mcp.ghidra is settings.static.ghidra
