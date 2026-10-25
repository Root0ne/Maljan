"""A tool rebuilt around another keeps offering the server's argument names.

LangChain offers a structured tool's model a copy of its argument model that
drops every alias, so an argument held under an internal field name
(``agents.server_names``) would be offered under that name. Only
``ServerNamedTool`` offers the server's. A plain ``StructuredTool`` rebuilt
with another tool's ``args_schema`` quietly turned those arguments back into
internal names (T-360), so no module may build one.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "maljan"


def _reads_args_schema(node: ast.AST) -> bool:
    """Whether ``node`` reads some object's ``args_schema``."""
    return any(
        (isinstance(n, ast.Attribute) and n.attr == "args_schema")
        or (isinstance(n, ast.Constant) and n.value == "args_schema")
        for n in ast.walk(node)
    )


def _borrowed(scope: ast.AST) -> set[str]:
    """The names ``scope`` binds to another tool's ``args_schema``."""
    names: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and _reads_args_schema(node.value):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
            if isinstance(node.target, ast.Name) and _reads_args_schema(node.value):
                names.add(node.target.id)
    return names


def offenders(source: str, where: str = "<source>") -> list[str]:
    """Each ``StructuredTool.from_function`` in ``source`` given another tool's ``args_schema``."""
    found: list[str] = []
    tree = ast.parse(source)
    scopes = [n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        scopes += [n for n in cls.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    for scope in scopes:
        borrowed = _borrowed(scope)
        for node in ast.walk(scope):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "from_function"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "StructuredTool"
            ):
                continue
            for kw in node.keywords:
                if kw.arg != "args_schema":
                    continue
                value = kw.value
                if _reads_args_schema(value) or (
                    isinstance(value, ast.Name) and value.id in borrowed
                ):
                    found.append(f"{where}:{node.lineno}")
    return found


def test_no_tool_is_rebuilt_around_another_as_a_plain_structured_tool() -> None:
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        found += offenders(path.read_text(encoding="utf-8"), str(path.relative_to(SRC)))
    assert found == [], (
        "rebuild these with agents.server_names.ServerNamedTool, which offers "
        f"the server's argument names: {found}"
    )


def test_the_guard_sees_each_way_a_schema_is_borrowed() -> None:
    direct = (
        "def f(tool):\n"
        "    return StructuredTool.from_function(coroutine=c, args_schema=tool.args_schema)\n"
    )
    held = (
        "def f(tool):\n"
        "    schema = getattr(tool, 'args_schema', None)\n"
        "    return StructuredTool.from_function(coroutine=c, args_schema=schema)\n"
    )
    method = (
        "class P:\n"
        "    def f(self, tool):\n"
        "        return StructuredTool.from_function(args_schema=tool.args_schema)\n"
    )
    own = (
        "def f():\n    return StructuredTool.from_function(coroutine=c, args_schema=AskArguments)\n"
    )
    named = (
        "def f(tool):\n"
        "    return ServerNamedTool.from_function(coroutine=c, args_schema=tool.args_schema)\n"
    )
    assert offenders(direct) == ["<source>:2"]
    assert offenders(held) == ["<source>:3"]
    assert offenders(method) == ["<source>:3"]
    assert offenders(own) == []
    assert offenders(named) == []
