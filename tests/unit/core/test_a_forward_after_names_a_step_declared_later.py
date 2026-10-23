"""A step placed after one declared further down the list is placed after it."""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from maljan.core.pack_steps import effective_steps


def _step(step_id: str, after: str = "") -> dict[str, Any]:
    return {"id": step_id, "server": "s", "tool": "t", **({"after": after} if after else {})}


def _ids(declared: list[dict[str, Any]]) -> list[str]:
    return [step.id for step in effective_steps(declared)]


def test_the_order_of_the_declarations_decides_nothing() -> None:
    a, b = _step("step_a", "step_b"), _step("step_b")
    assert _ids([a, b]) == _ids([b, a])
    ids = _ids([a, b])
    assert ids.index("step_a") == ids.index("step_b") + 1


def test_a_chain_declared_backwards_is_placed() -> None:
    ids = _ids([_step("s1", "s2"), _step("s2", "s3"), _step("s3")])
    assert ids.index("s3") + 1 == ids.index("s2") and ids.index("s2") + 1 == ids.index("s1")


@pytest.mark.parametrize(
    "order", list(itertools.permutations([("qb", "qc"), ("qa", "qb"), ("qc", "")]))
)
def test_a_chain_is_accepted_in_every_order(order: tuple[tuple[str, str], ...]) -> None:
    ids = _ids([_step(i, after) for i, after in order])
    assert ids.index("qc") + 1 == ids.index("qb") and ids.index("qb") + 1 == ids.index("qa")


def test_a_two_cycle_is_refused() -> None:
    with pytest.raises(ValueError, match="comes after|cycle"):
        effective_steps([_step("s1", "s2"), _step("s2", "s1")])


def test_a_three_cycle_names_its_members() -> None:
    declared = [_step("ca", "cb"), _step("cb", "cc"), _step("cc", "ca"), _step("cd", "ca")]
    with pytest.raises(ValueError, match="cycle") as refused:
        effective_steps(declared)
    for member in ("'ca'", "'cb'", "'cc'"):
        assert member in str(refused.value)
    assert "'cd'" not in str(refused.value)
