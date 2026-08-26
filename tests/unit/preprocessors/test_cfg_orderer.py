"""Tests for the CFGOrderer preprocessor."""

from maljan.preprocessors.cfg_orderer import CFGOrderer


def test_cfg_orderer_dag(tmp_path):
    """Test topological sorting on a simple DAG CFG."""
    cfg = {
        "binary_name": "test.exe",
        "functions": {
            "main": {"address": "0x100", "calls": ["func_a", "func_b"], "is_thunk": False},
            "func_a": {"address": "0x110", "calls": ["func_c"], "is_thunk": False},
            "func_b": {"address": "0x120", "calls": ["func_c"], "is_thunk": False},
            "func_c": {"address": "0x130", "calls": [], "is_thunk": False},
        },
    }

    orderer = CFGOrderer(cfg)
    order = orderer.get_topological_order()

    # In a topological sort, 'main' should come before 'func_a' and 'func_b',
    # and both should come before 'func_c'.
    assert order.index("main") < order.index("func_a")
    assert order.index("main") < order.index("func_b")
    assert order.index("func_a") < order.index("func_c")
    assert order.index("func_b") < order.index("func_c")


def test_cfg_orderer_with_cycle(tmp_path):
    """Test sorting on a CFG with cycles (recursive calls)."""
    cfg = {
        "binary_name": "test.exe",
        "functions": {
            "main": {"address": "0x100", "calls": ["func_a"], "is_thunk": False},
            "func_a": {"address": "0x110", "calls": ["func_b"], "is_thunk": False},
            "func_b": {"address": "0x120", "calls": ["func_a", "func_c"], "is_thunk": False},
            "func_c": {"address": "0x130", "calls": [], "is_thunk": False},
        },
    }

    orderer = CFGOrderer(cfg)
    order = orderer.get_topological_order()

    # Even with a cycle between func_a and func_b, 'main' must be first,
    # and 'func_c' must be last (or after the cycle component)
    assert order.index("main") < order.index("func_c")

    a_idx = order.index("func_a")
    b_idx = order.index("func_b")

    assert order.index("main") < a_idx
    assert order.index("main") < b_idx

    assert a_idx < order.index("func_c")
    assert b_idx < order.index("func_c")
