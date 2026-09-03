from maljan.core import settings_catalog as cat
from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER


def test_every_leaf_is_annotated_and_no_annotation_is_orphaned():
    leaves = {leaf.path for leaf in cat.core_leaves()}
    annotated = set(ANNOTATIONS)
    assert leaves - annotated == set(), f"unannotated settings: {sorted(leaves - annotated)}"
    missing = sorted(annotated - leaves)
    assert annotated - leaves == set(), f"annotations for missing settings: {missing}"


def test_every_annotation_has_a_title_and_description():
    empty = [
        k for k, a in ANNOTATIONS.items() if not a["title"].strip() or not a["description"].strip()
    ]
    assert empty == [], empty


def test_types_and_choices():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["llm.openai.api_key"].type == "secret" and by_path["llm.openai.api_key"].secret
    assert (
        by_path["memory.qdrant_api_key"].type == "secret"
        and by_path["memory.qdrant_api_key"].secret
    )
    assert by_path["reporting.default_tlp"].type == "enum"
    expected_tlp_choices = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]
    assert by_path["reporting.default_tlp"].choices == expected_tlp_choices
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
