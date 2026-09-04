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
    assert by_path["static.ghidra.args"].type == "list"
    assert by_path["static.ghidra.auth_token"].type == "secret"


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


def test_provider_selectors_lead_their_groups_and_have_the_registry_choices():
    by_path = {e.path: e for e in cat.core_catalog()}
    static = by_path["static.provider"]
    sandbox = by_path["sandbox.provider"]
    assert static.type == "enum" and static.order == -1
    assert static.choices == ["ghidra", "r2", "capa_yara", "generic_mcp", "none"]
    assert sandbox.type == "enum" and sandbox.order == -1
    assert sandbox.choices == ["mock", "cape2", "upload", "triage"]
    assert static.applies_when is None and sandbox.applies_when is None


def test_provider_specific_leaves_declare_when_they_apply():
    by_path = {e.path: e for e in cat.core_catalog()}
    assert by_path["static.ghidra.url"].applies_when == {"core.static.provider": ["ghidra"]}
    assert by_path["static.r2.binary_path"].applies_when == {"core.static.provider": ["r2"]}
    assert by_path["static.capa.rules_dir"].applies_when == {"core.static.provider": ["capa_yara"]}
    assert by_path["static.yara.rules_dir"].applies_when == {"core.static.provider": ["capa_yara"]}
    assert by_path["static.generic.command"].applies_when == {
        "core.static.provider": ["generic_mcp"]
    }
    assert by_path["sandbox.cape2.base_url"].applies_when == {"core.sandbox.provider": ["cape2"]}
    assert by_path["sandbox.triage.api_token"].applies_when == {"core.sandbox.provider": ["triage"]}
    assert by_path["sandbox.upload.max_report_bytes"].applies_when == {
        "core.sandbox.provider": ["upload"]
    }


def test_every_applies_when_names_a_real_key_and_real_choices():
    entries = cat.core_catalog()
    by_key = {e.key: e for e in entries}
    for e in entries:
        for key, values in (e.applies_when or {}).items():
            assert key in by_key, f"{e.key} depends on unknown {key}"
            assert by_key[key].choices is not None, f"{key} is not an enum"
            unknown = set(values) - set(by_key[key].choices or [])
            assert not unknown, f"{e.key}: {key} has no choices {sorted(unknown)}"


def test_static_group_exists_and_sandbox_group_is_renamed():
    titles = dict(GROUP_ORDER)
    assert titles["static"] == "Static analysis provider"
    assert titles["sandbox"] == "Sandbox provider"
    groups = [g for g, _ in GROUP_ORDER]
    assert groups.index("static") < groups.index("sandbox")


def test_entries_sort_by_order_then_path_within_a_group():
    static = [e for e in cat.core_catalog() if e.group == "static"]
    assert static[0].path == "static.provider"
    assert static == sorted(static, key=lambda e: (e.order, e.path))
