"""The indexed Sigma scan fires exactly what the per-pair evaluator fired, and scales linearly.

The evaluator used to build every value's regex, and pySigma re-parsed every
condition, for each (rule, event) pair over the whole corpus: a thousand
events took minutes. ``SigmaLayer.scan`` compiles each rule once, evaluates
identical rules once, skips an event identical to an earlier one, and in
strict mode lets a rule meet only the events that hold a field it needs.

The per-pair evaluator is inlined below as it stood, and both are run over
the same rules and events: every hit, its matched fields and every rule error
must be the same, except for a rule testing ``field: null``, which now reads
as the Sigma specification says. Cost is counted in rule-event evaluations,
never wall-clock.

The crafted rule set below runs everywhere and is the proof CI carries. The
shipped corpus (``data/sigma_rules``) is ignored by version control, so the
corpus case skips in CI and in any checkout without it; it is run by hand
where the corpus is.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path
from typing import Any

import pytest
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.types import (
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from maljan.analysis.sigma_layer import (
    _DEFAULT_RULES_DIR,
    EventContext,
    SigmaLayer,
    _is_rule_compatible,
    build_events_from_sandbox,
)

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"


# ---------------------------------------------------------------------------
# The per-pair evaluator, as it stood before the index.
# ---------------------------------------------------------------------------


class _PerPairEvaluator:
    def __init__(self, rule: Any) -> None:
        self.rule = rule

    def evaluate(self, event: dict[str, str], strict: bool = True) -> dict[str, str] | None:
        parsed = getattr(self.rule.detection, "parsed_condition", None) or []
        if not self.rule.detection or not parsed:
            return None
        for cond_tree in parsed:
            match_dict = self._eval_node(cond_tree.parsed, event, strict)
            if match_dict is not None:
                return match_dict
        return None

    def _eval_node(self, node: Any, event: dict[str, str], strict: bool) -> dict[str, str] | None:
        if isinstance(node, ConditionAND):
            combined: dict[str, str] = {}
            for arg in node.args:
                res = self._eval_node(arg, event, strict)
                if res is None:
                    return None
                combined.update(res)
            return combined
        if isinstance(node, ConditionOR):
            for arg in node.args:
                res = self._eval_node(arg, event, strict)
                if res is not None:
                    return res
            return None
        if isinstance(node, ConditionNOT):
            res = self._eval_node(node.args[0], event, strict)
            if res is None:
                return {}
            return None
        if isinstance(node, ConditionFieldEqualsValueExpression):
            field = node.field.lower() if node.field else None
            regex = self._to_regex(node.value, strict)
            if not strict:
                for v in event.values():
                    if regex.search(str(v)):
                        return {node.field or "raw": str(v)}
                return None
            if field is None:
                for k, v in event.items():
                    if regex.search(str(v)):
                        return {k: str(v)}
                return None
            for k, v in event.items():
                if k.lower() == field:
                    if regex.search(str(v)):
                        return {node.field: str(v)}
            return None
        return None

    def _to_regex(self, val: Any, strict: bool) -> re.Pattern[str]:
        if isinstance(val, SigmaRegularExpression):
            return re.compile(str(val.regexp), re.IGNORECASE)
        if isinstance(val, SigmaNumber):
            pat = re.escape(str(val.number))
            return re.compile(f"^{pat}$" if strict else pat, re.IGNORECASE)
        if isinstance(val, SigmaString):
            pattern = ""
            for part in val.s:
                if part == SpecialChars.WILDCARD_MULTI:
                    pattern += ".*"
                elif part == SpecialChars.WILDCARD_SINGLE:
                    pattern += "."
                else:
                    pattern += re.escape(str(part))
            return re.compile(f"^{pattern}$" if strict else pattern, re.IGNORECASE)
        pat = re.escape(str(val))
        return re.compile(f"^{pat}$" if strict else pat, re.IGNORECASE)


def _per_pair_scan(
    layer: SigmaLayer, events: list[dict[str, str]], strict: bool, platform: str | None
) -> tuple[list[tuple[int, dict[str, str]]], int, int]:
    """Hits, rule errors and evaluations of the old loop: every rule against every event."""
    hits: list[tuple[int, dict[str, str]]] = []
    errors = evaluations = 0
    for position, (rule, _evaluator) in enumerate(layer._evaluators):
        product = str(rule.logsource.product) if rule.logsource and rule.logsource.product else ""
        if not _is_rule_compatible(product, platform):
            continue
        evaluator = _PerPairEvaluator(rule)
        for event in events:
            evaluations += 1
            try:
                matched = evaluator.evaluate(event, strict=strict)
            except Exception:  # noqa: BLE001
                errors += 1
                break
            if matched is not None:
                hits.append((position, matched))
                break
    return hits, errors, evaluations


def _uses_null(rule: Any) -> bool:
    """Whether a rule tests ``field: null``, the one value whose reading changed on purpose."""
    try:
        conditions = getattr(rule.detection, "parsed_condition", None) or []
        stack = [condition.parsed for condition in conditions]
    except Exception:  # noqa: BLE001 — a rule that cannot parse tests nothing
        return False
    while stack:
        node = stack.pop()
        if isinstance(node, ConditionFieldEqualsValueExpression):
            if isinstance(node.value, SigmaNull):
                return True
        else:
            stack.extend(getattr(node, "args", None) or [])
    return False


def _null_positions(layer: SigmaLayer) -> set[int]:
    return {p for p, (rule, _e) in enumerate(layer._evaluators) if _uses_null(rule)}


def _assert_same(layer: SigmaLayer, events: list[dict[str, str]]) -> None:
    """Every rule fires as before, except a rule testing ``field: null`` in strict mode.

    ``null`` now reads as the Sigma specification says (the field absent or
    empty) where it used to be matched as the text of pySigma's object; only
    the rules that test it may differ, and only in strict mode.
    """
    nulls = _null_positions(layer)
    for strict, platform in ((True, None), (True, "windows"), (True, "linux"), (False, None)):
        batch = events if strict else [{"_raw": json.dumps(e)} for e in events]
        old_hits, old_errors, _ = _per_pair_scan(layer, batch, strict, platform)
        scan = layer.scan(batch, strict=strict, sample_platform=platform)
        new_hits = [(p, m) for p, _r, m in scan.hits]
        if strict:
            old_hits = [(p, m) for p, m in old_hits if p not in nulls]
            new_hits = [(p, m) for p, m in new_hits if p not in nulls]
        assert new_hits == old_hits, (strict, platform)
        assert scan.rule_errors == old_errors, (strict, platform)


# ---------------------------------------------------------------------------
# A rule set that exercises every shape the evaluator reads.
# ---------------------------------------------------------------------------

_RULES = {
    "endswith.yml": r"""
        title: Certutil Download
        id: 0a000000-0000-4000-8000-000000000001
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                Image|endswith: '\certutil.exe'
                CommandLine|contains: ['urlcache', 'verifyctl']
            condition: selection
    """,
    "endswith_copy.yml": r"""
        title: Certutil Download (a second copy)
        id: 0a000000-0000-4000-8000-000000000002
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                Image|endswith: '\certutil.exe'
                CommandLine|contains: ['urlcache', 'verifyctl']
            condition: selection
    """,
    "not_filter.yml": r"""
        title: Cmd Not From Explorer
        id: 0a000000-0000-4000-8000-000000000003
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                Image|endswith: 'cmd.exe'
            filter:
                ParentImage|endswith: '\explorer.exe'
            condition: selection and not filter
    """,
    "only_not.yml": r"""
        title: Anything Without A Parent
        id: 0a000000-0000-4000-8000-000000000004
        logsource: {product: windows}
        detection:
            filter:
                ParentImage|contains: 'e'
            condition: not filter
    """,
    "keywords_field_none.yml": r"""
        title: Whoami Anywhere
        id: 0a000000-0000-4000-8000-000000000005
        logsource: {category: process_creation}
        detection:
            keywords:
                - '*whoami*'
            condition: keywords
    """,
    "regex.yml": r"""
        title: Encoded PowerShell
        id: 0a000000-0000-4000-8000-000000000006
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                CommandLine|re: '-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{8,}'
            condition: selection
    """,
    "one_of.yml": r"""
        title: Run Key Or Service
        id: 0a000000-0000-4000-8000-000000000007
        logsource: {category: registry_set, product: windows}
        detection:
            sel_run:
                TargetObject|contains: '\CurrentVersion\Run'
            sel_svc:
                TargetObject|contains: '\Services\'
                Details|contains: '.exe'
            condition: 1 of sel_*
    """,
    "number.yml": r"""
        title: Event Id
        id: 0a000000-0000-4000-8000-000000000008
        logsource: {product: windows, service: security}
        detection:
            selection:
                EventID: 4688
            condition: selection
    """,
    "wildcard_single.yml": r"""
        title: Short Name
        id: 0a000000-0000-4000-8000-000000000009
        logsource: {category: process_creation, product: linux}
        detection:
            selection:
                Image|endswith: '/?h'
            condition: selection
    """,
    "pipe.yml": r"""
        title: Retired Pipe Syntax
        id: 0a000000-0000-4000-8000-00000000000a
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                Image|endswith: 'cmd.exe'
            condition: selection | count() > 5
    """,
    "unparsable.yml": r"""
        title: No Usable Detection
        id: 0a000000-0000-4000-8000-00000000000b
        logsource: {category: process_creation, product: windows}
        detection:
            condition: selection
    """,
    "null_filter.yml": r"""
        title: Svchost Not Under Services
        id: 0a000000-0000-4000-8000-00000000000d
        logsource: {category: process_creation, product: windows}
        detection:
            selection:
                Image|endswith: '\svchost.exe'
            filter_main_generic:
                ParentImage|endswith: '\services.exe'
            filter_main_parent_null:
                ParentImage: null
            filter_main_parent_empty:
                ParentImage:
                    - '-'
                    - ''
            condition: selection and not 1 of filter_main_*
    """,
    "two_conditions.yml": r"""
        title: Two Conditions
        id: 0a000000-0000-4000-8000-00000000000c
        logsource: {category: process_creation}
        detection:
            a:
                CommandLine|contains: 'vssadmin'
            b:
                Image|endswith: 'net.exe'
            condition:
                - a
                - b
    """,
}

_EVENTS: list[dict[str, str]] = [
    {
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil -urlcache -split -f http://x/a.exe",
        "ParentImage": "C:\\Windows\\explorer.exe",
    },
    {"Image": "certutil.exe", "CommandLine": "certutil -urlcache -f http://x/a"},
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"},
    {"Image": "cmd.exe", "CommandLine": "cmd", "ParentImage": "C:\\Windows\\explorer.exe"},
    {"image": "C:\\x\\CMD.EXE", "IMAGE": "other.exe"},
    {"CommandLine": "powershell -enc SQBFAFgAIABOAGUAdwA="},
    {"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"},
    {"TargetObject": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\x", "Details": "c:\\a.exe"},
    {"EventID": "4688"},
    {"Image": "/bin/sh", "CommandLine": "sh -c id"},
    {"CommandLine": "vssadmin delete shadows\nsecond line"},
    {"Image": "C:\\Windows\\System32\\net.exe"},
    {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"},
    {},
]


@pytest.fixture()
def shaped_layer(tmp_path: Path) -> SigmaLayer:
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    for name, body in _RULES.items():
        (rules_dir / name).write_text(textwrap.dedent(body), encoding="utf-8")
    return SigmaLayer.from_rules_dir(rules_dir)


def _fixture_events() -> list[list[dict[str, str]]]:
    batches = []
    for path in sorted(_FIXTURES.glob("*.json")):
        events = build_events_from_sandbox(json.loads(path.read_text(encoding="utf-8")))
        if events:
            batches.append(events)
    return batches


class TestTheIndexedScanFiresWhatThePerPairScanFired:
    def test_every_shape_over_crafted_events(self, shaped_layer: SigmaLayer) -> None:
        scan = shaped_layer.scan(_EVENTS)
        # The comparison means something: rules fire, and the pipe rule raises.
        assert len(scan.hits) >= 6
        assert scan.rule_errors == 1
        _assert_same(shaped_layer, _EVENTS)
        for event in _EVENTS:
            _assert_same(shaped_layer, [event])
        _assert_same(shaped_layer, list(reversed(_EVENTS)))

    def test_every_shape_over_the_fixture_reports(self, shaped_layer: SigmaLayer) -> None:
        batches = _fixture_events()
        assert batches, "the sandbox fixtures must yield events"
        for events in batches:
            _assert_same(shaped_layer, events + _EVENTS)

    def test_the_shipped_corpus_over_fixture_and_crafted_events(self) -> None:
        if not _DEFAULT_RULES_DIR.is_dir():
            pytest.skip("no sigma corpus vendored in this checkout")
        layer = SigmaLayer.from_default_rules()
        events = [e for batch in _fixture_events() for e in batch] + _EVENTS
        _assert_same(layer, events)

    def test_identical_rules_are_evaluated_once_and_each_reported(
        self, shaped_layer: SigmaLayer
    ) -> None:
        scan = shaped_layer.scan([_EVENTS[0]])
        titles = [rule.title for _p, rule, _m in scan.hits]
        assert "Certutil Download" in titles
        assert "Certutil Download (a second copy)" in titles
        assert shaped_layer.distinct_rule_count == len(shaped_layer._evaluators) - 1


# ---------------------------------------------------------------------------
# Cost, in rule-event evaluations.
# ---------------------------------------------------------------------------

_IMAGE_RULE = r"""
title: Image Only {n}
id: 0b000000-0000-4000-8000-0000000000{n:02d}
logsource: {{category: process_creation, product: windows}}
detection:
    selection:
        Image|endswith: '\never-{n}.exe'
    condition: selection
"""


@pytest.fixture()
def image_layer(tmp_path: Path) -> SigmaLayer:
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    for n in range(10):
        (rules_dir / f"r{n}.yml").write_text(_IMAGE_RULE.format(n=n), encoding="utf-8")
    return SigmaLayer.from_rules_dir(rules_dir)


def _process_events(count: int) -> list[dict[str, str]]:
    return [{"Image": f"C:\\p\\{i}.exe", "CommandLine": f"{i}.exe"} for i in range(count)]


class TestTheCostIsCountedInEvaluations:
    def test_an_event_meets_only_the_rules_that_need_a_field_it_holds(
        self, image_layer: SigmaLayer
    ) -> None:
        scan = image_layer.scan([{"TargetObject": "HKCU\\x"}] * 5)
        assert scan.evaluations == 0

    def test_evaluations_grow_linearly_with_the_events(self, image_layer: SigmaLayer) -> None:
        hundred = image_layer.scan(_process_events(100)).evaluations
        thousand = image_layer.scan(_process_events(1000)).evaluations
        assert hundred == 10 * 100
        assert thousand == 10 * hundred

    def test_collected_events_grow_linearly_too(self, image_layer: SigmaLayer) -> None:
        """Read as collected, each rule meets each event of its category twice at
        most: once for a hit, once to find whether it is unknown there."""

        def counted(count: int) -> int:
            events = _process_events(count)
            contexts = [EventContext(frozenset({"process_creation"}))] * count
            return image_layer.scan(events, contexts=contexts).evaluations

        assert counted(100) == 2 * 10 * 100
        assert counted(1000) == 10 * counted(100)

    def test_an_event_of_another_category_meets_none_of_them(self, image_layer: SigmaLayer) -> None:
        events = _process_events(5)
        contexts = [EventContext(frozenset({"registry_set"}))] * 5
        scan = image_layer.scan(events, contexts=contexts)
        assert scan.evaluations == 0
        assert scan.no_events_of == {"process_creation": 10}

    def test_an_event_repeated_is_evaluated_once(self, image_layer: SigmaLayer) -> None:
        assert image_layer.scan(_process_events(1) * 1000).evaluations == 10

    def test_the_index_never_costs_more_than_every_pair(self, shaped_layer: SigmaLayer) -> None:
        for strict in (True, False):
            batch = _EVENTS if strict else [{"_raw": json.dumps(e)} for e in _EVENTS]
            _hits, _errors, pairs = _per_pair_scan(shaped_layer, batch, strict, None)
            scan = shaped_layer.scan(batch, strict=strict)
            assert scan.evaluations <= pairs


# ---------------------------------------------------------------------------
# ``field: null`` reads as the Sigma specification says: absent or empty.
# ---------------------------------------------------------------------------

_NULL_ONLY = r"""
title: Parent Is Null
id: 0d000000-0000-4000-8000-000000000001
logsource: {category: process_creation, product: windows}
detection:
    selection:
        ParentImage: null
    condition: selection
"""

# The detection of the shipped "Uncommon Svchost Parent Process" rule.
_SVCHOST_PARENT = r"""
title: Uncommon Svchost Parent Process
id: 0d000000-0000-4000-8000-000000000002
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter_main_generic:
        ParentImage|endswith:
            - '\Mrt.exe'
            - '\MsMpEng.exe'
            - '\ngen.exe'
            - '\rpcnet.exe'
            - '\services.exe'
            - '\TiWorker.exe'
    filter_main_parent_null:
        ParentImage: null
    filter_main_parent_empty:
        ParentImage:
            - '-'
            - ''
    condition: selection and not 1 of filter_main_*
"""


def _layer_of(tmp_path: Path, *bodies: str) -> SigmaLayer:
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    for n, body in enumerate(bodies):
        (rules_dir / f"r{n}.yml").write_text(textwrap.dedent(body), encoding="utf-8")
    return SigmaLayer.from_rules_dir(rules_dir)


class TestNullIsAbsentOrEmpty:
    def test_a_null_test_on_an_absent_field_matches(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _NULL_ONLY)
        assert len(layer.scan([{"Image": "C:\\x\\a.exe"}]).hits) == 1

    def test_a_null_test_on_an_empty_field_matches(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _NULL_ONLY)
        assert len(layer.scan([{"Image": "a.exe", "ParentImage": ""}]).hits) == 1

    def test_a_null_test_on_a_present_value_does_not_match(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _NULL_ONLY)
        assert layer.scan([{"ParentImage": "C:\\Windows\\explorer.exe"}]).hits == []

    def test_a_parentless_svchost_no_longer_fires_uncommon_svchost_parent(
        self, tmp_path: Path
    ) -> None:
        layer = _layer_of(tmp_path, _SVCHOST_PARENT)
        parentless = {
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
        }
        assert layer.scan([parentless]).hits == []
        # The per-pair evaluator fired on it: the change is this rule's, on purpose.
        old_hits, _errors, _pairs = _per_pair_scan(layer, [parentless], True, None)
        assert len(old_hits) == 1

    def test_a_svchost_under_an_unusual_parent_still_fires(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _SVCHOST_PARENT)
        event = {
            "Image": "C:\\Windows\\resources\\svchost.exe",
            "ParentImage": "C:\\Windows\\resources\\spoolsv.exe",
        }
        assert len(layer.scan([event]).hits) == 1


# ---------------------------------------------------------------------------
# Events read as collected: three-valued logic, logsource categories.
# ---------------------------------------------------------------------------

_PROC = EventContext(frozenset({"process_creation"}))

_NOT_A_PATH = r"""
title: Execution Of Non-Existing File
id: 0e000000-0000-4000-8000-000000000001
logsource: {category: process_creation, product: windows}
detection:
    image_absolute_path:
        Image|contains: '\'
    filter_null:
        Image: null
    condition: not image_absolute_path and not filter_null
"""

_AND_OR = r"""
title: Certutil Or Original Name
id: 0e000000-0000-4000-8000-000000000002
logsource: {category: process_creation, product: windows}
detection:
    sel_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    sel_cli:
        CommandLine|contains: 'urlcache'
    condition: sel_img and sel_cli
"""


def _scan_one(layer: SigmaLayer, event: dict[str, str], context: EventContext) -> Any:
    return layer.scan([event], contexts=[context])


class TestAnEventReadAsCollected:
    def test_a_null_test_of_a_field_not_collected_is_unknown_not_true(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _SVCHOST_PARENT)
        parentless = {"Image": "C:\\Windows\\System32\\svchost.exe"}
        scan = _scan_one(layer, parentless, _PROC)
        assert scan.hits == []
        ((rule, fields),) = scan.not_evaluable[0]
        assert "ParentImage" in fields

    def test_a_null_test_of_a_field_collected_empty_is_true(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _SVCHOST_PARENT)
        event = {"Image": "C:\\Windows\\System32\\svchost.exe", "ParentImage": ""}
        scan = _scan_one(layer, event, _PROC)
        assert scan.hits == []
        assert scan.not_evaluable == {}

    def test_a_svchost_under_an_unusual_parent_fires(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _SVCHOST_PARENT)
        event = {
            "Image": "C:\\Windows\\resources\\svchost.exe",
            "ParentImage": "C:\\Windows\\resources\\spoolsv.exe",
        }
        assert len(_scan_one(layer, event, _PROC).hits) == 1

    def test_a_negated_path_test_of_a_bare_name_is_unknown(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _NOT_A_PATH)
        pathless = EventContext(frozenset({"process_creation"}), frozenset({"image"}))
        scan = _scan_one(layer, {"Image": "certutil.exe"}, pathless)
        assert scan.hits == []
        ((_rule, fields),) = scan.not_evaluable[0]
        assert fields == ("Image path",)
        # Read as complete, the same event fires, as it always did.
        assert len(layer.scan([{"Image": "certutil.exe"}]).hits) == 1

    def test_or_is_true_when_one_side_is_true_and_unknown_otherwise(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _AND_OR)
        hit = {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "x urlcache"}
        assert len(_scan_one(layer, hit, _PROC).hits) == 1
        other = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "x urlcache"}
        scan = _scan_one(layer, other, _PROC)
        assert scan.hits == []
        ((_rule, fields),) = scan.not_evaluable[0]
        assert fields == ("OriginalFileName",)

    def test_and_is_false_when_one_side_is_false_whatever_the_other(self, tmp_path: Path) -> None:
        layer = _layer_of(tmp_path, _AND_OR)
        event = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "dir"}
        scan = _scan_one(layer, event, _PROC)
        assert scan.hits == []
        assert scan.not_evaluable == {}

    def test_a_rule_of_another_category_is_not_run_and_counted_once(self, tmp_path: Path) -> None:
        dns = r"""
            title: Dns Query
            id: 0e000000-0000-4000-8000-000000000003
            logsource: {category: dns_query, product: windows}
            detection:
                selection:
                    Image|endswith: '\certutil.exe'
                condition: selection
        """
        layer = _layer_of(tmp_path, dns)
        events = [{"Image": "C:\\Windows\\System32\\certutil.exe"}] * 3
        scan = layer.scan(events, contexts=[_PROC] * 3)
        assert scan.hits == []
        assert scan.no_events_of == {"dns_query": 1}
        # Read as complete (no context), the category is not known and not checked.
        assert len(layer.scan(events).hits) == 1
