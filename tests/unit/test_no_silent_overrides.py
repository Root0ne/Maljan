"""No component may quietly rewrite what an agent decided.

This is the phase's direction, enforced rather than described. Six names carry
a decision somebody made: a claim's ``technique_id`` and ``confidence``, the
judge's own ``verdict``, and a report's ``severity``, ``malware_category`` and
``family``. Every layer that
used to write one of them wrote it over an answer that already existed — the
cascade over the analyst's confidence, the autocorrect over its technique id,
the report builder's arithmetic over a severity the judge was never asked for.

Both spellings are scanned, because the judge's bundle is a plain ``dict`` for
the whole of ``agents/judge_postprocess.py`` and an override there would be
``obj["confidence"] = …`` rather than an attribute write.

Three places may still write them, because in each the write *is* the answer
rather than a correction of one, and two acts below the scan's reach are driven
here instead: declining to export an object, and moving one of the judge's own
blocks to the property the schema reads it from:

* ``schemas/`` — the models these live on, where a field is constructed.
* ``tools/`` — a tool reporting what it found.
* ``pipeline/validation.py`` — the one place a finding is recorded, and even
  there only as a validity flag or a drop that the run summary carries.

Constructing a fresh object is always fine: ``Claim(technique_id=...)`` and
``{"confidence": x}`` are not overrides of anything, so only assignment to an
attribute or a key of an object that already exists is caught. Nothing about
this test is a style rule; a failure means a decision is being replaced
somewhere a reader of the report cannot see.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

SRC = Path(__file__).resolve().parents[2] / "src" / "maljan"

# The names that carry a decision. ``verdict`` is the one the whole run is
# printed under: the judge states it, the pipeline reads it and nothing else
# may write it, which is how a signed utility came to be published as malware
# over a judge that had called it benign.
GUARDED = frozenset(
    {"technique_id", "confidence", "severity", "malware_category", "family", "verdict"}
)

# Where a write to one of them is the answer rather than an override of one.
EXEMPT_PATHS = ("schemas/", "tools/", "pipeline/validation.py")

# Empty, and worth keeping empty. It exists for a module that has to fill one
# of these fields in on an object it is still building — the brief allows that
# — but nothing needs it today, and an exemption added without a reason is the
# hole this test exists to close.
WHITELIST: frozenset[str] = frozenset()


def _relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _is_exempt(relative: str) -> bool:
    return relative in WHITELIST or any(relative.startswith(prefix) for prefix in EXEMPT_PATHS)


def _guarded_target(node: ast.expr) -> str | None:
    """The guarded name this target writes, when it writes one on an object.

    ``obj.severity = x`` and ``obj["severity"] = x`` both count. A bare local
    (``severity = x``) does not: it is not somebody else's decision, and the
    object it eventually reaches is constructed from it. A computed key
    (``obj[name] = x``) does not either — there is nothing to read.
    """
    if isinstance(node, ast.Attribute) and node.attr in GUARDED:
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and key.value in GUARDED:
            return str(key.value)
    return None


def _setattr_target(node: ast.Call) -> str | None:
    """The guarded name a ``setattr(obj, "severity", x)`` call writes."""
    func = node.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
    if name != "setattr" or len(node.args) < 2:  # noqa: PLR2004 — setattr takes three
        return None
    key = node.args[1]
    if isinstance(key, ast.Constant) and key.value in GUARDED:
        return str(key.value)
    return None


def _constructor_lines(tree: ast.AST) -> set[int]:
    """Line numbers inside an ``__init__``."""
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "__init__":
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    inside.add(child.lineno)
    return inside


def _is_constructor_passthrough(
    node: ast.stmt, target: ast.expr, constructor_lines: set[int]
) -> bool:
    """``self.severity = severity`` inside an ``__init__`` — storing an argument.

    Deliberately narrow on both axes. It must be inside a constructor, and the
    value must be a *bare name*: nothing has decided it yet, this is the object
    being built, and the value passes straight through.
    ``self.severity = compute(...)`` in an ``__init__`` is a decision like any
    other and is caught, and so is any write outside one.
    """
    if node.lineno not in constructor_lines:
        return False
    if not (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return False
    return isinstance(getattr(node, "value", None), ast.Name)


def offences(source: str, label: str) -> list[str]:
    """Every guarded write in ``source``, as ``label:line: description``."""
    tree = ast.parse(source, filename=label)
    constructor_lines = _constructor_lines(tree)
    found: list[str] = []

    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AugAssign | ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Call):
            attribute = _setattr_target(node)
            if attribute:
                found.append(f"{label}:{node.lineno}: setattr(..., {attribute!r}, ...)")
            continue

        for target in targets:
            name = _guarded_target(target)
            if name is None or _is_constructor_passthrough(node, target, constructor_lines):
                continue
            how = "key" if isinstance(target, ast.Subscript) else "attribute"
            found.append(f"{label}:{node.lineno}: assignment to {how} {name!r}")

    return found


def test_nothing_outside_schemas_tools_and_validation_overrides_a_decision():
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        relative = _relative(path)
        if _is_exempt(relative):
            continue
        found.extend(offences(path.read_text(encoding="utf-8"), relative))

    assert not found, (
        "These write a decision an agent already made, where a reader of the "
        "report cannot see it happen. Report it as a "
        "``pipeline.validation.Violation`` and give the producer a turn to fix "
        "it, or construct a fresh object instead of writing into an existing "
        "one:\n  " + "\n  ".join(found)
    )


class TestTheScannerWouldActuallyCatchOne:
    """The test above passes trivially if the scan is broken, so prove it is not.

    Every probe is a source *string*. Planting a module in ``src/maljan`` to
    prove the scanner works would leave a stray file in the installed package
    if the run were interrupted, and could be walked by the scanning test above
    while it existed.
    """

    def test_an_attribute_write_is_caught(self):
        assert offences("claim.confidence = 0.4\n", "probe.py") == [
            "probe.py:1: assignment to attribute 'confidence'"
        ]

    def test_a_dict_key_write_is_caught(self):
        assert offences("obj['severity'] = 'High'\n", "probe.py") == [
            "probe.py:1: assignment to key 'severity'"
        ]

    def test_setattr_is_caught(self):
        assert offences("setattr(report, 'family', name)\n", "probe.py") == [
            "probe.py:1: setattr(..., 'family', ...)"
        ]

    def test_an_augmented_assignment_is_caught(self):
        assert offences("claim.confidence += 0.1\n", "probe.py") == [
            "probe.py:1: assignment to attribute 'confidence'"
        ]

    def test_constructing_a_fresh_object_is_not_caught(self):
        assert offences("c = Claim(technique_id='T1055', confidence=0.8)\n", "probe.py") == []

    def test_a_fresh_dict_literal_is_not_caught(self):
        assert offences("row = {'confidence': 0.8, 'severity': 'High'}\n", "probe.py") == []

    def test_a_bare_local_is_not_caught(self):
        assert offences("severity = compute()\n", "probe.py") == []

    def test_a_computed_key_is_not_caught(self):
        assert offences("row[name] = value\n", "probe.py") == []

    def test_a_constructor_passthrough_is_exempt(self):
        source = "class A:\n    def __init__(self, severity):\n        self.severity = severity\n"

        assert offences(source, "probe.py") == []

    def test_a_constructor_that_computes_the_value_is_not_exempt(self):
        source = "class A:\n    def __init__(self, data):\n        self.severity = score(data)\n"

        assert offences(source, "probe.py") == ["probe.py:3: assignment to attribute 'severity'"]

    def test_a_write_outside_a_constructor_is_never_exempt(self):
        source = "class A:\n    def later(self, severity):\n        self.severity = severity\n"

        assert offences(source, "probe.py") == ["probe.py:3: assignment to attribute 'severity'"]


class TestAMergeOnlyGrowsASet:
    """Two rows folded into one is the other way a decision could be rewritten.

    The scan above catches an assignment; it cannot catch arithmetic that
    averages two confidences into a third nobody wrote, or a fold that takes
    the higher of two severities because two agents agreed. So the fold itself
    is driven here, and what is asserted is that the numbers and the words
    come out as the first occurrence wrote them while the ids and the agents
    grow.
    """

    def _finding(self, title: str, confidence: float, evidence: list[str]) -> Any:
        from maljan.schemas.isr_models import Finding

        return Finding(
            title=title,
            technique_ids=["T1055"],
            confidence=confidence,
            evidence_ids=evidence,
        )

    def _isr(self, agent: str, finding: Any) -> Any:
        from maljan.schemas.isr_models import AgentISR

        return AgentISR(agent_id=agent, domain="static", claims=[], findings=[finding])

    def test_a_merged_finding_keeps_the_first_confidence_and_gains_the_second_agent(self) -> None:
        from maljan.reporting.dedupe import MergeTally
        from maljan.reporting.ledger_report import build_sections

        merges = MergeTally()
        sections = {
            section.key: section
            for section in build_sections(
                [],
                {
                    "static": self._isr(
                        "static", self._finding("Injects into explorer.exe", 0.4, ["ev_0001"])
                    ),
                    "reverser": self._isr(
                        "reverser", self._finding("injects into explorer.exe.", 0.9, ["ev_0002"])
                    ),
                },
                merges=merges,
            )
        }

        rows = sections["findings"].rows
        assert len(rows) == 1, "the same finding twice is one row"
        agent, title, techniques, confidence, evidence = rows[0]
        assert confidence == "0.40", "the second agent's higher confidence is not taken"
        assert title == "Injects into explorer.exe", "the first writer's words are kept"
        assert techniques == "T1055"
        assert agent == "static, reverser"
        assert evidence == "ev_0001, ev_0002"
        assert merges.findings_merged == 1

    def test_a_merged_indicator_keeps_the_first_notes_and_gains_the_second_id(self) -> None:
        from maljan.reporting.dedupe import MergeTally
        from maljan.reporting.ledger_report import build_sections
        from maljan.schemas.evidence import build_entry

        def _entry(entry_id: str, seq: int, value: str, notes: str) -> Any:
            return build_entry(
                entry_id=entry_id,
                seq=seq,
                agent="static",
                tool="iocs_from_file",
                args={},
                server="analysis",
                output=json.dumps({"iocs": [{"kind": "url", "value": value, "notes": notes}]}),
            )

        merges = MergeTally()
        sections = {
            section.key: section
            for section in build_sections(
                [
                    _entry("ev_0001", 1, "http://c2.evil.tld/gate.php", "hard-coded"),
                    _entry("ev_0002", 2, "hxxp://c2[.]evil[.]tld/gate.php", "seen in the sandbox"),
                ],
                merges=merges,
            )
        }

        rows = sections["iocs"].rows
        assert len(rows) == 1, "one endpoint written two ways is one indicator"
        kind, value, notes, evidence = rows[0]
        assert (kind, value) == ("url", "http://c2.evil.tld/gate.php")
        assert notes == "hard-coded", "the first writer's note is kept"
        assert evidence == "ev_0001, ev_0002"
        assert merges.indicators_merged == 1

    def test_two_different_indicators_are_never_folded(self) -> None:
        from maljan.reporting.dedupe import indicator_fingerprint

        assert indicator_fingerprint("url", "http://a.tld/one") != indicator_fingerprint(
            "url", "http://a.tld/two"
        )
        assert indicator_fingerprint("domain", "a.tld") != indicator_fingerprint("url", "a.tld")


def test_every_exempt_path_and_whitelist_entry_still_exists():
    """A stale exemption is a hole nobody notices."""
    for prefix in EXEMPT_PATHS:
        assert (SRC / prefix).exists(), f"{prefix} no longer exists; drop the exemption"
    for entry in WHITELIST:
        assert (SRC / entry).exists(), f"{entry} no longer exists; drop the whitelist entry"


class TestABundleShapeDoesNotOverrideAVerdict:
    """The third way a decision was rewritten: not by an assignment, but by
    being re-derived from something else.

    The fallback bundle carried a ``malware`` object whatever verdict the judge
    had expressed, and the pipeline read the verdict back off the objects — so
    "Suspicious", extracted from the judge's own text, was reported as Malware.
    A fallback bundle now states the verdict it carries and the reader takes it
    as stated.
    """

    @staticmethod
    def _fallback(decision: str, source: str, objects: list[dict[str, Any]]) -> Any:
        from maljan.schemas.stix_models import Bundle

        return Bundle.model_validate(
            {
                "objects": objects,
                "x_maljan_fallback_verdict": {"decision": decision, "source": source},
            }
        )

    def test_an_extracted_verdict_is_read_as_extracted(self) -> None:
        from maljan.pipeline.outcome import decide_from_bundle

        bundle = self._fallback(
            "Suspicious",
            "extracted",
            [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "T1055",
                }
            ],
        )

        assert decide_from_bundle(bundle) == "Suspicious"

    def test_a_pipeline_authored_verdict_is_never_malware(self) -> None:
        from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT, decide_from_bundle

        bundle = self._fallback(INCONCLUSIVE_VERDICT, "pipeline", [])

        assert decide_from_bundle(bundle) == INCONCLUSIVE_VERDICT

    def test_a_bundle_the_judge_produced_is_still_read_by_its_objects(self) -> None:
        from maljan.pipeline.outcome import decide_from_bundle
        from maljan.schemas.stix_models import Bundle

        bundle = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "malware",
                        "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                        "name": "sample",
                        "is_family": False,
                    }
                ]
            }
        )

        assert decide_from_bundle(bundle) == "Malware"


class TestAnObjectDeclinedIsRecordedNotRewritten:
    """The fourth allowed act: declining to *export* an object, out loud.

    The judge that called a signed utility benign still wrote a ``malware``
    object, and its own rationale said why: "the 'malware' classification is
    used here strictly as a container for the object type in STIX". A bundle is
    consumed by tooling that reads the object and not the rationale, so the
    export leaves it out — and says so, under its own code, with the judge's
    bundle unchanged behind it. Nothing is edited: the verdict published is the
    one the judge stated, and the object is still on the record.
    """

    @staticmethod
    def _rendered() -> tuple[Any, Any, Any]:
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
        from maljan.schemas.stix_models import Bundle

        judged = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "malware",
                        "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                        "name": "PuTTY",
                        "is_family": False,
                        "description": "Legitimate open-source terminal emulator.",
                    }
                ],
                "x_maljan_assessment": {
                    "verdict": "Benign",
                    "severity": {"rating": "Informational", "rationale": "signed and clean"},
                    "malware_category": "legitimate-utility",
                    "confidence": 1.0,
                },
            }
        )
        report = MalwareReportBuilder(
            file_hash="d" * 64,
            file_name="utility.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output=judged.model_dump(mode="json"),
            run_summary={},
            discussion_history=[],
            final_decision="Benign",
            overall_confidence=1.0,
            judge_assessment=judged.x_maljan_assessment,
            malware_category="legitimate-utility",
            evidence_ledger=[],
        ).build_deterministic()
        renderer = ExtendedSTIXRenderer()
        return judged, renderer, renderer.render(report, base_bundle=judged)

    def test_the_stated_verdict_is_what_is_published(self) -> None:
        from maljan.pipeline.outcome import decide_from_bundle

        judged, _renderer, _exported = self._rendered()

        assert decide_from_bundle(judged) == "Benign"

    def test_the_object_is_not_in_the_export(self) -> None:
        _judged, _renderer, exported = self._rendered()

        assert "malware" not in [getattr(obj, "type", "") for obj in exported.objects]

    def test_the_decline_is_recorded_under_its_own_code(self) -> None:
        _judged, renderer, _exported = self._rendered()

        assert [code for code, _why in renderer.declined] == ["stix.malware_object_under_benign"]

    def test_the_judge_own_bundle_still_carries_it(self) -> None:
        judged, _renderer, _exported = self._rendered()

        assert [getattr(obj, "type", "") for obj in judged.objects] == ["malware"]
        assert judged.objects[0].name == "PuTTY"


class TestARelocationMovesAndDoesNotEdit:
    """The fifth: moving the judge's own block to where the schema reads it.

    The block is the judge's words and it arrives complete; what is wrong is
    where in the answer it sits. Moving it is not deciding anything — the
    alternative was failing the whole bundle and extracting a verdict from the
    answer's prose, which is the pipeline deciding — and the move is published
    as settled rather than done quietly.
    """

    @staticmethod
    def _lifted() -> tuple[dict[str, Any], list[Any]]:
        from maljan.agents.judge_postprocess import lift_misplaced_extensions

        block = {
            "type": "x_maljan_assessment",
            "verdict": "Malware",
            "severity": {"rating": "High", "rationale": "it hollows a process"},
            "confidence": 0.8,
        }
        data = {
            "type": "bundle",
            "objects": [
                {
                    "type": "malware",
                    "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "loader",
                },
                block,
            ],
        }
        return data, lift_misplaced_extensions(data)

    def test_the_block_arrives_unchanged(self) -> None:
        data, _found = self._lifted()

        assert data["x_maljan_assessment"]["verdict"] == "Malware"
        assert data["x_maljan_assessment"]["confidence"] == 0.8
        assert data["x_maljan_assessment"]["severity"] == {
            "rating": "High",
            "rationale": "it hollows a process",
        }

    def test_the_move_is_recorded(self) -> None:
        _data, found = self._lifted()

        assert [v.code for v in found] == ["verdict.assessment_relocated"]
        assert found[0].path == "x_maljan_assessment"

    def test_the_objects_beside_it_are_kept(self) -> None:
        data, _found = self._lifted()

        assert [obj["type"] for obj in data["objects"]] == ["malware"]


class TestARejectedIdIsDroppedAndNeverRewritten:
    """The published technique list carries no id the catalogue rejected.

    Dropping a row from what is published is not a rewrite: the id the producer
    wrote is still on the record, in the capability matrix, marked. What must
    never happen is the other thing — the id being silently replaced with one
    that resolves, which is what the re-grounding pass this phase removed did.
    """

    @staticmethod
    def _matrix() -> Any:
        """One claim whose id the analyst's own loop marked unresolvable."""
        from maljan.extractors.capability_matrix import build_capability_matrix
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        claim = ClaimEvidence(
            claim="it hides its own code",
            evidence_ref="[ev_0001] packer signature",
            confidence=0.7,
            technique_id="T0000",
        )
        claim.technique_id_valid = False
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])
        return build_capability_matrix(stix_output=None, isr_reports={"static": isr})

    def test_the_matrix_keeps_the_id_exactly_as_written(self) -> None:
        cells, _mappings = self._matrix()

        assert [(c.technique_id, c.technique_id_valid) for c in cells] == [("T0000", False)]

    def test_the_published_list_carries_no_substitute_for_it(self) -> None:
        _cells, mappings = self._matrix()

        assert mappings == []
