"""What a producer wrote reaches the stored report through one helper.

A violation message is not an event. The publisher scrubs what it emits, and
nothing scrubbed what a producer's own words did on the way into
``run_summary.validation.unresolved`` — which the API stores, ``report.md``
prints and the console's run record draws verbatim. Measured on a judge bundle
whose indicator quoted a URL it had been shown: a 3 219-character
``stix.ungrounded_indicator`` row carrying ``operator:<key>@`` intact, and
three more rows beside it.

``pipeline.events.safe_finding_value`` is the one answer — ``scrub``'s four
passes and a length bound. The tests below check the rows that carry a
producer's text, and then the scan at the bottom closes the class rather than
the instances: it walks every ``Violation`` message this module builds and
fails on an interpolated value that is neither wrapped nor a value this
codebase owns.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Any

from maljan.pipeline.validation import (
    Violation,
    schema_violations,
    validate_isr,
    validate_verdict_bundle,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle
from tests.credential_shapes import prefixed_key
from tests.unit.pipeline.test_validation import _Attck

VALIDATION = pathlib.Path(__file__).resolve().parents[3] / "src/maljan/pipeline/validation.py"

# How long a row may be. ``safe_finding_value`` bounds the value it wraps at
# 200 characters; a message is that plus the sentence around it, and the rows
# this file is about were three thousand.
MESSAGE_LIMIT = 800


def credentialled_url() -> tuple[str, str]:
    """A URL whose userinfo and query both carry a credential shape."""
    secret = prefixed_key("ghs_")
    return secret, f"http://operator:{secret}@evil.example.com/a?token={secret}"


def _messages(violations: list[Violation]) -> str:
    return " ".join(v.message for v in violations)


class TestTheRowsThatQuoteAJudge:
    @staticmethod
    def _bundle(**assessment: Any) -> Bundle:
        secret, url = credentialled_url()
        payload: dict[str, Any] = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                    "pattern": f"[url:value = '{url}{'A' * 3000}']",
                    "pattern_type": "stix",
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332202",
                    "name": f"exfiltration over {url} " + "B" * 3000,
                },
            ]
        }
        if assessment:
            payload["x_maljan_assessment"] = assessment
        return Bundle.model_validate(payload)

    def test_an_ungrounded_indicator_does_not_quote_the_credential(self) -> None:
        secret, _url = credentialled_url()

        violations = validate_verdict_bundle(self._bundle(), evidence_corpus=set())

        row = next(v for v in violations if v.code == "stix.ungrounded_indicator")
        assert secret not in row.message
        assert "operator" not in row.message
        assert len(row.message) < MESSAGE_LIMIT

    def test_an_attack_pattern_with_no_id_does_not_either(self) -> None:
        secret, _url = credentialled_url()

        violations = validate_verdict_bundle(self._bundle(), evidence_corpus=set())

        row = next(v for v in violations if v.code == "attck.missing_id")
        assert secret not in row.message
        assert len(row.message) < MESSAGE_LIMIT

    def test_a_severity_outside_the_enum_does_not_either(self) -> None:
        secret, url = credentialled_url()
        bundle = self._bundle(
            verdict="Malware", severity={"rating": f"{url} {'C' * 3000}", "rationale": "r"}
        )

        violations = validate_verdict_bundle(bundle)

        row = next(v for v in violations if v.code == "verdict.severity_enum")
        assert secret not in row.message
        assert len(row.message) < MESSAGE_LIMIT

    def test_a_family_with_no_evidence_does_not_either(self) -> None:
        secret, url = credentialled_url()
        bundle = self._bundle(
            verdict="Malware", family={"name": f"{url} {'D' * 3000}", "confidence": 0.6}
        )

        violations = validate_verdict_bundle(bundle)

        row = next(v for v in violations if v.code == "attribution.ungrounded_family")
        assert secret not in row.message
        assert len(row.message) < MESSAGE_LIMIT


class TestTheRowsThatQuoteAnAnalyst:
    @staticmethod
    def _isr(**claim: Any) -> AgentISR:
        fields: dict[str, Any] = {"claim": "it exfiltrates", "evidence_ref": "ev_0001"}
        fields.update(claim)
        return AgentISR(agent_id="static", domain="static", claims=[ClaimEvidence(**fields)])

    def test_a_technique_id_the_catalogue_rejects_is_bounded_and_scrubbed(self) -> None:
        """The schema refuses this shape, so it is set the way a stored row carries it.

        The catalogue is the package's stand-in. What is being checked is the
        sentence the row is written with, which is the same one for any
        catalogue that answers "not a technique" — and the real module answers
        it by downloading three STIX bundles and an embedding model, which is
        the thing this package has a named test forbidding.
        """
        secret, url = credentialled_url()
        claim = ClaimEvidence(claim="it hides", evidence_ref="ev_0001", confidence=0.5)
        object.__setattr__(claim, "technique_id", f"T{url}{'E' * 3000}")
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])

        violations = validate_isr(isr, attck=_Attck())

        assert secret not in _messages(violations)
        for row in violations:
            assert len(row.message) < MESSAGE_LIMIT, row.code

    def test_a_confidence_that_is_not_a_number_is_bounded_and_scrubbed(self) -> None:
        secret, url = credentialled_url()
        claim = ClaimEvidence(claim="it exfiltrates", evidence_ref="ev_0001", confidence=0.5)
        object.__setattr__(claim, "confidence", f"{url} {'F' * 3000}")
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])

        violations = validate_isr(isr)

        row = next(v for v in violations if v.code == "isr.confidence_range")
        assert secret not in row.message
        assert len(row.message) < MESSAGE_LIMIT

    def test_a_coercion_failure_is_bounded_and_scrubbed(self) -> None:
        secret, url = credentialled_url()

        class _Model:
            @staticmethod
            def model_validate(payload: Any) -> Any:
                raise RuntimeError(f"{url} {'G' * 3000}")

        violations = schema_violations(_Model, {"a": 1}, code="composer.schema")

        assert secret not in violations[0].message
        assert len(violations[0].message) < MESSAGE_LIMIT


# ---------------------------------------------------------------------------
# The class, rather than the instances
# ---------------------------------------------------------------------------

# The values this codebase owns. Each is either a constant defined here, a
# count, a position, a name the pipeline itself chose, or a catalogue's own
# answer — never a producer's text. A name that is not on this list and not
# wrapped is what the scan exists to catch.
CODE_OWNED: frozenset[str] = frozenset(
    {
        # Vocabularies and constants this module defines or imports.
        "VERDICT_VALUES",
        "SEVERITY_RATINGS",
        "INCONCLUSIVE_VERDICT",
        "ASSESSMENT_PROPERTY",
        "MAX_SUGGESTIONS",
        "listed",
        "shown",
        "hint",
        "named",
        "code",
        "ASSESSMENT_MISSING_MESSAGE",
        # Positions and counts the loops keep.
        "index",
        "count",
        # What the pipeline itself decided about this run.
        "verdict",
        "rating",
        "label",
        "sample_words",
        "expected_domain",
        # The ATT&CK catalogue's own answers about a technique, and the
        # router's own answer about the sample.
        "platforms",
        "expected_platforms",
        "domain",
        "suggestions",
        "ranked",
        "best",
        "c",
        "gate_score",
        "threshold",
        "techniques",
        "keys",
        "grounding",
        # How many hexadecimal characters a digest of a named algorithm has,
        # read out of this codebase's own table.
        "expected",
    }
)

# Functions whose *answer* this codebase owns, whatever they are asked about: a
# catalogue lookup returns the catalogue's words, not the question's.
CODE_OWNED_CALLS: frozenset[str] = frozenset({"_retired_note", "len", "sorted", "int"})

# The functions that build a message for somebody else to put in a Violation.
# Their own f-strings are walked by the same rule, so a ``message=mismatch``
# is not a hole.
MESSAGE_BUILDERS: frozenset[str] = frozenset(
    {
        "platform_mismatch_message",
        "_weak_alignment",
        "_schema_message",
        "_indicator_problem",
        "mismatch",
        "weak",
        "problem",
    }
)

WRAPPER = "safe_finding_value"


def _root_names(node: ast.AST) -> set[str]:
    """Every free variable an expression reads.

    Names only: ``", ".join(platforms)`` reads ``platforms``, and the ``join``
    is a method of a literal rather than a value anybody wrote.
    """
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _is_wrapped(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Call)
        and (getattr(child.func, "id", "") or getattr(child.func, "attr", "")) == WRAPPER
        for child in ast.walk(node)
    )


def _wrapped_locals(function: ast.FunctionDef) -> set[str]:
    """Names this function assigns from an already-wrapped value.

    ``message = safe_finding_value(...)`` two lines above the f-string that
    prints it is the same wrap, and a scan that could not see that would push
    the helper into the f-string for no reason.
    """
    assigned: set[str] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign | ast.AnnAssign) or node.value is None:
            continue
        if not _is_wrapped(node.value):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        assigned.update(t.id for t in targets if isinstance(t, ast.Name))
    return assigned


def _is_code_owned(node: ast.AST, wrapped: frozenset[str] | set[str] = frozenset()) -> bool:
    """Whether the expression's value is one this codebase owns.

    A call to a function whose answer this codebase writes is owned however its
    argument was obtained: ``_retired_note(tid, attck)`` answers a catalogue
    release, not the technique id it was asked about.
    """
    if (
        isinstance(node, ast.Call)
        and (getattr(node.func, "id", "") or getattr(node.func, "attr", "")) in CODE_OWNED_CALLS
    ):
        return True
    names = _root_names(node)
    if not names:
        return True  # a literal, a count, or a join of constants
    return names <= CODE_OWNED | MESSAGE_BUILDERS | set(wrapped)


def _message_expressions(function: ast.FunctionDef) -> list[ast.expr]:
    """The expressions this function turns into a violation message.

    For a function that builds a message for somebody else, that is everything
    it says; for a function that constructs a ``Violation``, it is the
    ``message`` it passes, and not the ``path`` beside it — a path is a
    position this pipeline chose.
    """
    if function.name in MESSAGE_BUILDERS:
        return [function]
    found: list[ast.expr] = []
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Violation"):
            continue
        found.extend(kw.value for kw in node.keywords if kw.arg == "message")
    return found


def _interpolations(function: ast.FunctionDef) -> list[ast.expr]:
    """Every value the messages of this function substitute."""
    return [
        node.value
        for expression in _message_expressions(function)
        for node in ast.walk(expression)
        if isinstance(node, ast.FormattedValue)
    ]


def _functions_that_matter(tree: ast.AST) -> list[ast.FunctionDef]:
    """The functions that build a Violation, plus the ones that build a message."""
    found: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name in MESSAGE_BUILDERS:
            found.append(node)
            continue
        if any(
            isinstance(child, ast.Call) and getattr(child.func, "id", "") == "Violation"
            for child in ast.walk(node)
        ):
            found.append(node)
    return found


class TestEveryRowIsHeldToTheSameRule:
    """The scan, and the proof that it is looking at something."""

    @staticmethod
    def _tree() -> ast.AST:
        return ast.parse(VALIDATION.read_text(encoding="utf-8"), filename=str(VALIDATION))

    def test_it_inspects_the_module_it_claims_to(self) -> None:
        functions = _functions_that_matter(self._tree())

        assert len(functions) >= 8, "the scan found almost nothing to look at"
        assert sum(len(_interpolations(f)) for f in functions) >= 20

    def test_no_interpolated_value_escapes_the_helper(self) -> None:
        offences: list[str] = []
        for function in _functions_that_matter(self._tree()):
            wrapped = _wrapped_locals(function)
            for value in _interpolations(function):
                if _is_wrapped(value) or _is_code_owned(value, wrapped):
                    continue
                offences.append(f"{function.name}:{value.lineno}: {ast.unparse(value)}")

        assert not offences, (
            "These put a value into a finding row without passing it through "
            f"``{WRAPPER}``. A row is stored with the report and printed on the "
            "analysis page, so a producer's own text goes through the helper; a "
            "value this codebase owns goes on CODE_OWNED with a reason:\n  " + "\n  ".join(offences)
        )

    def test_a_message_nothing_built_here_comes_from_a_builder(self) -> None:
        """``message=mismatch`` is only safe because the builder is walked too."""
        offences: list[str] = []
        for node in ast.walk(self._tree()):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Violation"):
                continue
            message = next((kw.value for kw in node.keywords if kw.arg == "message"), None)
            if message is None or isinstance(message, ast.JoinedStr | ast.Constant):
                continue
            if _is_wrapped(message) or _is_code_owned(message):
                continue
            called = getattr(getattr(message, "func", None), "id", "")
            if called in MESSAGE_BUILDERS:
                continue
            offences.append(f"{node.lineno}: {ast.unparse(message)}")

        assert not offences, (
            "A Violation message that is neither a literal, an f-string checked "
            "above, a wrapped value nor a message builder walked by this scan:\n  "
            + "\n  ".join(offences)
        )

    def test_the_scan_catches_a_row_that_slips_through(self) -> None:
        """The scan passes trivially if it is broken, so prove it is not."""
        source = (
            "def leak(model_text):\n"
            "    return Violation(code='x', message=f'the model said {model_text}')\n"
        )
        tree = ast.parse(source)

        functions = _functions_that_matter(tree)
        offences = [
            ast.unparse(value)
            for function in functions
            for value in _interpolations(function)
            if not (_is_wrapped(value) or _is_code_owned(value))
        ]

        assert offences == ["model_text"]
