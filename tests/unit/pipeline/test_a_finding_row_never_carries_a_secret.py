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
the instances: it walks every ``Violation`` message every module in the tree
builds — keyword or positional — and fails on an interpolated value that is
neither wrapped nor a value this codebase owns. It read one module and one
keyword before, so seven construction sites in four other modules were never
looked at and a row written as ``Violation(code, message)`` was invisible.
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

SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"

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

# Every module in the tree that builds one. The scan used to read
# ``validation.py`` alone, and seven of the sites are in four other modules.
WALKED: tuple[str, ...] = (
    "pipeline/validation.py",
    "pipeline/nodes.py",
    "agents/delegation.py",
    "agents/judge_agent.py",
    "agents/judge_postprocess.py",
)

# The values this codebase owns. Each is either a constant defined here, a
# count, a position, a name the pipeline itself chose, or a catalogue's own
# answer — never a producer's text. A name that is not on this list and not
# wrapped is what the scan exists to catch. Anything bound at a module's top
# level is owned without being listed: it is this repository's own source text.
CODE_OWNED: frozenset[str] = frozenset(
    {
        # Names the walked modules bind inside a function.
        "listed",
        "shown",
        "hint",
        "named",
        "code",
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

# A builtin that answers about its argument in this interpreter's own words: a
# length, an order, a number. Whatever it is asked about, what comes back is
# not the question's text.
BUILTIN_ANSWERS: frozenset[str] = frozenset({"len", "sorted", "int"})

# Builtins that are a name in an expression rather than an answer of their own.
# ``str(x)`` gives back exactly what ``x`` said, so the name is owned and the
# argument is still asked.
BUILTIN_NAMES: frozenset[str] = BUILTIN_ANSWERS | frozenset(
    {"str", "float", "abs", "min", "max", "repr", "frozenset", "set", "tuple", "list", "dict"}
)

# Functions whose *answer* this codebase owns, whatever they are asked about: a
# catalogue lookup returns the catalogue's words, not the question's.
CODE_OWNED_CALLS: frozenset[str] = frozenset({"_retired_note"}) | BUILTIN_ANSWERS

# The functions that build a message for somebody else to put in a Violation.
# Their own f-strings are walked by the same rule, so a ``message=mismatch`` is
# not a hole — and the *name* is not what makes it safe: a local spelled like
# one of these is a local, and only an assignment from a call to one of them
# carries the builder's own guarantee.
MESSAGE_BUILDERS: frozenset[str] = frozenset(
    {
        "platform_mismatch_message",
        "_weak_alignment",
        "_schema_message",
        "_indicator_problem",
    }
)

# The two functions that copy a message some other ``Violation`` already wrote,
# with the names that carry it. Neither builds a row out of a producer's text:
# they rebuild a row this scan has already held to the rule, off a state
# channel or off a callee's own validation state, and wrapping the message
# again would cut a legitimate eight-hundred-character sentence to two hundred.
OWNED_IN: dict[str, frozenset[str]] = {
    # ``row`` is one violation's own dict, put on the state channel by an
    # analyst node that built it as a Violation.
    "_violations_from_rows": frozenset({"row"}),
    # The same rows, drained off a callee, with the callee named in front of
    # them. ``callee.name`` is an agent key an operator typed, which the scrub
    # leaves alone deliberately.
    "_hand_over_the_record": frozenset({"row", "callee"}),
}

WRAPPER = "safe_finding_value"


def _source(name: str) -> pathlib.Path:
    return SRC / name


def _tree_of(name: str) -> ast.AST:
    path = _source(name)
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _called(node: ast.AST) -> str:
    """The name a call calls, however it is spelled."""
    func = getattr(node, "func", None)
    return getattr(func, "id", "") or getattr(func, "attr", "")


def _root_names(node: ast.AST) -> set[str]:
    """Every free variable an expression reads.

    Names only: ``", ".join(platforms)`` reads ``platforms``, and the ``join``
    is a method of a literal rather than a value anybody wrote.
    """
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _module_names(tree: ast.AST) -> frozenset[str]:
    """Everything a module binds at its top level: imports and constants.

    A module-level binding is this repository's own source — a vocabulary, a
    sentence, a compiled expression, a table. A producer's text arrives as an
    argument, never as a global, and none of the walked modules rebinds one.
    """
    found: set[str] = set()
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            found.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            found.add(node.target.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            found.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return frozenset(found)


def _is_wrapped(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Call) and _called(child) == WRAPPER for child in ast.walk(node)
    )


def _is_text_expression(node: ast.AST) -> bool:
    """Whether every character this expression produces comes from a literal or
    from a substitution this scan can see."""
    if isinstance(node, ast.JoinedStr | ast.Constant):
        return True
    if isinstance(node, ast.IfExp):
        return _is_text_expression(node.body) and _is_text_expression(node.orelse)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_text_expression(node.left) and _is_text_expression(node.right)
    return False


def _is_code_owned(node: ast.AST, owned: frozenset[str] | set[str]) -> bool:
    """Whether the expression's value is one this codebase owns.

    A call to a function whose answer this codebase writes is owned however its
    argument was obtained: ``_retired_note(tid, attck)`` answers a catalogue
    release, not the technique id it was asked about.
    """
    if isinstance(node, ast.Call) and _called(node) in CODE_OWNED_CALLS:
        return True
    names = _root_names(node)
    if not names:
        return True  # a literal, a count, or a join of constants
    return names <= set(owned)


def _value_is_owned(node: ast.AST, owned: frozenset[str] | set[str]) -> bool:
    """Whether the text this expression produces is this codebase's own."""
    if _is_wrapped(node):
        return True
    if isinstance(node, ast.Call) and _called(node) in MESSAGE_BUILDERS | CODE_OWNED_CALLS:
        return True
    if _is_text_expression(node):
        return all(
            _value_is_owned(part.value, owned)
            for part in ast.walk(node)
            if isinstance(part, ast.FormattedValue)
        )
    return _is_code_owned(node, owned)


def _owned_locals(function: ast.FunctionDef, owned: frozenset[str]) -> set[str]:
    """Names this function assigns from a value whose text this codebase owns.

    ``message = safe_finding_value(...)`` two lines above the f-string that
    prints it is the same wrap, and a scan that could not see that would push
    the helper into the f-string for no reason. ``why = f"…{OWN_CONSTANT}…"``
    is the same thing said with a constant, and ``mismatch =
    platform_mismatch_message(...)`` is the builder's own guarantee — which is
    what makes it safe, not the name it was given.
    """
    assigned: set[str] = {
        alias.asname or alias.name.split(".")[0]
        for node in ast.walk(function)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    for _round in range(3):
        before = len(assigned)
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign | ast.AnnAssign) or node.value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if not names or names <= assigned:
                continue
            if _value_is_owned(node.value, owned | assigned):
                assigned |= names
        if len(assigned) == before:
            break
    return assigned


def _message_expressions(function: ast.FunctionDef) -> list[ast.expr]:
    """The expressions this function turns into a violation message.

    For a function that builds a message for somebody else, that is everything
    it says; for a function that constructs a ``Violation``, it is the
    ``message`` it passes, and not the ``path`` beside it — a path is a
    position this pipeline chose. Positionally too: ``Violation(code, message)``
    is the same row written without the keywords, and the scan read the keyword
    alone.
    """
    if function.name in MESSAGE_BUILDERS:
        return [function]
    found: list[ast.expr] = []
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and _called(node) == "Violation"):
            continue
        found.extend(_violation_messages(node))
    return found


def _violation_messages(node: ast.Call) -> list[ast.expr]:
    """The message one ``Violation(...)`` carries, keyword or positional."""
    found = [kw.value for kw in node.keywords if kw.arg == "message"]
    if len(node.args) >= 2:
        found.append(node.args[1])
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
            isinstance(child, ast.Call) and _called(child) == "Violation"
            for child in ast.walk(node)
        ):
            found.append(node)
    return found


def _owned_for(function: ast.FunctionDef, module: frozenset[str]) -> frozenset[str]:
    return frozenset(CODE_OWNED | BUILTIN_NAMES | module | OWNED_IN.get(function.name, frozenset()))


class TestEveryRowIsHeldToTheSameRule:
    """The scan, and the proof that it is looking at something."""

    def test_it_walks_every_module_that_builds_one(self) -> None:
        elsewhere = sorted(
            str(path.relative_to(SRC))
            for path in SRC.rglob("*.py")
            if any(
                isinstance(node, ast.Call) and _called(node) == "Violation"
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            )
            and str(path.relative_to(SRC)) not in WALKED
        )

        assert not elsewhere, (
            "These build a finding row and no scan looks at them. Add them to "
            "WALKED:\n  " + "\n  ".join(elsewhere)
        )

    def test_it_inspects_the_modules_it_claims_to(self) -> None:
        functions = [f for name in WALKED for f in _functions_that_matter(_tree_of(name))]

        assert len(functions) >= 13, "the scan found almost nothing to look at"
        assert sum(len(_interpolations(f)) for f in functions) >= 20

    def test_every_message_builder_it_trusts_is_one_of_these_functions(self) -> None:
        defined = {
            node.name
            for name in WALKED
            for node in ast.walk(_tree_of(name))
            if isinstance(node, ast.FunctionDef)
        }

        assert MESSAGE_BUILDERS <= defined, sorted(MESSAGE_BUILDERS - defined)

    def test_no_interpolated_value_escapes_the_helper(self) -> None:
        offences: list[str] = []
        for name in WALKED:
            tree = _tree_of(name)
            module = _module_names(tree)
            for function in _functions_that_matter(tree):
                owned = _owned_for(function, module)
                wrapped = _owned_locals(function, owned)
                for value in _interpolations(function):
                    if _is_wrapped(value) or _is_code_owned(value, owned | wrapped):
                        continue
                    offences.append(f"{name}:{value.lineno} {function.name}: {ast.unparse(value)}")

        assert not offences, (
            "These put a value into a finding row without passing it through "
            f"``{WRAPPER}``. A row is stored with the report and printed on the "
            "analysis page, so a producer's own text goes through the helper; a "
            "value this codebase owns goes on CODE_OWNED with a reason:\n  " + "\n  ".join(offences)
        )

    def test_a_message_nothing_built_here_comes_from_a_builder(self) -> None:
        """``message=mismatch`` is only safe because the builder is walked too."""
        offences: list[str] = []
        for name in WALKED:
            tree = _tree_of(name)
            module = _module_names(tree)
            for function in _functions_that_matter(tree):
                owned = _owned_for(function, module) | _owned_locals(
                    function, _owned_for(function, module)
                )
                for node in ast.walk(function):
                    if not (isinstance(node, ast.Call) and _called(node) == "Violation"):
                        continue
                    for message in _violation_messages(node):
                        if isinstance(message, ast.JoinedStr | ast.Constant):
                            continue
                        if _value_is_owned(message, owned):
                            continue
                        offences.append(f"{name}:{node.lineno}: {ast.unparse(message)}")

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

        assert self._offences(source) == ["model_text"]

    def test_it_catches_one_written_without_the_keywords(self) -> None:
        """``Violation(code, message)`` is the same row, and was never read."""
        source = (
            "def leak(model_text):\n"
            "    return Violation('x', f'the model said {model_text}', 'objects')\n"
        )

        assert self._offences(source) == ["model_text"]

    def test_it_does_not_trust_a_local_spelled_like_a_builder(self) -> None:
        """A name on MESSAGE_BUILDERS used to make any local of that name safe."""
        source = (
            "def leak(model_text):\n    problem = model_text\n    return Violation('x', problem)\n"
        )
        tree = ast.parse(source)
        module = _module_names(tree)

        offences = [
            ast.unparse(message)
            for function in _functions_that_matter(tree)
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and _called(node) == "Violation"
            for message in _violation_messages(node)
            if not _value_is_owned(
                message,
                _owned_for(function, module)
                | _owned_locals(function, _owned_for(function, module)),
            )
        ]

        assert offences == ["problem"]

    @staticmethod
    def _offences(source: str) -> list[str]:
        tree = ast.parse(source)
        module = _module_names(tree)
        found: list[str] = []
        for function in _functions_that_matter(tree):
            owned = _owned_for(function, module)
            wrapped = _owned_locals(function, owned)
            for value in _interpolations(function):
                if _is_wrapped(value) or _is_code_owned(value, owned | wrapped):
                    continue
                found.append(ast.unparse(value))
        return found
