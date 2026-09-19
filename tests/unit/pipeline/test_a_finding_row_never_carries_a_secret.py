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
from tests.unit.pipeline._source_names import called_name, names_reaching
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
# The constructor of a stored finding row. Never compared as a bare spelling:
# ``from ... import Violation as Finding`` renames it and a walk keyed on the
# one spelling goes quiet on the whole module. ``tests/unit/pipeline``'s other
# source guard was told the same thing about its own helper and the resolution
# is shared with it.
CONSTRUCTOR = "Violation"


def _source(name: str) -> pathlib.Path:
    return SRC / name


def _tree_of(name: str) -> ast.AST:
    path = _source(name)
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


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
        isinstance(child, ast.Call) and called_name(child) == WRAPPER for child in ast.walk(node)
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
    if isinstance(node, ast.Call) and called_name(node) in CODE_OWNED_CALLS:
        return True
    names = _root_names(node)
    if not names:
        return True  # a literal, a count, or a join of constants
    return names <= set(owned)


def _value_is_owned(node: ast.AST, owned: frozenset[str] | set[str]) -> bool:
    """Whether the text this expression produces is this codebase's own."""
    if _is_wrapped(node):
        return True
    if isinstance(node, ast.Call) and called_name(node) in MESSAGE_BUILDERS | CODE_OWNED_CALLS:
        return True
    if _is_text_expression(node):
        return all(
            _value_is_owned(part.value, owned)
            for part in ast.walk(node)
            if isinstance(part, ast.FormattedValue)
        )
    return _is_code_owned(node, owned)


# A binding with nothing to read: a parameter, a loop or comprehension target,
# a ``with`` or ``except`` name, a nested definition. Whatever it holds came
# from outside this function's own text, so the name is not this codebase's
# however it is spelled.
OPAQUE = object()
# A binding whose value is another module's own source.
IMPORTED = object()


def _bindings(function: ast.FunctionDef) -> dict[str, list[Any]]:
    """Every name this function binds, and what each binding was given.

    The value is the expression assigned, :data:`IMPORTED` for a name an import
    binds, or :data:`OPAQUE` for a binding with no expression to read.
    Collected so that a name can be *revoked*: ownership that only grows means
    a local spelled like one of the 251 names the walked modules bind at their
    top level — ``scrub``, ``reason_sentence``, ``corroboration_row`` — is
    trusted for its spelling, which is the rule this file exists to refuse.
    """
    found: dict[str, list[Any]] = {}

    def _bind(name: str, value: Any) -> None:
        found.setdefault(name, []).append(value)

    def _targets(node: ast.AST, value: Any) -> None:
        """Bind what this target binds, and nothing it merely reads.

        ``rows[name] = x`` and ``obj.field = x`` bind neither ``name`` nor
        ``field``: they read one and write through the other, and treating the
        index as a binding revoked a constant a function had imported.
        """
        if isinstance(node, ast.Name):
            _bind(node.id, value)
        elif isinstance(node, ast.Tuple | ast.List):
            for element in node.elts:
                _targets(element, value)
        elif isinstance(node, ast.Starred):
            _targets(node.value, value)

    for node in ast.walk(function):
        if isinstance(node, ast.arg):
            _bind(node.arg, OPAQUE)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                _bind(alias.asname or alias.name.split(".")[0], IMPORTED)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                _targets(target, node.value)
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            if isinstance(node.target, ast.Name):
                _bind(node.target.id, node.value if node.value is not None else OPAQUE)
        elif isinstance(node, ast.NamedExpr):
            _bind(node.target.id, node.value)
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            _targets(node.target, OPAQUE)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                _targets(node.optional_vars, OPAQUE)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            _bind(node.name, OPAQUE)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if node is not function:
                _bind(node.name, OPAQUE)
    return found


def _owned_locals(
    function: ast.FunctionDef, owned: frozenset[str], bindings: dict[str, list[Any]]
) -> set[str]:
    """Names this function binds whose every binding this codebase owns.

    ``message = safe_finding_value(...)`` two lines above the f-string that
    prints it is the same wrap, and a scan that could not see that would push
    the helper into the f-string for no reason. ``why = f"…{OWN_CONSTANT}…"``
    is the same thing said with a constant, and ``mismatch =
    platform_mismatch_message(...)`` is the builder's own guarantee — which is
    what makes it safe, not the name it was given. A name the function imports
    is owned for the reason a module-level one is: it is another module's own
    source, and half the vocabularies these sentences quote are imported where
    they are used.

    *Every* binding, because one of them is enough to carry a producer's text:
    a name given a constant on one line and a model's answer on the next is
    this codebase's on neither.
    """
    assigned: set[str] = set()
    for _round in range(len(bindings) + 1):
        before = len(assigned)
        for name, values in bindings.items():
            if name in assigned:
                continue
            if all(
                value is IMPORTED
                or (value is not OPAQUE and _value_is_owned(value, owned | assigned))
                for value in values
            ):
                assigned.add(name)
        if len(assigned) == before:
            break
    return assigned


def _message_expressions(
    function: ast.FunctionDef, constructors: frozenset[str] | set[str]
) -> list[ast.expr]:
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
        if not (isinstance(node, ast.Call) and called_name(node) in constructors):
            continue
        found.extend(_violation_messages(node))
    return found


def _violation_messages(node: ast.Call) -> list[ast.expr]:
    """The message one ``Violation(...)`` carries, keyword or positional."""
    found = [kw.value for kw in node.keywords if kw.arg == "message"]
    if len(node.args) >= 2:
        found.append(node.args[1])
    return found


def _interpolations(
    function: ast.FunctionDef, constructors: frozenset[str] | set[str]
) -> list[ast.expr]:
    """Every value the messages of this function substitute."""
    return [
        node.value
        for expression in _message_expressions(function, constructors)
        for node in ast.walk(expression)
        if isinstance(node, ast.FormattedValue)
    ]


def _functions_that_matter(
    tree: ast.AST, constructors: frozenset[str] | set[str]
) -> list[ast.FunctionDef]:
    """The functions that build a Violation, plus the ones that build a message."""
    found: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name in MESSAGE_BUILDERS:
            found.append(node)
            continue
        if any(
            isinstance(child, ast.Call) and called_name(child) in constructors
            for child in ast.walk(node)
        ):
            found.append(node)
    return found


def _builds_a_row(tree: ast.AST) -> bool:
    """Whether this module constructs a finding row, under any name it gave it."""
    constructors = names_reaching(tree, CONSTRUCTOR)
    return any(
        isinstance(node, ast.Call) and called_name(node) in constructors for node in ast.walk(tree)
    )


def _owned_for(function: ast.FunctionDef, module: frozenset[str]) -> frozenset[str]:
    """Every name whose value this codebase owns *where this function reads it*.

    A module-level name is owned until the function binds that spelling itself.
    Then the binding is what reaches the interpolation, and only the binding can
    say whether the text is this repository's — which is why a local is asked
    about its value and never about its name.
    """
    bindings = _bindings(function)
    # ``CODE_OWNED`` survives a binding and the module's own names do not, and
    # the difference is who vouched for what. Each name on ``CODE_OWNED`` is a
    # local somebody read and wrote a reason for. A module-level name is owned
    # because of where it is *bound*, so a function that binds that spelling
    # itself is reading something else entirely — and there are 251 of those
    # spellings across the walked modules, several of them ordinary lowercase
    # words a function would reach for.
    vouched = CODE_OWNED | OWNED_IN.get(function.name, frozenset())
    outer = frozenset(vouched | ((BUILTIN_NAMES | module) - set(bindings)))
    return outer | frozenset(_owned_locals(function, outer, bindings))


class TestEveryRowIsHeldToTheSameRule:
    """The scan, and the proof that it is looking at something."""

    def test_it_walks_every_module_that_builds_one(self) -> None:
        elsewhere = sorted(
            str(path.relative_to(SRC))
            for path in SRC.rglob("*.py")
            if _builds_a_row(ast.parse(path.read_text(encoding="utf-8")))
            and str(path.relative_to(SRC)) not in WALKED
        )

        assert not elsewhere, (
            "These build a finding row and no scan looks at them. Add them to "
            "WALKED:\n  " + "\n  ".join(elsewhere)
        )

    def test_it_inspects_the_modules_it_claims_to(self) -> None:
        found: list[tuple[ast.FunctionDef, set[str]]] = []
        for name in WALKED:
            tree = _tree_of(name)
            constructors = names_reaching(tree, CONSTRUCTOR)
            found += [(f, constructors) for f in _functions_that_matter(tree, constructors)]

        assert len(found) >= 13, "the scan found almost nothing to look at"
        assert sum(len(_interpolations(f, c)) for f, c in found) >= 20

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
            constructors = names_reaching(tree, CONSTRUCTOR)
            for function in _functions_that_matter(tree, constructors):
                owned = _owned_for(function, module)
                for value in _interpolations(function, constructors):
                    if _is_wrapped(value) or _is_code_owned(value, owned):
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
            constructors = names_reaching(tree, CONSTRUCTOR)
            for function in _functions_that_matter(tree, constructors):
                owned = _owned_for(function, module)
                for node in ast.walk(function):
                    if not (isinstance(node, ast.Call) and called_name(node) in constructors):
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

    def test_it_catches_one_built_under_an_alias(self) -> None:
        """A renaming import used to take the whole module out of the scan."""
        source = (
            "from maljan.pipeline.validation import Violation as V\n"
            "def leak(model_text):\n"
            "    return V('x', f'said {model_text}')\n"
        )

        assert self._offences(source) == ["model_text"]
        assert _builds_a_row(ast.parse(source))

    def test_it_catches_one_built_through_a_module_alias(self) -> None:
        source = (
            "from maljan.pipeline import validation as val\n"
            "def leak(model_text):\n"
            "    return val.Violation('x', f'said {model_text}')\n"
        )

        assert self._offences(source) == ["model_text"]
        assert _builds_a_row(ast.parse(source))

    def test_it_does_not_trust_a_local_spelled_like_a_builder(self) -> None:
        """A name on MESSAGE_BUILDERS used to make any local of that name safe."""
        source = (
            "def leak(model_text):\n    problem = model_text\n    return Violation('x', problem)\n"
        )

        assert self._message_offences(source) == ["problem"]

    def test_it_does_not_trust_a_local_spelled_like_a_module_constant(self) -> None:
        """Ownership that only grows trusts a local for the name it borrowed."""
        source = (
            "OWN = 'constant'\n"
            "def leak(model_text):\n"
            "    OWN = model_text\n"
            "    return Violation('x', f'said {OWN}')\n"
        )

        assert self._offences(source) == ["OWN"]

    def test_a_name_given_a_constant_and_then_a_producer_s_text_is_neither(self) -> None:
        source = (
            "OWN = 'constant'\n"
            "def leak(model_text):\n"
            "    OWN = 'still ours'\n"
            "    OWN = model_text\n"
            "    return Violation('x', f'said {OWN}')\n"
        )

        assert self._offences(source) == ["OWN"]

    def test_a_loop_target_that_borrows_a_module_name_is_not_owned(self) -> None:
        source = (
            "STEP = 'constant'\n"
            "def leak(rows):\n"
            "    for STEP in rows:\n"
            "        return Violation('x', f'said {STEP}')\n"
        )

        assert self._offences(source) == ["STEP"]

    def test_an_except_target_that_borrows_a_module_name_is_not_owned(self) -> None:
        source = (
            "WHERE = 'constant'\n"
            "def leak():\n"
            "    try:\n"
            "        pass\n"
            "    except ValueError as WHERE:\n"
            "        return Violation('x', f'said {WHERE}')\n"
        )

        assert self._offences(source) == ["WHERE"]

    def test_a_with_target_that_borrows_a_module_name_is_not_owned(self) -> None:
        source = (
            "SEEN = 'constant'\n"
            "def leak(opened):\n"
            "    with opened as SEEN:\n"
            "        return Violation('x', f'said {SEEN}')\n"
        )

        assert self._offences(source) == ["SEEN"]

    def test_a_walrus_that_borrows_a_module_name_is_not_owned(self) -> None:
        source = (
            "TALLY = 'constant'\n"
            "def leak(model_text):\n"
            "    return Violation('x', f'said {(TALLY := model_text)}')\n"
        )

        assert "TALLY := model_text" in " ".join(self._offences(source))

    def test_a_comprehension_target_that_borrows_a_module_name_is_not_owned(self) -> None:
        source = (
            "PLACE = 'constant'\n"
            "def leak(rows):\n"
            "    said = ', '.join(PLACE for PLACE in rows)\n"
            "    return Violation('x', f'said {said}')\n"
        )

        assert self._offences(source) == ["said"]

    def test_it_reads_a_row_built_inside_a_nested_function(self) -> None:
        source = (
            "def outer(model_text):\n"
            "    def inner():\n"
            "        return Violation('x', f'said {model_text}')\n"
            "    return inner\n"
        )

        assert self._offences(source) == ["model_text", "model_text"]

    def test_it_reads_a_row_built_in_a_class_body_s_method(self) -> None:
        source = (
            "MARK = 'constant'\n"
            "class Rows:\n"
            "    def build(self, model_text):\n"
            "        MARK = model_text\n"
            "        return Violation('x', f'said {MARK}')\n"
        )

        assert self._offences(source) == ["MARK"]

    @staticmethod
    def _scan(source: str) -> tuple[ast.AST, frozenset[str], set[str]]:
        tree = ast.parse(source)
        return tree, _module_names(tree), names_reaching(tree, CONSTRUCTOR)

    def _offences(self, source: str) -> list[str]:
        """Every interpolated value the scan would refuse in this source."""
        tree, module, constructors = self._scan(source)
        found: list[str] = []
        for function in _functions_that_matter(tree, constructors):
            owned = _owned_for(function, module)
            for value in _interpolations(function, constructors):
                if _is_wrapped(value) or _is_code_owned(value, owned):
                    continue
                found.append(ast.unparse(value))
        return found

    def _message_offences(self, source: str) -> list[str]:
        """Every whole message the scan would refuse in this source."""
        tree, module, constructors = self._scan(source)
        found: list[str] = []
        for function in _functions_that_matter(tree, constructors):
            owned = _owned_for(function, module)
            for node in ast.walk(function):
                if not (isinstance(node, ast.Call) and called_name(node) in constructors):
                    continue
                for message in _violation_messages(node):
                    if isinstance(message, ast.JoinedStr | ast.Constant):
                        continue
                    if _value_is_owned(message, owned):
                        continue
                    found.append(ast.unparse(message))
        return found
