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

# The values this codebase owns, per place. A bare spelling vouched for a name
# wherever it appeared, so ``label``, ``code``, ``best``, ``keys`` and nine
# other ordinary words were owned in every walked function at once — and a
# function nobody reviewed would reach for exactly those words. The facts
# behind each entry were always per-function; the key says so, and a name is
# owned only where somebody read it.
#
# Each is a constant defined here, a count, a position, a value bounded by a
# membership test against one of this repository's own tables, or a
# catalogue's own answer — never a producer's text. A name that is not here
# and not wrapped is what the scan exists to catch. Anything bound at a
# module's top level is owned without being listed: it is this repository's own
# source text.
CODE_OWNED: dict[tuple[str, str], frozenset[str]] = {
    # The ATT&CK catalogue's own answers about a technique, and the router's
    # own answer about the sample. Neither quotes the producer.
    ("pipeline/validation.py", "platform_mismatch_message"): frozenset(
        {"platforms", "expected_platforms", "domain", "expected_domain"}
    ),
    # A join of this module's own vocabulary of unsupported claims.
    ("pipeline/validation.py", "unsupported_benign_violations"): frozenset({"listed"}),
    ("pipeline/validation.py", "unsupported_malware_violations"): frozenset({"listed"}),
    # The pipeline's own pick of which evidence id to show, and the
    # catalogue's own nearest technique ids to the one the analyst wrote.
    ("pipeline/validation.py", "validate_isr"): frozenset({"shown", "suggestions"}),
    # The gate's own score, the threshold it was compared with, and the
    # catalogue rows it ranked — numbers and this codebase's own rows.
    ("pipeline/validation.py", "_weak_alignment"): frozenset(
        {"ranked", "best", "c", "gate_score", "threshold"}
    ),
    # The technique ids the grounding check itself collected, the check's own
    # label for what it was looking for, and its own counted answer.
    ("pipeline/validation.py", "ungrounded_capabilities"): frozenset(
        {"techniques", "label", "grounding"}
    ),
    # The field names of this repository's own schema.
    ("pipeline/validation.py", "_schema_message"): frozenset({"keys"}),
    # How many hexadecimal characters a digest of a named algorithm has, read
    # out of this codebase's own table.
    ("pipeline/validation.py", "_indicator_problem"): frozenset({"expected"}),
    # ``verdict`` is the pipeline's own reading of the bundle
    # (``decide_from_bundle``). ``rating`` is the judge's own word and is NOT
    # the pipeline's: it reaches the sentence unwrapped, and what bounds it is
    # the line above, which requires it to be a member of
    # ``_CONFLICTING_RATINGS`` — one of this repository's own frozensets. A
    # membership test against a fixed table is what makes it safe, and any
    # change that drops the test takes the reason with it.
    ("pipeline/validation.py", "assessment_conflict_violations"): frozenset({"verdict", "rating"}),
    # A position in a list this function is walking.
    ("agents/judge_postprocess.py", "lift_misplaced_extensions"): frozenset({"index"}),
    # The corpus's own tally of what it could not hold: a count it incremented
    # itself. The tool names beside it are wrapped, because a tool name comes
    # from a server rather than from this repository.
    ("pipeline/validation.py", "partial_evidence_note"): frozenset({"state"}),
}

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
# ``_object_path`` answers with a position this codebase counted and the
# judge's label, which it passes through ``safe_finding_value`` itself.
# ``_object_problem`` answers in the same way: its sentence is this codebase's,
# and every value of the judge's it quotes goes through the helper inside it.
CODE_OWNED_CALLS: frozenset[str] = (
    frozenset({"_retired_note", "_object_path", "_object_problem"}) | BUILTIN_ANSWERS
)

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
        "joined_within_the_bound",
        "shortened_evidence_note",
        "partial_evidence_note",
    }
)

# The two functions that copy a message some other ``Violation`` already wrote,
# with the names that carry it. Neither builds a row out of a producer's text:
# they rebuild a row this scan has already held to the rule, off a state
# channel or off a callee's own validation state, and wrapping the message
# again would cut a legitimate eight-hundred-character sentence to two hundred.
OWNED_IN: dict[tuple[str, str], frozenset[str]] = {
    # ``row`` is one violation's own dict, put on the state channel by an
    # analyst node that built it as a Violation.
    ("pipeline/nodes.py", "_violations_from_rows"): frozenset({"row"}),
    # The same rows, drained off a callee, with the callee named in front of
    # them. ``callee.name`` is an agent key an operator typed, which the scrub
    # leaves alone deliberately.
    ("agents/delegation.py", "_hand_over_the_record"): frozenset({"row", "callee"}),
    # The same two facts one function further down: ``message`` is a row a
    # walked validator wrote, already wrapped and already bounded, and
    # ``name`` is the agent key. This function writes no sentence of its own —
    # it puts the name in front and cuts the route when the whole grows past
    # the limit the rows are held to.
    ("agents/delegation.py", "joined_within_the_bound"): frozenset(
        {"sentence", "route", "kept", "steps", "whole", "step", "chain"}
    ),
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
        if not _is_row_call(node, constructors):
            continue
        found.extend(_violation_messages(node))
    return found


def _violation_messages(node: ast.Call) -> list[ast.expr]:
    """The message one row construction carries, however it was written.

    Keyword, positional, or a whole mapping splatted in: ``Violation(**payload)``
    is a row whose message this scan cannot see, so the mapping itself is what
    it asks about. A ``payload`` built out of literals and owned values passes;
    one built out of a producer's answer does not, which is the same rule the
    keyword form is held to.
    """
    found = [kw.value for kw in node.keywords if kw.arg == "message"]
    found += [kw.value for kw in node.keywords if kw.arg is None]
    found += [kw.value for kw in node.keywords if kw.arg == "update"]
    if len(node.args) >= 2:
        found.append(node.args[1])
    return found


# The rewriters: a call that writes a new row off an old one rather than
# constructing one. ``dataclasses.replace`` and pydantic's ``model_copy`` are
# the two this tree can reach. Identified by the keyword they carry rather than
# by their name alone, so ``str.replace`` and an ordinary ``model_copy`` are
# not mistaken for one.
REWRITERS: frozenset[str] = frozenset({"replace", "model_copy"})


def _writes_a_message(node: ast.Call) -> bool:
    """Whether this rewriting call sets a row's ``message``.

    Three spellings: the keyword, a mapping splatted into it, and
    ``model_copy(update={...})``. A rewriter whose message this scan cannot
    see is one it asks about, exactly as it asks about ``Violation(**payload)``.
    """
    for keyword in node.keywords:
        if keyword.arg == "message" or keyword.arg is None:
            return True
        if keyword.arg == "update":
            return True
    return False


def _is_row_call(node: ast.AST, constructors: frozenset[str] | set[str]) -> bool:
    """Whether this call writes a finding row.

    A rewriter counts only where the module also constructs one — ``replace``
    and ``model_copy`` are ordinary names on ordinary objects, and treating
    every one of them as a row call put six modules that have never seen a
    ``Violation`` into the walk. The constructor set carries that decision:
    :func:`_row_constructors` puts the rewriters in it only for a module that
    builds a row outright.
    """
    if not isinstance(node, ast.Call):
        return False
    name = called_name(node)
    if name in constructors:
        return True
    return name in REWRITERS and name in constructors


def _row_constructors(tree: ast.AST) -> set[str]:
    """Every plain name a row is constructed by in this module.

    The constructor's own spelling and its import aliases, and then anything
    that subclasses one of them: ``class Finding(Violation)`` gives the row a
    second constructor, and a scan keyed on the base's name never sees a row
    built through the child.
    """
    found = names_reaching(tree, CONSTRUCTOR)
    for _round in range(8):
        before = len(found)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if any(
                (isinstance(base, ast.Name) and base.id in found)
                or (isinstance(base, ast.Attribute) and base.attr in found)
                for base in node.bases
            ):
                found.add(node.name)
        if len(found) == before:
            break
    # The rewriters, in a module that builds a row outright. ``replace`` and
    # ``model_copy`` are ordinary names on ordinary objects, so a module with
    # no constructor call has no row for one of them to rewrite — and reading
    # every such call as a row call put six modules that have never held a
    # ``Violation`` into the walk.
    if any(isinstance(node, ast.Call) and called_name(node) in found for node in ast.walk(tree)):
        found |= {
            called_name(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and called_name(node) in REWRITERS
            and _writes_a_message(node)
        }
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


def _every_function(tree: ast.AST) -> list[ast.FunctionDef]:
    """Every function in a module, because a mutation names no constructor.

    ``_functions_that_matter`` finds the functions that *call* one; a message
    written straight onto a row is an assignment, so the function that does it
    may name nothing this scan keys on.
    """
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]


def _message_mutations(function: ast.FunctionDef) -> list[ast.expr]:
    """Every ``something.message = …`` this function writes.

    A row is a mutable dataclass, so a message can be set after the row exists
    and no call names it. ``message`` is the only attribute asked about, which
    is why this cannot fire on an unrelated object's unrelated field.
    """
    found: list[ast.expr] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr == "message":
                found.append(node.value)
    return found


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
        if any(_is_row_call(child, constructors) for child in ast.walk(node)):
            found.append(node)
    return found


def _builds_a_row(tree: ast.AST) -> bool:
    """Whether this module constructs a finding row, under any name it gave it."""
    constructors = _row_constructors(tree)
    return any(_is_row_call(node, constructors) for node in ast.walk(tree))


def _qualified(tree: ast.AST) -> dict[int, str]:
    """Every function in this module, by id, under its qualified name.

    ``Class.method`` and ``outer.inner`` rather than a bare ``method``: keyed
    by the bare name, a nested function or a method sharing the name of a
    vouched function in the same module inherited its vouching, and a helper
    called ``_indicator_problem`` inside another function was owned for it.
    """
    found: dict[int, str] = {}

    def _walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                name = f"{prefix}.{child.name}" if prefix else child.name
                if not isinstance(child, ast.ClassDef):
                    found[id(child)] = name
                _walk(child, name)
            else:
                _walk(child, prefix)

    _walk(tree, "")
    return found


def _owned_for(
    function: ast.FunctionDef, module: frozenset[str], where: str = "", name: str = ""
) -> frozenset[str]:
    """Every name whose value this codebase owns *where this function reads it*.

    A module-level name is owned until the function binds that spelling itself.
    Then the binding is what reaches the interpolation, and only the binding can
    say whether the text is this repository's — which is why a local is asked
    about its value and never about its name.

    ``where`` is the walked module the function was read from and ``name`` its
    qualified name inside it, because both vouched lists are keyed by the place
    as well as the spelling — a method or a nested function that borrows a
    vouched function's bare name is a different function.
    """
    bindings = _bindings(function)
    # ``CODE_OWNED`` survives a binding and the module's own names do not, and
    # the difference is who vouched for what. Each name on ``CODE_OWNED`` is a
    # local somebody read and wrote a reason for, in the one function they read
    # it in. A module-level name is owned because of where it is *bound*, so a
    # function that binds that spelling itself is reading something else
    # entirely — and there are 251 of those spellings across the walked
    # modules, several of them ordinary lowercase words a function would reach
    # for.
    key = (where, name or function.name)
    vouched = CODE_OWNED.get(key, frozenset()) | OWNED_IN.get(key, frozenset())
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
            constructors = _row_constructors(tree)
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
            constructors = _row_constructors(tree)
            qualified = _qualified(tree)
            for function in _functions_that_matter(tree, constructors):
                owned = _owned_for(function, module, name, qualified.get(id(function), ""))
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

    def test_no_message_is_written_straight_onto_a_row(self) -> None:
        """A row is mutable, so a message can be set with no call to name it."""
        offences: list[str] = []
        for name in WALKED:
            tree = _tree_of(name)
            module = _module_names(tree)
            qualified = _qualified(tree)
            for function in _every_function(tree):
                owned = _owned_for(function, module, name, qualified.get(id(function), ""))
                for value in _message_mutations(function):
                    if _value_is_owned(value, owned):
                        continue
                    offences.append(f"{name}:{value.lineno}: {ast.unparse(value)}")

        assert not offences, (
            "These write a message onto a row after it was built, without passing "
            f"it through ``{WRAPPER}``:\n  " + "\n  ".join(offences)
        )

    def test_a_message_nothing_built_here_comes_from_a_builder(self) -> None:
        """``message=mismatch`` is only safe because the builder is walked too."""
        offences: list[str] = []
        for name in WALKED:
            tree = _tree_of(name)
            module = _module_names(tree)
            constructors = _row_constructors(tree)
            qualified = _qualified(tree)
            for function in _functions_that_matter(tree, constructors):
                owned = _owned_for(function, module, name, qualified.get(id(function), ""))
                for node in ast.walk(function):
                    if not _is_row_call(node, constructors):
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

    def test_it_reads_a_row_splatted_out_of_a_mapping(self) -> None:
        """``Violation(**payload)`` hid the message behind a dict."""
        source = (
            "def leak(model_text):\n"
            "    payload = {'code': 'x', 'message': f'said {model_text}'}\n"
            "    return Violation(**payload)\n"
        )

        assert self._message_offences(source) == ["payload"]
        assert _builds_a_row(ast.parse(source))

    def test_a_splatted_mapping_this_codebase_wrote_is_not_an_offence(self) -> None:
        """The rule is the value, not the spelling: an owned mapping passes."""
        source = (
            "OWN = {'code': 'x', 'message': 'a sentence of ours'}\n"
            "def held():\n"
            "    return Violation(**OWN)\n"
        )

        assert self._message_offences(source) == []

    def test_it_reads_a_row_built_through_a_subclass(self) -> None:
        """A subclass is a second constructor and the scan saw only the base."""
        source = (
            "from maljan.pipeline.validation import Violation\n"
            "class Finding(Violation):\n"
            "    pass\n"
            "def leak(model_text):\n"
            "    return Finding('x', f'said {model_text}')\n"
        )

        assert self._offences(source) == ["model_text"]
        assert _builds_a_row(ast.parse(source))

    def test_it_reads_a_row_rewritten_by_dataclasses_replace(self) -> None:
        """``replace(violation, message=…)`` writes a row without a constructor."""
        source = (
            "from dataclasses import replace\n"
            "def held():\n"
            "    return Violation('x', 'a sentence of ours')\n"
            "def leak(violation, model_text):\n"
            "    return replace(violation, message=f'said {model_text}')\n"
        )

        assert self._offences(source) == ["model_text"]
        assert _builds_a_row(ast.parse(source))

    def test_it_reads_a_row_rewritten_by_a_splatted_mapping(self) -> None:
        source = (
            "from dataclasses import replace\n"
            "def held():\n"
            "    return Violation('x', 'a sentence of ours')\n"
            "def leak(violation, model_text):\n"
            "    return replace(violation, **{'message': model_text})\n"
        )

        assert self._message_offences(source) == ["{'message': model_text}"]

    def test_it_reads_a_row_rewritten_by_model_copy(self) -> None:
        source = (
            "def held():\n"
            "    return Violation('x', 'a sentence of ours')\n"
            "def leak(violation, model_text):\n"
            "    return violation.model_copy(update={'message': model_text})\n"
        )

        assert self._message_offences(source) == ["{'message': model_text}"]

    def test_a_rewriter_in_a_module_that_holds_no_row_is_not_one(self) -> None:
        """The boundary, stated: ``replace`` and ``model_copy`` are ordinary names.

        Reading every one of them as a row call put six modules that have never
        held a ``Violation`` into the walk. A module with no constructor call
        has no row for a rewriter to rewrite.
        """
        source = (
            "from dataclasses import replace\n"
            "def held(config, model_text):\n"
            "    return replace(config, message=model_text)\n"
        )

        assert not _builds_a_row(ast.parse(source))
        assert self._message_offences(source) == []

    def test_it_reads_a_message_written_straight_onto_a_row(self) -> None:
        """``violation.message = model_text`` writes a row without any call."""
        source = (
            "def held():\n"
            "    return Violation('x', 'a sentence of ours')\n"
            "def leak(violation, model_text):\n"
            "    violation.message = model_text\n"
            "    return violation\n"
        )

        assert self._mutations(source) == ["model_text"]

    def test_an_owned_message_written_straight_onto_a_row_is_not_an_offence(self) -> None:
        source = (
            "OWN = 'a sentence of ours'\n"
            "def held(violation):\n"
            "    violation.message = OWN\n"
            "    return violation\n"
        )

        assert self._mutations(source) == []

    def test_a_replace_that_writes_no_message_is_left_alone(self) -> None:
        """``str.replace`` and a path-only rewrite are not row constructions."""
        source = (
            "def held(violation, model_text):\n"
            "    said = model_text.replace('a', 'b')\n"
            "    return replace(violation, path=said)\n"
        )

        assert self._offences(source) == []
        assert not _builds_a_row(ast.parse(source))

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
        return tree, _module_names(tree), _row_constructors(tree)

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

    def _mutations(self, source: str) -> list[str]:
        """Every message written straight onto a row that the scan would refuse."""
        tree, module, _constructors = self._scan(source)
        found: list[str] = []
        qualified = _qualified(tree)
        for function in _every_function(tree):
            owned = _owned_for(function, module, "", qualified.get(id(function), ""))
            for value in _message_mutations(function):
                if _value_is_owned(value, owned):
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
                if not _is_row_call(node, constructors):
                    continue
                for message in _violation_messages(node):
                    if isinstance(message, ast.JoinedStr | ast.Constant):
                        continue
                    if _value_is_owned(message, owned):
                        continue
                    found.append(ast.unparse(message))
        return found


# Where a row may be put on an agent's own list, and what puts it there. The
# list is drained straight onto the state channel by ``_analyst_node``, and
# ``_violations_from_rows`` rebuilds the rows off that channel under the
# vouching above — so the vouching is only worth what this invariant is. It was
# read once and written down nowhere, and a sixth module extending the list
# with something a model wrote would have kept every guard green.
FINDING_LIST = "validation_findings"
WRITES_THE_LIST: dict[tuple[str, str], str] = {
    # The owner: it holds the list, empties it on construction and hands it
    # over on a drain.
    ("agents/base_agent.py", "__init__"): "the list is created here",
    ("agents/base_agent.py", "drain_validation_findings"): "the drain empties it",
    # The one place anything is added to it: the output of ``validate_isr``,
    # which is walked source.
    ("agents/base_agent.py", "_validate_isr"): "what the walked validator returned",
    # A callee's own drained rows, each rebuilt as a Violation naming the
    # callee. Walked source too, and vouched for by name in ``OWNED_IN``.
    ("agents/delegation.py", "_hand_over_the_record"): "a callee's rows, rebuilt",
}


def _writes_to(tree: ast.AST, attribute: str) -> set[str]:
    """The functions in this module that add to, or replace, ``obj.<attribute>``.

    Three shapes: ``x.attr.append(...)`` and its siblings, ``x.attr = ...``,
    and ``x.attr += ...``. Reading it is not writing it, and a local of the
    same name is not the attribute.

    What it cannot see, written down so the next reader knows the boundary
    rather than assuming there is none: ``setattr(agent, "…", rows)``, a local
    alias (``rows = agent.validation_findings`` and then ``rows.append(r)``),
    ``agent.__dict__["…"].append(r)``, ``list.append(agent.…, r)``,
    ``operator.iadd``, a write at module level or in a class body, and a lambda
    bound at module level. The alias is the one an author could reach by
    accident; the rest are evasions no AST guard stops, and the runtime rule
    they would have to get past is that the list is drained straight onto the
    state channel and every row on it was built by walked source.
    """
    mutators = {"append", "extend", "insert", "clear", "pop", "remove", "__setitem__"}
    found: set[str] = set()

    def _is_it(node: ast.AST) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == attribute

    for parent in ast.walk(tree):
        if not isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(parent):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in mutators
                and _is_it(node.func.value)
            ):
                found.add(parent.name)
            elif isinstance(node, ast.Assign) and any(_is_it(t) for t in node.targets):
                found.add(parent.name)
            elif isinstance(node, ast.AnnAssign | ast.AugAssign) and _is_it(node.target):
                found.add(parent.name)
            elif isinstance(node, ast.Subscript) and _is_it(node.value):
                found.add(parent.name)
    return found


class TestOnlyTheWalkedValidatorsFillTheList:
    """An agent's finding list is written in four places, all of them read.

    ``_violations_from_rows`` is trusted with ``row`` because every row on the
    state channel was built as a ``Violation`` by walked source. That trust is
    an invariant of who writes the list, and nothing stated it.
    """

    def test_nothing_else_in_the_tree_writes_it(self) -> None:
        found: set[tuple[str, str]] = set()
        for path in SRC.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            where = str(path.relative_to(SRC))
            found |= {(where, function) for function in _writes_to(tree, FINDING_LIST)}

        unexpected = sorted(found - set(WRITES_THE_LIST))
        assert not unexpected, (
            f"These write an agent's ``{FINDING_LIST}`` and nobody vouched for what they "
            "put there. A row on that list is drained onto the state channel and rebuilt "
            "by ``_violations_from_rows`` without being wrapped again, so what fills it "
            "must be a walked validator's own output. Add the place and its reason to "
            "WRITES_THE_LIST once it has been read:\n  "
            + "\n  ".join(f"{where}: {function}" for where, function in unexpected)
        )

    def test_every_place_it_names_still_writes_it(self) -> None:
        """A declaration that has gone stale vouches for nothing."""
        gone: list[str] = []
        for where, function in sorted(WRITES_THE_LIST):
            tree = _tree_of(where)
            if function not in _writes_to(tree, FINDING_LIST):
                gone.append(f"{where}: {function}")

        assert not gone, "declared as writing the list and no longer does:\n  " + "\n  ".join(gone)

    def test_the_scan_sees_each_shape_of_write(self) -> None:
        """The scan passes trivially if it is broken, so prove it is not."""
        appended = "def leak(agent, row):\n    agent.validation_findings.append(row)\n"
        extended = "def leak(agent, rows):\n    agent.validation_findings.extend(rows)\n"
        assigned = "def leak(agent, rows):\n    agent.validation_findings = rows\n"
        augmented = "def leak(agent, rows):\n    agent.validation_findings += rows\n"
        indexed = "def leak(agent, row):\n    agent.validation_findings[0] = row\n"
        read = "def held(agent):\n    return list(agent.validation_findings)\n"
        elsewhere = "def held(rows):\n    validation_findings = rows\n    return rows\n"

        for source in (appended, extended, assigned, augmented, indexed):
            assert _writes_to(ast.parse(source), FINDING_LIST) == {"leak"}, source
        for source in (read, elsewhere):
            assert _writes_to(ast.parse(source), FINDING_LIST) == set(), source
