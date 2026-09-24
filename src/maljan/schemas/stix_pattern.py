"""Read what a STIX pattern compares, in one place, for everybody who asks.

Two readers of the same syntax used to live here: the validator split a pattern
on its quotes to ask whether each value is grounded in the run's evidence, and
the STIX renderer split it again to ask whether each endpoint may be exported.
Neither read an escaped quote — ``[file:name = 'it\\'s.exe']`` came back as the
literal ``it\\`` — and they had already drifted about what a quoted key is: the
validator decided it from the object path, the renderer from the property name.
Two readings of one pattern is how one of them publishes what the other vetoes.

This is a reader, not a grammar. It answers three questions about each quoted
value a comparison carries — which object path it is compared against, with
which operator, and what the value itself is once its escapes are undone — and
where it cannot answer them it says so, in :attr:`Comparison.readable`. A
caller declines an unreadable comparison; nothing here guesses.

What it deliberately skips rather than misreads:

* a **quoted key inside an object path** — ``file:hashes.'MD5'`` names an
  algorithm and ``file:extensions['pe']`` names an extension. A quote opening
  where the path is still being written continues the path; a value is what
  follows the comparison operator.
* a **qualifier's own literal** — ``[…] START '2026-01-01T00:00:00Z' STOP …``
  quotes two timestamps after the observation expression has closed. They
  belong to the qualifier, not to the comparison before them, and crediting
  them to it declined a sound indicator for an endpoint nobody had written.

One record per value, so an ``IN ('a', 'b')`` list — which writes its path once
and quotes twice — yields one record for each value, each carrying that shared
path and operator. A pattern is not one comparison, and a caller answers for
every value in it.

The scan is a single left-to-right pass, so a pattern quoting a thousand values
costs a thousand steps rather than a thousand squared.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from dataclasses import dataclass

# An object path written outside the quotes: the type, then the property. The
# property steps through plain names, list indices and quoted keys, because
# ``network-traffic:dst_ref.value``, ``domain-name:resolves_to_refs[*].value``
# and ``file:extensions['pe'].pe_imphash`` are all one path. Case carries no
# meaning in a STIX object path and a judge writes ``[URL:value = …]`` often
# enough that reading it as some other kind would be a hole.
_OBJECT_PATH_RE = re.compile(
    r"([a-z0-9-]+):([a-z0-9_]+(?:\.[a-z0-9_]+|\.'(?:\\.|[^'\\])*'|\['(?:\\.|[^'\\])*'\]|\[[^\]']*\])*)",
    re.IGNORECASE,
)

# The two characters a STIX literal escapes. A backslash before anything else
# is a backslash: a judge writes ``'C:\Windows\system32\x.exe'`` unescaped far
# more often than it writes a path that needed escaping, and reading every
# backslash as an escape would eat the separators out of it. It is read as
# the backslash it means and marked (``Comparison.stray_backslash``), because
# the grammar itself refuses it.
_ESCAPABLE = ("'", "\\")

# What a name is written with, for the bracket question below: a bracket that
# opens a step through a property has a property name right before it, while
# the one that opens an observation expression has nothing.
_NAME_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


@dataclass(frozen=True)
class Comparison:
    """One quoted value, and what the pattern compares it against.

    ``readable`` is false when the reader could not say what this value is
    compared against — an unterminated quote, or a value with no object path
    written before it anywhere in the pattern. The caller declines it; it is
    never guessed at and never silently published.
    """

    object_type: str
    prop: str
    operator: str
    literal: str
    readable: bool
    # The type as the pattern writes it. ``object_type`` is folded to lower
    # case for the questions that read it; STIX types are lower case, and a
    # capitalised one is a type the grammar refuses.
    written_type: str = ""
    # Whether the quoted value writes a backslash the grammar has no escape
    # for. A STIX string escapes two characters, the quote and the backslash
    # itself, and refuses the whole pattern over any other ``\x``. The reader
    # still reads such a value — as the backslash it plainly means — so the
    # questions about it can be asked; this says the pattern is not valid.
    stray_backslash: bool = False

    @property
    def path(self) -> str:
        """The object path this value is compared against, lowercased."""
        return f"{self.object_type}:{self.prop}" if self.object_type else ""


def read_comparisons(pattern: str) -> list[Comparison]:
    """Every quoted value in ``pattern``, in the order it is written.

    One pass: the text outside the quotes is never copied until a *value*
    closes a comparison, and a key is answered from the few characters right
    before it. A pattern that chains keys therefore costs what its length
    costs, rather than the square of it.
    """
    text = str(pattern or "")
    found: list[Comparison] = []
    outside = 0
    object_type = ""
    written_type = ""
    prop = ""
    operator = ""
    observation_closed = False
    index = 0
    while index < len(text):
        if text[index] != "'":
            index += 1
            continue
        literal, end, closed, stray = _read_quoted(text, index)
        if closed and _opens_a_key(text, outside, index):
            # A key continues the path rather than answering it, and the path
            # regex above reads it back out of the text it is written in.
            index = end
            continue
        before = text[outside:index]
        index = end
        outside = end
        paths = list(_OBJECT_PATH_RE.finditer(before))
        if paths:
            object_type = paths[-1].group(1).lower()
            written_type = paths[-1].group(1)
            prop = paths[-1].group(2).lower()
            operator = before[paths[-1].end() :].strip().lower()
            observation_closed = False
        else:
            # No new path: either the value list of the comparison before this
            # one goes on, or the observation expression has closed and what
            # follows belongs to a qualifier.
            observation_closed = observation_closed or "]" in before
            if observation_closed:
                continue
        found.append(
            Comparison(
                object_type=object_type,
                written_type=written_type,
                prop=prop,
                operator=operator,
                literal=literal,
                readable=closed and bool(object_type),
                stray_backslash=stray,
            )
        )
    return found


def _opens_a_key(text: str, start: int, quote: int) -> bool:
    """Whether the quote at ``quote`` continues an object path.

    ``file:hashes.'MD5'`` and ``file:extensions['pe']`` step through a key; the
    ``[`` that opens an observation expression steps through nothing, so a
    bracket is a key's only when a property name is written right before it.
    Read from the characters themselves rather than from a copy of everything
    written since the last value, because a pattern may chain keys.
    """
    index = quote - 1
    while index >= start and text[index].isspace():
        index -= 1
    if index < start:
        return False
    if text[index] == ".":
        return True
    return text[index] == "[" and index - 1 >= start and text[index - 1] in _NAME_CHARACTERS


def _read_quoted(text: str, start: int) -> tuple[str, int, bool, bool]:
    """The literal opening at ``text[start]``: its value, its end, whether it closed.

    And whether it wrote a backslash before a character the grammar does not
    escape, which the value keeps as the backslash it plainly means.
    """
    value: list[str] = []
    stray = False
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in _ESCAPABLE:
            value.append(text[index + 1])
            index += 2
            continue
        if char == "\\":
            stray = True
        if char == "'":
            return "".join(value), index + 1, True, stray
        value.append(char)
        index += 1
    return "".join(value), len(text), False, stray


def reads_whole(pattern: str) -> bool:
    """Whether ``pattern`` is a pattern the official validator accepts.

    The official validator — ``stix2-patterns``, pinned in the runtime
    dependencies — decides, acceptance and refusal alike. The grammar reader in
    this module answers only where the package cannot be imported.
    """
    return not pattern_refusal(pattern)


def pattern_refusal(pattern: str) -> str:
    """Why the pattern grammar refuses ``pattern``, in words, or ``""`` when it does not.

    The STIX 2.1 pattern grammar, read over the same quoted values every other
    question here reads: observation expressions in brackets joined by
    ``AND``, ``OR`` and ``FOLLOWEDBY`` and grouped in parentheses, each with
    its qualifiers (``START … STOP …``, ``WITHIN … SECONDS``, ``REPEATS …
    TIMES``); inside the brackets, comparisons joined by ``AND`` and ``OR``,
    each an object path, an optional ``NOT``, an operator — ``=``, ``!=``,
    ``<>``, ``<``, ``>``, ``<=``, ``>=``, ``LIKE``, ``MATCHES``, ``ISSUBSET``,
    ``ISSUPERSET``, or ``IN`` and a parenthesised list — and a literal, or
    ``EXISTS`` and a path. A shape check that wanted ``=`` threw away every
    ``LIKE`` a judge wrote; one that asked only for balanced brackets kept
    ``[file:name]``, which a consumer's parser refuses.

    Whether the path is one its type defines, and whether a quoted value writes
    a backslash the grammar cannot read, are asked by
    :func:`object_path_problems` and :func:`stray_backslash_values`.
    """
    text = str(pattern or "")
    if not text.strip():
        return "it is empty"
    verdict = _validator_verdict(text)
    if verdict is not None:
        return verdict
    return _grammar_refusal(text)


def _grammar_refusal(text: str) -> str:
    """The grammar reader's refusal, for where the official validator is not installed."""
    tokens, broken = _pattern_tokens(text)
    if broken:
        return broken
    if not tokens:
        return "it is empty"
    return _PatternGrammar(tokens).read()


def _validator_verdict(pattern: str) -> str | None:
    """The official validator's answer — ``""`` accepted, its first refusal otherwise.

    ``None`` only when ``stix2-patterns`` cannot be imported. Where it can, its
    answer is the whole answer, acceptance and refusal alike: ``==`` and
    ``NOT EXISTS`` are the grammar's own, and a reader of the grammar that
    refused them told a judge its valid pattern was not one.
    """
    try:
        from stix2patterns.validator import run_validator
    except ImportError:
        return None
    try:
        errors = run_validator(pattern)
    except Exception:  # noqa: BLE001 — a validator that cannot read it refuses it
        return "the official pattern validator could not read it"
    return str(errors[0]).removeprefix("FAIL: ") if errors else ""


# The keywords of the pattern grammar, which it spells in capitals.
_KEYWORDS = frozenset(
    {
        "AND",
        "OR",
        "NOT",
        "FOLLOWEDBY",
        "LIKE",
        "MATCHES",
        "ISSUBSET",
        "ISSUPERSET",
        "IN",
        "EXISTS",
        "START",
        "STOP",
        "WITHIN",
        "SECONDS",
        "REPEATS",
        "TIMES",
    }
)
_COMPARATORS = frozenset(
    {"=", "==", "!=", "<>", "<", ">", "<=", ">=", "LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET"}
)
# The operators whose right-hand side the grammar requires to be a quoted string.
_STRING_COMPARATORS = frozenset({"LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET"})
_SYMBOL_RE = re.compile(r"<>|!=|<=|>=|==|=|<|>|\[|\]|\(|\)|,")
_NUMBER_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _pattern_tokens(text: str) -> tuple[list[tuple[str, str]], str]:
    """``(kind, text)`` per token, and why the text cannot be split into tokens, or ``""``."""
    tokens: list[tuple[str, str]] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char in "thb" and text[index + 1 : index + 2] == "'":
            literal, end, closed, _stray = _read_quoted(text, index + 1)
            if not closed:
                return tokens, "a quoted value never closes"
            tokens.append(({"t": "timestamp", "h": "hex", "b": "binary"}[char], literal))
            index = end
            continue
        if char == "'":
            literal, end, closed, _stray = _read_quoted(text, index)
            if not closed:
                return tokens, (
                    "a quoted value never closes (a backslash right before a closing quote "
                    "escapes it)"
                )
            tokens.append(("string", literal))
            index = end
            continue
        path = _OBJECT_PATH_RE.match(text, index)
        if path is not None:
            tokens.append(("path", path.group(0)))
            index = path.end()
            continue
        symbol = _SYMBOL_RE.match(text, index)
        if symbol is not None:
            tokens.append(("symbol", symbol.group(0)))
            index = symbol.end()
            continue
        number = _NUMBER_RE.match(text, index)
        if number is not None:
            tokens.append(("number", number.group(0)))
            index = number.end()
            continue
        word = _WORD_RE.match(text, index)
        if word is not None:
            value = word.group(0)
            if value in _KEYWORDS:
                tokens.append(("keyword", value))
            elif value in ("true", "false"):
                tokens.append(("boolean", value))
            else:
                return tokens, f"{value!r} is neither an object path, a keyword nor a value"
            index = word.end()
            continue
        return tokens, f"{char!r} is not part of the pattern grammar"
    return tokens, ""


_LITERALS = frozenset({"string", "timestamp", "hex", "binary", "number", "boolean"})


class _PatternGrammar:
    """A recursive-descent reading of one pattern's tokens; ``read`` says what it refused."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.at = 0

    def _peek(self) -> tuple[str, str]:
        return self.tokens[self.at] if self.at < len(self.tokens) else ("end", "")

    def _take(self, kind: str, text: str | None = None) -> bool:
        found = self._peek()
        if found[0] == kind and (text is None or found[1] == text):
            self.at += 1
            return True
        return False

    def _where(self) -> str:
        kind, text = self._peek()
        return "the end of the pattern" if kind == "end" else repr(text)

    def read(self) -> str:
        refusal = self._observations()
        if refusal:
            return refusal
        if self._peek()[0] != "end":
            return f"{self._where()} follows a complete pattern"
        return ""

    def _observations(self) -> str:
        refusal = self._observation()
        while not refusal and self._peek() in (
            ("keyword", "AND"),
            ("keyword", "OR"),
            ("keyword", "FOLLOWEDBY"),
        ):
            self.at += 1
            refusal = self._observation()
        return refusal

    def _observation(self) -> str:
        if self._take("symbol", "["):
            refusal = self._comparisons()
            if refusal:
                return refusal
            if not self._take("symbol", "]"):
                return f"{self._where()} where the observation expression should close"
        elif self._take("symbol", "("):
            refusal = self._observations()
            if refusal:
                return refusal
            if not self._take("symbol", ")"):
                return f"{self._where()} where a parenthesis should close"
        else:
            return f"{self._where()} where an observation expression should open with ["
        return self._qualifiers()

    def _qualifiers(self) -> str:
        while True:
            if self._take("keyword", "START"):
                if not (
                    self._take("timestamp")
                    and self._take("keyword", "STOP")
                    and self._take("timestamp")
                ):
                    return "START is not followed by t'…' STOP t'…'"
            elif self._take("keyword", "WITHIN"):
                if not (self._take("number") and self._take("keyword", "SECONDS")):
                    return "WITHIN is not followed by a number and SECONDS"
            elif self._take("keyword", "REPEATS"):
                count = self._peek()
                if not (
                    count[0] == "number"
                    and count[1].lstrip("+-").isdigit()
                    and self._take("number")
                    and self._take("keyword", "TIMES")
                ):
                    return "REPEATS is not followed by a whole number and TIMES"
            else:
                return ""

    def _comparisons(self) -> str:
        refusal = self._comparison()
        while not refusal and self._peek() in (("keyword", "AND"), ("keyword", "OR")):
            self.at += 1
            refusal = self._comparison()
        return refusal

    def _comparison(self) -> str:
        if self._take("symbol", "("):
            refusal = self._comparisons()
            if refusal:
                return refusal
            return (
                ""
                if self._take("symbol", ")")
                else f"{self._where()} where a parenthesis should close"
            )
        if self._peek() == ("keyword", "NOT") and self.tokens[self.at + 1 : self.at + 2] == [
            ("keyword", "EXISTS")
        ]:
            self.at += 1
        if self._take("keyword", "EXISTS"):
            return "" if self._take("path") else "EXISTS is not followed by an object path"
        kind, text = self._peek()
        if kind != "path":
            return f"{self._where()} where a comparison should begin with an object path"
        self.at += 1
        self._take("keyword", "NOT")
        if self._take("keyword", "IN"):
            if not self._take("symbol", "("):
                return f"IN after {text!r} is not followed by a parenthesised list"
            if self._take("symbol", ")"):
                return ""
            while True:
                if self._peek()[0] not in _LITERALS:
                    return (
                        f"the list after {text!r} IN holds {self._where()} where a value should be"
                    )
                self.at += 1
                if self._take("symbol", ")"):
                    return ""
                if not self._take("symbol", ","):
                    return f"the list after {text!r} IN never closes"
        operator = self._peek()
        if operator[1] not in _COMPARATORS or operator[0] not in ("symbol", "keyword"):
            return f"no comparison operator follows {text!r}"
        self.at += 1
        if self._peek()[0] not in _LITERALS:
            return f"{text!r} {operator[1]} is followed by {self._where()}, not by a value"
        if operator[1] in _STRING_COMPARATORS and self._peek()[0] != "string":
            return (
                f"{operator[1]} after {text!r} compares with a quoted string, not {self._where()}"
            )
        self.at += 1
        return ""


def stray_backslash_values(pattern: str) -> list[str]:
    """The quoted values of ``pattern`` that write a backslash the grammar cannot read.

    Each once, in the order written. A STIX string escapes the quote and the
    backslash and nothing else, so ``'C:\\Windows\\x.exe'`` written with single
    backslashes is a pattern the official validator refuses whole.
    """
    found: list[str] = []
    for comparison in read_comparisons(pattern):
        if comparison.stray_backslash and comparison.literal not in found:
            found.append(comparison.literal)
    return found


# The two wildcards of ``LIKE``: any run of characters, and any one.
_LIKE_WILDCARDS_RE = re.compile(r"[%_]+")


def like_fixed_text(literal: str) -> list[str]:
    """The runs of text a ``LIKE`` value fixes, between its wildcards.

    ``'%host.example%'`` matches any value that contains
    ``host.example``; it is not that value. What a value matching it must
    contain is these runs, in order, and nothing else is said by it. A value
    that is all wildcards fixes nothing.
    """
    return [part for part in _LIKE_WILDCARDS_RE.split(str(literal or "")) if part]


# What makes a regular expression more than its text, once its anchors and the
# escaped dots are read.
_REGEX_METACHARACTERS = frozenset("\\.^$|?*+()[]{}")


def matches_fixed_text(expression: str) -> list[str]:
    """The one run of text a ``MATCHES`` expression fixes, when it is only that text.

    ``'^host\\.example$'`` fixes ``host.example``: anchors at its ends and
    escaped characters read as themselves. An expression that is anything more
    — a class, an alternation, a repetition — fixes no one value, and says so
    by answering nothing.
    """
    text = str(expression or "").removeprefix("^").removesuffix("$")
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in _REGEX_METACHARACTERS:
            out.append(text[index + 1])
            index += 2
            continue
        if char in _REGEX_METACHARACTERS:
            return []
        out.append(char)
        index += 1
    return ["".join(out)] if out else []


# The Cyber-observable object types STIX 2.1 defines. A pattern compares a
# property of one of these, or of a custom type a producer declared under the
# ``x-`` prefix; a pattern over any other type names objects no consumer has,
# and so matches nothing anybody will ever hold.
CYBER_OBSERVABLE_TYPES: frozenset[str] = frozenset(
    {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
)


def is_observable_type(object_type: str) -> bool:
    """Whether a pattern may name this type: a STIX one, or a custom ``x-`` one.

    As written: STIX types are lower case, and ``IPv4-Addr`` is a type the
    grammar refuses, however plainly it means ``ipv4-addr``.
    """
    name = str(object_type or "").strip()
    return name in CYBER_OBSERVABLE_TYPES or name.startswith("x-")


def unknown_object_types(pattern: str) -> list[str]:
    """The object types ``pattern`` compares against that STIX does not have.

    Each named once, in the order written. A comparison the reader could not
    place names no type and is not counted here: it is declined for being
    unreadable, which is a different answer.
    """
    found: list[str] = []
    for comparison in read_comparisons(pattern):
        name = comparison.written_type or comparison.object_type
        if name and not is_observable_type(name) and name not in found:
            found.append(name)
    return found


# The top-level properties each Cyber-observable type defines (STIX 2.1,
# section 6), which is as deep as this reader asks. A step past a reference or
# into an extension is the referenced object's or the extension's business,
# and a custom ``x_`` property is the producer's own.
# The properties every Cyber-observable carries, whatever its type (STIX 2.1,
# the SCO common properties).
SCO_COMMON_PROPERTIES: frozenset[str] = frozenset(
    {
        "id",
        "type",
        "spec_version",
        "defanged",
        "object_marking_refs",
        "granular_markings",
        "extensions",
    }
)

SCO_PROPERTIES: dict[str, frozenset[str]] = {
    "artifact": frozenset(
        {"mime_type", "payload_bin", "url", "hashes", "encryption_algorithm", "decryption_key"}
    ),
    "autonomous-system": frozenset({"number", "name", "rir"}),
    "directory": frozenset({"path", "path_enc", "ctime", "mtime", "atime", "contains_refs"}),
    "domain-name": frozenset({"value", "resolves_to_refs"}),
    "email-addr": frozenset({"value", "display_name", "belongs_to_ref"}),
    "email-message": frozenset(
        {
            "is_multipart",
            "date",
            "content_type",
            "from_ref",
            "sender_ref",
            "to_refs",
            "cc_refs",
            "bcc_refs",
            "message_id",
            "subject",
            "received_lines",
            "additional_header_fields",
            "body",
            "body_multipart",
            "raw_email_ref",
        }
    ),
    "file": frozenset(
        {
            "hashes",
            "size",
            "name",
            "name_enc",
            "magic_number_hex",
            "mime_type",
            "ctime",
            "mtime",
            "atime",
            "parent_directory_ref",
            "contains_refs",
            "content_ref",
        }
    ),
    "ipv4-addr": frozenset({"value", "resolves_to_refs", "belongs_to_refs"}),
    "ipv6-addr": frozenset({"value", "resolves_to_refs", "belongs_to_refs"}),
    "mac-addr": frozenset({"value"}),
    "mutex": frozenset({"name"}),
    "network-traffic": frozenset(
        {
            "start",
            "end",
            "is_active",
            "src_ref",
            "dst_ref",
            "src_port",
            "dst_port",
            "protocols",
            "src_byte_count",
            "dst_byte_count",
            "src_packets",
            "dst_packets",
            "ipfix",
            "src_payload_ref",
            "dst_payload_ref",
            "encapsulates_refs",
            "encapsulated_by_ref",
        }
    ),
    "process": frozenset(
        {
            "is_hidden",
            "pid",
            "created_time",
            "cwd",
            "command_line",
            "environment_variables",
            "opened_connection_refs",
            "creator_user_ref",
            "image_ref",
            "parent_ref",
            "child_refs",
        }
    ),
    "software": frozenset({"name", "cpe", "swid", "languages", "vendor", "version"}),
    "url": frozenset({"value"}),
    "user-account": frozenset(
        {
            "user_id",
            "credential",
            "account_login",
            "account_type",
            "display_name",
            "is_service_account",
            "is_privileged",
            "can_escalate_privs",
            "is_disabled",
            "account_created",
            "account_expires",
            "credential_last_changed",
            "account_first_login",
            "account_last_login",
        }
    ),
    "windows-registry-key": frozenset(
        {"key", "values", "modified_time", "creator_user_ref", "number_of_subkeys"}
    ),
    "x509-certificate": frozenset(
        {
            "is_self_signed",
            "hashes",
            "version",
            "serial_number",
            "signature_algorithm",
            "issuer",
            "validity_not_before",
            "validity_not_after",
            "subject",
            "subject_public_key_algorithm",
            "subject_public_key_modulus",
            "subject_public_key_exponent",
            "x509_v3_extensions",
        }
    ),
}

# The predefined extensions each type has; any type may carry a custom ``x-``
# one or one an extension definition names.
SCO_EXTENSIONS: dict[str, frozenset[str]] = {
    "file": frozenset(
        {"archive-ext", "ntfs-ext", "pdf-ext", "raster-image-ext", "windows-pebinary-ext"}
    ),
    "network-traffic": frozenset({"http-request-ext", "icmp-ext", "socket-ext", "tcp-ext"}),
    "process": frozenset({"windows-process-ext", "windows-service-ext"}),
    "user-account": frozenset({"unix-account-ext"}),
}

# The properties each predefined extension defines (STIX 2.1, section 6), so a
# step into an extension is asked the question a step into a type is.
SCO_EXTENSION_PROPERTIES: dict[str, frozenset[str]] = {
    "archive-ext": frozenset({"contains_refs", "comment"}),
    "ntfs-ext": frozenset({"sid", "alternate_data_streams"}),
    "pdf-ext": frozenset({"version", "is_optimized", "document_info_dict", "pdfid0", "pdfid1"}),
    "raster-image-ext": frozenset({"image_height", "image_width", "bits_per_pixel", "exif_tags"}),
    "windows-pebinary-ext": frozenset(
        {
            "pe_type",
            "imphash",
            "machine_hex",
            "number_of_sections",
            "time_date_stamp",
            "pointer_to_symbol_table_hex",
            "number_of_symbols",
            "size_of_optional_header",
            "characteristics_hex",
            "file_header_hashes",
            "optional_header",
            "sections",
        }
    ),
    "http-request-ext": frozenset(
        {
            "request_method",
            "request_value",
            "request_version",
            "request_header",
            "message_body_length",
            "message_body_data_ref",
        }
    ),
    "icmp-ext": frozenset({"icmp_type_hex", "icmp_code_hex"}),
    "socket-ext": frozenset(
        {
            "address_family",
            "is_blocking",
            "is_listening",
            "options",
            "socket_type",
            "socket_descriptor",
            "socket_handle",
        }
    ),
    "tcp-ext": frozenset({"src_flags_hex", "dst_flags_hex"}),
    "windows-process-ext": frozenset(
        {
            "aslr_enabled",
            "dep_enabled",
            "priority",
            "owner_sid",
            "window_title",
            "startup_info",
            "integrity_level",
        }
    ),
    "windows-service-ext": frozenset(
        {
            "service_name",
            "descriptions",
            "display_name",
            "group_name",
            "start_type",
            "service_dll_refs",
            "service_type",
            "service_status",
        }
    ),
    "unix-account-ext": frozenset({"gid", "groups", "home_dir", "shell"}),
}

_FIRST_STEP_RE = re.compile(r"^([a-z0-9_]+)")
_EXTENSION_KEY_RE = re.compile(r"^extensions(?:\.'((?:\\.|[^'\\])*)'|\['((?:\\.|[^'\\])*)'\])")
# A key written inside brackets. The pattern grammar steps into a dictionary
# with ``.'key'`` and into a list with ``[*]`` or ``[n]``; ``['key']`` is
# neither, and the official validator refuses the whole pattern for it.
_BRACKETED_KEY_RE = re.compile(r"\['((?:\\.|[^'\\])*)'\]")


def object_path_problems(pattern: str) -> list[str]:
    """What is wrong with the object paths ``pattern`` compares, one sentence each.

    Asked only of a STIX type written as STIX writes it: a property the type
    does not define, an extension it does not have, a property the extension
    does not define, or a key written in brackets, which the grammar has no
    form for. Each comparison's problems are one sentence, so the judge reads
    everything wrong with a path at once, and each sentence is named once. A
    type STIX does not have is :func:`unknown_object_types`' answer.
    """
    found: list[str] = []
    for comparison in read_comparisons(pattern):
        kind = comparison.written_type or comparison.object_type
        properties = SCO_PROPERTIES.get(kind)
        if properties is None:
            continue
        parts: list[str] = [
            f"a key is written .'{key}' in a pattern, never ['{key}']"
            for key in dict.fromkeys(_BRACKETED_KEY_RE.findall(comparison.prop))
        ]
        step = _FIRST_STEP_RE.match(comparison.prop)
        name = step.group(1) if step else comparison.prop
        if name == "extensions":
            key_match = _EXTENSION_KEY_RE.match(comparison.prop)
            key = (key_match.group(1) or key_match.group(2) or "") if key_match else ""
            allowed = SCO_EXTENSIONS.get(kind, frozenset())
            if not key or not (
                key in allowed or key.startswith("x-") or key.startswith("extension-definition--")
            ):
                listed = ", ".join(sorted(allowed)) if allowed else "no predefined extension"
                parts.append(f"{kind} has no extension {key!r} (it has {listed})")
            elif key in SCO_EXTENSION_PROPERTIES and key_match is not None:
                inside = _FIRST_STEP_RE.match(comparison.prop[key_match.end() :].lstrip("."))
                defined = SCO_EXTENSION_PROPERTIES[key]
                if (
                    inside
                    and inside.group(1) not in defined
                    and not inside.group(1).startswith("x_")
                ):
                    parts.append(
                        f"{key} has no property {inside.group(1)!r} "
                        f"(it has {', '.join(sorted(defined))})"
                    )
        elif not (name in properties or name in SCO_COMMON_PROPERTIES or name.startswith("x_")):
            parts.append(f"{kind} has no property {name!r}")
        if not parts:
            continue
        problem = "; and ".join(parts)
        if problem not in found:
            found.append(problem)
    return found


def observable_type_for(object_type: str, literal: str) -> str:
    """The STIX type a misnamed comparison most likely meant, or ``""``.

    An address is answered from the value itself, because the value says which
    family it is and the misspelt name rarely does. Anything else is answered
    only when the written name is close to one type and to no other, or is the
    start of the type it is closest to: a guess between two is not an answer,
    and the sentence then lists the types instead.
    """
    try:
        return f"ipv{ipaddress.ip_address(str(literal).strip()).version}-addr"
    except ValueError:
        pass
    name = str(object_type or "").strip().lower()
    close = difflib.get_close_matches(name, sorted(CYBER_OBSERVABLE_TYPES), n=2, cutoff=0.6)
    if len(close) == 1 or (close and close[0].startswith(name)):
        return close[0]
    return ""
