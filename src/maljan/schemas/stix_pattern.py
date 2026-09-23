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
# backslash as an escape would eat the separators out of it.
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
        literal, end, closed = _read_quoted(text, index)
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


def _read_quoted(text: str, start: int) -> tuple[str, int, bool]:
    """The literal opening at ``text[start]``, where it ends, and whether it closed."""
    value: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in _ESCAPABLE:
            value.append(text[index + 1])
            index += 2
            continue
        if char == "'":
            return "".join(value), index + 1, True
        value.append(char)
        index += 1
    return "".join(value), len(text), False


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

_FIRST_STEP_RE = re.compile(r"^([a-z0-9_]+)")
_EXTENSION_KEY_RE = re.compile(r"^extensions(?:\.'((?:\\.|[^'\\])*)'|\['((?:\\.|[^'\\])*)'\])")


def object_path_problems(pattern: str) -> list[str]:
    """What is wrong with the object paths ``pattern`` compares, one sentence each.

    Asked only of a STIX type written as STIX writes it: a property the type
    does not define, or an extension it does not have. Each problem is named
    once. A type STIX does not have is :func:`unknown_object_types`' answer.
    """
    found: list[str] = []
    for comparison in read_comparisons(pattern):
        kind = comparison.written_type or comparison.object_type
        properties = SCO_PROPERTIES.get(kind)
        if properties is None:
            continue
        step = _FIRST_STEP_RE.match(comparison.prop)
        name = step.group(1) if step else comparison.prop
        if name == "extensions":
            key_match = _EXTENSION_KEY_RE.match(comparison.prop)
            key = (key_match.group(1) or key_match.group(2) or "") if key_match else ""
            allowed = SCO_EXTENSIONS.get(kind, frozenset())
            if key and (
                key in allowed or key.startswith("x-") or key.startswith("extension-definition--")
            ):
                continue
            listed = ", ".join(sorted(allowed)) if allowed else "no predefined extension"
            problem = f"{kind} has no extension {key!r} (it has {listed})"
        elif name in properties or name in SCO_COMMON_PROPERTIES or name.startswith("x_"):
            continue
        else:
            problem = f"{kind} has no property {name!r}"
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
