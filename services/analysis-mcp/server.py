"""Static analysis over stdio MCP: identify, strings, structure, rules.

Every tool is a one-line delegation to ``maljan.tools`` — the sidecar runs in
the same uv environment as the pipeline, so it imports the implementation
rather than carrying a copy of it. What this file adds is the two things a
tool server owes a model: an error is *returned*, never raised (an exception
across the MCP boundary ends the call with a stack trace the model cannot act
on), and a tool whose optional library is missing still appears on the
manifest so the model learns why it is empty instead of never seeing the
capability at all.

``put_sample`` implements the remote-delivery convention (see
``maljan.agents.sample_staging``): a caller on another host uploads the bytes
and gets back the path to pass to every other tool here.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import os
import stat
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.core.paths import resolve_data
from maljan.tools import binary as binary_tools
from maljan.tools import identify as identify_tools
from maljan.tools import rules as rule_tools
from maljan.tools import staging
from maljan.tools import strings as string_tools
from maljan.tools.binary import carved_name_prefix
from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, manifest, module
from maljan.tools.errors import (
    BAD_ARGUMENT,
    NO_SUCH_FILE,
    PATH_OUTSIDE_ROOTS,
    code_for_exception,
    normalise_error,
    tool_error,
)
from maljan.tools.roots import PathOutsideRoots, resolve_under, resolve_under_roots
from maljan.tools.strings import DEFAULT_STRINGS_LIMIT

mcp = FastMCP("AnalysisMCP")

# What each tool needs beyond the interpreter, probed once when the server
# starts. A tool that is not listed always answers.
# The wall clock each rule engine is given. Named once so the tool's own
# default and the manifest that declares it cannot drift: a model told
# ``timeout_s: null`` for a scan that gives up after a minute has been told
# something untrue by the structure whose premise is that it was computed.
YARA_TIMEOUT_S = 60
CAPA_TIMEOUT_S = 300

TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds("identify_file"),
    ToolNeeds("hashes"),
    ToolNeeds("signing_info"),
    ToolNeeds("strings"),
    ToolNeeds("iocs_from_text"),
    ToolNeeds("iocs_from_file"),
    ToolNeeds("pe_info", (module("pefile"),)),
    ToolNeeds("elf_info", (module("elftools"),)),
    ToolNeeds("macho_info", (module("macholib"),)),
    ToolNeeds("apk_info", (module("androguard"),), without="the zip-level facts"),
    ToolNeeds("carve_payloads"),
    ToolNeeds("archive_list", (module("py7zr"),), without="zip and tar members; 7z needs py7zr"),
    ToolNeeds("document_info", (module("olefile"),), without="the PDF and OOXML halves"),
    ToolNeeds(
        "yara_scan",
        (module("yara"),),
        timeout_s=YARA_TIMEOUT_S,
        without="the regex fallback over the corpus",
    ),
    ToolNeeds("sigma_match", (module("sigma"),)),
    ToolNeeds("sigma_match_sandbox", (module("sigma"),)),
    ToolNeeds("capa", (module("capa"),), timeout_s=CAPA_TIMEOUT_S),
    ToolNeeds("put_sample"),
    ToolNeeds("put_sample_begin"),
    ToolNeeds("put_sample_chunk"),
    ToolNeeds("put_sample_finish"),
]
CAPABILITIES = manifest("analysis", TOOL_NEEDS)

# Chunked uploads in flight, keyed by upload id. Bounded by the number of
# concurrent stagers, which is the number of agents in a profile — but a
# ``put_sample_begin`` whose caller vanished would otherwise hold its chunks
# for the process lifetime, so they are evicted by age as well, and by count:
# each entry is cheap, and fifteen minutes of them is a long time to admit
# 2 GiB of chunks apiece.
_UPLOADS: dict[str, dict[str, Any]] = {}
_UPLOAD_TTL_SECONDS = 15 * 60
_MAX_UPLOADS = 32

# A chunk larger than this is refused rather than buffered: the convention
# splits at 8 MiB and a caller sending more is not speaking it.
_MAX_CHUNK_BYTES = 16 * 1024 * 1024
# The largest sample this server will accept by either route. A tool server
# reachable over HTTP is a place to post arbitrary bytes, and an unbounded
# accept is an unbounded write.
_MAX_SAMPLE_BYTES = 2 * 1024 * 1024 * 1024


def _too_long_to_decode(encoded: str, limit: int) -> bool:
    """Whether this base64 argument would exceed ``limit`` once decoded.

    Asked before decoding, not after. Base64 is four characters to three
    bytes, so the length of the argument bounds the length of the blob without
    materialising it — and materialising it was the problem: a 4 GiB argument
    was held as a string and again as bytes before the ceiling below refused
    it. The bound is generous by the padding and any whitespace, which costs
    nothing: what is being prevented is the order of magnitude.
    """
    return (len(encoded) // 4) * 3 > limit


# How long a staged sample is kept. Every ``put_sample*`` call prunes, so a
# long-lived server does not accumulate malware bytes without bound.
_DEFAULT_STAGING_TTL_HOURS = 24.0


# What a model writes when it means "I am not passing this one". A local model
# asked for an optional filter it does not want fills the field in rather than
# omitting it, and these are the two words it writes. Read as the absence they
# mean, once, here — every tool on this server goes through ``_guard``, so no
# tool has to know about it and none of them can disagree.
#
# Case-sensitive, and only these two: ``NULL`` is an ordinary token to search a
# binary for, and a search for it has to keep working. A string of nothing but
# spaces is the third form of the same intention and is read the same way, and
# so is a string of nothing but quote characters: a live run passed the
# two-character string "" as a directory name, and a directory literally
# named "" was created for it.
_ABSENT_WORDS = frozenset({"null", "None"})
_ABSENT_CHARACTERS = " \t\r\n\"'"


def _within(asked: Any, declared: int) -> int:
    """One tool's wall clock, held to the value its own manifest declares.

    A model that asks for a day gets the minute the manifest promised: the
    declared value is what every reader of ``capabilities`` was told, and a
    tool that quietly took more would make that structure untrue. Asking for
    less is allowed — a caller in a hurry is entitled to be.
    """
    try:
        wanted = int(asked)
    except (TypeError, ValueError):
        return declared
    return max(1, min(wanted, declared))


def _optional_string_params(call: Any) -> frozenset[str]:
    """The parameters of ``call`` whose absence is spelled ``None``.

    Only those: a required argument that arrived as the word "null" is a call
    that is wrong in a way the tool itself should answer, and turning it into
    ``None`` would trade a readable error for a confusing one.
    """
    import inspect

    try:
        parameters = inspect.signature(call).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins have no signature
        return frozenset()
    return frozenset(name for name, parameter in parameters.items() if parameter.default is None)


def _means_absent(value: Any) -> bool:
    """Whether a string argument is one of the ways of writing "not passing this"."""
    return isinstance(value, str) and (
        value in _ABSENT_WORDS or not value.strip(_ABSENT_CHARACTERS)
    )


def _read_absent_words(call: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """``kwargs`` with each optional argument's "null" read as ``None``."""
    optional = _optional_string_params(call)
    return {
        name: None if name in optional and _means_absent(value) else value
        for name, value in kwargs.items()
    }


# The arguments that name a file on this host. Held to the allowed roots in
# ``_guard`` rather than in each tool, so a tool added later is confined by
# having gone through the guard every tool here already goes through.
_PATH_ARGUMENTS = ("path", "pcap_path")

# The file a previous call in this run produced, rather than the sample. It is
# the model's to name — which of the payloads ``carve_payloads`` wrote is worth
# reading is an analysis decision — and the sample's own path is not, so this
# argument is qualified for what it holds and the sample's is hidden from the
# model entirely (``agents.tool_pinning``).
#
# Held to the staging base alone rather than to the sample roots: everything a
# tool here writes lands there, and nothing else the model could name should be
# reachable through an argument the model chose. A relative value is read as a
# name inside the staging area, which is how a model that pastes back the tail
# of a returned path is understood rather than refused.
CARVED_ARGUMENT = "carved_path"

# What ``carved_path`` may reach: the carved tree of the file this call is
# already reading, and that file itself. **Not** the whole staging base — a
# sample carrying another sample's digest in its own bytes, and one instruction
# to read it, was enough to pull another run's carved payload into this run's
# evidence, and another run's upload is named by sixteen hex characters and the
# original file name. The digest is the one thing this server can derive from
# what it was given, and it is exactly the key ``carve_payloads`` writes under.
#
# The tree now lives inside the job's own directory, so two jobs on the same
# sample carve into two trees and neither can name the other's by any spelling.
CARVED_DIRECTORY = "carved"

# What a caller is told when the argument resolves onto something that is not
# a file to read. Its own sentence rather than the roots one, which would be
# untrue of a directory that really is inside the staging area.
NOT_A_REGULAR_FILE_MESSAGE = (
    "the carved_path argument does not name a regular file; pass one of the paths "
    "carve_payloads returned"
)

# Every ``carved_path`` failure is answered in this argument's own words. The
# general file remediations name a sample path the model cannot see — the
# pinning took that parameter out of the schema — and a live analyst was handed
# "pass the absolute sample path the prompt names" on all six of its attempts.
CARVED_REMEDIATION = (
    "pass the carved_path value of an entry carve_payloads returned, exactly as it was "
    "returned and with no quotes around it"
)

# How many carved file names a refusal lists. Enough to choose from, short
# enough to read; the names are the tails this run wrote and nothing else.
_LISTED_CARVED_FILES = 12

# The longest value this argument takes, which is the longest path a
# filesystem takes. A carved path is a staging directory, a sha256 and a name
# the writer composed, so anything past this was never going to name a file and
# is answered here rather than by the kernel.
_MAX_CARVED_LENGTH = 4096

# How much of a value a refusal echoes back. The message travels to the ledger
# and, through the remediation, to the event feed, and a caller that sent three
# thousand characters does not need all three thousand back to see what it
# sent.
_ECHOED_VALUE_CHARS = 80

# The quote characters a model wraps a value in when it copies it out of the
# JSON it read. One matching pair is removed and nothing else is: no
# unescaping, no globbing, no case folding, because anything more would be
# guessing at what was meant rather than reading what was written.
_SURROUNDING_QUOTES = ('"', "'", "`")

# How many sample digests are remembered at once. One per sample a long-lived
# server sees, and a digest is sixty-four characters: the bound is against a
# process that runs for weeks, not against a run.
_MAX_REMEMBERED_DIGESTS = 64
_DIGESTS: dict[tuple[str, int, int], str] = {}


class NotARegularFile(Exception):
    """A path argument resolved onto something that cannot be read as a file."""

    def __init__(self, message: str = NOT_A_REGULAR_FILE_MESSAGE) -> None:
        super().__init__(message)


class CarvedFileNotFound(Exception):
    """``carved_path`` named nothing this run carved, and says what it did."""


def _unquoted(value: str) -> str:
    """``value`` with surrounding whitespace and one matching pair of quotes gone.

    A model that copies a path out of the JSON answer it just read copies the
    quotes with it: six live calls in a row passed
    ``"\"/srv/staging/carved/<sha>/body_0x364000_2bc01a3a74e5\""``. A quoted
    path is not absolute, so it took the relative branch and missed. Removing
    one matching pair is reading what was written; the confinement question is
    then asked of the result exactly as it is asked of anything else.
    """
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in _SURROUNDING_QUOTES:
        text = text[1:-1].strip()
    return text


def _carved_files(tree: Path) -> list[Path]:
    """Every file this run carved, in a stable order.

    Read with ``lstat``, so a symlink is not one. A link is not something this
    server wrote — ``carve_payloads`` is the only writer under this tree — and
    treating one as a carved file is how a name-shaped link came to be listed
    as a payload and matched by name. It is neither listed in a refusal's tails
    nor found by the label branch, and the confinement check below refuses it
    wherever it points.
    """
    if not tree.is_dir():
        return []
    found: list[Path] = []
    for entry in tree.rglob("*"):
        try:
            if stat.S_ISREG(entry.lstat().st_mode):
                found.append(entry)
        except OSError:  # an entry another call removed while this walked
            continue
    return sorted(found, key=lambda e: e.name)


def _by_display_name(tree: Path, asked: str) -> Path | None:
    """The one carved file whose display label is ``asked``, or ``None``.

    ``carve_payloads`` answers with both a ``name`` — the label, ``body+0x364000``
    — and the path it wrote, and a model passed the label back. The label
    decides the first half of the file's name (``binary.carved_name_prefix``),
    which is the mapping the writer itself uses, so the file can be found again
    without guessing. Exactly one match, or none: two payloads sharing a label
    are two files, and choosing between them is not this code's to do.
    """
    prefix = carved_name_prefix(asked)
    matched = [entry for entry in _carved_files(tree) if entry.name.startswith(prefix)]
    return matched[0] if len(matched) == 1 else None


def _inside(candidate: Path, roots: tuple[Path, ...]) -> Path:
    """``candidate`` resolved inside ``roots`` and readable as a file, or refused.

    The one place confinement is decided, so every spelling of the argument is
    decided the same way. A branch that returned its own answer skipped this:
    a symlink named like a payload was matched by its label and read, while the
    same file named by its tail and by its absolute path was refused, and the
    answer then recorded the in-tree name rather than what had been read.
    """
    resolved = resolve_under(candidate, roots)
    if not resolved.is_file():
        raise NotARegularFile()
    return resolved


def _carved_miss(tree: Path, asked: str) -> CarvedFileNotFound:
    """The refusal for a name this run did not carve, listing what it did.

    The names only, never a path: a refusal travels into the ledger and onto
    the event feed, and the tails are what a caller needs to choose again.
    """
    names = [entry.name for entry in _carved_files(tree)][:_LISTED_CARVED_FILES]
    listed = ", ".join(names) if names else "this run carved nothing"
    return CarvedFileNotFound(f"no carved file named {_echoed(asked)}; this run carved: {listed}")


def _echoed(value: str) -> str:
    """One value as a refusal quotes it back, bounded."""
    text = str(value or "")
    shown = text if len(text) <= _ECHOED_VALUE_CHARS else f"{text[:_ECHOED_VALUE_CHARS]}…"
    return repr(shown)


def _digest_of(target: Path) -> str:
    """The sha256 of a file, remembered while its size and mtime are unchanged.

    Read in pieces, because this runs on live samples and the upload ceiling
    admits two gigabytes of them, and remembered because every tool call on the
    same sample would otherwise hash it again.
    """
    try:
        info = target.stat()
    except OSError:
        return ""
    key = (str(target), info.st_size, info.st_mtime_ns)
    remembered = _DIGESTS.get(key)
    if remembered is not None:
        return remembered
    hasher = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
    except OSError:
        return ""
    digest = hasher.hexdigest()
    if len(_DIGESTS) >= _MAX_REMEMBERED_DIGESTS:
        _DIGESTS.clear()
    _DIGESTS[key] = digest
    return digest


def _carved_tree(digest: str) -> Path:
    """Where everything this job carved out of one sample lands."""
    return _staging_root() / CARVED_DIRECTORY / digest


# What every tool that takes it says about it, appended once so the fourteen
# descriptions cannot come to disagree.
CARVED_NOTE = (
    "Give ``carved_path`` to read a file an earlier call in this run wrote instead of the "
    "sample: pass the ``carved_path`` value of an entry ``carve_payloads`` returned, exactly "
    "as it was returned and with no quotes around it. Leave it out and the sample is read."
)

# The argument that names a rule corpus rather than a sample. It is a path
# too, and it is chosen by the same model, but the directories it may name are
# the rule directories rather than the sample ones — so it is held to
# ``rule_tools.corpus_roots()`` instead. ``default`` and the empty string name
# the shipped corpus and are not paths at all.
_CORPUS_ARGUMENT = "ruleset"
_CORPUS_WORDS = ("", "default")


def reads_a_carved_file(fn: Any) -> Any:
    """Say once, in this tool's own description, what ``carved_path`` is for.

    Applied under ``@mcp.tool()`` so the decorator that publishes the
    description reads the amended one. The sentence is written in a single
    place because fourteen copies of it would drift.
    """
    fn.__doc__ = f"{(fn.__doc__ or '').rstrip()}\n\n{CARVED_NOTE}"
    return fn


def _confined(kwargs: dict[str, Any]) -> dict[str, Any]:
    """``kwargs`` with every path argument resolved inside the allowed roots.

    The resolved path replaces the one the caller passed, so the tool opens
    the file the check was made about rather than resolving the argument a
    second time. A ruleset is checked where it stands: the tool resolves that
    one itself, against the roots it was checked against.

    ``carved_path`` is resolved against this job's staging directory alone and
    becomes the ``path`` the tool is called with, then leaves: the
    implementations take one file argument, and which file it is is decided
    here.
    """
    out = dict(kwargs)
    for name in _PATH_ARGUMENTS:
        value = out.get(name)
        if not isinstance(value, str) or not value.strip():
            continue
        inside = resolve_under_roots(value, extra_roots=(_staging_root(),))
        out[name] = str(staging.confined_to_this_job(inside))
    # Read before the roots are consulted, because a model that writes "null"
    # for an optional argument it is not passing means the absence — and this
    # one is not a parameter of the implementation, so the general reading of
    # those words above never sees it.
    carved = out.pop(CARVED_ARGUMENT, None)
    # The quotes come off before the absence words are read, so a model that
    # writes ``"null"`` between quotes has said the same thing as one that
    # writes it without them.
    carved = _unquoted(carved) if isinstance(carved, str) else carved
    sample = Path(out["path"]) if isinstance(out.get("path"), str) and out["path"] else None
    # ``carve_payloads`` writes under the sample's own tree whatever file it
    # was pointed at, so a payload carved out of a payload stays inside the
    # one directory this run may read.
    if "sample_digest" in out:
        out["sample_digest"] = _digest_of(sample) if sample is not None else ""
    if isinstance(carved, str) and not _means_absent(carved):
        out["path"] = str(_carved_file(carved, sample))
    corpus = out.get(_CORPUS_ARGUMENT)
    if isinstance(corpus, str) and corpus not in _CORPUS_WORDS:
        resolve_under_roots(resolve_data(corpus), extra_roots=rule_tools.corpus_roots())
    return out


def _carved_file(asked: str, sample: Path | None) -> Path:
    """The file ``carved_path`` names, held to what this sample produced.

    Three spellings are understood, because all three are things a model
    writes: the absolute path ``carve_payloads`` handed back, the tail of it —
    relative to this job's staging directory or to the sample's own carved
    directory — and
    the payload's display ``name``, which is the other field of the same entry.
    Any of them may arrive wrapped in the quotes the model read it between.
    Whichever it is, the resolved path has to land inside that directory or on
    the sample itself; symlinks are followed on both sides first, so a link
    planted under staging and a climb out of it land where they really point
    and are refused there.
    """
    if sample is None:
        raise PathOutsideRoots()
    if len(asked) > _MAX_CARVED_LENGTH:
        raise CarvedFileNotFound(
            f"the carved_path argument is {len(asked)} characters; no file this run wrote "
            f"has a name that long"
        )
    tree = _carved_tree(_digest_of(sample))
    roots = (tree, sample)
    target = Path(asked)
    candidates = [target] if target.is_absolute() else [tree / target, _staging_root() / target]
    other: Path | None = None
    inside = False
    for candidate in candidates:
        try:
            resolved = resolve_under(candidate, roots)
        except PathOutsideRoots:
            continue
        # A spelling that lands inside the tree but names nothing is not the
        # one the caller meant: the other spellings are tried before the answer
        # is decided, so a tail written against the staging base is not read
        # as a tail against the tree that happens to be inside it too.
        if resolved.is_file():
            return resolved
        inside = True
        if resolved.exists():
            other = other or resolved
    # The display label of a payload this run carved names its file through the
    # writer's own rule — and then answers the same confinement question the
    # other two spellings answer, on the path it resolves to.
    by_name = _by_display_name(tree, asked)
    if by_name is not None:
        return _inside(by_name, roots)
    # A directory, a FIFO, a device or a socket is not a file to read, and a
    # reader that opened a FIFO with no writer would wait for one forever.
    if other is not None:
        raise NotARegularFile()
    if inside:
        raise _carved_miss(tree, asked)
    raise PathOutsideRoots()


def _asked_for_a_carved_file(kwargs: dict[str, Any]) -> bool:
    """Whether this call named a carved file rather than reading the sample."""
    asked = kwargs.get(CARVED_ARGUMENT)
    return isinstance(asked, str) and not _means_absent(_unquoted(asked))


def _guard(tool: str, call: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one tool call, turning any exception into a returned error.

    A raised exception reaches the model as a transport-level failure with no
    structure; a returned error is something it can read and route around,
    which is the difference between an agent that tries another tool and one
    that retries the same broken call until its step budget is gone. The
    error carries a code and a remediation (``maljan.tools.errors``), and an
    implementation's flat ``{"error": "<text>"}`` is rewritten into the same
    shape on the way out.

    A path argument is held to the allowed roots first, and a refusal is
    answered in that same shape — the sample is adversary-authored content
    that this model reads, so the path it asks for is the one argument that
    may have been written by the sample's author.
    """
    try:
        asked = _confined(_read_absent_words(call, kwargs))
        answer = dict(normalise_error(dict(call(**asked))))
        # Which file was read, when it was not the sample. The ledger stores
        # the answer, so a run that analysed a carved payload says which one
        # rather than leaving a reader to infer it from the arguments.
        #
        # First, not appended. An answer wider than the caller's output
        # guardrail is cut from the end before anything records it, and a key
        # behind a long list is a key that does not survive the cut: one
        # measured run's ``strings`` over a carved PE returned 150 rows, was
        # cut at six thousand characters, and stored ``read_path`` nowhere
        # while its shorter siblings all carried it. At the front it is in the
        # part of the answer every reader keeps.
        if _asked_for_a_carved_file(kwargs):
            answer = {"read_path": answer.get("read_path") or asked.get("path", ""), **answer}
        return answer
    except PathOutsideRoots as refusal:
        # A ``carved_path`` refusal is answered in that argument's own words:
        # the general remediation names the sample path, which is a parameter
        # this server does not advertise to a model any more.
        return tool_error(
            PATH_OUTSIDE_ROOTS,
            str(refusal),
            tool=tool,
            remediation=CARVED_REMEDIATION if _asked_for_a_carved_file(kwargs) else None,
        )
    except CarvedFileNotFound as refusal:
        return tool_error(NO_SUCH_FILE, str(refusal), tool=tool, remediation=CARVED_REMEDIATION)
    except NotARegularFile as refusal:
        return tool_error(BAD_ARGUMENT, str(refusal), tool=tool, remediation=CARVED_REMEDIATION)
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        # A call that named a carved file is answered in that argument's words
        # however it failed. Anything the filesystem itself refuses — a name
        # the kernel will not take, a read that goes wrong mid-way — lands
        # here, and the catch-all remedy would send the caller back to a
        # manifest that has nothing to say about this argument.
        return tool_error(
            code_for_exception(exc),
            f"{type(exc).__name__}: {exc}",
            tool=tool,
            remediation=CARVED_REMEDIATION if _asked_for_a_carved_file(kwargs) else None,
        )


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, its optional dependency, and whether it is available.
    """
    # Deep, so "computed once when the server started" also means a
    # caller cannot reach in and change what it says.
    return copy.deepcopy(CAPABILITIES)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@mcp.tool()
@reads_a_carved_file
def identify_file(path: str, carved_path: str = "") -> dict[str, Any]:
    """Detect a file's format, platform, mime type, size and magic bytes."""
    return _guard("identify_file", identify_tools.identify_file, path=path, carved_path=carved_path)


@mcp.tool()
@reads_a_carved_file
def hashes(path: str, carved_path: str = "") -> dict[str, Any]:
    """Compute md5, sha1, sha256 and any available fuzzy or import hash."""
    return _guard("hashes", identify_tools.hashes, path=path, carved_path=carved_path)


@mcp.tool()
@reads_a_carved_file
def signing_info(path: str, file_type: str = "", carved_path: str = "") -> dict[str, Any]:
    """Report whether the file carries a code signature, for one format.

    ``file_type`` is the format the sample was routed as ("pe", "apk",
    "mach-o"); with none, the format is read from the bytes. The answer covers
    that format alone — a PE is asked about Authenticode and nothing else.
    """
    return _guard(
        "signing_info",
        identify_tools.signing_info,
        path=path,
        carved_path=carved_path,
        file_type=file_type or None,
    )


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


@mcp.tool()
@reads_a_carved_file
def strings(
    path: str,
    carved_path: str = "",
    min_len: int = 6,
    encodings: list[str] | None = None,
    limit: int = DEFAULT_STRINGS_LIMIT,
    offset: int = 0,
    pattern: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> dict[str, Any]:
    """List printable ASCII and UTF-16LE runs with their byte offsets.

    The page is small on purpose: 150 runs by default, because a larger answer
    is cut before you see it. Read ``next_offset`` in the answer and pass it as
    ``offset`` to get the following page — it is ``null`` when this page was
    the last one — and read ``total_matched`` to see how many runs the filters
    kept in all. Paging counts runs, not bytes.

    Use ``start``/``end`` for a byte range and ``pattern`` to keep only the runs
    containing a marker (case-insensitive substring, or ``re:<expression>`` for
    a regular expression); searching with ``pattern`` finds more in one call
    than paging through everything.
    """
    return _guard(
        "strings",
        string_tools.strings,
        path=path,
        carved_path=carved_path,
        min_len=min_len,
        encodings=tuple(encodings or ("ascii", "utf16le")),
        limit=limit,
        offset=offset,
        pattern=pattern,
        start=start,
        end=end,
    )


@mcp.tool()
def iocs_from_text(text: str, kinds: list[str] | None = None) -> dict[str, Any]:
    """Extract typed indicators (url, domain, ip, path, secret, ...) from text."""
    return _guard("iocs_from_text", string_tools.iocs_from_text, text=text, kinds=kinds)


@mcp.tool()
@reads_a_carved_file
def iocs_from_file(
    path: str, kinds: list[str] | None = None, carved_path: str = ""
) -> dict[str, Any]:
    """Extract typed indicators from a file's ASCII and wide strings."""
    return _guard(
        "iocs_from_file",
        string_tools.iocs_from_file,
        path=path,
        carved_path=carved_path,
        kinds=kinds,
    )


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


@mcp.tool()
@reads_a_carved_file
def pe_info(
    path: str,
    carved_path: str = "",
    sections: bool = True,
    imports: bool = True,
    exports: bool = True,
    resources: bool = True,
    overlay: bool = True,
    pdb: bool = True,
) -> dict[str, Any]:
    """Parse a PE: sections with entropy, imports, exports, resources, overlay, PDB path.

    Imports are listed without interpretation: each row is dll, function (the name
    or Ordinal_N), ordinal, hint and address. Ask api_capability what an API is
    used for.
    """
    return _guard(
        "pe_info",
        binary_tools.pe_info,
        path=path,
        carved_path=carved_path,
        sections=sections,
        imports=imports,
        exports=exports,
        resources=resources,
        overlay=overlay,
        pdb=pdb,
    )


@mcp.tool()
@reads_a_carved_file
def elf_info(path: str, carved_path: str = "") -> dict[str, Any]:
    """Parse an ELF: sections, imports (listed without interpretation), exports, segments,
    interpreter, DT_NEEDED. Ask api_capability with platform="linux" what a symbol is used for."""
    return _guard("elf_info", binary_tools.elf_info, path=path, carved_path=carved_path)


@mcp.tool()
@reads_a_carved_file
def macho_info(path: str, carved_path: str = "") -> dict[str, Any]:
    """Parse a Mach-O: headers, load commands, dylibs, code-signature presence."""
    return _guard("macho_info", binary_tools.macho_info, path=path, carved_path=carved_path)


@mcp.tool()
@reads_a_carved_file
def apk_info(
    path: str,
    carved_path: str = "",
    manifest: bool = True,
    permissions: bool = True,
    certs: bool = True,
    components: bool = True,
    native_libs: bool = True,
    dex_strings: bool = False,
    limit: int = 500,
) -> dict[str, Any]:
    """Read an APK's manifest, permissions, components, certificates and native libs."""
    return _guard(
        "apk_info",
        binary_tools.apk_info,
        path=path,
        carved_path=carved_path,
        manifest=manifest,
        permissions=permissions,
        certs=certs,
        components=components,
        native_libs=native_libs,
        dex_strings=dex_strings,
        limit=limit,
    )


@mcp.tool()
@reads_a_carved_file
def carve_payloads(path: str, carved_path: str = "") -> dict[str, Any]:
    """Write each embedded payload found in the file out as its own file.

    The carved files land under the sidecar's private staging directory, in
    carved/<sha256 of the sample>/, and the returned paths point there; the
    destination is not an argument. Each entry answers with its ``carved_path``
    — the value to pass back as this argument on any tool that reads a file.
    """
    return _guard(
        "carve_payloads",
        _carve_under_staging,
        path=path,
        carved_path=carved_path,
        sample_digest="",
    )


def _carve_under_staging(path: str, sample_digest: str = "") -> dict[str, Any]:
    """Carve into ``<staging>/carved/<sha256>/``, created private like the staging dir.

    A model-chosen destination let a tool write live malware anywhere the
    sidecar could write, and one live run wrote a carved PE body into the
    sidecar's own cwd. The sample's hash names the directory, so two samples
    never share one and a re-run lands in the same place.

    ``sample_digest`` is the digest of the file this call was *pinned* to,
    which is the sample; the guard fills it. A payload carved out of a carved
    payload nests under the sample's own directory rather than opening a
    directory of its own, so everything one run produces is one tree — the
    tree that run may read back, and the tree the sweep prunes.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "carve_payloads"}
    digest = _digest_of(target)
    anchor = sample_digest or digest
    destination = _carved_tree(anchor)
    if digest != anchor:
        destination = destination / digest
    _staging_dir()
    for directory in (destination.parent, destination):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return binary_tools._carve_into(path, destination)


@mcp.tool()
@reads_a_carved_file
def archive_list(path: str, limit: int = 500, carved_path: str = "") -> dict[str, Any]:
    """List a zip, 7z, tar or gzip archive's members without extracting them."""
    return _guard(
        "archive_list",
        binary_tools.archive_list,
        path=path,
        carved_path=carved_path,
        limit=limit,
    )


@mcp.tool()
@reads_a_carved_file
def document_info(path: str, carved_path: str = "") -> dict[str, Any]:
    """Inspect an OLE2, OOXML or PDF document for macros, parts and action markers."""
    return _guard("document_info", binary_tools.document_info, path=path, carved_path=carved_path)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@mcp.tool()
@reads_a_carved_file
def yara_scan(
    path: str = "",
    carved_path: str = "",
    text: str = "",
    ruleset: str = "default",
    timeout_s: int = YARA_TIMEOUT_S,
) -> dict[str, Any]:
    """Scan a file or a block of text against a YARA rule corpus."""
    return _guard(
        "yara_scan",
        rule_tools.yara_scan,
        path=path or None,
        carved_path=carved_path,
        text=text or None,
        ruleset=ruleset,
        timeout_s=_within(timeout_s, YARA_TIMEOUT_S),
    )


@mcp.tool()
def sigma_match(events: list[dict[str, Any]], ruleset: str = "default") -> dict[str, Any]:
    """Match structured events against a Sigma rule corpus."""
    return _guard("sigma_match", rule_tools.sigma_match, events=events, ruleset=ruleset)


@mcp.tool()
def sigma_match_sandbox(report: dict[str, Any], ruleset: str = "default") -> dict[str, Any]:
    """Derive Sysmon-shaped events from a sandbox report and match Sigma rules."""
    return _guard(
        "sigma_match_sandbox", rule_tools.sigma_match_sandbox, report=report, ruleset=ruleset
    )


@mcp.tool()
@reads_a_carved_file
def capa(
    path: str, timeout_s: int = CAPA_TIMEOUT_S, backend: str = "auto", carved_path: str = ""
) -> dict[str, Any]:
    """Run capa and report the capabilities it finds, with ATT&CK and MBC metadata."""
    return _guard(
        "capa",
        rule_tools.capa,
        path=path,
        carved_path=carved_path,
        timeout_s=_within(timeout_s, CAPA_TIMEOUT_S),
        backend=backend,
    )


# ---------------------------------------------------------------------------
# Sample delivery
# ---------------------------------------------------------------------------


def _staging_ttl_seconds() -> float:
    """``MALJAN_STAGING_TTL_HOURS``, or a day. Zero or less disables pruning."""
    raw = os.environ.get(staging.STAGING_TTL_ENV, "").strip()
    try:
        hours = float(raw) if raw else _DEFAULT_STAGING_TTL_HOURS
    except ValueError:
        hours = _DEFAULT_STAGING_TTL_HOURS
    return hours * 3600.0


def _staging_base() -> Path:
    """The staging path this server is configured for, created or not.

    The *base*, shared by every job on this host: ``MALJAN_STAGING_DIR`` or the
    default. Nothing is written here directly any more — see ``_staging_root``
    — but the sweep walks it, because the job directories are its children.
    """
    return staging.staging_base()


def _staging_root() -> Path:
    """The directory this job may write and read, created or not.

    ``<base>/<MALJAN_STAGING_JOB>`` when the process that spawned this server
    named a job, and the base itself when nothing did — a server started by
    hand or by a settings probe, which has no job to be confined to.

    Separate from ``_staging_dir`` because every read goes through the root
    check and a read must not create a directory, validate one or fail on a
    staging path that is wrong in a way only an upload would care about.
    """
    return staging.staging_root()


def _private_dir(path: Path) -> Path:
    """``path`` as a directory only this user may enter, or an error.

    The rule lives in ``maljan.tools.staging`` so the worker's capture
    directory is opened under exactly the same checks this server opens its
    own staging directory under.
    """
    return staging.private_dir(path)


def _staging_dir() -> Path:
    """Where this job's uploaded samples land, created private.

    The base is created and checked first and the job directory inside it
    second, so a base somebody else owns is refused before anything of this
    job's is written into it.
    """
    base = _private_dir(_staging_base())
    root = _staging_root()
    return base if root == base else _private_dir(root)


def _prune_staging(base: Path) -> int:
    """Delete staged files past their TTL. Returns how many went.

    Called from every ``put_sample*`` entry point rather than on a timer: this
    server has no scheduler, and the moment a sample arrives is exactly when
    the last one is most likely to be stale.

    Three things live under the base: the job directories of this release, the
    flat uploads of the one before it, and the carved tree those uploads went
    with. All three are swept, so an upgrade leaves nothing to migrate.
    """
    ttl = _staging_ttl_seconds()
    if ttl <= 0:
        return 0
    cutoff = time.time() - ttl
    removed = 0
    for entry in base.iterdir():
        try:
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                if staging.is_job_directory_name(entry.name):
                    removed += _prune_job_directory(entry, cutoff)
                continue
            if info.st_mtime >= cutoff:
                continue
            entry.unlink()
            removed += 1
        except OSError:  # a file another call already removed
            continue
    removed += _prune_carved(base / CARVED_DIRECTORY, cutoff)
    return removed + _prune_legacy_captures(cutoff)


def _prune_legacy_captures(cutoff: float) -> int:
    """Take away the sandbox captures the release before this left in the open.

    Captures used to be fetched into one directory under the system temp
    directory, shared by every job and every worker on the host, and nothing
    ever removed them. They now live inside the job's own staging directory and
    go with it; this reaches what is already on disk. The directory is this
    project's own and its name is fixed, so there is nothing here an operator
    configured and nothing to guess at.
    """
    root = Path(tempfile.gettempdir()) / staging.LEGACY_CAPTURE_DIR_NAME
    if not root.is_dir() or root.is_symlink():
        return 0
    removed = 0
    for entry in root.iterdir():
        try:
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            # A link is unlinked, never followed and never counted: whatever
            # it points at is somebody else's, and leaving it would keep the
            # directory alive for as long as the link was there.
            if stat.S_ISLNK(info.st_mode):
                entry.unlink()
                continue
            if info.st_mtime >= cutoff:
                continue
            entry.unlink()
            removed += 1
        except OSError:  # a file another sweep already removed
            continue
    with contextlib.suppress(OSError):  # only when the last capture has gone
        root.rmdir()
    return removed


def _newest_mtime(root: Path) -> float:
    """The most recent mtime in this tree, the directory itself included.

    Read with ``lstat`` throughout: a symlink's own timestamp is what counts,
    never the timestamp of whatever it points at, which may be a file somebody
    else is still writing.
    """
    try:
        newest = root.lstat().st_mtime
    except OSError:
        return 0.0
    for entry in root.rglob("*"):
        try:
            newest = max(newest, entry.lstat().st_mtime)
        except OSError:  # an entry another call removed while this walked
            continue
    return newest


def _prune_job_directory(directory: Path, cutoff: float) -> int:
    """Prune one job's directory: whole when it is stale, inside it when not.

    A job directory is one unit — an upload, the tree carved out of it, and
    nothing another job may name — so the age that decides it is the newest
    mtime anywhere inside. A worker that removed its own directory on the way
    out leaves nothing for this; what it reaches is what a killed worker left.

    A directory still in use is swept the way the flat base always was, so a
    long job does not keep every payload it ever carved.
    """
    if _newest_mtime(directory) < cutoff:
        held = sum(1 for entry in directory.rglob("*") if not stat.S_ISDIR(entry.lstat().st_mode))
        return held if staging.remove_tree(directory) else 0
    removed = 0
    for entry in directory.iterdir():
        try:
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode) or info.st_mtime >= cutoff:
                continue
            entry.unlink()
            removed += 1
        except OSError:  # a file another call already removed
            continue
    return removed + _prune_carved(directory / CARVED_DIRECTORY, cutoff)


def _prune_carved(root: Path, cutoff: float) -> int:
    """Delete carved payloads past their TTL, and the trees left empty by it.

    The sweep above skips directories, which is right for the staging base —
    nothing else there is one — and meant the carved trees never expired at
    all: every run that carved anything left its payloads on disk for the life
    of the host. Only files this server wrote are unlinked; a symlink is left
    exactly where it is rather than followed.
    """
    removed = 0
    if not root.is_dir():
        return 0
    for tree in sorted(root.rglob("*"), key=lambda entry: len(entry.parts), reverse=True):
        try:
            info = tree.lstat()
            if stat.S_ISDIR(info.st_mode):
                with contextlib.suppress(OSError):  # a tree still holding payloads
                    tree.rmdir()
                continue
            if stat.S_ISLNK(info.st_mode) or info.st_mtime >= cutoff:
                continue
            tree.unlink()
            removed += 1
        except OSError:  # an entry another call already removed
            continue
    return removed


def _evict_stale_uploads() -> None:
    """Drop chunked uploads whose caller never finished them."""
    cutoff = time.monotonic() - _UPLOAD_TTL_SECONDS
    for upload_id in [k for k, v in _UPLOADS.items() if v.get("started_at", 0.0) < cutoff]:
        _UPLOADS.pop(upload_id, None)


def _write_sample(filename: str, blob: bytes, sha256: str) -> dict[str, Any]:
    """Write the bytes under the staging directory, checking the digest first.

    Created with ``O_CREAT|O_EXCL|O_NOFOLLOW`` at 0o600, not written and then
    chmodded: the two-step form leaves the file readable at the process umask
    for as long as the write takes, and would follow a symlink planted at the
    destination.
    """
    if len(blob) > _MAX_SAMPLE_BYTES:
        return {"error": f"sample exceeds {_MAX_SAMPLE_BYTES} bytes"}
    actual = hashlib.sha256(blob).hexdigest()
    if sha256 and actual != sha256.lower():
        return {"error": f"sha256 mismatch: expected {sha256}, received {actual}"}
    root = _staging_dir()
    # Swept from the base rather than from this job's own directory, because
    # what expires is mostly other jobs': their directories are siblings of
    # this one, and the flat files of the release before this are its parents'.
    _prune_staging(_staging_base())
    # The caller's filename names the file, never the directory: a name
    # carrying ``..`` or an absolute prefix must not decide where this writes.
    safe = Path(filename or actual).name or actual
    destination = root / f"{actual[:16]}_{safe}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    if not destination.exists():
        flags |= os.O_EXCL
    fd = os.open(destination, flags, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    os.chmod(destination, 0o600)
    return {"path": str(destination), "sha256": actual, "size": len(blob)}


@mcp.tool()
def put_sample(filename: str, content_b64: str, sha256: str = "") -> dict[str, Any]:
    """Upload a sample in one call and get back the path to analyse it at."""
    _evict_stale_uploads()
    if _too_long_to_decode(content_b64, _MAX_SAMPLE_BYTES):
        return tool_error(
            BAD_ARGUMENT, f"sample exceeds {_MAX_SAMPLE_BYTES} bytes", tool="put_sample"
        )
    try:
        blob = base64.b64decode(content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return tool_error(
            BAD_ARGUMENT, f"content_b64 is not valid base64: {exc}", tool="put_sample"
        )
    return _guard("put_sample", _write_sample, filename=filename, blob=blob, sha256=sha256)


@mcp.tool()
def put_sample_begin(filename: str, sha256: str, size: int) -> dict[str, Any]:
    """Start a chunked upload for a sample too large to send in one call."""
    _evict_stale_uploads()
    declared = int(size)
    if declared < 0 or declared > _MAX_SAMPLE_BYTES:
        return tool_error(
            BAD_ARGUMENT,
            f"declared size must be between 0 and {_MAX_SAMPLE_BYTES} bytes",
            tool="put_sample_begin",
        )
    if len(_UPLOADS) >= _MAX_UPLOADS:
        return tool_error(
            BAD_ARGUMENT,
            f"too many uploads in flight (limit {_MAX_UPLOADS}); finish one before starting "
            "another",
            tool="put_sample_begin",
        )
    upload_id = uuid.uuid4().hex
    _UPLOADS[upload_id] = {
        "filename": filename,
        "sha256": sha256,
        "size": declared,
        "chunks": {},
        "received": 0,
        "started_at": time.monotonic(),
    }
    return {"upload_id": upload_id}


@mcp.tool()
def put_sample_chunk(upload_id: str, seq: int, content_b64: str) -> dict[str, Any]:
    """Send one chunk of a chunked upload, identified by its sequence number."""
    _evict_stale_uploads()
    upload = _UPLOADS.get(upload_id)
    if upload is None:
        return tool_error(BAD_ARGUMENT, f"unknown upload_id {upload_id!r}", tool="put_sample_chunk")
    if _too_long_to_decode(content_b64, _MAX_CHUNK_BYTES):
        return tool_error(
            BAD_ARGUMENT, f"chunk exceeds {_MAX_CHUNK_BYTES} bytes", tool="put_sample_chunk"
        )
    try:
        blob = base64.b64decode(content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return tool_error(
            BAD_ARGUMENT, f"content_b64 is not valid base64: {exc}", tool="put_sample_chunk"
        )
    if len(blob) > _MAX_CHUNK_BYTES:
        return tool_error(
            BAD_ARGUMENT, f"chunk exceeds {_MAX_CHUNK_BYTES} bytes", tool="put_sample_chunk"
        )
    # Keyed by sequence rather than appended: a transport that reorders or
    # retries a chunk must not silently corrupt the file, and the digest check
    # at finish would only tell the caller *that* it did.
    previous = upload["chunks"].get(int(seq))
    running = upload["received"] - (len(previous) if previous else 0) + len(blob)
    # Enforced as the chunks arrive, not at assembly: refusing a 3 GB upload
    # after buffering all of it is not a limit, it is a slower way to run out
    # of memory.
    if running > min(upload["size"] or _MAX_SAMPLE_BYTES, _MAX_SAMPLE_BYTES):
        _UPLOADS.pop(upload_id, None)
        return tool_error(BAD_ARGUMENT, "upload exceeds its declared size", tool="put_sample_chunk")
    upload["chunks"][int(seq)] = blob
    upload["received"] = running
    return {"upload_id": upload_id, "seq": int(seq), "received": len(blob)}


@mcp.tool()
def put_sample_finish(upload_id: str) -> dict[str, Any]:
    """Assemble a chunked upload, verify its digest and return the sample's path."""
    _evict_stale_uploads()
    upload = _UPLOADS.pop(upload_id, None)
    if upload is None:
        return tool_error(
            BAD_ARGUMENT, f"unknown upload_id {upload_id!r}", tool="put_sample_finish"
        )
    chunks: dict[int, bytes] = upload["chunks"]
    blob = b"".join(chunks[seq] for seq in sorted(chunks))
    expected = int(upload.get("size") or 0)
    if expected and len(blob) != expected:
        return tool_error(
            BAD_ARGUMENT,
            f"size mismatch: expected {expected} bytes, assembled {len(blob)}",
            tool="put_sample_finish",
        )
    return _guard(
        "put_sample_finish",
        _write_sample,
        filename=upload["filename"],
        blob=blob,
        sha256=upload["sha256"],
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
