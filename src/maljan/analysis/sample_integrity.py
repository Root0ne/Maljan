"""Whether the copies of the sample the platform handed out stayed the bytes it took in.

The worker hashes every copy it hands out — its download, which the sample
path names, and each mirror it wrote for a server that reads a mount — once
when the job starts and once when the run ends, before any copy is removed,
and compares each reading with the SHA-256 taken at intake. A store that
answered with other bytes, a tool server that writes into its mount, or a
copy another job left in place shows here, as a reading that is not the
intake digest.

The record is a run fact (``run_summary["sample_integrity"]``) and is said in
the isolation part of the disclosure record, under the run's own readers
(:func:`integrity_lines`). A changed copy never fails the run: the record says
which copy, what it read and when it was seen, and the analyst decides what
it touches. A run stored before the record existed carries none and reads as
before.

A sandbox that detonated the sample names the target it ran in its own
report. Where that hash is not the intake digest, the run keeps a second
record (``run_summary["sandbox_target"]``, :func:`sandbox_target_record`),
said in the same part (:func:`sandbox_target_lines`): what the sandbox
observed may be of other bytes. A report that names no target hash, or the
intake one, adds nothing.

Each reading is one streaming pass over the copy (:func:`file_sha256`), of no
more than the intake size: a copy of another size is a change without being
read. The cost is linear in the sample's size, with no limit of its own.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import Any

# The run summary key and the isolation part key the record is kept under.
RECORD_KEY = "sample_integrity"
# The same, for a sandbox report that named another target.
SANDBOX_KEY = "sandbox_target"

_SHA256 = re.compile(r"[0-9a-f]{64}")

# When a reading was taken.
AT_START = "start"
AT_END = "end"

# Which copy a reading is of: the worker's download, or a mirror it wrote.
DOWNLOAD = "download"
MIRROR = "mirror"

_WHEN = {AT_START: "when the job started", AT_END: "when the run ended"}


# How much of a copy one read takes.
_CHUNK_BYTES = 1024 * 1024


def file_sha256(path: str | os.PathLike[str], size: int | None = None) -> tuple[str, str]:
    """``(sha256, "")`` of the regular file at ``path``, or ``("", why)`` where it is not read.

    The file's directory is opened first, without following a link there,
    and the file is opened through it, without following a link and without
    blocking: a link put in place of the copy or of its directory, or a pipe
    put in place of the copy, is a reading that failed, never a read of
    something else. Only a regular file is read. A hard link put in the
    copy's place is read, and shows as the bytes it holds.

    ``size`` is the sample's size at intake. A copy of another size is not
    read at all (``why`` says both sizes), and no more than ``size`` bytes
    are ever read, so a copy grown during the run costs no more than the
    sample does; one whose size moved while it was read says so too.
    Without ``size`` the whole file is read. Either way one streaming pass.
    ``why`` names the failure's kind, never the path. Never raises.
    """
    where = os.fspath(path)
    try:
        dir_fd = os.open(
            os.path.dirname(where) or ".",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        return "", type(exc).__name__
    try:
        fd = os.open(
            os.path.basename(where),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dir_fd,
        )
    except OSError as exc:
        return "", type(exc).__name__
    finally:
        os.close(dir_fd)
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode):
            return "", "not a regular file"
        if size is not None and held.st_size != size:
            return "", f"size {held.st_size} is not the intake size {size}"
        os.set_blocking(fd, True)
        digest = hashlib.sha256()
        left = held.st_size if size is None else size
        while left > 0:
            chunk = os.read(fd, min(_CHUNK_BYTES, left))
            if not chunk:
                break
            digest.update(chunk)
            left -= len(chunk)
        after = os.fstat(fd).st_size
        if after != held.st_size or left:
            return "", f"size moved from {held.st_size} to {after} while it was read"
        return digest.hexdigest(), ""
    except OSError as exc:
        return "", type(exc).__name__
    finally:
        os.close(fd)


def reading(
    copy: str, where: str, at: str, sha256: str, error: str, seen_at: str
) -> dict[str, Any]:
    """One reading of one copy: which copy, when, what it read or why it was not hashed."""
    return {
        "copy": copy,
        "where": where,
        "at": at,
        "sha256": sha256,
        "error": error,
        "seen_at": seen_at,
    }


def matches(entry: Mapping[str, Any], expected: str) -> bool:
    """Whether ``entry`` read the intake digest."""
    return bool(expected) and str(entry.get("sha256") or "").lower() == expected.lower()


def integrity_record(expected: str, readings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The record: the intake digest, every reading, and whether any reading was not it."""
    held = [dict(entry) for entry in readings]
    return {
        "expected_sha256": expected,
        "readings": held,
        "changed": any(not matches(entry, expected) for entry in held),
    }


def sandbox_target_record(
    expected: str, claimed: Any, *, provider: str = "", task_id: str = ""
) -> dict[str, Any] | None:
    """The record of a sandbox report whose target hash is not ``expected``; else ``None``.

    ``claimed`` is the target SHA-256 the sandbox's report names, as the
    provider's reader put it in the neutral report. No claim, or the intake
    digest in any case, is no record. A claim that is not a SHA-256 is the
    sandbox's own text: it is kept as :func:`_shown` keeps it, marked
    ``sandbox_sha256_valid: False``.
    """
    claim = str(claimed or "").strip().lower()
    if not claim or not expected or claim == expected.lower():
        return None
    if _SHA256.fullmatch(claim):
        return {
            "expected_sha256": expected,
            "sandbox_sha256": claim,
            "provider": provider,
            "task_id": task_id,
        }
    return {
        "expected_sha256": expected,
        "sandbox_sha256": _shown(claim),
        "sandbox_sha256_valid": False,
        "provider": provider,
        "task_id": task_id,
    }


def _shown(value: str) -> str:
    """A sandbox's value that is not a SHA-256, as a sandbox failure's words are kept.

    A URL loses its credentials, every line break becomes a space, every
    other control character is dropped, and the value is cut to the bound a
    sandbox failure's words have (``app.SANDBOX_FAILURE_CHARS``) with the cut
    mark. Only a bounded head of it is read.
    """
    from maljan.app import SANDBOX_FAILURE_CHARS
    from maljan.core.settings_overrides import redact_url
    from maljan.utils.marked_cut import CUT_MARK, marked_cut

    head = value[: 4 * SANDBOX_FAILURE_CHARS]
    one_line = " ".join(redact_url(head).splitlines())
    printable = "".join(ch for ch in one_line if unicodedata.category(ch) != "Cc")
    cut = marked_cut(printable, SANDBOX_FAILURE_CHARS)
    if len(value) > len(head) and not cut.endswith(CUT_MARK):
        # Only the head was read: what is shown still says it was cut.
        cut = cut[: max(0, SANDBOX_FAILURE_CHARS - len(CUT_MARK))].rstrip() + CUT_MARK
    return cut


def with_integrity(disclosure: Any, record: Mapping[str, Any], key: str = RECORD_KEY) -> Any:
    """``disclosure`` with ``record`` in its isolation part; unchanged when it has no such part."""
    if not isinstance(disclosure, Mapping):
        return disclosure
    part = disclosure.get("isolation")
    if not isinstance(part, Mapping) or "rows" not in part:
        return disclosure
    return {**disclosure, "isolation": {**part, key: dict(record)}}


def _copy_name(entry: Mapping[str, Any], code: Callable[[str], str]) -> str:
    if entry.get("copy") == MIRROR:
        where = str(entry.get("where") or "")
        return f"the mirror in {code(where)}" if where else "a mirror"
    return "the worker's copy"


def integrity_lines(record: Any, code: Callable[[str], str]) -> list[str]:
    """The record's sentences; ``[]`` for a part stored without one."""
    if not isinstance(record, Mapping) or not isinstance(record.get("readings"), list):
        return []
    expected = str(record.get("expected_sha256") or "")
    readings = [entry for entry in record["readings"] if isinstance(entry, Mapping)]
    if not readings:
        return []
    off = [entry for entry in readings if not matches(entry, expected)]
    copies = len({(entry.get("copy"), entry.get("where")) for entry in readings})
    held = "copy" if copies == 1 else f"{copies} copies"
    if not off:
        whens = {str(entry.get("at") or "") for entry in readings}
        said = " and ".join(_WHEN[at] for at in (AT_START, AT_END) if at in whens)
        return [
            f"The sample the platform handed out ({held}) was hashed {said}, and every "
            f"reading was its intake SHA-256 {code(expected)}."
        ]
    lines = [
        f"A copy of the sample the platform handed out did not read as its intake SHA-256 "
        f"{code(expected)}. The run was not failed for it; which findings it touches is "
        "the analyst's call."
    ]
    for entry in off:
        when = _WHEN.get(str(entry.get("at") or ""), "at a time not recorded")
        seen = str(entry.get("seen_at") or "")
        when = f"{when} ({seen})" if seen else when
        who = _copy_name(entry, code)
        sha = str(entry.get("sha256") or "")
        if sha:
            lines.append(f"{who[:1].upper()}{who[1:]} read {code(sha)} {when}.")
        else:
            why = str(entry.get("error") or "no reason recorded")
            lines.append(f"{who[:1].upper()}{who[1:]} was not hashed {when}: {why}.")
    return lines


def sandbox_target_lines(record: Any, code: Callable[[str], str]) -> list[str]:
    """The sandbox target record's sentences; ``[]`` for a part stored without one."""
    if not isinstance(record, Mapping):
        return []
    claim = str(record.get("sandbox_sha256") or "")
    expected = str(record.get("expected_sha256") or "")
    if not claim or not expected:
        return []
    provider = str(record.get("provider") or "")
    task_id = str(record.get("task_id") or "")
    which = f"The report of the sandbox {code(provider)}" if provider else "The sandbox report"
    if task_id:
        which += f" (task {code(task_id)})"
    if record.get("sandbox_sha256_valid") is False:
        said = (
            f"{which} names its target with a value that is not a SHA-256, {code(claim)}, "
            f"so what it observed cannot be tied to the sample's intake SHA-256 "
            f"{code(expected)}."
        )
    else:
        said = (
            f"{which} names its target SHA-256 as {code(claim)}, not the sample's intake "
            f"SHA-256 {code(expected)}: what it observed may be of other bytes."
        )
    return [
        f"{said} The run was not failed for it; which findings it touches is the analyst's call."
    ]
