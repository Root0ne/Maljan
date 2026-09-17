"""Which directories a tool server may read, and how a path argument is held to them.

A sample is adversary-authored content, and the analyst model reads it: the
strings in a binary, the resources in a PE, the text of a document. A tool
that opens whatever path it is handed therefore opens whatever the sample's
author asked for — ``iocs_from_file`` over a credentials file, ``strings``
over a private key — and the answer travels back through the ledger, the
report and the event feed. The write side of the sidecars was already
confined; this is the read side.

Two kinds of root, and the sidecar names both:

* the staging directory it writes uploads into, which it already knows, and
* ``MALJAN_SAMPLE_ROOTS``: the directories the deployment says hold samples,
  as a list separated by the platform's path separator (``:`` on POSIX).
  Empty by default — a server nobody told anything reads only what it staged
  itself.

A caller that *creates* one of those directories says so rather than leaving
the operator to configure what the process already knows: the worker exports
the sample mirror it copies into, and the application exports the directory it
fetches a capture to. Those paths come from the deployment, never from a
model.

The check resolves both sides with ``realpath``, so a symlink planted under a
root and a ``..`` climb out of one both land where they really point and are
refused there.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from maljan.tools.errors import PATH_OUTSIDE_ROOTS, REMEDIATIONS

# The environment list, and the character between its entries. ``os.pathsep``
# is ``:`` on every platform this runs on and is what a reader of ``PATH``
# expects; naming it rather than writing the colon keeps a Windows host from
# reading a drive letter as a separator.
SAMPLE_ROOTS_ENV = "MALJAN_SAMPLE_ROOTS"
ROOT_SEPARATOR = os.pathsep

# What the model is told. It names no host path on purpose: the refusal goes
# back to the model, into the ledger and onto the event feed, and the argument
# it is about is the one part of it the sample's author may have written.
OUTSIDE_ROOTS_MESSAGE = "the path argument is outside the directories this server may read"


class PathOutsideRoots(Exception):
    """A path argument resolved outside every root this server was given.

    Carries its own remediation, so a handler that may not repeat an
    exception's message still has something to tell the reader.
    """

    remediation = REMEDIATIONS[PATH_OUTSIDE_ROOTS]

    def __init__(self, message: str = OUTSIDE_ROOTS_MESSAGE) -> None:
        super().__init__(message)


def configured_roots() -> list[Path]:
    """The directories ``MALJAN_SAMPLE_ROOTS`` names, in the order given.

    Read on every call rather than at import: a worker exports its mirror
    directory once it has one, and a server that cached the empty default
    would refuse the sample it was started for.
    """
    raw = os.environ.get(SAMPLE_ROOTS_ENV, "")
    return [Path(part) for part in raw.split(ROOT_SEPARATOR) if part.strip()]


def add_sample_root(path: str | Path) -> None:
    """Name ``path`` as a root for every sidecar this process starts *after* this.

    For the caller that creates the directory: the worker's sample mirror, the
    capture a sandbox provider fetches, the file an operator passed on the
    command line. The value is a deployment fact either way, never something a
    model chose.

    "After this" is the whole of the contract. A sidecar's environment is
    copied into the child when it is spawned (``agents.subprocess_env``), so a
    root added once a server is running does not reach that server. Every
    caller here runs before the registry opens anything.
    """
    entry = str(path).strip()
    if not entry:
        return
    present = os.environ.get(SAMPLE_ROOTS_ENV, "")
    if entry in [part for part in present.split(ROOT_SEPARATOR) if part]:
        return
    os.environ[SAMPLE_ROOTS_ENV] = f"{present}{ROOT_SEPARATOR}{entry}" if present else entry


def resolve_under_roots(path: str | Path, *, extra_roots: Iterable[str | Path] = ()) -> Path:
    """``path`` resolved, if it lands inside one of the roots. Otherwise refused.

    Symlinks are followed on both sides before the comparison, which is what
    makes a link planted under a root, and a ``..`` climb out of one, land
    where they really point.

    Raises:
        PathOutsideRoots: when the resolved path is in none of them.
    """
    resolved = Path(os.path.realpath(str(path)))
    for root in (*extra_roots, *configured_roots()):
        try:
            base = Path(os.path.realpath(str(root)))
        except OSError:  # pragma: no cover - a root that cannot be resolved is not one
            continue
        if resolved == base or base in resolved.parents:
            return resolved
    raise PathOutsideRoots()
