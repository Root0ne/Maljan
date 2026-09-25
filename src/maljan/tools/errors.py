"""The shape of a tool failure, and what a reader may do about it.

A tool that cannot answer says so in a fixed shape::

    {"error": {"code": "missing_dependency",
               "message": "olefile is not installed",
               "remediation": "install the optional tool libraries: uv sync --extra tools"},
     "tool": "document_info"}

The code is a small closed vocabulary a program can branch on; the message is
what went wrong, in the tool's own words; the remediation is a static,
authored sentence naming the action that would make the next call succeed.
Nothing here is model-generated: a remediation is written once, in this file,
per code.

The older flat shape — ``{"error": "<text>"}``, which every implementation in
``maljan.tools`` and every external server still writes — is read too.
``error_parts`` answers both, and ``normalise_error`` turns the flat shape into
the structured one, inferring the code from the text where the text says
enough and leaving it ``tool_failed`` otherwise. The sidecars' guards and the
triage pack run every answer through it, so a model, the ledger and the
console see one shape whichever way a tool spoke.
"""

from __future__ import annotations

import re
from typing import Any

# The codes. A new one needs a remediation below; a code without one is a
# reason with no action, which is the thing this module exists to prevent.
MISSING_DEPENDENCY = "missing_dependency"
TIMEOUT = "timeout"
BAD_ARGUMENT = "bad_argument"
NO_SUCH_FILE = "no_such_file"
PATH_OUTSIDE_ROOTS = "path_outside_roots"
UNSUPPORTED_FORMAT = "unsupported_format"
NOT_CONFIGURED = "not_configured"
SERVER_RESTING = "server_resting"
TOOL_FAILED = "tool_failed"


REMEDIATIONS: dict[str, str] = {
    MISSING_DEPENDENCY: (
        "install the optional tool libraries on the host that runs this server: "
        "uv sync --extra tools"
    ),
    TIMEOUT: (
        "raise the tool's timeout, or ask for less: a narrower range, a smaller limit, "
        "a lighter backend"
    ),
    BAD_ARGUMENT: (
        "check the argument names and types against the tool's manifest and call it again"
    ),
    # Neither of these names the sample's own path any more. A model is not
    # offered that parameter — the platform supplies it — so telling one to
    # "pass the absolute sample path the prompt names" sent a live analyst
    # after a field it could not see, six calls in a row.
    NO_SUCH_FILE: (
        "the file this call named is not there; pass a path a tool in this run handed "
        "back, exactly as it was returned and with no quotes around it, or leave the "
        "argument out to read the file this call was given"
    ),
    PATH_OUTSIDE_ROOTS: (
        "this server reads the file it was given and the files it wrote for this run; "
        "pass a path a tool in this run handed back, or leave the argument out"
    ),
    UNSUPPORTED_FORMAT: (
        "this tool reads another format; call identify_file and use the tool for the "
        "format it reports"
    ),
    NOT_CONFIGURED: (
        "set the credential or setting this tool needs in Settings and run the probe again"
    ),
    SERVER_RESTING: (
        "this server did not answer several calls in a row and is not being called for now; "
        "use another tool, or call this one again after the time the message names"
    ),
    TOOL_FAILED: (
        "read the message; if it names nothing you can change, report it with the server log"
    ),
}

# What a capture tool says when the capture it was asked for is not one it may
# read. Its own sentences, because ``pcap_path`` is required on every tool that
# takes one and the general advice to leave a path argument out sent a live
# analyst after a call that cannot be made; the captures are listed by the
# names a caller can pass back, never by host path.
NO_CAPTURE_REMEDIATION = (
    "this run holds no packet capture, so there is nothing for {argument} to name; read "
    "the sandbox's network view instead"
)
CAPTURES_REMEDIATION = "pass {argument} as one of this run's captures, exactly as written: {names}"


# What a flat error text says about its own cause. Ordered: the first
# pattern that matches names the code, and the last is the catch-all.
_CODE_BY_TEXT: tuple[tuple[str, re.Pattern[str]], ...] = (
    (MISSING_DEPENDENCY, re.compile(r"is not installed|No module named|ModuleNotFoundError", re.I)),
    (TIMEOUT, re.compile(r"timed? ?out|within its budget|TimeoutExpired|TimeoutError", re.I)),
    # Before the file patterns, because a bare "not found" is as often about a
    # credential as about a path, and reading "API key not found" as a missing
    # file hands the model the remedy for the wrong problem.
    (
        NOT_CONFIGURED,
        re.compile(r"not configured|api key|missing api key|no token|credential", re.I),
    ),
    # Narrow on purpose: the words have to be about a file.
    (
        NO_SUCH_FILE,
        re.compile(r"no such file|file not found|does not exist|FileNotFoundError", re.I),
    ),
    (
        UNSUPPORTED_FORMAT,
        re.compile(r"\bnot an? [A-Za-z0-9\-]+ file\b|unsupported|no MZ magic|wrong magic", re.I),
    ),
    (
        BAD_ARGUMENT,
        re.compile(r"^(?:TypeError|ValueError|KeyError|ValidationError)\b|invalid argument", re.I),
    ),
)


def tool_error(
    code: str, message: str, *, tool: str | None = None, remediation: str | None = None
) -> dict[str, Any]:
    """The structured failure for ``code``, with the authored remediation.

    A code this module does not know is kept as written and given the
    catch-all remediation, so a server author's own code still reaches the
    reader instead of being replaced.
    """
    hint = remediation if remediation else REMEDIATIONS.get(code, REMEDIATIONS[TOOL_FAILED])
    out: dict[str, Any] = {
        "error": {"code": str(code), "message": str(message), "remediation": str(hint)}
    }
    if tool:
        out["tool"] = str(tool)
    return out


def code_for_text(text: str) -> str:
    """The code a flat error text most plausibly means."""
    for code, pattern in _CODE_BY_TEXT:
        if pattern.search(text or ""):
            return code
    return TOOL_FAILED


def code_for_exception(exc: BaseException) -> str:
    """The code an exception raised inside a tool most plausibly means."""
    if isinstance(exc, ImportError):
        return MISSING_DEPENDENCY
    if isinstance(exc, TimeoutError):
        return TIMEOUT
    if isinstance(exc, FileNotFoundError | IsADirectoryError | NotADirectoryError):
        return NO_SUCH_FILE
    if isinstance(exc, TypeError | ValueError | KeyError):
        return BAD_ARGUMENT
    name = type(exc).__name__
    if name in ("TimeoutExpired", "ReadTimeout", "ConnectTimeout"):
        return TIMEOUT
    return code_for_text(f"{name}: {exc}")


def error_parts(value: Any) -> tuple[str, str, str | None] | None:
    """``(code, message, remediation)`` when ``value`` carries a failure, else ``None``.

    Reads every shape a tool answer may take: the structured one, the flat
    ``{"error": "<text>"}``, the MCP client's ``{"tool_error": ...}`` marker
    and a JSON string of any of those. An empty ``error`` is not a failure.
    """
    parsed = value
    if isinstance(parsed, str):
        text = parsed.strip()
        if not text.startswith("{"):
            return None
        import json

        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return None
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    if isinstance(error, dict):
        message = str(error.get("message") or "").strip()
        if not message and not error.get("code"):
            return None
        code = str(error.get("code") or code_for_text(message))
        remediation = error.get("remediation")
        return code, message or code, (str(remediation) if remediation else None)
    if isinstance(error, str) and error.strip():
        return code_for_text(error), error.strip(), None
    marker = parsed.get("tool_error")
    if isinstance(marker, str) and marker.strip():
        detail = str(parsed.get("detail") or parsed.get("type") or "").strip()
        message = f"{marker}: {detail}" if detail else marker
        return code_for_text(message), message, None
    return None


def normalise_error(value: Any) -> Any:
    """``value`` with a flat error rewritten in the structured shape; otherwise unchanged.

    The remediation is the authored one for the inferred code. A structured
    error already carrying a remediation is left exactly as the tool wrote it,
    and one without gets the code's.
    """
    if not isinstance(value, dict):
        return value
    error = value.get("error")
    if isinstance(error, str):
        if not error.strip():
            return value
        code = code_for_text(error)
        return {
            **value,
            "error": {"code": code, "message": error.strip(), "remediation": REMEDIATIONS[code]},
        }
    if isinstance(error, dict) and error and not error.get("remediation"):
        code = str(error.get("code") or code_for_text(str(error.get("message") or "")))
        return {
            **value,
            "error": {
                **error,
                "code": code,
                "remediation": REMEDIATIONS.get(code, REMEDIATIONS[TOOL_FAILED]),
            },
        }
    return value


def error_sentence(value: Any) -> str | None:
    """``"<message>; <remediation>"`` for a failed answer, or ``None``."""
    parts = error_parts(value)
    if parts is None:
        return None
    _code, message, remediation = parts
    return f"{message}; {remediation}" if remediation else message
