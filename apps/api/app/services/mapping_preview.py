"""Run a REST-sandbox mapping against a pasted response, and count what it did.

An operator configuring a sandbox nobody has integrated has exactly one hard
question: does this JSONPath select the thing I think it selects. Answering it
by submitting a sample and reading the report afterwards costs a detonation
and several minutes. Answering it here costs a paste.

Server-side because the mapping has one implementation
(``providers/sandbox/rest_mapping.py``) and one set of error messages; a
JSONPath engine in the browser would be a second of both.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.core.config import RestMappingConfig
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import CHANNELS, apply_mapping, compile_mapping

# A pasted sample response, not a real report: 4 MiB is generous for one and
# far below the 64 MiB an uploaded report is allowed, which is deliberate —
# this endpoint parses and walks whatever it is given, inside a request.
PREVIEW_MAX_BYTES = 4 * 1024 * 1024

_EMPTY = {
    "matched": 0,
    "kept": 0,
    "dropped": 0,
    "truncated": False,
    "sample_rows": [],
    "error": None,
}


def _clean_row(row: Any) -> Any:
    """A kept row with its unmatched fields dropped rather than shown as null.

    The mapping's own row shape carries every consumer field so downstream
    code can rely on the key existing; a preview is read by a person deciding
    whether a path is right, and a field the sandbox never published reads as
    noise there, not as information.
    """
    if isinstance(row, dict):
        return {k: v for k, v in row.items() if v is not None}
    return row


def preview_mapping(sample: dict[str, Any], mapping: dict[str, Any]) -> dict[str, Any]:
    """Per channel: what the path selected, what survived, and what went wrong.

    A channel whose path does not compile reports its own error and does not
    stop the others: an operator fixing six paths wants six answers, not the
    first failure six times. Every channel that *does* compile is then run
    through one shared ``apply_mapping`` call — the same call a job would
    make — so a cross-channel effect (a call attached to its process, an
    orphan counted against ``calls`` rather than silently dropped) shows up
    here exactly as it would in a real report, instead of the different
    numbers a channel run in isolation would produce.

    ``target_sha256`` is read straight off its own path match, with none of
    the 64-hex validation the real report applies — this is a check that the
    path selects the right value, not a check that the value is usable yet.
    """
    channels: dict[str, Any] = {name: dict(_EMPTY) for name in CHANNELS}
    target = ""
    expressions: dict[str, str] = {}
    for name in (*CHANNELS, "target_sha256"):
        value = mapping.get(name)
        if isinstance(value, str) and value:
            expressions[name] = value

    field_names_value = mapping.get("field_names")
    field_names: dict[str, str] = field_names_value if isinstance(field_names_value, dict) else {}

    # Pass 1: compile each channel on its own, so a bad path is named against
    # that channel alone and does not keep the others from being applied.
    valid: dict[str, str] = {}
    for name, expression in expressions.items():
        try:
            compile_mapping(
                RestMappingConfig.model_validate({name: expression, "field_names": field_names})
            )
        except ProviderConfigurationError as exc:
            if name != "target_sha256":
                channels[name] = {**_EMPTY, "error": str(exc)}
            continue
        valid[name] = expression

    target_expression = valid.pop("target_sha256", None)
    if target_expression is not None:
        target_compiled = compile_mapping(
            RestMappingConfig.model_validate({"target_sha256": target_expression})
        )
        if target_compiled.target_sha256 is not None:
            found = [node.value for node in target_compiled.target_sha256.finditer(sample)]
            if found:
                target = str(found[0])

    # Pass 2: every channel whose path compiled, mapped together in the one
    # call a job would make.
    if valid:
        combined = compile_mapping(
            RestMappingConfig.model_validate({**valid, "field_names": field_names})
        )
        result = apply_mapping(combined, sample, provider="preview", task_id="preview")
        for name in valid:
            stats = result.stats[name]
            rows = [_clean_row(r) for r in stats.sample_rows]
            channels[name] = {
                "matched": stats.matched,
                "kept": stats.kept,
                "dropped": stats.dropped,
                "truncated": stats.truncated,
                "sample_rows": json.loads(json.dumps(rows, default=str)),
                "error": stats.error or None,
            }
    return {"target_sha256": target, "channels": channels}
