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

_EMPTY = {"matched": 0, "kept": 0, "dropped": 0, "sample_rows": [], "error": None}


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
    first failure six times. ``target_sha256`` is read straight off the path
    match, with none of the 64-hex validation the real report applies — this
    is a check that the path selects the right value, not a check that the
    value is usable yet.
    """
    channels: dict[str, Any] = {name: dict(_EMPTY) for name in CHANNELS}
    target = ""
    per_channel: dict[str, str] = {}
    for name in (*CHANNELS, "target_sha256"):
        value = mapping.get(name)
        if isinstance(value, str) and value:
            per_channel[name] = value

    field_names_value = mapping.get("field_names")
    field_names: dict[str, str] = field_names_value if isinstance(field_names_value, dict) else {}

    for name, expression in per_channel.items():
        try:
            compiled = compile_mapping(
                RestMappingConfig.model_validate({name: expression, "field_names": field_names})
            )
        except ProviderConfigurationError as exc:
            if name != "target_sha256":
                channels[name] = {**_EMPTY, "error": str(exc)}
            continue
        if name == "target_sha256":
            found = (
                [node.value for node in compiled.target_sha256.finditer(sample)]
                if compiled.target_sha256 is not None
                else []
            )
            if found:
                target = str(found[0])
            continue
        result = apply_mapping(compiled, sample, provider="preview", task_id="preview")
        stats = result.stats[name]
        rows = [_clean_row(r) for r in stats.sample_rows]
        channels[name] = {
            "matched": stats.matched,
            "kept": stats.kept,
            "dropped": stats.dropped,
            "sample_rows": json.loads(json.dumps(rows, default=str)),
            "error": stats.error or None,
        }
    return {"target_sha256": target, "channels": channels}
