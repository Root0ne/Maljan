"""Ghidra's function hashes: its REST API's per-function normalized-opcode hashes.

The Ghidra provider's answer to ``StaticProvider.function_hashes``. The
aggregation and rendering that read them are the platform's
(``maljan.analysis.function_hash_attribution``).
"""

from __future__ import annotations

import json
from typing import Any

from maljan.core.logger import logger


def _extract_functions(data: Any) -> list[dict[str, Any]]:
    """Pull the ``functions`` list out of a get_bulk_function_hashes payload.

    Defensive against transport wrapping: accepts the list at the top level or
    nested under ``result``/``data``. Returns ``[]`` for anything unexpected.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return []
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("functions", "result", "data"):
        val = data.get(key)
        if isinstance(val, list):
            return [f for f in val if isinstance(f, dict)]
        if isinstance(val, dict):  # nested wrapper -> recurse once
            inner = val.get("functions")
            if isinstance(inner, list):
                return [f for f in inner if isinstance(f, dict)]
    return []


def fetch_bulk_function_hashes(
    *,
    base_url: str,
    auth_token: str,
    file_path: str,
    min_instructions: int,
    page_limit: int = 2000,
    max_pages: int = 8,
    timeout: float = 120.0,
    note_key: str,
    sample_open: Any = None,
    sample_notes: Any = None,
    shared: bool = True,
) -> list[tuple[str, str]]:
    """Return ``(func_name, func_hash)`` for the binary's meaningful functions.

    Opens the sample through the general opener with the tools the Ghidra
    block declares (``sample_open``) and the job's note (``sample_notes``), so
    a path the job already opened is selected rather than imported again; with
    none declared, a best-effort ``load_program`` + switch + ``run_analysis``.
    Every page names the job's program by the argument the block declares.
    On a server other jobs share (``shared``), no declaration, no declared
    argument or no program the job opened yields no hashes, with the reason
    logged; Ghidra's current program is read only on one no other job shares.
    Then paginates ``get_bulk_function_hashes``
    and keeps only functions with at least ``min_instructions`` instructions.
    Fail-safe: any error yields an empty list.
    """
    try:
        import httpx
    except Exception as exc:  # pragma: no cover - httpx is a hard dep in practice
        logger.warning("function-hash fetch: httpx unavailable (%s).", exc)
        return []

    base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        from maljan.providers.sample_open import SampleOpener, declared, program_argument
        from maljan.providers.static.ghidra.program import (
            SWITCH_PARAM,
            SWITCH_PATH,
            program_name_from_load,
        )

        with httpx.Client(timeout=timeout, headers=headers) as http:
            # Best-effort load + activate + analyse; another pre-pass may have
            # done this. The activate step is not optional cleanup: a load only
            # becomes Ghidra's *current* program when nothing is current yet, so
            # without it `get_bulk_function_hashes` below returns the hashes of
            # whichever binary the container looked at first — attributing this
            # sample to another sample's functions, silently and plausibly.
            # The program each request names: Ghidra's current program is the
            # server's, and another job may have made another one current.
            program: dict[str, str] = {}
            if declared(sample_open):
                if not _opened_for_hashes(
                    http, base, file_path, sample_open, sample_notes, note_key
                ):
                    return []
                from maljan.providers.static.ghidra.provider import sample_notes_of

                argument = program_argument(sample_open)
                opened = SampleOpener(note_key, sample_open, sample_notes_of(sample_notes))
                name = opened.name_of(file_path)
                if argument and name:
                    program = {argument: name}
                elif shared:
                    logger.warning(
                        "function-hash fetch: %s; no hashes rather than whichever program is "
                        "current on %s, which other jobs share.",
                        f"{file_path} is not a program this job opened"
                        if argument
                        else "the Ghidra block declares no program argument (sample_open)",
                        note_key,
                    )
                    return []
            elif shared:
                logger.warning(
                    "function-hash fetch: the Ghidra block declares no sample_open; no hashes "
                    "rather than whichever program is current on %s, which other jobs share.",
                    note_key,
                )
                return []
            else:
                try:
                    loaded = http.post(f"{base}/load_program", json={"file": file_path})
                    name = program_name_from_load(loaded.text)
                except Exception:  # noqa: BLE001 - a transport failure is the same as no load
                    name = None
                if not name:
                    # A refused load answers 200 with an `error` body. Hashing on
                    # regardless would attribute this sample to whichever binary is
                    # still current — the wrong family, stated confidently.
                    logger.warning(
                        "function-hash fetch: load_program did not yield a program for %s; "
                        "skipping attribution rather than hashing the previously loaded binary.",
                        file_path,
                    )
                    return []
                try:
                    http.post(f"{base}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={})
                    http.post(f"{base}/run_analysis", json={})
                except Exception as exc:  # noqa: BLE001 - the current program is now unknown
                    logger.warning(
                        "function-hash fetch: could not switch Ghidra to %s (%s); skipping "
                        "attribution rather than hashing whichever binary is current.",
                        name,
                        type(exc).__name__,
                    )
                    return []

            offset = 0
            for _ in range(max_pages):
                resp = http.get(
                    f"{base}/get_bulk_function_hashes",
                    params={"offset": offset, "limit": page_limit, **program},
                )
                resp.raise_for_status()
                items = _extract_functions(resp.json() if resp.text.strip() else None)
                if not items:
                    break
                for it in items:
                    fh = it.get("hash")
                    name = it.get("name", "") or ""
                    ic = it.get("instruction_count", 0)
                    if not isinstance(fh, str) or not fh:
                        continue
                    if not isinstance(ic, int) or ic < min_instructions:
                        continue
                    if fh in seen:
                        continue
                    seen.add(fh)
                    out.append((name, fh))
                if len(items) < page_limit:
                    break
                offset += len(items)
        logger.info(
            "function-hash fetch: %d functions (>= %d instr) from '%s'.",
            len(out),
            min_instructions,
            file_path,
        )
        return out
    except Exception as exc:  # fail-safe
        logger.warning(
            "function-hash fetch failed (%s: %s); continuing without hashes.",
            type(exc).__name__,
            exc,
        )
        return []


def _opened_for_hashes(
    http: Any, base: str, file_path: str, spec: Any, notes: Any, key: str
) -> bool:
    """Open the sample for the hash pass through the general opener; whether it is current.

    The make-current step is not optional cleanup: a load only becomes
    Ghidra's *current* program when nothing is current yet, so without it
    ``get_bulk_function_hashes`` returns the hashes of whichever binary the
    container looked at first. The opener notes a path only once its declared
    select and analysis answered, so a path it did not note is not known to be
    current, and attribution is skipped with a warning.
    """
    from maljan.providers.sample_open import SampleOpener
    from maljan.providers.static.ghidra.program import rest_tool_call
    from maljan.providers.static.ghidra.provider import sample_notes_of

    opener = SampleOpener(key, spec, sample_notes_of(notes))
    try:
        answer = opener.open(file_path, rest_tool_call(http, base), held=file_path)
    except Exception as exc:  # noqa: BLE001 - a transport failure is the same as no load
        answer = f"{type(exc).__name__}: {exc}"
    if opener.name_of(file_path) is not None:
        return True
    logger.warning(
        "function-hash fetch: Ghidra did not open, select and analyse %s (%s); skipping "
        "attribution rather than hashing whichever binary is current.",
        file_path,
        str(answer)[:160],
    )
    return False
