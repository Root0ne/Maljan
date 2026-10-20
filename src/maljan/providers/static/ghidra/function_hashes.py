"""Ghidra's function hashes: its REST API's per-function normalized-opcode hashes.

The Ghidra provider's answer to ``StaticProvider.function_hashes``. The
aggregation and rendering that read them are the platform's
(``maljan.analysis.function_hash_attribution``).
"""

from __future__ import annotations

import json
import time
from typing import Any

from maljan.core.logger import logger


class FunctionHashes(list[tuple[str, str]]):
    """The ``(name, hash)`` pairs a hash pass read, and why it read none when it could not.

    A list, so every reader that iterates or tests it reads it as before.
    ``unavailable`` is empty for a pass that read the program, its functions
    all there (an empty list is then a program with no qualifying function),
    and otherwise says why no hash could be read: "no matches" is a finding,
    and a failed read must never pass for one. ``cut`` is empty for a read
    that reached the server's last page, and otherwise says where and why
    the walk stopped short of it (a server repeating a page, a caller's own
    page count): the pairs are then some of the program's, never all.
    ``unbounded`` says the walk ran with no deadline of any kind (no call
    budget, no stage or job deadline), so only the server's own pages ended
    it; empty where something bounded it.
    """

    def __init__(
        self, pairs: Any = (), unavailable: str = "", cut: str = "", unbounded: str = ""
    ) -> None:
        super().__init__(pairs)
        self.unavailable = unavailable
        self.cut = cut
        self.unbounded = unbounded


def _entry_key(item: dict[str, Any]) -> tuple[str, str] | None:
    """What identifies one function's entry: its address (its entry point, else its name,
    where none is given) and its hash; ``None`` for an entry that names none of them.

    Two entries with one key are one function read again. An entry with no
    identity cannot be told from another, so it never counts as a repeat.
    """
    where = item.get("address") or item.get("entry_point") or item.get("name")
    if where in (None, ""):
        return None
    return str(where), str(item.get("hash") or "")


def _step_refusal(response: Any) -> str | None:
    """Why a load-time step's answer is a refusal (a 4xx/5xx or an error body), else ``None``."""
    from maljan.providers.sample_open import is_refusal

    status = int(getattr(response, "status_code", 200) or 200)
    text = str(getattr(response, "text", "") or "")
    if status >= 400:
        return f"HTTP {status}: {text[:160]}"
    if is_refusal(text):
        return text[:160]
    return None


def unavailable_hashes(reason: str) -> FunctionHashes:
    """No hashes, with the reason none could be read; logged as the pass's warning."""
    logger.warning("function-hash fetch: %s", reason)
    return FunctionHashes(unavailable=reason)


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
    max_pages: int | None = None,
    timeout: float = 120.0,
    note_key: str,
    sample_open: Any = None,
    sample_notes: Any = None,
    shared: bool = True,
    walk_budget: float = 0.0,
    deadline: float | None = None,
) -> FunctionHashes:
    """Return ``(func_name, func_hash)`` for the binary's meaningful functions.

    Opens the sample through the general opener with the tools the Ghidra
    block declares (``sample_open``) and the job's note (``sample_notes``), so
    a path the job already opened is selected rather than imported again; with
    none declared, a best-effort ``load_program`` + switch + ``run_analysis``.
    Every page names the job's program by the argument the block declares.
    On a server other jobs share (``shared``), no declaration, no declared
    argument or no program the job opened yields no hashes, with the reason
    logged; Ghidra's current program is read only on one no other job shares.
    Then reads every page of ``get_bulk_function_hashes`` (``page_limit``
    functions asked for a page, until a page answers none, so a server whose
    pages are shorter is read whole) and keeps only functions with at least
    ``min_instructions`` instructions. The walk ends short of the last page
    only where something already bounding the job's calls ends it, and the
    result says so (``cut``): a page that names no function not already read
    (a server repeating itself), the call budget the job's guard gives one
    call to this server (``walk_budget``, seconds; zero, none), the deadline
    of the stage or job the walk runs in (``deadline``, a ``time.monotonic``
    instant, where the pipeline has one), or a page count a caller sets
    (``max_pages``). With neither budget nor deadline the result says the walk
    was unbounded (``unbounded``); a page that names nothing new still ends it.
    Fail-safe: any error yields no hashes, with ``unavailable`` saying why
    (:class:`FunctionHashes`), never an empty read that looks like no matches.
    """
    try:
        import httpx
    except Exception as exc:  # pragma: no cover - httpx is a hard dep in practice
        return unavailable_hashes(f"httpx unavailable ({exc}).")

    base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    out = FunctionHashes()
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
                    # The opener's own words are in the warning it logged.
                    return FunctionHashes(
                        unavailable=f"Ghidra did not open, select and analyse {file_path}."
                    )
                from maljan.providers.static.ghidra.provider import sample_notes_of

                argument = program_argument(sample_open)
                opened = SampleOpener(note_key, sample_open, sample_notes_of(sample_notes))
                name = opened.name_of(file_path)
                if argument and name:
                    program = {argument: name}
                elif shared:
                    why = (
                        f"{file_path} is not a program this job opened"
                        if argument
                        else "the Ghidra block declares no program argument (sample_open)"
                    )
                    return unavailable_hashes(
                        f"{why}; no hashes rather than whichever program is current on "
                        f"{note_key}, which other jobs share."
                    )
            elif shared:
                return unavailable_hashes(
                    "the Ghidra block declares no sample_open; no hashes rather than whichever "
                    f"program is current on {note_key}, which other jobs share."
                )
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
                    return unavailable_hashes(
                        f"load_program did not yield a program for {file_path}; skipping "
                        "attribution rather than hashing the previously loaded binary."
                    )
                try:
                    switched = http.post(
                        f"{base}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={}
                    )
                    refused = _step_refusal(switched)
                    step = "switch"
                    if refused is None:
                        analysed = http.post(f"{base}/run_analysis", json={})
                        refused = _step_refusal(analysed)
                        step = "run_analysis"
                except Exception as exc:  # noqa: BLE001 - the current program is now unknown
                    return unavailable_hashes(
                        f"could not switch Ghidra to {name} ({type(exc).__name__}); skipping "
                        "attribution rather than hashing whichever binary is current."
                    )
                if refused is not None:
                    # Refused in words or by status: what is current, or whether
                    # it was analysed, is not known, so nothing is hashed.
                    return unavailable_hashes(
                        f"Ghidra refused the {step} of {name} ({refused}); skipping "
                        "attribution rather than hashing whichever binary is current."
                    )

            offset = 0
            pages = 0
            # Every page until an empty one: what a page names is the server's
            # to say, so a page that names nothing new (a server answering one
            # page again) ends the read rather than looping, and so does the
            # budget the job's guard gives one call to this server.
            entries: set[tuple[str, str]] = set()
            hashes_read: set[str] = set()
            # The page before, to tell a server that clamps an offset past its
            # end (it answers its last page again: the read is complete) from
            # one repeating what it already sent further back (a cut).
            previous: list[dict[str, Any]] | None = None
            read_any = False
            budget_end = time.monotonic() + walk_budget if walk_budget > 0 else None
            if budget_end is None and deadline is None:
                out.unbounded = (
                    "no call budget and no stage or job deadline bound this walk; only the "
                    "server's own pages, and a page naming nothing new, end it"
                )
                logger.warning("function-hash fetch: %s.", out.unbounded)
            while True:
                now = time.monotonic() if pages else None
                if now is not None and budget_end is not None and now >= budget_end:
                    out.cut = (
                        f"the walk ran past the {walk_budget:.0f}s one call to this server "
                        "may take (mcp.breaker.call_timeout_seconds, else the Ghidra block's "
                        f"call_timeout_seconds); the functions past offset {offset} were not "
                        "read"
                    )
                    break
                if now is not None and deadline is not None and now >= deadline:
                    out.cut = (
                        "the walk reached the deadline of the stage it runs in; the functions "
                        f"past offset {offset} were not read"
                    )
                    break
                if max_pages is not None and pages >= max_pages:
                    out.cut = (
                        f"the read stopped at the {max_pages} pages of {page_limit} asked for; "
                        f"the functions past offset {offset} were not read"
                    )
                    break
                pages += 1
                try:
                    resp = http.get(
                        f"{base}/get_bulk_function_hashes",
                        params={"offset": offset, "limit": page_limit, **program},
                    )
                    resp.raise_for_status()
                    items = _extract_functions(resp.json() if resp.text.strip() else None)
                except Exception as exc:
                    if not read_any:
                        raise
                    # What the pages before it gave is kept: a later page that
                    # failed cuts the read there, it does not undo it.
                    out.cut = (
                        f"the page at offset {offset} failed ({type(exc).__name__}: "
                        f"{str(exc)[:160]}); the functions past it were not read"
                    )
                    break
                read_any = True
                if not items:
                    break
                if items == previous:
                    if len(items) < page_limit:
                        # A short page again: the last page, for an offset past
                        # the end. The read is complete.
                        break
                    # A full page again is what a server ignoring the offset
                    # sends: the functions past it were never seen.
                    out.cut = (
                        f"the server answered the same full page of {len(items)} for offset "
                        f"{offset} as for the one before; it may ignore the offset, so the "
                        "functions past it may not have been read"
                    )
                    break
                previous = items
                keys = {key for key in map(_entry_key, items) if key is not None}
                fresh = keys - entries
                # An entry with no identity is new only by a hash not read yet.
                anonymous = {
                    str(it.get("hash") or "")
                    for it in items
                    if _entry_key(it) is None and it.get("hash")
                }
                new_hashes = anonymous - hashes_read
                if not fresh and not new_hashes:
                    # Not a last page: the server answered what was already
                    # read, so what lies past it was never seen.
                    out.cut = (
                        f"the page at offset {offset} repeats entries already read; the walk "
                        "ended there, before an empty page, so the functions past it "
                        "may not have been read"
                    )
                    break
                entries |= fresh
                hashes_read |= new_hashes
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
                # A short page is not taken as the last: a server may answer
                # fewer than asked for on every page. The empty one ends it.
                offset += len(items)
            if out.cut:
                logger.warning("function-hash fetch: %s.", out.cut)
        logger.info(
            "function-hash fetch: %d functions (>= %d instr) from '%s'.",
            len(out),
            min_instructions,
            file_path,
        )
        return out
    except Exception as exc:  # fail-safe
        return unavailable_hashes(
            f"the read failed ({type(exc).__name__}: {exc}); continuing without hashes."
        )


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
