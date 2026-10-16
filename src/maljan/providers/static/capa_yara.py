"""capa and YARA: evidence for the analyst, not tools for the model.

No tool server and no ReAct loop — this provider runs two deterministic
passes over the sample's bytes and hands the pipeline a
``StaticEvidenceBundle``. Because there is no loop, there is nothing to write
its calls to the evidence ledger, so ``ledger_entries`` does it here: the capa
rule hits and the YARA matches become entries in the shape the ``capa`` and
``yara_scan`` tools return, under the agent id ``capa_yara``, and reach the
report's sections the same way every other tool call does. The rendered
tables stay for the Composer's evidence bundles.

Both libraries are optional. A missing one lowers ``provides_evidence`` to
False with one warning — the same shape as ``SandboxNotAvailableError`` —
rather than failing a job over an integration the operator may not want.

capa API surface pinned against flare-capa 9.4.0 (the version installed in
this environment via ``uv sync --extra capa``); a few names moved since the
7.x line this module was originally sketched against:

- ``capa.rules.get_rules`` (not ``capa.loader.get_rules``).
- ``capa.rules.cache`` must be imported explicitly — ``capa.rules.get_rules``
  references ``capa.rules.cache.get_default_cache_directory()`` at call time
  without importing the submodule itself, so a bare ``import capa.rules``
  leaves that attribute missing and every call raises ``AttributeError``.
- ``capa.loader.get_extractor`` takes an explicit ``input_format`` (there is
  no ``FORMAT_AUTO``-does-everything shortcut inside it for the vivisect
  backend); the format is detected up front with ``capa.helpers.get_auto_format``.
- ``capa.loader`` has no ``BACKEND_MAP``; the per-backend constants
  (``BACKEND_VIV`` / ``BACKEND_PEFILE`` / ``BACKEND_BINJA``) are looked up by
  name in this module instead.
- ``auto`` is not a ``capa.loader`` constant. capa's command line picks the
  backend for the format it detected (``capa.main.get_backend_from_cli``), and
  the child asks capa the same way, so a managed assembly reaches capa's .NET
  backend rather than vivisect, which refuses the ``dotnet`` format.
- ``capa.render.result_document.ResultDocument.from_capa`` takes the
  ``Capabilities.matches`` mapping, not the ``Capabilities`` object itself
  (``collect_metadata`` takes the whole object).
"""

from __future__ import annotations

import multiprocessing as mp
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from maljan.core.logger import logger
from maljan.core.paths import resolve_data
from maljan.providers.base import (
    VERIFICATION_DISCIPLINE,
    EvidenceAnswer,
    ProviderProbe,
    StaticCapabilities,
    StaticEvidenceBundle,
    StaticProvider,
    declared_tool_of_kind,
    evidence_entries,
)
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings, StaticCapaConfig, StaticYaraConfig

# capa backend name -> capa.loader constant, resolved lazily so importing this
# module never requires capa to be installed. ``auto`` names no constant: the
# capa child resolves it from the format capa detects (``_capa_backend``).
_AUTO_BACKEND = "auto"
_BACKEND_NAMES: dict[str, str] = {
    "auto": _AUTO_BACKEND,
    "vivisect": "BACKEND_VIV",
    "pefile": "BACKEND_PEFILE",
    "binja": "BACKEND_BINJA",
}


def _capa_backend(backend_name: str, input_format: str) -> str:
    """The capa backend one run uses, for the format capa's own detection returned.

    A named backend is the ``capa.loader`` constant of that name, exactly as
    configured. ``auto`` is the backend capa itself picks for the format when
    no backend is forced (``capa.main.get_backend_from_cli``): its .NET backend
    for a managed assembly, and vivisect for native code, as before. Called in
    the capa child only, where capa is imported anyway.
    """
    if backend_name != _AUTO_BACKEND:
        import capa.loader as capa_loader

        return str(getattr(capa_loader, backend_name))
    import argparse

    import capa.main as capa_main

    no_override = argparse.Namespace(backend=capa_main.BACKEND_AUTO)
    return str(capa_main.get_backend_from_cli(no_override, input_format))


# A fired capa rule's technique hit carries no confidence. capa says the
# rule's pattern is present — an instruction sequence, a string, an API call in
# the right context — which is a presence and not a probability; the 0.70 each
# hit used to carry was this platform's number, read by the analysts as if capa
# had stated it.


class _CapaWorker(Protocol):
    """Shape of the picklable, module-level function run in the capa subprocess."""

    def __call__(
        self,
        sample_path: str,
        rules_dir: str,
        signatures_dir: str,
        backend_name: str,
        queue: Any,
    ) -> None: ...


def _capa_worker(
    sample_path: str,
    rules_dir: str,
    signatures_dir: str,
    backend_name: str,
    queue: Any,
) -> None:
    """Run one capa pass to completion and put the result on ``queue``.

    Runs in a ``multiprocessing.get_context("spawn")`` child, so it must be
    module-level (picklable by reference) and its imports must be local to
    itself: the spawn start method re-imports this module in the child
    process, and every import this function makes is one the child actually
    pays for. Only capa and the stdlib are imported here — never the FastAPI
    app, never ``Settings`` — so a capa run never drags the rest of the
    worker's dependency graph into a process whose only job is to run capa
    and exit (or be killed).
    """
    try:
        import capa.capabilities.common as capa_capabilities
        import capa.helpers as capa_helpers
        import capa.loader as capa_loader
        import capa.render.result_document as capa_rd
        import capa.rules as capa_rules
        import capa.rules.cache  # noqa: F401 - get_rules() references this submodule

        path = Path(sample_path)
        rules_path = Path(rules_dir)
        rules = capa_rules.get_rules([rules_path], enable_cache=False)
        input_format = capa_helpers.get_auto_format(path)
        backend = _capa_backend(backend_name, input_format)
        sig_dir = Path(signatures_dir)
        sigpaths = capa_loader.get_signatures(sig_dir) if sig_dir.is_dir() else []
        extractor = capa_loader.get_extractor(
            path,
            input_format,
            capa_loader.OS_AUTO,
            backend,
            sigpaths,
            should_save_workspace=False,
            disable_progress=True,
        )
        capabilities = capa_capabilities.find_capabilities(rules, extractor, disable_progress=True)
        meta = capa_loader.collect_metadata(
            [], path, input_format, capa_loader.OS_AUTO, [rules_path], extractor, capabilities
        )
        document = capa_rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
        # This process's peak resident memory, measured by the kernel, before
        # the result: the parent reads what capa costs on this host from it.
        import resource

        queue.put(("peak", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024))
        queue.put(("ok", document.model_dump(mode="json")))
    except Exception as exc:  # noqa: BLE001 - reported to the parent, never raised here
        queue.put(("error", f"{type(exc).__name__}: {exc}"))


# The largest resident memory a capa child reached in this process's lifetime,
# as its own kernel accounting reported it; ``None`` until one has run.
_CAPA_PEAK_BYTES: int | None = None
_CAPA_PEAK_LOCK = threading.Lock()


def note_capa_peak(value: Any) -> None:
    """Keep the largest capa peak seen. Never raises."""
    global _CAPA_PEAK_BYTES
    try:
        peak = int(value)
    except (TypeError, ValueError):
        return
    if peak <= 0:
        return
    with _CAPA_PEAK_LOCK:
        _CAPA_PEAK_BYTES = max(peak, _CAPA_PEAK_BYTES or 0)


def measured_capa_peak_bytes() -> int | None:
    """The largest resident memory a capa run has reached in this process, or ``None``."""
    with _CAPA_PEAK_LOCK:
        return _CAPA_PEAK_BYTES


# How often a wait with no budget looks at whether its child is still alive.
_CHILD_POLL_SECONDS = 1.0


def _next_message(
    queue: Any, process: Any, timeout_seconds: float | None, started: float
) -> tuple[str, Any]:
    """The child's next message, within the budget left, or raise when there is none to come.

    With no budget the wait polls, so a child that died without writing — the
    server killed it, or it crashed — ends the wait instead of hanging it.
    """
    import queue as queue_module

    while True:
        if timeout_seconds is None:
            wait = _CHILD_POLL_SECONDS
        else:
            left = timeout_seconds - (time.monotonic() - started)
            if left <= 0:
                raise TimeoutError("capa exceeded its budget")
            wait = min(_CHILD_POLL_SECONDS, left)
        try:
            message: tuple[str, Any] = queue.get(timeout=wait)
            return message
        except queue_module.Empty:
            if not process.is_alive():
                # One last look: a child can write and exit between two polls.
                try:
                    message = queue.get(timeout=0.1)
                    return message
                except queue_module.Empty:
                    raise RuntimeError("the capa worker exited without an answer") from None


def run_capa_document(
    *,
    sample_path: str,
    rules_dir: str,
    signatures_dir: str,
    backend_name: str,
    timeout_seconds: float | None,
    target: _CapaWorker | None = None,
) -> dict[str, Any] | None:
    """Run the capa pipeline in a subprocess, killed if it overruns its budget.

    capa's vivisect backend has no cooperative cancellation point inside a
    disassembly loop, so it cannot be interrupted from inside the calling
    process — a thread-based timeout (this function's first cut, as a provider
    method) could only report a timeout to the caller while the actual vivisect
    thread kept running for however long the analysis really took, and
    ``ThreadPoolExecutor`` registers an ``atexit`` hook that joins every
    outstanding worker thread, which would have hung an arq worker's shutdown
    on a slow sample. A ``multiprocessing`` child process can actually be
    killed: on expiry this calls ``terminate()``, escalates to ``kill()`` if
    the process is still alive after a short grace period, and returns ``None``
    either way — the existing warn-and-degrade contract, just backed by
    something that can really stop the work.

    A free function rather than a provider method because the ``capa`` tool
    runs the same pass with no provider and no ``Settings`` around it, and two
    copies of a spawn-and-kill loop is one too many.
    """
    worker = target or _capa_worker
    ctx = mp.get_context("spawn")
    queue: Any = ctx.Queue()
    process = ctx.Process(
        target=worker,
        args=(sample_path, rules_dir, signatures_dir, backend_name, queue),
        daemon=True,
    )
    process.start()
    # The server kills this child when every caller of its run has gone
    # (``tools.children``); the wait below then sees it die rather than
    # waiting on a queue nothing will write to.
    from maljan.tools import children

    # Only while it is alive: a reaped child's pid can be another process's.
    children.register(
        lambda: children.kill_process_group(int(process.pid or 0)) if process.is_alive() else None
    )
    try:
        # Read before joining: the child's result is routinely well over the OS
        # pipe buffer (a full capa ResultDocument), and a child that has put a
        # large item blocks in its feeder thread until the parent drains the
        # queue. Joining first therefore deadlocks the parent's wait on a child
        # that has *already* produced its result — the join times out, the
        # child is killed as a false "exceeded its budget", and a real result
        # is thrown away. Draining the queue first lets that feeder thread
        # unblock and the child exit on its own well within the same budget.
        started = time.monotonic()
        kind, payload = _next_message(queue, process, timeout_seconds, started)
        # A child may say what it cost before it answers; the answer still has
        # the rest of the same budget.
        while kind == "peak":
            note_capa_peak(payload)
            kind, payload = _next_message(queue, process, timeout_seconds, started)
    except Exception as exc:  # noqa: BLE001 - stdlib queue.Empty, or a crashed child
        if isinstance(exc, RuntimeError):
            # It died on its own, or was killed with its run: not a budget.
            logger.warning(
                "capa on %s: the worker process exited without an answer (exit code %s).",
                sample_path,
                process.exitcode,
            )
        else:
            logger.warning(
                "capa on %s exceeded its %ss budget; terminating the worker process.",
                sample_path,
                timeout_seconds,
            )
        process.terminate()
        process.join(5.0)
        if process.is_alive():
            process.kill()
            process.join(5.0)
        queue.close()
        return None
    # The result is already in hand; give the child a short grace period to
    # exit on its own now that the queue is drained, then reap it.
    process.join(5.0)
    if process.is_alive():
        process.terminate()
        process.join(5.0)
        if process.is_alive():
            process.kill()
            process.join(5.0)
    queue.close()
    if kind != "ok":
        logger.warning(
            "capa failed on %s (%s); continuing without capa evidence.", sample_path, payload
        )
        return None
    result: dict[str, Any] = payload
    return result


@register_static_provider("capa_yara")
class CapaYaraStaticProvider(StaticProvider):
    """capa and YARA: evidence for the analyst, not tools for the model."""

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "capa + YARA"
    choice_order = 2
    title = "capa + YARA"
    description = "Rule sets on disk name the capabilities and match the file; no server to run."
    probe_label = "Test capa + YARA rules"
    settings_intro = "The rule directories to load. Both are read at the start of every analysis."

    def __init__(self, capa: StaticCapaConfig, yara: StaticYaraConfig) -> None:
        self._capa = capa
        self._yara = yara
        self._capa_available: bool | None = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> CapaYaraStaticProvider:
        return cls(cfg.static.capa, cfg.static.yara)

    async def probe(self) -> ProviderProbe:
        """Count capa and YARA rule files without touching a sample.

        No live handshake exists for either (both are local libraries reading
        local rule directories), so the connection test is the check the
        provider makes before a run: is the library importable, and does each
        configured directory hold rule files. Naming which is missing stops an
        operator from discovering an evidence-free run only after it finishes.
        """
        import importlib.util

        t0 = time.perf_counter()
        parts: list[str] = []
        capa_ok = False
        if importlib.util.find_spec("capa") is None:
            parts.append("capa library is not installed (uv sync --extra capa)")
        else:
            capa_dir = Path(resolve_data(str(self._capa.rules_dir or "")))
            capa_rules = list(capa_dir.rglob("*.yml")) if capa_dir.is_dir() else []
            if not capa_dir.is_dir():
                parts.append(f"capa rules directory {capa_dir} does not exist")
            elif not capa_rules:
                parts.append(f"capa rules directory {capa_dir} has no *.yml rules")
            else:
                capa_ok = True
                parts.append(f"{len(capa_rules)} rules under {capa_dir}")
        yara_dir = Path(resolve_data(str(self._yara.rules_dir or "")))
        yara_files = (
            [*yara_dir.glob("*.yml"), *yara_dir.glob("*.yaml")] if yara_dir.is_dir() else []
        )
        if not yara_dir.is_dir():
            parts.append(f"YARA rules directory {yara_dir} does not exist")
        elif not yara_files:
            parts.append(f"YARA rules directory {yara_dir} has no rule file")
        else:
            parts.append(f"{len(yara_files)} YARA rule file(s) under {yara_dir}")
        return ProviderProbe(capa_ok, "; ".join(parts), int((time.perf_counter() - t0) * 1000))

    def prompt_fragment(self) -> str:
        """The verification discipline every static analyst carries, and nothing else.

        This provider's fragment was empty before the discipline was shared;
        it gains the discipline and no sentence of the citation's, so its
        prompt carries no technique id it did not carry.
        """
        return VERIFICATION_DISCIPLINE

    def guidance_fragment(self) -> str:
        return VERIFICATION_DISCIPLINE

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_tools=False,
            provides_evidence=self._capa_available is not False,
            needs_sample_mirror=False,
            degrade_on_failure=True,
        )

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        """capa and YARA over the sample, for a run whose triage pack did not run them.

        When a triage stage ran, the pack is the producer: its ``capa`` and
        ``yara_scan`` entries are already in the ledger and the report node
        does not call this (``triage_pack.rules_already_recorded``).
        """
        capa_result = self._run_capa(sample_path)
        yara_hits = self._run_yara(sample_path)
        if capa_result is None and not yara_hits:
            return None

        hits: list[dict[str, Any]] = []
        rows: list[dict[str, str]] = []
        capa_rows: list[dict[str, Any]] = []
        for name, rule in ((capa_result or {}).get("rules") or {}).items():
            meta = rule.get("meta") or {}
            namespace = str(meta.get("namespace") or "")
            rows.append({"rule": str(name), "namespace": namespace})
            capa_rows.append(
                {
                    "namespace": namespace,
                    "rule": str(name),
                    "attck": [
                        str((attack or {}).get("id") or "")
                        for attack in meta.get("attack") or []
                        if (attack or {}).get("id")
                    ],
                    "mbc": [],
                    "match_count": len(rule.get("matches") or []),
                }
            )
            for attack in meta.get("attack") or []:
                tid = str((attack or {}).get("id") or "")
                if not tid:
                    continue
                hits.append(
                    {
                        "technique_id": tid,
                        "name": str(name),
                        "matched_apis": [namespace] if namespace else [],
                        "source": "capa",
                    }
                )

        evidence: dict[str, str] = {}
        if rows:
            evidence["capa"] = _render_table(rows)
        if yara_hits:
            evidence["yara"] = _render_yara(yara_hits)

        answers: list[EvidenceAnswer] = []
        for kind, payload in (
            ("capability_rules", {"capabilities": capa_rows} if capa_rows else None),
            (
                "signature_rules",
                {"matches": list(yara_hits), "rule_count": len(yara_hits), "filtered": 0}
                if yara_hits
                else None,
            ),
        ):
            tool = declared_tool_of_kind(self.declaration_source, kind)
            if payload is not None and tool:
                answers.append(EvidenceAnswer(tool=tool, kind=kind, payload=payload))
        return StaticEvidenceBundle(
            technique_hits=hits,
            strings=[],
            technical_evidence=evidence,
            entries=tuple(answers),
        )

    # ------------------------------------------------------------------
    # capa
    # ------------------------------------------------------------------

    def _run_capa(self, sample_path: str) -> dict[str, Any] | None:
        """Run capa, or return None and warn once when it is unavailable."""
        try:
            import capa.capabilities.common  # noqa: F401
            import capa.helpers  # noqa: F401
            import capa.loader  # noqa: F401
            import capa.render.result_document  # noqa: F401
            import capa.rules  # noqa: F401
            import capa.rules.cache  # noqa: F401 - get_rules() references this submodule
        except ImportError as exc:
            if self._capa_available is not False:
                logger.warning(
                    "capa is not installed (%s); the capa_yara provider contributes no "
                    "capa evidence. Install it with: uv sync --extra capa",
                    exc,
                )
            self._capa_available = False
            return None

        rules_dir = Path(resolve_data(self._capa.rules_dir))
        if not rules_dir.is_dir() or not any(rules_dir.rglob("*.yml")):
            if self._capa_available is not False:
                logger.warning(
                    "capa rules directory %s is missing or empty; no capa evidence.", rules_dir
                )
            self._capa_available = False
            return None

        self._capa_available = True
        try:
            return self._run_capa_bounded(sample_path, rules_dir)
        except Exception as exc:  # noqa: BLE001 - capa must never fail a run
            logger.warning(
                "capa failed on %s (%s: %s); continuing without capa evidence.",
                sample_path,
                type(exc).__name__,
                exc,
            )
            return None

    def _run_capa_bounded(
        self,
        sample_path: str,
        rules_dir: Path,
        target: _CapaWorker | None = None,
    ) -> dict[str, Any] | None:
        """This provider's budget and backend, applied to ``run_capa_document``.

        ``target`` defaults to the module-level ``_capa_worker`` and exists so
        a test can inject a fake (module-level, picklable) target — e.g. one
        that only sleeps — to exercise the timeout/kill path without needing
        capa installed or a real multi-minute analysis.
        """
        return run_capa_document(
            sample_path=sample_path,
            rules_dir=str(rules_dir),
            signatures_dir=str(Path(resolve_data(self._capa.signatures_dir))),
            backend_name=_BACKEND_NAMES.get(self._capa.backend, "BACKEND_VIV"),
            timeout_seconds=self._capa.timeout_seconds,
            target=target,
        )

    # ------------------------------------------------------------------
    # YARA
    # ------------------------------------------------------------------

    def _run_yara(self, sample_path: str) -> list[dict[str, Any]]:
        """Scan with the operator's own rules directory, reusing the YARA layer.

        The deterministic ``analysis/yara_layer.YaraLayer`` already owns rule
        compilation and matching; a second YARA code path in this project
        would be a second place for rule handling to be wrong. Anything this
        cannot load is a warning and an empty list.

        ``YaraLayer.from_yaml`` loads one YAML file, while the operator setting
        (``static.yara.rules_dir``) is a directory — the first ``*.yml``/
        ``*.yaml`` file found there is used, matching how the capa rules
        directory is a directory of many small rule files but the YARA layer's
        own corpus format is one file listing every rule.
        """
        rules_dir = Path(resolve_data(self._yara.rules_dir))
        if not rules_dir.is_dir():
            return []
        rule_file = next(iter([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")]), None)
        if rule_file is None:
            return []
        try:
            from maljan.analysis.yara_layer import YaraLayer

            layer = YaraLayer.from_yaml(rule_file)
            data = Path(sample_path).read_bytes()
            return [
                {"rule": m.rule_id, "strings": [m.evidence_ref], "technique": m.technique_id}
                for m in layer.scan(data)
            ]
        except Exception as exc:  # noqa: BLE001 - YARA must never fail a run
            logger.warning(
                "YARA scan of %s failed (%s: %s); continuing without YARA evidence.",
                sample_path,
                type(exc).__name__,
                exc,
            )
            return []


def _render_table(rows: list[dict[str, str]]) -> str:
    """Render capa rule hits as a compact Markdown table, every hit.

    Whole: the table is a ledger entry the evidence budget stores and a model
    reads through the context budget, which sizes it with a notice. A fixed
    6,000 characters used to end it mid-row with no word of what was left out.
    """
    lines = ["| rule | namespace |", "| --- | --- |"]
    for row in rows:
        lines.append(f"| {row.get('rule', '')} | {row.get('namespace', '')} |")
    return "\n".join(lines)


def _render_yara(hits: list[dict[str, Any]]) -> str:
    """Render YARA hits as a compact Markdown table, every hit, whole."""
    lines = ["| rule | strings |", "| --- | --- |"]
    for hit in hits:
        strings = ", ".join(str(s) for s in hit.get("strings") or [])
        lines.append(f"| {hit.get('rule', '')} | {strings} |")
    return "\n".join(lines)


def ledger_entries(
    bundle: StaticEvidenceBundle,
    counter: Any,
    stage: str = "analysis",
    source: str = "provider:capa_yara",
) -> list[Any]:
    """The bundle as evidence-ledger entries (``providers.base.evidence_entries``)."""
    return evidence_entries(bundle, counter, stage, source=source, agent="capa_yara")
