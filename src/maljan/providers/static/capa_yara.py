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

The capa pass itself runs in a child process of its own (``capa_child``, which
holds the capa API notes), started with an environment built here rather than
the worker's: ``run_capa_document`` is the one place a capa run is started,
for this provider, the triage pack and the analysis server's ``capa`` tool.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.agents.subprocess_env import child_env
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
from maljan.providers.static import capa_child
from maljan.tools import staging

if TYPE_CHECKING:
    from maljan.core.config import Settings, StaticCapaConfig, StaticYaraConfig

# capa backend name -> capa.loader constant, resolved in the capa child so
# importing this module never requires capa to be installed. ``auto`` names no
# constant: the child resolves it from the format capa detects.
_BACKEND_NAMES: dict[str, str] = {
    "auto": capa_child.AUTO_BACKEND,
    "vivisect": "BACKEND_VIV",
    "pefile": "BACKEND_PEFILE",
    "binja": "BACKEND_BINJA",
}


def signatures_argument(signatures_dir: str) -> str:
    """The signature directory a capa run is handed: the setting resolved, or empty when it is.

    An empty setting stays empty rather than resolving to the project root,
    which every file under the project would then be searched for signatures in.
    """
    return str(resolve_data(signatures_dir)) if str(signatures_dir or "").strip() else ""


# A fired capa rule's technique hit carries no confidence. capa says the
# rule's pattern is present — an instruction sequence, a string, an API call in
# the right context — which is a presence and not a probability; the 0.70 each
# hit used to carry was this platform's number, read by the analysts as if capa
# had stated it.


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


# The capa child is this tree's own entry file, run by its path: in isolated
# mode ``-m`` would find the module through site-packages, which a source run
# (a worktree, a PYTHONPATH) points at another tree, and it would import the
# provider packages into the child.
_CHILD_ENTRY = Path(capa_child.__file__)
# Each run's directory, under this job's scratch directory.
_SCRATCH_DIRECTORY = "capa"
# How long a child told to stop is given before it is killed.
_GRACE_SECONDS = 5.0
# The longest a wait sleeps between two looks at whether its child has ended.
_POLL_SECONDS = 0.05


def _scratch() -> Path:
    """This job's directory for capa runs, created private, as FLOSS's is."""
    base = staging.private_dir(staging.staging_base())
    root = staging.staging_root()
    if root != base:
        staging.private_dir(root)
    return staging.private_dir(root / _SCRATCH_DIRECTORY)


def _child_environment(run: Path) -> dict[str, str]:
    """The capa child's environment: the stdio servers' base names, and its run as home.

    ``child_env`` keeps the ``BASE_KEYS`` present (search path, locale, time
    zone, interpreter's virtual environment) and nothing else of the worker's:
    no database URL, no settings encryption key, no token key, no object store
    or queue credential, no model key. Two names are set rather than inherited:
    ``HOME`` and ``TMPDIR`` are the run's own directory, because capa writes a
    ruleset cache under ``$HOME/.cache/capa`` on every run and vivisect and the
    interpreter take their temporary files from ``TMPDIR``; both then go with
    the run instead of collecting in the worker's home.
    """
    return child_env({"HOME": str(run), "TMPDIR": str(run)})


def _ended(
    process: subprocess.Popen[bytes], timeout_seconds: float | None, started: float
) -> tuple[int, Any] | None:
    """The child's exit status and resource usage once it ends, or ``None`` at the budget.

    Reaped with ``os.wait4``, which hands over the child's own resource usage,
    its peak resident memory among it, as the kernel measured it.
    """
    delay = 0.0005
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return process.returncode, usage
        if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
            return None
        delay = min(delay * 2, _POLL_SECONDS)
        time.sleep(delay)


def _stop(process: subprocess.Popen[bytes]) -> Any:
    """Stop the child's whole group, killing it after a grace, and return its resource usage."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    ended = _ended(process, _GRACE_SECONDS, time.monotonic())
    if ended is not None:
        return ended[1]
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    return usage


def _note_peak(usage: Any) -> None:
    """The child's peak resident memory, which the kernel gives in kilobytes."""
    note_capa_peak(getattr(usage, "ru_maxrss", 0) * 1024)


def run_capa_document(
    *,
    sample_path: str,
    rules_dir: str,
    signatures_dir: str,
    backend_name: str,
    timeout_seconds: float | None,
    child: Sequence[str] | None = None,
) -> dict[str, Any] | None:
    """Run one capa pass in a child process, killed if it overruns its budget.

    capa's vivisect backend has no cooperative cancellation point inside a
    disassembly loop, so it cannot be interrupted from inside the calling
    process; a child process can be killed. On expiry its whole group is told
    to stop, is killed if it is still there after a short grace, and ``None``
    is returned: the existing warn-and-degrade contract, backed by something
    that can really stop the work.

    The child is ``capa_child``, run by its path as ``python -I`` in its own
    session, with the environment ``_child_environment`` builds, in a directory
    of its own under this job's scratch directory. It writes its answer to a
    file there, read once it has ended, so a large document never waits on a
    pipe; the directory goes when the run ends, however it ends. Its peak
    resident memory is read as it is reaped. ``child`` stands in for the
    ``python -I`` and entry part of the command in a test; the same arguments
    follow it.

    ``None`` is also returned, with a warning, when the child ended without an
    answer (it crashed, or the server killed it with its run) or with capa's
    own error. A free function rather than a provider method because the
    ``capa`` tool runs the same pass with no provider and no ``Settings``.
    """
    run = Path(tempfile.mkdtemp(prefix="run-", dir=_scratch()))
    answer = run / "answer.json"
    entry = list(child) if child else [sys.executable, "-I", str(_CHILD_ENTRY)]
    command = [*entry, sample_path, rules_dir, signatures_dir, backend_name, str(answer)]
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - our interpreter and entry, our paths
                command,
                env=_child_environment(run),
                cwd=run,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            logger.warning(
                "capa on %s: the worker process could not be started (%s).", sample_path, exc
            )
            return None
        # The server kills this child's group when every caller of its run has
        # gone (``tools.children``); the wait below then sees it end. Only
        # while it runs: a reaped child's pid can be another process's.
        from maljan.tools import children

        children.register(
            lambda: children.kill_process_group(process.pid) if process.returncode is None else None
        )
        ended = _ended(process, timeout_seconds, time.monotonic())
        if ended is None:
            logger.warning(
                "capa on %s exceeded its %ss budget; terminating the worker process.",
                sample_path,
                timeout_seconds,
            )
            _note_peak(_stop(process))
            return None
        code, usage = ended
        _note_peak(usage)
        try:
            written = json.loads(answer.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # It died on its own, or was killed with its run: not a budget.
            logger.warning(
                "capa on %s: the worker process exited without an answer (exit code %s).",
                sample_path,
                code,
            )
            return None
        document = written.get("ok") if isinstance(written, dict) else None
        if not isinstance(document, dict):
            failure = written.get("error") if isinstance(written, dict) else written
            logger.warning(
                "capa failed on %s (%s); continuing without capa evidence.", sample_path, failure
            )
            return None
        return document
    finally:
        shutil.rmtree(run, ignore_errors=True)


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
        child: Sequence[str] | None = None,
    ) -> dict[str, Any] | None:
        """This provider's budget and backend, applied to ``run_capa_document``.

        ``child`` stands in for the capa child's command so a test can run one
        that only sleeps, crashes or writes a given answer, to exercise the
        timeout, kill and failure paths without capa installed or a real
        multi-minute analysis.
        """
        return run_capa_document(
            sample_path=sample_path,
            rules_dir=str(rules_dir),
            signatures_dir=signatures_argument(self._capa.signatures_dir),
            backend_name=_BACKEND_NAMES.get(self._capa.backend, "BACKEND_VIV"),
            timeout_seconds=self._capa.timeout_seconds,
            child=child,
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
