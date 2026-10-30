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
import stat
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
# What a run's directory is called where no job directory exists to hold it.
_LOOSE_RUN_PREFIX = "maljan-capa-"
# How long a child told to stop is given before it is killed.
_GRACE_SECONDS = 5.0
# The longest a wait sleeps between two looks at whether its child has ended.
_POLL_SECONDS = 0.05


def _sweep_loose_runs() -> None:
    """Remove the ``maljan-capa-*`` directories runs with no job left, once past the TTL.

    A run removes its own directory when it ends; one whose process was
    killed outright leaves it, and no job's teardown or server's sweep looks
    in the system's temporary directory. So the next run with no job sweeps
    there before it makes its own: a directory of this user's whose newest
    mtime is older than the staging TTL (``MALJAN_STAGING_TTL_HOURS``, the
    one the analysis server sweeps its staging by) goes. A live run touches
    its directory as capa writes its cache and its answer, and no capa run
    lasts a TTL. Never raises: a sweep that fails costs only the sweep.
    """
    ttl = staging.staging_ttl_seconds()
    if ttl <= 0:
        return
    cutoff = time.time() - ttl
    try:
        entries = list(Path(tempfile.gettempdir()).glob(f"{_LOOSE_RUN_PREFIX}*"))
    except OSError:
        return
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            continue
        if staging.newest_mtime(entry) < cutoff:
            staging.remove_tree(entry)


def _run_directory(scratch: str | Path | None) -> Path:
    """A new directory, only this user's, for one run: in the job's own directory when one exists.

    ``scratch`` is the directory a caller in the worker opened in its job's
    staging directory (``staging.open_job_directory(job, "capa")``: the
    triage pack's step and this provider). A tool server started for a job
    joins its own job directory and ``capa``. Either way the run's directory
    is ``<staging base>/job-…/capa/run-*``, which goes with the job: its
    teardown removes the job directory, and a server's sweep removes a job
    directory a dead worker left once it is past its TTL.

    With neither — a script calling the tool, a tool server started by hand —
    no job directory exists, and the run gets a temporary directory of its
    own (``tempfile.mkdtemp``, 0o700, ``maljan-capa-*`` in the system's
    temporary directory), and first sweeps the ones a killed run left there
    past the staging TTL (``_sweep_loose_runs``). Every one is removed when
    the run ends.
    """
    if scratch is not None:
        parent = staging.private_dir(Path(scratch))
    else:
        base = staging.staging_base()
        root = staging.staging_root()
        if root == base:
            _sweep_loose_runs()
            return Path(tempfile.mkdtemp(prefix=_LOOSE_RUN_PREFIX))
        staging.private_dir(base)
        staging.private_dir(root)
        parent = staging.private_dir(root / staging.CAPA_DIRECTORY)
    return Path(tempfile.mkdtemp(prefix="run-", dir=parent))


def _child_environment(run: Path) -> dict[str, str]:
    """The capa child's environment: the stdio servers' base names, and its run as home.

    ``child_env`` keeps the ``BASE_KEYS`` present (search path, locale, time
    zone, interpreter's virtual environment) and nothing else of the worker's:
    no database URL, no settings encryption key, no token key, no object store
    or queue credential, no model key. Two names are set rather than inherited:
    ``HOME`` and ``TMPDIR`` are the run's own directory, because capa writes a
    ruleset cache under ``$HOME/.cache/capa`` on every run and vivisect and the
    interpreter take their temporary files from ``TMPDIR``; both then go with
    the run instead of collecting in the worker's home. ``server`` names it
    in ``child_env``'s warning, should a platform secret ever be handed to it.

    The worker pins ``LC_CTYPE`` in its own process (``core.ctype_locale``)
    for C code that folds case; the child takes the locale names of the
    environment as they are. Nothing it runs folds case in C: capa matches
    its rules' strings and patterns in Python, which folds Unicode whatever
    the locale, and it loads no YARA.
    """
    return child_env({"HOME": str(run), "TMPDIR": str(run)}, server="capa")


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
    """Stop the child, killing it after a grace, and return its resource usage.

    By its pid: the child shares the caller's process group, and capa starts
    no process of its own that outlives a call (only its Binary Ninja backend
    runs a short lookup), so there is no group of its own to stop.
    """
    with contextlib.suppress(ProcessLookupError):
        os.kill(process.pid, signal.SIGTERM)
    ended = _ended(process, _GRACE_SECONDS, time.monotonic())
    if ended is not None:
        return ended[1]
    with contextlib.suppress(ProcessLookupError):
        os.kill(process.pid, signal.SIGKILL)
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
    scratch: str | Path | None = None,
) -> dict[str, Any] | None:
    """Run one capa pass in a child process, killed if it overruns its budget.

    capa's vivisect backend has no cooperative cancellation point inside a
    disassembly loop, so it cannot be interrupted from inside the calling
    process; a child process can be killed. On expiry it is told to stop, is
    killed if it is still there after a short grace, and ``None`` is returned:
    the existing warn-and-degrade contract, backed by something that can
    really stop the work.

    The child is ``capa_child``, run by its path as ``python -I`` in the
    caller's process group, with the environment ``_child_environment``
    builds, in a directory of its own (``_run_directory``: in the job's
    staging directory, ``scratch`` when the caller opened one there). It dies
    with its parent: the kernel kills it when the calling thread ends
    (``capa_child.die_with_parent``, handed this process's pid), and a group
    kill of the caller reaches it. It writes its answer to a file there, read
    once it has ended, so a large document never waits on a pipe; the
    directory goes when the run ends. Its peak resident memory is read as it
    is reaped. ``child`` stands in for the ``python -I`` and entry part of the
    command in a test; the same arguments follow it.

    ``None`` is also returned, with a warning, when the child ended without an
    answer (it crashed, or the server killed it with its run) or with capa's
    own error. A free function rather than a provider method because the
    ``capa`` tool runs the same pass with no provider and no ``Settings``.
    """
    run = _run_directory(scratch)
    answer = run / "answer.json"
    entry = list(child) if child else [sys.executable, "-I", str(_CHILD_ENTRY)]
    command = [
        *entry,
        sample_path,
        rules_dir,
        signatures_dir,
        backend_name,
        str(os.getpid()),
        str(answer),
    ]
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - our interpreter and entry, our paths
                command,
                env=_child_environment(run),
                cwd=run,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.warning(
                "capa on %s: the worker process could not be started (%s).", sample_path, exc
            )
            return None
        # The server kills this child when every caller of its run has gone
        # (``tools.children``; it leads no group, so its pid is killed); the
        # wait below then sees it end. Only while it runs: a reaped child's
        # pid can be another process's.
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
        # The job this provider serves, set by the container that built it
        # (``ServiceContainer.get_static_provider``): each capa run goes in
        # that job's staging directory, which the job's teardown removes.
        # Empty for a provider built outside a job, whose runs then get a
        # temporary directory of their own (``_run_directory``).
        self.job_key = ""

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

    _native_yara_ran = False

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        """capa and YARA over the sample, for a run whose triage pack did not run them.

        When a triage stage ran, the pack is the producer: its ``capa`` and
        ``yara_scan`` entries are already in the ledger and the report node
        does not call this (``triage_pack.rules_already_recorded``).
        """
        capa_result = self._run_capa(sample_path)
        yara_hits = self._run_yara(sample_path)
        # The operator's rules are scanned in this process, by the engine whose
        # case folding follows the process locale. When a native scan ran, a
        # broken engine is stated, on a scan with no hit as on one with hits:
        # an empty answer from it is not "no rule matched".
        from maljan.core.ctype_locale import yara_case_folding_problem

        folding_problem = yara_case_folding_problem() if self._native_yara_ran else None
        if capa_result is None and not yara_hits and not folding_problem:
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
        if yara_hits or folding_problem:
            evidence["yara"] = (
                _render_yara(yara_hits) if yara_hits else "No operator YARA rule matched."
            )
            if folding_problem:
                evidence["yara"] += f"\n\nNote: {folding_problem}."

        answers: list[EvidenceAnswer] = []
        for kind, payload in (
            ("capability_rules", {"capabilities": capa_rows} if capa_rows else None),
            (
                "signature_rules",
                {
                    "matches": list(yara_hits),
                    "rule_count": len(yara_hits),
                    "filtered": 0,
                    **({"engine_note": folding_problem} if folding_problem else {}),
                }
                if yara_hits or folding_problem
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

        The run goes in the job's staging directory (``job_key``), opened as
        the triage pack opens it for its own capa step. ``child`` stands in
        for the capa child's command so a test can run one that only sleeps,
        crashes or writes a given answer, to exercise the timeout, kill and
        failure paths without capa installed or a real multi-minute analysis.
        """
        scratch = (
            staging.open_job_directory(self.job_key, staging.CAPA_DIRECTORY)
            if self.job_key
            else None
        )
        return run_capa_document(
            sample_path=sample_path,
            rules_dir=str(rules_dir),
            signatures_dir=signatures_argument(self._capa.signatures_dir),
            backend_name=_BACKEND_NAMES.get(self._capa.backend, "BACKEND_VIV"),
            timeout_seconds=self._capa.timeout_seconds,
            child=child,
            scratch=scratch,
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
        (``static.yara.rules_dir``) is a directory: every ``*.yml``/``*.yaml``
        file in it is loaded and scanned, in name order, and the hits are
        joined. A file that cannot be loaded costs that file only.

        No budget is applied to the scan, by measurement and by construction:
        an operator rule is a list of literal strings (``YaraTTPRule``), which
        the engine matches in time linear in the sample, 0.03 s for 16 MB and
        1.1 s for 512 MB against the 31 shipped rules. A ``timeout`` would cut
        a real scan of a large sample short for a risk this rule form does not
        carry; ``core.reporting.detection_rule_check_seconds`` bounds the drafted rule's
        check (a full YARA condition language), which this is not.
        """
        self._native_yara_ran = False
        rules_dir = Path(resolve_data(self._yara.rules_dir))
        if not rules_dir.is_dir():
            return []
        rule_files = sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])
        if not rule_files:
            return []
        try:
            data = Path(sample_path).read_bytes()
        except Exception as exc:  # noqa: BLE001 - YARA must never fail a run
            logger.warning(
                "YARA scan of %s failed (%s: %s); continuing without YARA evidence.",
                sample_path,
                type(exc).__name__,
                exc,
            )
            return []
        from maljan.analysis.yara_layer import YaraLayer

        hits: list[dict[str, Any]] = []
        for rule_file in rule_files:
            try:
                layer = YaraLayer.from_yaml(rule_file)
                # Only the compiled engine folds case by the locale; the
                # regex fallback folds in Python and needs no note.
                if getattr(layer, "_yara_rules", None) is not None:
                    self._native_yara_ran = True
                hits.extend(
                    {"rule": m.rule_id, "strings": [m.evidence_ref], "technique": m.technique_id}
                    for m in layer.scan(data)
                )
            except Exception as exc:  # noqa: BLE001 - YARA must never fail a run
                logger.warning(
                    "YARA rules %s failed on %s (%s: %s); continuing without that file.",
                    rule_file.name,
                    sample_path,
                    type(exc).__name__,
                    exc,
                )
        return hits


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
