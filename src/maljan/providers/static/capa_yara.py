"""capa and YARA: evidence for the analyst, not tools for the model.

No tool server and no ReAct loop — this provider runs two deterministic
passes over the sample's bytes and hands the pipeline a
``StaticEvidenceBundle`` that ``ReportBuilder`` folds into the same
``StaticAnalysis`` the PE extractor fills. capa namespaces become capability
counters, capa's ATT&CK metadata becomes technique hits with the matching
rule as evidence, and the rendered tables plus any YARA hits become
``technical_evidence`` for the report's technical spine.

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
- ``capa.render.result_document.ResultDocument.from_capa`` takes the
  ``Capabilities.matches`` mapping, not the ``Capabilities`` object itself
  (``collect_metadata`` takes the whole object).
"""

from __future__ import annotations

import multiprocessing as mp
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from maljan.core.logger import logger
from maljan.core.paths import resolve_data
from maljan.providers.base import StaticCapabilities, StaticEvidenceBundle, StaticProvider
from maljan.providers.registry import register_static_provider
from maljan.reporting.models import StaticAnalysis
from maljan.schemas.tool_evidence import MAX_OUTPUT_CHARS, trim_output

if TYPE_CHECKING:
    from maljan.core.config import Settings, StaticCapaConfig, StaticYaraConfig

# capa backend name -> capa.loader constant, resolved lazily so importing this
# module never requires capa to be installed.
_BACKEND_NAMES: dict[str, str] = {
    "auto": "BACKEND_VIV",
    "vivisect": "BACKEND_VIV",
    "pefile": "BACKEND_PEFILE",
    "binja": "BACKEND_BINJA",
}

# ``api_technique_hits`` already has one producer — the import-capability
# Layer 0 (analysis/import_capability_layer.py) — whose rows start at
# confidence_base ~0.38-0.5 (data/api_attck_map_v1.json) and rise slowly with
# the number of *distinct imports* corroborating the technique, because a
# resolved import merely *being present* in the table is weak evidence on its
# own. A fired capa rule is not that: capa already requires the matching
# code pattern (an instruction sequence, a string, an API call in the right
# context) to be present, the same bar the deterministic YARA layer clears —
# so this reuses YARA's own deterministic floor
# (``analysis/yara_layer._CONFIDENCE_FLOOR`` = 0.70) rather than
# import_capability_layer's low-and-rising scheme: the corroboration
# import_capability_layer earns via extra imports, a capa match already has
# by construction.
_CAPA_TECHNIQUE_CONFIDENCE: float = 0.70


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
        backend = getattr(capa_loader, backend_name)
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
        queue.put(("ok", document.model_dump(mode="json")))
    except Exception as exc:  # noqa: BLE001 - reported to the parent, never raised here
        queue.put(("error", f"{type(exc).__name__}: {exc}"))


@register_static_provider("capa_yara")
class CapaYaraStaticProvider(StaticProvider):
    """capa and YARA: evidence for the analyst, not tools for the model."""

    def __init__(self, capa: StaticCapaConfig, yara: StaticYaraConfig) -> None:
        self._capa = capa
        self._yara = yara
        self._capa_available: bool | None = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> CapaYaraStaticProvider:
        return cls(cfg.static.capa, cfg.static.yara)

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_tools=False,
            provides_evidence=self._capa_available is not False,
            needs_sample_mirror=False,
            supports_tool_curation=False,
            degrade_on_failure=True,
        )

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        capa_result = self._run_capa(sample_path)
        yara_hits = self._run_yara(sample_path)
        if capa_result is None and not yara_hits:
            return None

        capabilities: dict[str, int] = {}
        hits: list[dict[str, Any]] = []
        rows: list[dict[str, str]] = []
        for name, rule in ((capa_result or {}).get("rules") or {}).items():
            meta = rule.get("meta") or {}
            namespace = str(meta.get("namespace") or "")
            top = namespace.split("/", 1)[0] if namespace else "uncategorised"
            capabilities[top] = capabilities.get(top, 0) + 1
            rows.append({"rule": str(name), "namespace": namespace})
            for attack in meta.get("attack") or []:
                tid = str((attack or {}).get("id") or "")
                if not tid:
                    continue
                hits.append(
                    {
                        "technique_id": tid,
                        "name": str(name),
                        "confidence": _CAPA_TECHNIQUE_CONFIDENCE,
                        "matched_apis": [namespace] if namespace else [],
                        "source": "capa",
                    }
                )

        evidence: dict[str, str] = {}
        if rows:
            evidence["capa"] = _render_table(rows)
        if yara_hits:
            evidence["yara"] = _render_yara(yara_hits)

        return StaticEvidenceBundle(
            api_capabilities=capabilities,
            technique_hits=hits,
            strings=[],
            technical_evidence=evidence,
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
        """Run the capa pipeline in a subprocess, killed if it overruns its budget.

        capa's vivisect backend has no cooperative cancellation point inside a
        disassembly loop, so it cannot be interrupted from inside the calling
        process — a thread-based timeout (this method's first cut) could only
        report a timeout to the caller while the actual vivisect thread kept
        running for however long the analysis really took, and
        ``ThreadPoolExecutor`` registers an ``atexit`` hook that joins every
        outstanding worker thread, which would have hung an arq worker's
        shutdown on a slow sample. A ``multiprocessing`` child process can
        actually be killed: on expiry this calls ``terminate()``, escalates to
        ``kill()`` if the process is still alive after a short grace period,
        and returns ``None`` either way — the existing warn-and-degrade
        contract, just backed by something that can really stop the work.

        ``target`` defaults to the module-level ``_capa_worker`` and exists so
        a test can inject a fake (module-level, picklable) target — e.g. one
        that only sleeps — to exercise the timeout/kill path without needing
        capa installed or a real multi-minute analysis.
        """
        worker = target or _capa_worker
        ctx = mp.get_context("spawn")
        queue: Any = ctx.Queue()
        backend_name = _BACKEND_NAMES.get(self._capa.backend, "BACKEND_VIV")
        signatures_dir = str(Path(resolve_data(self._capa.signatures_dir)))
        process = ctx.Process(
            target=worker,
            args=(sample_path, str(rules_dir), signatures_dir, backend_name, queue),
            daemon=True,
        )
        process.start()
        process.join(self._capa.timeout_seconds)
        if process.is_alive():
            logger.warning(
                "capa on %s exceeded its %ss budget; terminating the worker process.",
                sample_path,
                self._capa.timeout_seconds,
            )
            process.terminate()
            process.join(5.0)
            if process.is_alive():
                process.kill()
                process.join(5.0)
            queue.close()
            return None
        try:
            kind, payload = queue.get_nowait()
        except Exception:  # noqa: BLE001 - an empty queue is a crashed/killed child
            logger.warning("capa on %s exited without a result.", sample_path)
            return None
        finally:
            queue.close()
        if kind != "ok":
            logger.warning(
                "capa failed on %s (%s); continuing without capa evidence.", sample_path, payload
            )
            return None
        result: dict[str, Any] = payload
        return result

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
    """Render capa rule hits as a compact Markdown table, capped like every
    other captured tool output (``schemas.tool_evidence.MAX_OUTPUT_CHARS``)."""
    lines = ["| rule | namespace |", "| --- | --- |"]
    for row in rows:
        lines.append(f"| {row.get('rule', '')} | {row.get('namespace', '')} |")
    return trim_output("\n".join(lines), MAX_OUTPUT_CHARS)


def _render_yara(hits: list[dict[str, Any]]) -> str:
    """Render YARA hits as a compact Markdown table, capped the same way."""
    lines = ["| rule | strings |", "| --- | --- |"]
    for hit in hits:
        strings = ", ".join(str(s) for s in hit.get("strings") or [])
        lines.append(f"| {hit.get('rule', '')} | {strings} |")
    return trim_output("\n".join(lines), MAX_OUTPUT_CHARS)


def merge_static_evidence(static: StaticAnalysis, bundle: StaticEvidenceBundle) -> StaticAnalysis:
    """Fold a ``StaticEvidenceBundle`` into an existing ``StaticAnalysis``.

    Returns a new object (``model_copy``) — the caller's ``static`` is never
    mutated. Counters are summed key-by-key; technique hits are appended,
    never deduplicated (the PE extractor's and capa's hits are independent
    evidence for the same technique, not the same claim twice).
    """
    if not bundle.api_capabilities and not bundle.technique_hits:
        return static
    capabilities = dict(static.api_capabilities)
    for key, count in bundle.api_capabilities.items():
        capabilities[key] = capabilities.get(key, 0) + count
    hits = [*static.api_technique_hits, *bundle.technique_hits]
    return static.model_copy(update={"api_capabilities": capabilities, "api_technique_hits": hits})
