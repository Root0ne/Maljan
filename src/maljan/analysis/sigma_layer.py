"""Sigma rule-based log analysis — ATT&CK Layer 0 deterministic detection.

Sigma and YARA are complementary layers:
  - YARA: looks at the sample's binary content.
  - Sigma: looks at structured telemetry events (process creation, registry
    writes) built from the sandbox report (Sysmon/Windows-Event-Log shaped).

2026-07 audit: the pipeline feeds Sigma structured events built from real
sandbox telemetry via ``build_events_from_sandbox`` + ``scan_events`` (strict
field matching). The legacy ``scan_report_text``/``scan_log_lines`` prose path
is retained only for tests/back-compat — it must NOT be used on analyst prose,
because ``strict=False`` matches rule values against arbitrary text and
manufactures false detections.

Together they cover the full deterministic-signal surface. Without Sigma,
log-based attack patterns (e.g. LSASS access, unnecessary LOLBin usage)
have to be handed entirely to the LLM.

Design decisions:
  - Self-contained: rules are parsed via pySigma into an AST and evaluated
    in-process; no out-of-process Sigma backend is required.
  - Graceful degradation: if the rules directory is missing, an empty
    instance is returned and the pipeline keeps running.
  - Singleton: accessed via ServiceContainer.get_sigma_layer().
  - to_isr(): matches are converted directly into AgentISR with
    domain="sigma".

Rule set source: data/sigma_rules/**/*.yml
    Sigma YAML format: https://sigmahq.io/docs/basics/rules.html

Usage:
    layer = SigmaLayer.from_default_rules()
    matches = layer.scan_log_lines(log_lines, log_source="sysmon")
    matches += layer.scan_report_text(report_text)
    isr = layer.to_isr(matches)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

# pySigma imports
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR

# ---------------------------------------------------------------------------
# Default rules directory
# ---------------------------------------------------------------------------

_DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "data" / "sigma_rules"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigmaMatch:
    """One Sigma rule match result.

    ``technique_id`` is ``None`` when the matched Sigma rule carries no
    ``attack.t####`` tag — previously this surfaced as the literal string
    ``"T0000"``, which polluted the STIX bundle with an invalid MITRE
    AttackPattern SDO. (2026-05-19 audit SIG-T0000-01.)

    ``rule_platforms`` (Wave 4): the canonical platform bucket(s) the rule
    declared via ``logsource.product``. Empty when the rule is generic.
    Carried into the ISR so the TTP cascade can do platform-aware filtering.
    """

    rule_id: str
    rule_title: str
    technique_id: str | None
    confidence: float
    log_source: str
    matched_fields: dict[str, str] = field(default_factory=dict)
    rule_platforms: tuple[str, ...] = ()

    @property
    def evidence_ref(self) -> str:
        """Short evidence reference — used as ISR ClaimEvidence.evidence_ref."""
        fields_str = ", ".join(f"{k}={v}" for k, v in list(self.matched_fields.items())[:3])
        return (
            f"Sigma rule '{self.rule_title}' matched: {fields_str}"
            if fields_str
            else f"Sigma rule '{self.rule_title}' matched"
        )

    @property
    def claim_text(self) -> str:
        """Description used as ISR ClaimEvidence.claim."""
        tech = self.technique_id if self.technique_id else "unmapped"
        return (
            f"Sigma rule detection: {self.rule_title} (technique {tech}, source={self.log_source})"
        )


# ---------------------------------------------------------------------------
# In-Memory AST Evaluator
# ---------------------------------------------------------------------------


class SigmaMemoryEvaluator:
    """Engine that evaluates pySigma rules in-process against Python dicts."""

    def __init__(self, rule: SigmaRule) -> None:
        self.rule = rule

    def evaluate(self, event: dict[str, str], strict: bool = True) -> dict[str, str] | None:
        """Try the rule against the given event dict.

        Args:
            event: Event log dict to scan.
            strict: True for exact match (anchored regex), False for search (substring).

        Returns:
            Matched-fields dict on hit, otherwise None.
        """
        if not self.rule.detection or not self.rule.detection.parsed_condition:
            return None

        # Multiple conditions are rare; any one matching is enough.
        for cond_tree in self.rule.detection.parsed_condition:
            match_dict = self._eval_node(cond_tree.parsed, event, strict)
            if match_dict is not None:
                return match_dict
        return None

    def _eval_node(self, node: Any, event: dict[str, str], strict: bool) -> dict[str, str] | None:
        if isinstance(node, ConditionAND):
            combined = {}
            for arg in node.args:
                res = self._eval_node(arg, event, strict)
                if res is None:
                    return None
                combined.update(res)
            return combined

        if isinstance(node, ConditionOR):
            for arg in node.args:
                res = self._eval_node(arg, event, strict)
                if res is not None:
                    return res
            return None

        if isinstance(node, ConditionNOT):
            res = self._eval_node(node.args[0], event, strict)
            if res is None:
                return {}  # NOT condition matched (the inner was False)
            return None  # NOT condition failed (the inner was True)

        if isinstance(node, ConditionFieldEqualsValueExpression):
            field = node.field.lower() if node.field else None
            regex = self._to_regex(node.value, strict)

            # strict=False: ignore field names, search within values
            # (backward compatibility for unstructured scans)
            if not strict:
                for v in event.values():
                    if regex.search(str(v)):
                        return {node.field or "raw": str(v)}
                return None

            # Field belirtilmemisse tum degerlerde ara
            if field is None:
                for k, v in event.items():
                    if regex.search(str(v)):
                        return {k: str(v)}
                return None

            # Search within a specific field.
            for k, v in event.items():
                if k.lower() == field:
                    if regex.search(str(v)):
                        return {node.field: str(v)}
            return None

        return None

    def _to_regex(self, val: Any, strict: bool) -> re.Pattern:
        """Sigma degerini Python Regex'ine cevirir."""
        if isinstance(val, SigmaRegularExpression):
            return re.compile(str(val.regexp), re.IGNORECASE)

        if isinstance(val, SigmaNumber):
            pat = re.escape(str(val.number))
            return re.compile(f"^{pat}$" if strict else pat, re.IGNORECASE)

        if isinstance(val, SigmaString):
            pattern = ""
            for part in val.s:
                if part == SpecialChars.WILDCARD_MULTI:
                    pattern += ".*"
                elif part == SpecialChars.WILDCARD_SINGLE:
                    pattern += "."
                else:
                    pattern += re.escape(str(part))
            return re.compile(f"^{pattern}$" if strict else pattern, re.IGNORECASE)

        pat = re.escape(str(val))
        return re.compile(f"^{pat}$" if strict else pat, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Log source classifier
# ---------------------------------------------------------------------------


def _classify_log_source(log_source: str, product: str) -> str:
    """Normalize log source identifier to canonical string."""
    ls = log_source.lower()
    pr = product.lower()
    if "sysmon" in ls or (pr == "windows" and "process" in ls):
        return "sysmon"
    if "security" in ls or "4688" in ls or "4624" in ls:
        return "windows_security"
    if "zeek" in ls or "bro" in ls:
        return "zeek"
    if "suricata" in ls:
        return "suricata"
    return "generic"


# ---------------------------------------------------------------------------
# Platform compatibility (Wave 4, 2026-05-28)
# ---------------------------------------------------------------------------


# Network-log products: same story — they expect Zeek/Suricata-style
# structured events, not text scans of analyst report blobs.
_NETWORK_LOG_PRODUCTS = frozenset(
    {
        "zeek",
        "suricata",
        "modsecurity",
        "fortios",
        "cisco",
        "paloalto",
        "netflow",
        "rpc_firewall",
    }
)

# Direct one-to-one match with our canonical SampleIdentity.platform values.
# OS-support scope (2026-06-02): Windows + Linux only.
_OS_PRODUCTS = frozenset({"windows", "linux"})


def _normalise_product(product: str | None) -> str:
    """Lowercase + strip the SigmaRule.logsource.product value."""
    if not product:
        return ""
    return str(product).strip().lower()


def _is_rule_compatible(rule_product: str | None, sample_platform: str | None) -> bool:
    """Return True when the rule should be evaluated against this sample.

    ``sample_platform`` semantics:

    * ``None`` → legacy / no-filter caller (older tests / direct CLI
      usage). Keep every rule so existing behaviour is preserved.
    * ``"unknown"`` → caller explicitly declared "platform inference
      failed" (Step 1 bootstrap couldn't disambiguate). Drop
      non-generic rules to avoid the platform-blind cascade FPs that
      motivated Wave 4. Generic rules still run.
    * any concrete platform string → exact match against the rule's
      ``logsource.product``.

    Resolution order for non-``None`` sample_platform:
      1. rule_product empty → generic; compatible with every sample.
      2. rule_product in network-log set → drop (no network-log layer
         today).
      3. rule_product in OS set → keep only when sample matches.
      4. anything else (unmapped product — incl. cloud/SaaS/macOS rules) →
         drop conservatively. OS-support scope is Windows + Linux only.
    """
    product = _normalise_product(rule_product)
    if sample_platform is None:
        return True  # legacy / no-filter caller
    if not product:
        return True  # generic rule, always compatible
    if product in _NETWORK_LOG_PRODUCTS:
        return False
    sp = sample_platform.strip().lower()
    if sp == "" or sp == "unknown":
        return False  # explicit unknown → drop non-generic rules
    if product in _OS_PRODUCTS:
        return product == sp
    return False


def _rule_platforms_tuple(product: str | None) -> tuple[str, ...]:
    """Tuple form of the rule's declared platform — propagated to ISR."""
    p = _normalise_product(product)
    if not p:
        return ()
    return (p,)


# ---------------------------------------------------------------------------
# SigmaLayer
# ---------------------------------------------------------------------------


class SigmaLayer:
    """Sigma rule-based log analysis — ATT&CK Layer 0 deterministic detection.

    Uses pySigma to parse rules into an AST and the in-tree
    ``SigmaMemoryEvaluator`` to evaluate events.
    """

    def __init__(self, collection: SigmaCollection) -> None:
        self._collection = collection
        # Filter out SigmaCorrelationRule; we only evaluate SigmaRule
        self._evaluators: list[tuple[SigmaRule, SigmaMemoryEvaluator]] = [
            (rule, SigmaMemoryEvaluator(rule))
            for rule in collection.rules
            if isinstance(rule, SigmaRule)
        ]
        # Wave 4 (2026-05-28) platform filter telemetry.
        self._filtered_count: int = 0

    @classmethod
    def from_rules_dir(cls, rules_dir: Path) -> SigmaLayer:
        if not rules_dir.exists():
            logger.warning(
                "SigmaLayer: rules directory not found: %s — running without Sigma rules.",
                rules_dir,
            )
            return cls(SigmaCollection(init_rules=[]))

        all_rules = []
        yaml_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
        loaded = 0
        for yf in yaml_files:
            try:
                rule_col = SigmaCollection.from_yaml(
                    yf.read_text(encoding="utf-8"), collect_errors=True
                )
                all_rules.extend(rule_col.rules)
                loaded += 1
            except Exception as e:
                logger.debug("SigmaLayer: Failed to parse %s: %s", yf, e)

        collection = SigmaCollection(
            init_rules=all_rules  # type: ignore[arg-type]
        )

        logger.info(
            "SigmaLayer: loaded %d rules from %d YAML files in %s using pySigma.",
            len(collection.rules),
            loaded,
            rules_dir,
        )
        return cls(collection)

    @classmethod
    def from_default_rules(cls) -> SigmaLayer:
        return cls.from_rules_dir(_DEFAULT_RULES_DIR)

    @property
    def rule_count(self) -> int:
        return len(self._collection.rules)

    def techniques_covered(self) -> set[str]:
        covered: set[str] = set()
        for rule in self._collection.rules:
            for tag in rule.tags:
                tag_str = str(tag).lower()
                if tag_str.startswith("attack.t"):
                    tech_id = ".".join(tag_str.split(".")[1:]).upper()
                    covered.add(tech_id)
        return covered

    def _extract_technique_id(self, rule: SigmaRule) -> str | None:
        """Return the MITRE ATT&CK technique ID for a Sigma rule, or None.

        Previously returned the hardcoded ``"T0000"`` sentinel when a rule
        had no ``attack.t####`` tag — that placeholder leaked through the
        cascade into the STIX bundle as an invalid AttackPattern SDO
        (audit 2026-05-19 SIG-T0000-01). Now we return ``None`` so
        downstream consumers that already accept ``Optional[str]`` (the
        ISR ClaimEvidence model, the cascade engine's regex filter) treat
        the rule as "untagged" rather than "T0000".
        """
        for tag in rule.tags:
            tag_str = str(tag).lower()
            if tag_str.startswith("attack.t"):
                return ".".join(tag_str.split(".")[1:]).upper()
        return None

    def _get_confidence(self, rule: SigmaRule) -> float:
        status = str(rule.status.name).lower() if rule.status else "experimental"
        return {
            "stable": 0.88,
            "test": 0.80,
            "experimental": 0.75,
            "deprecated": 0.60,
        }.get(status, 0.75)

    def scan_events(
        self,
        events: list[dict[str, str]],
        log_source: str = "generic",
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        """Scan structured (JSON/dict) logs. Platform-aware (Wave 4)."""
        if not self._collection.rules or not events:
            return []

        matches: list[SigmaMatch] = []
        for rule, evaluator in self._evaluators:
            product = (
                str(rule.logsource.product) if rule.logsource and rule.logsource.product else ""
            )
            if not _is_rule_compatible(product, sample_platform):
                self._filtered_count += 1
                continue
            for event in events:
                matched_fields = evaluator.evaluate(event, strict=True)
                if matched_fields is not None:
                    canonical_src = _classify_log_source(log_source, product)
                    matches.append(
                        SigmaMatch(
                            rule_id=str(rule.id) if rule.id else "unknown",
                            rule_title=str(rule.title),
                            technique_id=self._extract_technique_id(rule),
                            confidence=self._get_confidence(rule),
                            log_source=canonical_src,
                            matched_fields=matched_fields,
                            rule_platforms=_rule_platforms_tuple(product),
                        )
                    )
                    break  # Each rule fires at most once per event batch.

        return matches

    def scan_log_lines(
        self,
        log_lines: list[str],
        log_source: str = "generic",
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        """Scan unstructured raw text lines. (Backward compatibility path.)"""
        if not self._collection.rules or not log_lines:
            return []

        matches: list[SigmaMatch] = []
        for rule, evaluator in self._evaluators:
            product = (
                str(rule.logsource.product) if rule.logsource and rule.logsource.product else ""
            )
            if not _is_rule_compatible(product, sample_platform):
                self._filtered_count += 1
                continue
            for line in log_lines:
                event = {"_raw": line}
                matched_fields = evaluator.evaluate(event, strict=False)
                if matched_fields is not None:
                    canonical_src = _classify_log_source(log_source, product)
                    matches.append(
                        SigmaMatch(
                            rule_id=str(rule.id) if rule.id else "unknown",
                            rule_title=str(rule.title),
                            technique_id=self._extract_technique_id(rule),
                            confidence=self._get_confidence(rule),
                            log_source=canonical_src,
                            matched_fields=matched_fields,
                            rule_platforms=_rule_platforms_tuple(product),
                        )
                    )
                    break  # Each rule fires at most once per log batch.

        return matches

    def scan_report_text(
        self,
        report_text: str,
        sample_platform: str | None = None,
    ) -> list[SigmaMatch]:
        if not report_text or not self._collection.rules:
            return []
        lines = report_text.split("\n")
        return self.scan_log_lines(lines, log_source="generic", sample_platform=sample_platform)

    @property
    def last_filtered_count(self) -> int:
        """How many rules the most-recent scan suite dropped for platform.

        Caller pattern is ``reset_filter_stats() -> scan_*() -> last_filtered_count``;
        the counter accumulates across scan_events / scan_log_lines / scan_report_text
        within one logical scan suite so the judge node can log a single
        aggregate number per pipeline run.
        """
        return self._filtered_count

    def reset_filter_stats(self) -> None:
        """Zero the rule-drop counter before a fresh scan suite."""
        self._filtered_count = 0

    def to_isr(self, matches: list[SigmaMatch]) -> AgentISR:
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        claims: list[ClaimEvidence] = []
        for match in matches:
            claims.append(
                ClaimEvidence(
                    claim=match.claim_text,
                    evidence_ref=match.evidence_ref,
                    confidence=match.confidence,
                    technique_id=match.technique_id,
                    rule_platforms=list(match.rule_platforms) if match.rule_platforms else None,
                )
            )

        return AgentISR(
            agent_id="sigma_layer",
            domain="sigma",
            claims=claims,
            dissent_items=[],
            revision_round=0,
        )


# ---------------------------------------------------------------------------
# Telemetry -> Sysmon-shaped events (2026-07 deep re-architecture)
# ---------------------------------------------------------------------------


def _sandbox_arg_value(args: Any, names: tuple[str, ...]) -> str | None:
    """Pull the first matching argument value from a CAPE call's ``arguments``.

    Handles both the direct-key form (``{"FullName": "..."}``) and the
    name/value-pair form (``{"name": "FullName", "value": "..."}``).
    """
    if not isinstance(args, list):
        return None
    for item in args:
        if not isinstance(item, dict):
            continue
        for name in names:
            if name in item and item[name] not in (None, ""):
                return str(item[name])
        if str(item.get("name")) in names and item.get("value") not in (None, ""):
            return str(item.get("value"))
    return None


def build_events_from_sandbox(sandbox_report: dict[str, Any] | None) -> list[dict[str, str]]:
    """Translate real sandbox telemetry into Sysmon-shaped events for strict
    Sigma evaluation.

    2026-07 audit: Sigma previously scanned concatenated analyst prose with
    ``strict=False``, which matched a rule's *values* against any text — e.g.
    the Ghidra tool name ``list_imports`` appearing in an analyst report
    satisfied a ``CommandLine|contains: list_imports`` rule and surfaced as a
    fake "CommandLine" detection. We now build structured events from actual
    process/registry telemetry and evaluate with ``strict=True`` so a rule only
    fires against the field it targets. No telemetry -> no events -> no matches
    (the correct outcome for static-only runs).

    Returns a list of ``{field: value}`` dicts (process-creation and
    registry-write shapes). Fail-safe: any malformed input yields ``[]``.
    """
    if not isinstance(sandbox_report, dict):
        return []
    behavior = sandbox_report.get("behavior")
    if not isinstance(behavior, dict):
        behavior = {}

    events: list[dict[str, str]] = []

    procs = behavior.get("processes")
    pid_to_name: dict[int, str] = {}
    if isinstance(procs, list):
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            try:
                pid = int(proc.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            name = str(proc.get("process_name") or proc.get("name") or "").strip()
            if pid and name:
                pid_to_name[pid] = name
        for proc in procs:
            if not isinstance(proc, dict):
                continue
            name = str(proc.get("process_name") or proc.get("name") or "").strip()
            cmd = str(proc.get("command_line") or proc.get("cmd") or "").strip()
            if not (name or cmd):
                continue
            try:
                ppid = int(proc.get("ppid") or 0)
            except (TypeError, ValueError):
                ppid = 0
            event = {
                "Image": name,
                "CommandLine": cmd or name,
                "ParentImage": pid_to_name.get(ppid, ""),
            }
            trimmed = {k: v for k, v in event.items() if v}
            if trimmed:
                events.append(trimmed)

    calls = behavior.get("calls")
    if isinstance(calls, list):
        for call in calls:
            if not isinstance(call, dict):
                continue
            api = str(call.get("api") or "").strip()
            if not api.startswith("Reg"):
                continue
            if not ("Set" in api or "Create" in api or "Delete" in api):
                continue
            args = call.get("arguments") or []
            key = _sandbox_arg_value(args, ("FullName", "Key", "lpSubKey", "key"))
            if not key:
                continue
            reg_event: dict[str, str] = {"TargetObject": key}
            details = _sandbox_arg_value(args, ("Buffer", "Value", "lpData", "data"))
            if details:
                reg_event["Details"] = details
            events.append(reg_event)

    return events
