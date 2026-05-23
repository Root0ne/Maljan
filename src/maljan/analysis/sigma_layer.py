"""Sigma rule-based log analysis — ATT&CK Layer 0 deterministic detection.

Sigma and YARA are complementary layers:
  - YARA: looks at binary content and analysis text.
  - Sigma: looks at log lines (Windows Event Log, Sysmon, Zeek, Suricata).

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
    """

    rule_id: str
    rule_title: str
    technique_id: str | None
    confidence: float
    log_source: str
    matched_fields: dict[str, str] = field(default_factory=dict)

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
    ) -> list[SigmaMatch]:
        """Yapisal (Structured) JSON/Dict loglarini tarar."""
        if not self._collection.rules or not events:
            return []

        matches: list[SigmaMatch] = []
        for rule, evaluator in self._evaluators:
            for event in events:
                matched_fields = evaluator.evaluate(event, strict=True)
                if matched_fields is not None:
                    product = (
                        str(rule.logsource.product)
                        if rule.logsource and rule.logsource.product
                        else ""
                    )
                    canonical_src = _classify_log_source(log_source, product)
                    matches.append(
                        SigmaMatch(
                            rule_id=str(rule.id) if rule.id else "unknown",
                            rule_title=str(rule.title),
                            technique_id=self._extract_technique_id(rule),
                            confidence=self._get_confidence(rule),
                            log_source=canonical_src,
                            matched_fields=matched_fields,
                        )
                    )
                    break  # Each rule fires at most once per event batch.

        return matches

    def scan_log_lines(
        self,
        log_lines: list[str],
        log_source: str = "generic",
    ) -> list[SigmaMatch]:
        """Scan unstructured raw text lines. (Backward compatibility path.)"""
        if not self._collection.rules or not log_lines:
            return []

        matches: list[SigmaMatch] = []
        for rule, evaluator in self._evaluators:
            for line in log_lines:
                event = {"_raw": line}
                matched_fields = evaluator.evaluate(event, strict=False)
                if matched_fields is not None:
                    product = (
                        str(rule.logsource.product)
                        if rule.logsource and rule.logsource.product
                        else ""
                    )
                    canonical_src = _classify_log_source(log_source, product)
                    matches.append(
                        SigmaMatch(
                            rule_id=str(rule.id) if rule.id else "unknown",
                            rule_title=str(rule.title),
                            technique_id=self._extract_technique_id(rule),
                            confidence=self._get_confidence(rule),
                            log_source=canonical_src,
                            matched_fields=matched_fields,
                        )
                    )
                    break  # Each rule fires at most once per log batch.

        return matches

    def scan_report_text(self, report_text: str) -> list[SigmaMatch]:
        if not report_text or not self._collection.rules:
            return []
        lines = report_text.split("\n")
        return self.scan_log_lines(lines, log_source="generic")

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
                )
            )

        return AgentISR(
            agent_id="sigma_layer",
            domain="sigma",
            claims=claims,
            dissent_items=[],
            revision_round=0,
        )
