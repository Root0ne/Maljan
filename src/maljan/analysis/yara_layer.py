"""YARA-TTP Layer 0 — Deterministic signature-based ATT&CK technique detection.

This module implements the Layer 0 (pre-LLM) grounding step of the Maljan
TTP cascade pipeline. It scans analysis text against a YAML-configured rule
set and produces a synthetic AgentISR with domain="yara".

Key design decisions:
  - Zero hard dependencies: pure Python string matching (no yara-python required).
  - Optional yara-python integration: if the package is importable, compiled YARA
    rules are preferred over simple string matching for performance and accuracy.
  - Confidence floor: YARA matches are deterministic, so base confidence is always
    at least 0.70, independent of the LLM agents.
  - Domain weight: the cascade engine assigns LAYER_WEIGHTS["yara"] = 0.90,
    meaning YARA evidence outweighs all probabilistic LLM-derived signals.

Rule file format (YAML):
    version: "1.0"
    rules:
      - id: proc_injection_classic
        technique_id: "T1055"
        confidence: 0.88
        description: "Classic process injection indicators"
        patterns: ["VirtualAllocEx", "WriteProcessMemory"]

Integration:
    yara_layer = YaraLayer.from_default_rules()
    matches = yara_layer.scan(combined_analyst_text)
    if matches:
        isr = yara_layer.to_isr(matches)
        # Merge into isr_reports before cascade computation
        isr_reports["yara_layer"] = isr
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# Default rules file relative to the repository root
_DEFAULT_RULES_PATH = Path(__file__).parent.parent.parent.parent / "data" / "yara_ttp_rules.yaml"

# Minimum confidence to apply to any YARA match (deterministic floor)
_CONFIDENCE_FLOOR: float = 0.70


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class YaraTTPRule:
    """A single YARA-TTP mapping rule.

    Attributes:
        id:           Unique rule identifier (snake_case).
        technique_id: MITRE ATT&CK technique ID.
        confidence:   Match confidence in [0.70, 1.0].
        description:  Human-readable description of what the rule detects.
        patterns:     List of string patterns (case-insensitive, literal match).
    """

    id: str
    technique_id: str
    confidence: float
    description: str
    patterns: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> YaraTTPRule:
        """Construct a YaraTTPRule from a YAML rule dict."""
        confidence = max(float(data.get("confidence", 0.75)), _CONFIDENCE_FLOOR)
        patterns = tuple(str(p) for p in data.get("patterns", []))
        return cls(
            id=str(data["id"]),
            technique_id=str(data["technique_id"]),
            confidence=confidence,
            description=str(data.get("description", "")),
            patterns=patterns,
        )


@dataclass
class YaraMatch:
    """A single YARA rule match result.

    Attributes:
        rule_id:      Identifier of the matched rule.
        technique_id: ATT&CK technique mapped by the rule.
        confidence:   Rule-specified confidence value.
        description:  Human-readable rule description.
        matched_patterns: Specific patterns from the rule that were found.
    """

    rule_id: str
    technique_id: str
    confidence: float
    description: str
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def evidence_ref(self) -> str:
        """Short evidence reference string for use in ClaimEvidence."""
        if self.matched_patterns:
            snippets = ", ".join(f"'{p}'" for p in self.matched_patterns[:3])
            return f"YARA rule '{self.rule_id}': patterns matched: {snippets}"
        return f"YARA rule '{self.rule_id}' matched"

    @property
    def claim_text(self) -> str:
        """Claim sentence for use in ClaimEvidence."""
        return (
            f"Deterministic YARA signature match: {self.description} "
            f"(rule: {self.rule_id}, {len(self.matched_patterns)} pattern(s) found)"
        )


# ---------------------------------------------------------------------------
# YaraLayer
# ---------------------------------------------------------------------------


class YaraLayer:
    """Deterministic YARA-based ATT&CK technique detection layer.

    Scans analysis text against a YAML-configured pattern rule set and
    returns a list of YaraMatch objects. Each match is converted to a
    ClaimEvidence, which is then packaged into a synthetic AgentISR
    (domain="yara") for injection into the TTP cascade engine.

    Usage:
        layer = YaraLayer.from_default_rules()
        matches = layer.scan(analyst_reports_text)
        if matches:
            isr = layer.to_isr(matches)
    """

    def __init__(self, rules: list[YaraTTPRule]) -> None:
        self._rules = rules
        self._compiled: dict[str, list[re.Pattern[str]]] = {
            rule.id: [re.compile(re.escape(p), re.IGNORECASE) for p in rule.patterns]
            for rule in rules
        }
        logger.debug("YaraLayer initialized with %d rules.", len(rules))

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> YaraLayer:
        """Load rules from a YAML file.

        Args:
            path: Path to the YAML rule file.

        Returns:
            Configured YaraLayer instance.

        Raises:
            FileNotFoundError: If the rules file does not exist.
            ValueError: If the YAML structure is invalid.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required for YaraLayer.from_yaml(). Install it with: uv add pyyaml"
            ) from exc

        rules_path = Path(path)
        if not rules_path.exists():
            raise FileNotFoundError(f"YARA rules file not found: {rules_path}")

        with rules_path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError(f"Invalid YARA rules YAML: expected top-level 'rules' key in {path}")

        rules: list[YaraTTPRule] = []
        for entry in data["rules"] or []:
            try:
                rules.append(YaraTTPRule.from_dict(entry))
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("Skipping malformed YARA rule %s: %s", entry.get("id", "?"), exc)

        logger.info("YaraLayer: loaded %d rules from %s", len(rules), rules_path.name)
        return cls(rules)

    @classmethod
    def from_default_rules(cls) -> YaraLayer:
        """Load rules from the default data/yara_ttp_rules.yaml file.

        Searches for the file relative to the installed package location,
        falling back to the current working directory if not found.

        Returns:
            Configured YaraLayer instance, or an empty-rules instance if
            the default rules file cannot be found (graceful degradation).
        """
        candidates = [
            _DEFAULT_RULES_PATH,
            Path.cwd() / "data" / "yara_ttp_rules.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                return cls.from_yaml(candidate)

        logger.warning(
            "YaraLayer: default rules file not found (checked: %s). "
            "Layer will produce no matches. Run 'make prepare-attck' to generate data.",
            [str(c) for c in candidates],
        )
        return cls(rules=[])

    # ------------------------------------------------------------------
    # Core scanning
    # ------------------------------------------------------------------

    def scan(self, text: str) -> list[YaraMatch]:
        """Scan text against all loaded rules.

        For each rule, checks whether any of its patterns appear in the
        text. A rule match is recorded if at least one pattern is found.
        Multiple patterns from the same rule that match are all reported.

        The same technique_id may appear in multiple matches if more than
        one rule covers it — higher-level callers deduplicate by taking
        the maximum confidence.

        Args:
            text: Combined analysis text (analyst reports + ISR evidence_refs).

        Returns:
            List of YaraMatch objects, one per triggered rule.
        """
        if not text or not self._rules:
            return []

        matches: list[YaraMatch] = []

        for rule in self._rules:
            triggered_patterns: list[str] = []
            compiled_patterns = self._compiled[rule.id]

            for pattern_re, pattern_str in zip(compiled_patterns, rule.patterns, strict=False):
                if pattern_re.search(text):
                    triggered_patterns.append(pattern_str)

            if triggered_patterns:
                matches.append(
                    YaraMatch(
                        rule_id=rule.id,
                        technique_id=rule.technique_id,
                        confidence=rule.confidence,
                        description=rule.description,
                        matched_patterns=triggered_patterns,
                    )
                )

        if matches:
            logger.info(
                "YaraLayer: %d rule(s) triggered — techniques: %s",
                len(matches),
                sorted({m.technique_id for m in matches}),
            )

        return matches

    # ------------------------------------------------------------------
    # ISR conversion
    # ------------------------------------------------------------------

    def to_isr(self, matches: list[YaraMatch]) -> Any:
        """Convert YARA matches into a synthetic AgentISR.

        The ISR has domain="yara" and agent_id="yara_layer". Each match
        becomes one ClaimEvidence entry with deterministic confidence.

        The ISR is injected into isr_reports before cascade computation,
        where it contributes as an independent high-confidence layer.

        Args:
            matches: List of YaraMatch objects from scan().

        Returns:
            AgentISR with domain="yara" and one claim per match.
        """
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
            agent_id="yara_layer",
            domain="yara",  # type: ignore[arg-type]
            claims=claims,
            dissent_items=[],
            revision_round=0,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._rules)

    def techniques_covered(self) -> set[str]:
        """Set of ATT&CK technique IDs covered by the loaded rules."""
        return {rule.technique_id for rule in self._rules}

    def __repr__(self) -> str:
        return f"YaraLayer(rules={self.rule_count}, techniques={len(self.techniques_covered())})"
