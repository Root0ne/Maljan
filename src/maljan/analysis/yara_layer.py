"""YARA matching over the sample's bytes, behind ``tools.rules.yara_scan``.

Scans the **sample's raw bytes** against a YAML-configured rule set and reports
what matched, where. An agent asks for the scan and decides what a hit means;
this module asserts no technique of its own.

The scan target is the bytes and not analyst prose. Scanning prose let a rule
fire whenever an analyst merely *mentioned* an API name (e.g. "no evidence of
WriteProcessMemory"), manufacturing high-confidence false T1055/T1497 evidence.
Matching against the binary keeps every hit grounded in what the sample
actually contains.

Key design decisions:
  - Zero hard dependencies: pure Python string matching (no yara-python required).
  - Optional yara-python integration: if the package is importable, compiled YARA
    rules are preferred over simple string matching for performance and accuracy.
  - Each rule carries the confidence its author wrote down, reported as the
    rule's own number rather than folded into anything.

Rule file format (YAML):
    version: "1.0"
    rules:
      - id: proc_injection_classic
        technique_id: "T1055"
        confidence: 0.88
        description: "Classic process injection indicators"
        patterns: ["VirtualAllocEx", "WriteProcessMemory"]

Rule set source: data/yara_ttp_rules.yaml, or ``MALJAN_YARA_RULES_DIR``.

Integration:
    layer = YaraLayer.from_default_rules()
    matches = layer.scan(sample_bytes)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# Optional yara-python integration (C extension, not available on all platforms)
try:
    import yara  # type: ignore[import-untyped]

    _YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False

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
        platform:     Sample-platform allowlist. Tuple
                      such as ``("windows",)`` for rules whose patterns are
                      Windows-only APIs/strings, ``("any",)`` for
                      cross-platform concepts. Empty / missing in the YAML
                      defaults to ``("any",)`` so legacy rules don't
                      silently drop out.
    """

    id: str
    technique_id: str
    confidence: float
    description: str
    patterns: tuple[str, ...]
    platform: tuple[str, ...] = ("any",)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> YaraTTPRule:
        """Construct a YaraTTPRule from a YAML rule dict."""
        confidence = max(float(data.get("confidence", 0.75)), _CONFIDENCE_FLOOR)
        patterns = tuple(str(p) for p in data.get("patterns", []))
        raw_platforms = data.get("platform") or ["any"]
        if isinstance(raw_platforms, str):
            raw_platforms = [raw_platforms]
        platform = tuple(str(p).strip().lower() for p in raw_platforms if str(p).strip())
        if not platform:
            platform = ("any",)
        return cls(
            id=str(data["id"]),
            technique_id=str(data["technique_id"]),
            confidence=confidence,
            description=str(data.get("description", "")),
            patterns=patterns,
            platform=platform,
        )


# ---------------------------------------------------------------------------
# Platform compatibility
# ---------------------------------------------------------------------------


def _yara_rule_compatible(rule_platforms: tuple[str, ...], sample_platform: str | None) -> bool:
    """Return True when the YARA rule should be scanned against this sample.

    Same semantics as the Sigma layer:
      * ``sample_platform=None`` → legacy / no-filter caller; keep everything.
      * ``"any"`` in ``rule_platforms`` → compatible with any sample.
      * ``sample_platform="unknown"`` → drop platform-specific rules; keep
        ``any`` rules.
      * concrete platform → match against ``rule_platforms``.
    """
    if sample_platform is None:
        return True
    if "any" in rule_platforms:
        return True
    sp = sample_platform.strip().lower()
    if sp == "" or sp == "unknown":
        return False
    return sp in rule_platforms


@dataclass
class YaraMatch:
    """A single YARA rule match result.

    Attributes:
        rule_id:      Identifier of the matched rule.
        technique_id: ATT&CK technique mapped by the rule.
        confidence:   Rule-specified confidence value.
        description:  Human-readable rule description.
        matched_patterns: Specific patterns from the rule that were found.
        rule_platforms: Source rule's declared platform tuple —
                        ``("any",)`` for cross-platform rules. Reported with
                        the match so the agent reading it knows what the rule
                        author said the rule was for, which is often narrower
                        than what the MITRE catalog says the technique targets.
        source_label: Which blob matched. Empty for the sample itself, and set
                        to the carve label (``"overlay+0x1a400"``) when the hit
                        came from an embedded payload. A rule firing on a
                        carved child says something different from one firing
                        on the sample — the difference between "this dropper
                        carries Emotet" and "this *is* Emotet" — and dropping
                        the distinction turns a dropper into a misattribution.
    """

    rule_id: str
    technique_id: str
    confidence: float
    description: str
    matched_patterns: list[str] = field(default_factory=list)
    rule_platforms: tuple[str, ...] = ()
    source_label: str = ""

    @property
    def evidence_ref(self) -> str:
        """Short evidence reference string for use in ClaimEvidence."""
        where = f"[{self.source_label}] " if self.source_label else ""
        if self.matched_patterns:
            snippets = ", ".join(f"'{p}'" for p in self.matched_patterns[:3])
            return f"{where}YARA rule '{self.rule_id}': patterns matched: {snippets}"
        return f"{where}YARA rule '{self.rule_id}' matched"

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
    """The compiled YARA corpus, behind ``tools.rules.yara_scan``.

    Scans the sample's bytes against a YAML-configured pattern rule set and
    returns a list of ``YaraMatch`` objects: which rule fired, where, what it
    matched, and the technique and confidence its author wrote down. What a
    hit means is the reading of whichever agent asked.

    Usage:
        layer = YaraLayer.from_default_rules()
        matches = layer.scan(sample_bytes)
        if matches:
            isr = layer.to_isr(matches)
    """

    def __init__(self, rules: list[YaraTTPRule]) -> None:
        self._rules = rules
        self._yara_rules: Any = None
        self._yara_id_map: dict[str, str] = {}
        self._compiled: dict[str, list[re.Pattern[str]]] = {}
        # Platform-filter telemetry (parallel to SigmaLayer).
        self._filtered_count: int = 0

        if _YARA_AVAILABLE and rules:
            compiled, id_map = self._compile_yara_rules(rules)
            self._yara_rules = compiled
            self._yara_id_map = id_map

        if self._yara_rules:
            # yara-python is the canonical engine; the regex fallback is dead
            # weight when it succeeds. Free that memory.
            logger.info("YaraLayer: compiled %d rules with yara-python engine.", len(rules))
        else:
            # No yara-python: build the regex fallback so scanning still works.
            self._compiled = {
                rule.id: [re.compile(re.escape(p), re.IGNORECASE) for p in rule.patterns]
                for rule in rules
            }
            if rules:
                logger.info(
                    "YaraLayer: yara-python unavailable; using %d-rule regex fallback.",
                    len(rules),
                )
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
    # YARA compilation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compile_yara_rules(rules: list[YaraTTPRule]) -> tuple[Any, dict[str, str]]:
        """Compile YAML pattern rules into a yara.Rules object.

        Translates each YaraTTPRule into a YARA rule string and compiles
        the combined source. Returns None if compilation fails.
        """
        if yara is None:
            return None, {}

        def _escape_yara_string(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')

        def _yara_safe_id(rule_id: str) -> str:
            """YARA rule names must be alphanumeric + underscore, max 128 chars."""
            safe = "".join(c if c.isalnum() or c == "_" else "_" for c in rule_id)[:128]
            return safe

        # Map yara-safe rule name back to original rule id
        _id_map: dict[str, str] = {}

        rule_sources: list[str] = []
        for rule in rules:
            yara_id = _yara_safe_id(rule.id)
            _id_map[yara_id] = rule.id
            strings_block = "\n".join(
                f'        ${i} = "{_escape_yara_string(p)}" nocase'
                for i, p in enumerate(rule.patterns)
            )
            # YARA meta values: string, integer, boolean only (no float)
            src = (
                f"rule {yara_id} {{\n"
                f"    meta:\n"
                f'        original_id = "{rule.id}"\n'
                f'        technique_id = "{rule.technique_id}"\n'
                f'        confidence = "{rule.confidence}"\n'
                f'        description = "{_escape_yara_string(rule.description)}"\n'
                f"    strings:\n"
                f"{strings_block}\n"
                f"    condition:\n"
                f"        any of them\n"
                f"}}\n"
            )
            rule_sources.append(src)

        combined = "\n".join(rule_sources)
        try:
            compiled = yara.compile(source=combined)
            return compiled, _id_map
        except Exception as exc:
            logger.warning(
                "YaraLayer: yara-python compilation failed: %s. Falling back to regex.",
                exc,
            )
            return None, {}

    def _yara_scan(self, data: bytes) -> list[YaraMatch]:
        """Scan raw bytes using the compiled yara-python engine."""
        if self._yara_rules is None or yara is None:
            return []

        try:
            matches = self._yara_rules.match(data=data)
        except Exception as exc:
            logger.warning("YaraLayer: yara-python scan failed: %s. Falling back to regex.", exc)
            return []

        id_map: dict[str, str] = self._yara_id_map
        results: list[YaraMatch] = []
        for match in matches:
            meta = match.meta
            yara_id = match.rule
            rule_id = id_map.get(yara_id, yara_id)
            technique_id = meta.get("technique_id", "")
            confidence = float(meta.get("confidence", "0.75"))
            description = meta.get("description", "")

            # Collect matched strings from yara result.
            # yara-python >=4.5 uses StringMatch / StringMatchInstance objects.
            matched_patterns: list[str] = []
            seen: set[str] = set()
            for string_match in match.strings:
                identifier = string_match.identifier
                # Identifier format is "$pN" where N is the pattern index
                if identifier.startswith("$p"):
                    try:
                        idx = int(identifier[2:])
                        if 0 <= idx < len(self._rules):
                            # Find the rule to get the original pattern text
                            for r in self._rules:
                                if r.id == rule_id and idx < len(r.patterns):
                                    pat = r.patterns[idx]
                                    if pat not in seen:
                                        matched_patterns.append(pat)
                                        seen.add(pat)
                                    break
                    except ValueError:
                        pass
                else:
                    # Fallback: use matched_data bytes
                    for instance in string_match.instances:
                        data = instance.matched_data
                        try:
                            decoded = data.decode("utf-8", errors="replace")
                        except (AttributeError, UnicodeDecodeError):
                            decoded = str(data)
                        if decoded not in seen:
                            matched_patterns.append(decoded)
                            seen.add(decoded)

            results.append(
                YaraMatch(
                    rule_id=rule_id,
                    technique_id=technique_id,
                    confidence=confidence,
                    description=description,
                    matched_patterns=matched_patterns,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Core scanning
    # ------------------------------------------------------------------

    def scan(self, data: bytes | str, sample_platform: str | None = None) -> list[YaraMatch]:
        """Scan the sample's raw bytes against all loaded rules.

        Uses the compiled yara-python engine when available; falls back to
        regex-based string matching otherwise.

        The scan target is now the
        **sample bytes**, not analyst prose. An API-name pattern such as
        ``WriteProcessMemory`` therefore only fires when the string is
        actually present in the binary (import table / embedded strings),
        never because an analyst merely mentioned it in a report. A ``str``
        is still accepted (encoded as UTF-8) for legacy/test callers.

        Args:
            data: Raw sample bytes (preferred) or text.
            sample_platform: Drop rules whose declared
                ``platform`` field doesn't intersect the sample's
                canonical platform. ``None`` keeps legacy callers green.

        Returns:
            List of YaraMatch objects, one per triggered rule.
        """
        if not data or not self._rules:
            return []

        data_bytes = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")

        # Pre-filter the rule list by platform compatibility.
        # We keep _rules as the canonical full set so callers querying
        # ``rule_count`` see the corpus; only the scan loop is filtered.
        if sample_platform is None:
            active_rules = self._rules
        else:
            active_rules = []
            for r in self._rules:
                if _yara_rule_compatible(r.platform, sample_platform):
                    active_rules.append(r)
                else:
                    self._filtered_count += 1

        if not active_rules:
            return []

        # Prefer yara-python engine when available
        if self._yara_rules is not None:
            matches = self._yara_scan(data_bytes)
            # Drop matches whose original rule is platform-incompatible.
            # (Compiled yara_rules is built from the full corpus; we filter
            # here rather than rebuild the compiled object per-scan.)
            if sample_platform is not None:
                active_ids = {r.id for r in active_rules}
                matches = [m for m in matches if m.rule_id in active_ids]
            # Attach the rule's declared platforms to the match, so the
            # answer carries what its author said it was for.
            id_to_platforms = {r.id: r.platform for r in self._rules}
            for m in matches:
                m.rule_platforms = id_to_platforms.get(m.rule_id, ())
            if matches:
                logger.info(
                    "YaraLayer: %d rule(s) triggered (yara-python) — techniques: %s",
                    len(matches),
                    sorted({m.technique_id for m in matches}),
                )
            return matches

        # Fallback: regex-based string matching. Decode the bytes leniently so
        # ASCII API names / string IOCs embedded in the binary still match.
        text = data_bytes.decode("utf-8", errors="replace")
        regex_matches: list[YaraMatch] = []

        for rule in active_rules:
            triggered_patterns: list[str] = []
            compiled_patterns = self._compiled[rule.id]

            for pattern_re, pattern_str in zip(compiled_patterns, rule.patterns, strict=False):
                if pattern_re.search(text):
                    triggered_patterns.append(pattern_str)

            if triggered_patterns:
                regex_matches.append(
                    YaraMatch(
                        rule_id=rule.id,
                        technique_id=rule.technique_id,
                        confidence=rule.confidence,
                        description=rule.description,
                        matched_patterns=triggered_patterns,
                        rule_platforms=rule.platform,
                    )
                )

        if regex_matches:
            logger.info(
                "YaraLayer: %d rule(s) triggered (regex) — techniques: %s",
                len(regex_matches),
                sorted({m.technique_id for m in regex_matches}),
            )

        return regex_matches

    @property
    def last_filtered_count(self) -> int:
        """How many rules the most-recent scan dropped for platform."""
        return self._filtered_count

    def reset_filter_stats(self) -> None:
        """Zero the rule-drop counter before a fresh scan."""
        self._filtered_count = 0

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
