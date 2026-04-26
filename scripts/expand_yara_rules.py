"""expand_yara_rules.py — MITRE ATT&CK verisi kullanarak YARA kural setini genisletir.

Problem:
    data/yara_ttp_rules.yaml elle yazilmis ~40 kuralla geldi.
    Bu, 691 aktif ATT&CK tekniğinin yalnizca ~%4'unu kapsiyor ve Layer 0'in
    deterministik gucunu buyuk olcude kisitliyor.

Cozum:
    Depoda zaten mevcut olan MITRE verisi:
      - data/attck_labeled_sentences.jsonl  (relationship_description layer)
      - ~/.cache/maljan/enterprise-attack.json (STIX bundle)
    bu iki kaynaktan pattern cikararak eksik teknikler icin kurallar olusturur.

Veri kaynaklari (oncelik sirasi):
    1. attck_labeled_sentences.jsonl — relationship_description layer:
       MITRE'nin "bu malware bu teknigi SU SEKILDE kullanir" cumlelerinden
       en sik gecen token'lari pattern olarak cikarir.
    2. x_mitre_detection alanlari (STIX bundle): API adlari, arac isimleri,
       event ID'leri icerir.

Pattern secim kurallari:
    - Windows API adi (buyuk harf baslangici, 4+ karakter) -> confidence 0.88
    - Bilinen arac adi (mimikatz, certutil vb.) -> confidence 0.85
    - Genel terim -> confidence 0.75
    - 3 karakterden kisa -> atlanir.
    - Minimum 2, maksimum 8 pattern/kural.
    - Mevcut elle yazilmis kurallar KORUNUR (sadece eksik teknikler eklenir).

Kural ID formati: {tactic_slug}_{technique_normalized}_{seq}
Ornek: defense_evasion_t1055_001_0

Cikti:
    data/yara_ttp_rules.yaml — genisletilmis kural seti (version 2.0)

Kullanim:
    uv run python scripts/expand_yara_rules.py
    uv run python scripts/expand_yara_rules.py --dry-run
    uv run python scripts/expand_yara_rules.py --sentences data/attck_labeled_sentences.jsonl
    uv run python scripts/expand_yara_rules.py --attck-cache ~/.cache/maljan/
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent

DEFAULT_SENTENCES = ROOT_DIR / "data" / "attck_labeled_sentences.jsonl"
DEFAULT_OUTPUT = ROOT_DIR / "data" / "yara_ttp_rules.yaml"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "maljan"

# Minimum/maximum patterns per generated rule
MIN_PATTERNS = 2
MAX_PATTERNS = 8

# Confidence buckets
CONF_API = 0.88  # Windows API call (e.g. VirtualAllocEx, WriteProcessMemory)
CONF_TOOL = 0.85  # Known security tool / LOLBin name
CONF_GENERIC = 0.75  # General behavioral term

# Well-known LOLBin / security tool names — exact lowercase match
_KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "mimikatz",
        "meterpreter",
        "cobalt strike",
        "cobaltstrike",
        "certutil",
        "mshta",
        "regsvr32",
        "rundll32",
        "wscript",
        "cscript",
        "bitsadmin",
        "wmic",
        "sc.exe",
        "at.exe",
        "net.exe",
        "netsh",
        "powershell",
        "cmd.exe",
        "psexec",
        "procdump",
        "wce",
        "fgdump",
        "pwdump",
        "secretsdump",
        "vssadmin",
        "wbadmin",
        "bcdedit",
        "ntdsutil",
        "urldownloadtofile",
        "urlmon",
        "wininet",
        "winhttp",
        "systeminfo",
        "tasklist",
        "whoami",
        "ipconfig",
        "nslookup",
        "ping",
        "tracert",
        "arp",
        "nmap",
        "netcat",
        "nc.exe",
    }
)

# Token exclusion list — too generic to be useful as patterns
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "or",
        "not",
        "for",
        "with",
        "this",
        "that",
        "from",
        "into",
        "over",
        "can",
        "may",
        "will",
        "such",
        "via",
        "using",
        "used",
        "use",
        "also",
        "been",
        "have",
        "has",
        "are",
        "was",
        "were",
        "its",
        "it",
        "to",
        "in",
        "on",
        "of",
        "by",
        "a",
        "an",
        "is",
        "at",
        "be",
        "do",
        "if",
        "no",
        "as",
        "so",
        "but",
        "they",
        "them",
        "their",
        "these",
        "those",
        "when",
        "where",
        "how",
        "all",
        "any",
        "both",
        "each",
        "few",
        "more",
        "most",
        "other",
        "than",
        "then",
        "through",
        "during",
        "between",
        "about",
        "against",
        "after",
        "before",
        "system",
        "windows",
        "linux",
        "attacker",
        "adversary",
        "malware",
        "software",
        "code",
        "file",
        "files",
        "data",
        "process",
        "processes",
        "user",
        "users",
        "host",
        "hosts",
        "network",
        "registry",
        "memory",
        "execution",
        "based",
        "attack",
        "allow",
        "allows",
        "enable",
        "enables",
        "prevent",
        "prevents",
        "without",
        "within",
        "across",
        "below",
        "above",
        "while",
        "typically",
        "commonly",
        "often",
        "might",
        "could",
        "should",
        "would",
        "same",
        "new",
        "create",
        "creates",
        "run",
        "runs",
        "access",
        "accesses",
        "read",
        "write",
        "open",
        "close",
        "execute",
        "executes",
        "download",
        "upload",
        "send",
        "receive",
        "connect",
        "connection",
        "local",
        "remote",
        "target",
        "source",
        "method",
        "multiple",
        "command",
        "commands",
        "activity",
        "activities",
        "operation",
        "operations",
        "behavior",
        "behaviours",
        "technique",
        "techniques",
        "function",
        "functions",
        "module",
        "modules",
        "service",
        "services",
        "tool",
        "tools",
        "artifact",
        "artifacts",
        "indicator",
        "indicators",
        "signature",
        "signatures",
    }
)

# Windows API pattern: starts with capital letter, 4+ chars, no spaces
_RE_WIN_API = re.compile(r"^[A-Z][A-Za-z]{3,}(?:Ex|W|A|64)?$")

# Tactic slug mapping for rule ID generation
_TACTIC_SLUGS: dict[str, str] = {
    "initial-access": "initial_access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command-and-control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "resource-development": "resource_development",
    "reconnaissance": "reconnaissance",
}


# ---------------------------------------------------------------------------
# YAML serializer (no external dependency)
# ---------------------------------------------------------------------------


def _yaml_dump_rules(rules: list[dict], indent: int = 2) -> str:
    """Serialize the rules list to YAML format without PyYAML dependency."""
    lines: list[str] = []
    pad = " " * indent
    for rule in rules:
        lines.append(f"{pad}- id: {rule['id']}")
        lines.append(f'{pad}  technique_id: "{rule["technique_id"]}"')
        lines.append(f"{pad}  confidence: {rule['confidence']:.2f}")
        lines.append(f'{pad}  description: "{rule["description"]}"')
        pattern_list = ", ".join(f'"{p}"' for p in rule["patterns"])
        lines.append(f"{pad}  patterns: [{pattern_list}]")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# STIX bundle helpers
# ---------------------------------------------------------------------------


def _load_stix_bundle(cache_dir: Path) -> dict:
    """Load the cached STIX bundle. Returns empty dict if not found."""
    bundle_path = cache_dir / "enterprise-attack.json"
    if not bundle_path.exists():
        return {}
    try:
        return json.loads(bundle_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _get_attck_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id", "")
            if re.match(r"^T\d{4}(\.\d{3})?$", ext_id):
                return ext_id
    return None


def _is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _build_technique_meta(objects: list[dict]) -> dict[str, dict]:
    """Build technique_id -> {name, tactics, platforms, detection} map."""
    meta: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if not _is_active(obj):
            continue
        tid = _get_attck_id(obj)
        if not tid:
            continue
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]
        meta[tid] = {
            "name": obj.get("name", tid),
            "tactics": phases,
            "platforms": platforms,
            "detection": obj.get("x_mitre_detection", ""),
        }
    return meta


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> list[str]:
    """Tokenize text into meaningful words."""
    raw = re.findall(r"\b[A-Za-z][A-Za-z0-9_\-]{2,}\b", text)
    result: list[str] = []
    for t in raw:
        if t.lower() in _STOPWORDS:
            continue
        if len(t) < 3:
            continue
        result.append(t)
    return result


def _classify_token(token: str) -> tuple[str, float]:
    """Classify a token and return (token, confidence)."""
    tl = token.lower()
    if tl in _KNOWN_TOOLS:
        return token, CONF_TOOL
    if _RE_WIN_API.match(token) and token[0].isupper():
        return token, CONF_API
    return token, CONF_GENERIC


def _extract_patterns_from_text(
    text: str, max_count: int = MAX_PATTERNS
) -> list[tuple[str, float]]:
    """Extract top candidate patterns from a text block with confidence scores."""
    tokens = _tokenize(text)
    freq: Counter[str] = Counter(tokens)

    scored: list[tuple[str, float, int]] = []
    for token, count in freq.most_common():
        if count < 1:
            continue
        canonical, conf = _classify_token(token)
        # Boost API / tool names that appear at least twice
        if count >= 2 and conf >= CONF_TOOL:
            conf = min(conf + 0.02, 0.95)
        scored.append((canonical, conf, count))

    # Sort by confidence desc, frequency desc
    scored.sort(key=lambda x: (-x[1], -x[2]))

    seen: set[str] = set()
    result: list[tuple[str, float]] = []
    for canonical, conf, _ in scored:
        lower = canonical.lower()
        if lower in seen:
            continue
        seen.add(lower)
        result.append((canonical, conf))
        if len(result) >= max_count:
            break

    return result


# ---------------------------------------------------------------------------
# Labeled sentences loader
# ---------------------------------------------------------------------------


def _load_labeled_sentences(path: Path) -> dict[str, list[str]]:
    """Load attck_labeled_sentences.jsonl and group texts by technique label.

    Only includes relationship_description layer — most specific signal.
    """
    groups: dict[str, list[str]] = defaultdict(list)
    if not path.exists():
        print(f"  [WARN] Labeled sentences not found: {path}", file=sys.stderr)
        return {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("layer") != "relationship_description":
                continue
            label = obj.get("label", "")
            text = obj.get("text", "").strip()
            if label and text:
                groups[label].append(text)
    return groups


# ---------------------------------------------------------------------------
# YARA YAML reader
# ---------------------------------------------------------------------------


def _parse_existing_rules(yaml_path: Path) -> tuple[str, list[str], list[dict]]:
    """Parse existing YAML rules file.

    Returns:
        (header_block, covered_technique_ids, rules_list)
    The rules_list contains raw dicts only for existing rule blocks.
    The header_block is everything before the first '- id:' line.
    """
    if not yaml_path.exists():
        return "", [], []

    raw = yaml_path.read_text(encoding="utf-8")
    lines = raw.split("\n")

    # Find where rules list starts
    header_lines: list[str] = []
    rules_raw: list[str] = []
    in_rules = False
    for line in lines:
        if not in_rules:
            if line.strip().startswith("- id:"):
                in_rules = True
                rules_raw.append(line)
            else:
                header_lines.append(line)
        else:
            rules_raw.append(line)

    header = "\n".join(header_lines)

    # Extract covered technique IDs from raw text
    covered: list[str] = re.findall(r'technique_id:\s*"([^"]+)"', raw)

    # Build rules list for reference (we keep the raw block verbatim)
    raw_rules_block = "\n".join(rules_raw)

    return header, list(set(covered)), raw_rules_block


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _make_rule_id(tactic: str, technique_id: str, seq: int) -> str:
    tactic_slug = _TACTIC_SLUGS.get(tactic, tactic.replace("-", "_"))
    tech_norm = technique_id.lower().replace(".", "_")
    return f"{tactic_slug}_{tech_norm}_{seq}"


def _generate_rules_for_technique(
    technique_id: str,
    meta: dict,
    sentence_texts: list[str],
) -> list[dict] | None:
    """Generate YARA rules for a single technique.

    Returns None if not enough patterns can be extracted.
    """
    # Filter to Windows/Linux platforms only
    platforms = meta.get("platforms", [])
    if platforms and not any(p in ("windows", "linux") for p in platforms):
        return None

    # Collect all text for this technique
    combined_text = " ".join(sentence_texts)
    detection_text = meta.get("detection", "")

    # Extract from relationship descriptions first (higher quality)
    patterns_rel = _extract_patterns_from_text(combined_text, max_count=MAX_PATTERNS)

    # Then from detection text
    patterns_det = _extract_patterns_from_text(detection_text, max_count=MAX_PATTERNS)

    # Merge: prefer higher confidence, deduplicate
    seen_lower: set[str] = set()
    merged: list[tuple[str, float]] = []
    for pat, conf in patterns_rel + patterns_det:
        pl = pat.lower()
        if pl in seen_lower:
            continue
        seen_lower.add(pl)
        merged.append((pat, conf))
        if len(merged) >= MAX_PATTERNS:
            break

    if len(merged) < MIN_PATTERNS:
        return None

    # Group by confidence bucket to determine rule count
    # If all patterns have the same confidence, emit one rule
    tactics = meta.get("tactics", ["unknown"])
    primary_tactic = tactics[0] if tactics else "unknown"
    tech_name = meta.get("name", technique_id)

    rule_patterns = [p for p, _ in merged]
    avg_conf = sum(c for _, c in merged) / len(merged)
    avg_conf = round(avg_conf, 2)

    rule = {
        "id": _make_rule_id(primary_tactic, technique_id, 0),
        "technique_id": technique_id,
        "confidence": avg_conf,
        "description": f"MITRE ATT&CK derived: {tech_name} ({technique_id})",
        "patterns": rule_patterns[:MAX_PATTERNS],
    }
    return [rule]


# ---------------------------------------------------------------------------
# YAML writer
# ---------------------------------------------------------------------------


def _build_output_yaml(
    existing_header: str,
    existing_rules_block: str,
    new_rules: list[dict],
    sentences_path: Path,
) -> str:
    """Assemble the final YAML content."""
    import datetime

    today = datetime.date.today().isoformat()

    # Update header to version 2.0
    header = existing_header
    header = re.sub(r'version:\s*"[^"]*"', 'version: "2.0"', header)
    header = re.sub(
        r'description:\s*"[^"]*"',
        'description: "Maljan YARA-TTP rule set — hand-crafted + MITRE ATT&CK derived."',
        header,
    )

    # If no existing header structure, build a fresh one
    if "rules:" not in header:
        header = (
            f'version: "2.0"\n'
            f'description: "Maljan YARA-TTP rule set — hand-crafted + MITRE ATT&CK derived."\n'
            f'generated_at: "{today}"\n'
            f"sources:\n"
            f'  - "hand-crafted (baseline)"\n'
            f'  - "mitre-attack/attack-stix-data (ATT&CK Enterprise)"\n'
            f'  - "data/attck_labeled_sentences.jsonl (TRAM2 format)"\n'
            f"\n"
            f"rules:\n"
        )
    else:
        # Inject generated_at and sources after version/description
        if "generated_at:" not in header:
            header = header.rstrip()
            header += f'\ngenerated_at: "{today}"\n'
        if "sources:" not in header:
            header = header.rstrip()
            header += (
                "\nsources:\n"
                '  - "hand-crafted (baseline)"\n'
                '  - "mitre-attack/attack-stix-data (ATT&CK Enterprise)"\n'
                '  - "data/attck_labeled_sentences.jsonl (TRAM2 format)"\n'
            )

    header = header.rstrip()
    if not header.endswith("\nrules:") and "rules:" in header:
        pass
    elif "rules:" not in header:
        header += "\n\nrules:\n"
    else:
        header += "\n"

    # Section separator for generated rules
    generated_block = ""
    if new_rules:
        generated_block = (
            "\n"
            "  # -----------------------------------------------------------------------\n"
            f"  # MITRE ATT&CK derived rules (auto-generated {today} — do not edit manually)\n"
            "  # Source: attck_labeled_sentences.jsonl + x_mitre_detection fields\n"
            "  # -----------------------------------------------------------------------\n"
        )
        generated_block += _yaml_dump_rules(new_rules)

    # Assemble
    parts = [header.rstrip()]
    if existing_rules_block.strip():
        parts.append(existing_rules_block.rstrip())
    if generated_block:
        parts.append(generated_block.rstrip())

    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def expand(
    sentences_path: Path = DEFAULT_SENTENCES,
    output_path: Path = DEFAULT_OUTPUT,
    attck_cache_dir: Path = DEFAULT_CACHE_DIR,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Run the expansion pipeline.

    Returns:
        (existing_technique_count, new_rules_added)
    """
    print("Maljan YARA Rule Expander", flush=True)
    print("=" * 50, flush=True)

    # Step 1: Read existing rules
    print(f"\n[1] Reading existing rules: {output_path}", flush=True)
    existing_header, covered_ids, existing_rules_block = _parse_existing_rules(output_path)
    covered_set = set(covered_ids)
    print(f"    Existing covered techniques: {len(covered_set)}", flush=True)

    # Step 2: Load STIX technique metadata
    print(f"\n[2] Loading STIX bundle from cache: {attck_cache_dir}", flush=True)
    bundle = _load_stix_bundle(attck_cache_dir)
    objects = bundle.get("objects", [])
    if objects:
        tech_meta = _build_technique_meta(objects)
        print(f"    Loaded {len(tech_meta)} active techniques from STIX bundle.", flush=True)
    else:
        tech_meta = {}
        print(
            "    [WARN] STIX bundle not found in cache. "
            "Run: uv run python scripts/prepare_attck_malware_fixtures.py",
            file=sys.stderr,
        )

    # Step 3: Load labeled sentences
    print(f"\n[3] Loading labeled sentences: {sentences_path}", flush=True)
    sentence_groups = _load_labeled_sentences(sentences_path)
    print(f"    Techniques with relationship descriptions: {len(sentence_groups)}", flush=True)

    # Step 4: Determine techniques to process (not yet covered)
    all_techniques: set[str] = set(sentence_groups.keys()) | set(tech_meta.keys())
    missing = sorted(all_techniques - covered_set)
    print(f"\n[4] Techniques not yet covered: {len(missing)}", flush=True)

    # Step 5: Generate rules for missing techniques
    print("\n[5] Generating rules...", flush=True)
    new_rules: list[dict] = []
    skipped = 0

    for tid in missing:
        meta = tech_meta.get(tid, {"name": tid, "tactics": ["unknown"], "platforms": []})
        sentence_texts = sentence_groups.get(tid, [])
        detection_text = meta.get("detection", "")

        # Skip if no usable text at all
        if not sentence_texts and not detection_text:
            skipped += 1
            continue

        generated = _generate_rules_for_technique(tid, meta, sentence_texts)
        if generated:
            new_rules.extend(generated)
        else:
            skipped += 1

    print(f"    Generated: {len(new_rules)} new rules", flush=True)
    print(f"    Skipped  : {skipped} techniques (no patterns / wrong platform)", flush=True)

    # Step 6: Write output
    if dry_run:
        print(
            f"\n[DRY RUN] Would write {len(new_rules)} new rules to {output_path}",
            flush=True,
        )
        print("          Pass without --dry-run to apply changes.", flush=True)
        return len(covered_set), len(new_rules)

    print(f"\n[6] Writing expanded rules to: {output_path}", flush=True)
    yaml_content = _build_output_yaml(
        existing_header,
        existing_rules_block,
        new_rules,
        sentences_path,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml_content, encoding="utf-8")

    total_covered = len(covered_set) + len(new_rules)
    print(
        f"\nDone.\n"
        f"  Pre-existing covered techniques : {len(covered_set)}\n"
        f"  New rules added                : {len(new_rules)}\n"
        f"  Total estimated coverage       : {total_covered}+ techniques\n"
        f"  Output                         : {output_path}\n",
        flush=True,
    )
    return len(covered_set), len(new_rules)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expand Maljan YARA rule set from MITRE ATT&CK data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--sentences",
        type=Path,
        default=DEFAULT_SENTENCES,
        help="Path to attck_labeled_sentences.jsonl.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to yara_ttp_rules.yaml (read + write).",
    )
    parser.add_argument(
        "--attck-cache",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help="Directory containing cached enterprise-attack.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show how many rules would be added without writing.",
    )
    args = parser.parse_args()

    _, new_count = expand(
        sentences_path=args.sentences,
        output_path=args.output,
        attck_cache_dir=args.attck_cache,
        dry_run=args.dry_run,
    )

    if new_count == 0 and not args.dry_run:
        print(
            "[INFO] No new rules added — all techniques already covered or no patterns found.",
            flush=True,
        )


if __name__ == "__main__":
    main()
