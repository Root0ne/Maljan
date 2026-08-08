"""Does the STIX integrity pass earn its place, judged by someone else's validator?

`enforce_bundle_integrity` drops empty-pattern indicators, deduplicates attack-patterns
by technique id while rewriting relationship refs to the survivor, sweeps relationships
whose endpoints no longer resolve, and trims dangling ``object_refs``. That is a design
description. §1.6 has never reported how often it fires or what it recovers, and the
2026-08-08 review found the gap is narrower than assumed: eLLM-CTI already contributes a
*STIX accuracy* metric for valid and complete bundles, and the **OASIS cti-stix-validator
has existed all along**. So "we repair bundles" only becomes a claim if the repair is
measured — and measured with the standard instrument rather than with our own checks,
which is what our own §3.4 says to do.

Two arms.

**Real bundles.** Four bundles produced by actual pipeline runs, stored in the long-term
memory. Small, and the sample size is stated everywhere it matters, but they are
authentic LLM output including the case that motivated the cascade-reconciliation fix
(11 STIX objects against 39 techniques in the same report).

**Injected defects.** The pass exists for malformed input, and clean bundles cannot
exercise it. Each real bundle is mutated with the defect classes §1.6 names — an
empty-pattern indicator, a duplicated attack-pattern, a relationship pointing at a
non-existent object, a dangling ``object_refs`` entry — and the question is not merely
"does the pass remove them" (it does, by construction) but **what survives**: rejection
discards a whole bundle, repair keeps the objects that were never at fault. That
difference is the contribution, and it is countable.

Deterministic: no LLM. Needs the Qdrant container for the real arm; runs the injected
arm regardless.

Run:
    uv run python tests/evaluation/eval_stix_integrity.py \
        --out tests/evaluation/stix_integrity.json
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.agents.judge_postprocess import enforce_bundle_integrity

# ---------------------------------------------------------------------------
# Validation via the OASIS validator (the external instrument)
# ---------------------------------------------------------------------------


# A syntactically valid SHA-256 pattern: the validator parses patterns, so a
# placeholder like 'ab' fails on hash length rather than on anything we control.
_PROBE_PATTERN = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"

_REF_WARNING = "enforce-relationship-refs"


def assert_validator_usable() -> None:
    """Fail loudly if the validator cannot find its schemas.

    ``stix2-validator`` 3.3.1's PyPI wheel **ships without the OASIS JSON schemas** —
    they are a git submodule that is not packaged — and ``ValidationOptions(schema_dir=…)``
    is not consulted for the core/base schema lookup. The failure mode is silent and
    dangerous: *every* bundle, including a textbook-valid one, comes back invalid with
    "Cannot locate a schema for the object's type". Measuring our own bundles against
    that would have produced a confident, entirely wrong finding.

    So the harness proves the instrument works on a known-good bundle before it grades
    anything, and refuses to run otherwise. Setup:

        git clone --depth 1 https://github.com/oasis-open/cti-stix2-json-schemas \\
            data/external/stix-schemas
        ln -sfn "$PWD/data/external/stix-schemas/schemas" \\
            .venv/lib/python*/site-packages/stix2validator/schemas-2.1/schemas
    """
    canonical = {
        "type": "bundle",
        "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "name": "example",
                "is_family": False,
            }
        ],
    }
    probe = validate(canonical)
    if probe["n_errors"]:
        raise SystemExit(
            "OASIS validator is not usable in this environment — a known-good bundle "
            f"failed with: {probe['errors'][:1]}\n"
            "See assert_validator_usable() for the schema setup this needs."
        )


def validate(bundle: dict[str, Any]) -> dict[str, Any]:
    """Validate one bundle with ``enforce_refs`` on.

    Referential integrity is reported by this validator as a **warning**
    (``enforce-relationship-refs``), not an error, while an unparseable pattern is an
    error. Since the pass under test exists mostly to fix referential integrity,
    counting only errors would grade it on a test it cannot fail — so both are counted
    and ``clean`` means neither.
    """
    from stix2validator import ValidationOptions, validate_parsed_json

    opts = ValidationOptions(version="2.1", enforce_refs=True, silent=True)
    try:
        results = validate_parsed_json(bundle, opts)
    except Exception as exc:  # noqa: BLE001 - a validator crash is a result, not a stop
        return {
            "clean": False,
            "errors": [f"{type(exc).__name__}: {exc}"],
            "n_errors": 1,
            "warnings": [],
            "n_warnings": 0,
            "n_ref_warnings": 0,
        }

    errors: list[str] = []
    warnings: list[str] = []
    for r in results if isinstance(results, list) else [results]:
        errors.extend(str(e) for e in getattr(r, "errors", []) or [])
        warnings.extend(str(w) for w in getattr(r, "warnings", []) or [])
    ref_warnings = [w for w in warnings if _REF_WARNING in w]
    return {
        "clean": not errors and not ref_warnings,
        "errors": errors[:10],
        "n_errors": len(errors),
        "warnings": warnings[:5],
        "n_warnings": len(warnings),
        "n_ref_warnings": len(ref_warnings),
    }


def shape(bundle: dict[str, Any]) -> dict[str, int]:
    objs = bundle.get("objects") or []
    types: dict[str, int] = {}
    for o in objs:
        types[o.get("type", "?")] = types.get(o.get("type", "?"), 0) + 1
    ids = {o.get("id") for o in objs}
    dangling = sum(
        1
        for o in objs
        if o.get("type") == "relationship"
        and (o.get("source_ref") not in ids or o.get("target_ref") not in ids)
    )
    return {
        "objects": len(objs),
        "attack_patterns": types.get("attack-pattern", 0),
        "indicators": types.get("indicator", 0),
        "relationships": types.get("relationship", 0),
        "dangling_relationships": dangling,
    }


def apply_pass(bundle: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(bundle)
    out["objects"] = enforce_bundle_integrity(list(out.get("objects") or []))
    return out


# ---------------------------------------------------------------------------
# Defect injection — the classes §1.6 names, seeded from real bundles
# ---------------------------------------------------------------------------


def inject_defects(bundle: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Return a mutated copy plus the number of defective objects introduced.

    Each defect is one a real judge has produced: a pattern that came back empty, a
    technique emitted twice under different object ids, a relationship to an object
    that was dropped by an earlier filter, and a Report referencing something absent.
    """
    out = copy.deepcopy(bundle)
    objs: list[dict[str, Any]] = list(out.get("objects") or [])
    injected = 0

    objs.append(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--00000000-0000-4000-8000-00000000dead",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "pattern": "   ",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
        }
    )
    injected += 1

    ap = next((o for o in objs if o.get("type") == "attack-pattern"), None)
    if ap is not None:
        dup = copy.deepcopy(ap)
        dup["id"] = "attack-pattern--00000000-0000-4000-8000-00000000beef"
        objs.append(dup)
        injected += 1

    objs.append(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--00000000-0000-4000-8000-00000000cafe",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "malware--00000000-0000-4000-8000-0000000000ff",
            "target_ref": "attack-pattern--00000000-0000-4000-8000-0000000000aa",
        }
    )
    injected += 1

    report = next((o for o in objs if o.get("type") == "report"), None)
    if report is not None:
        report.setdefault("object_refs", []).append(
            "attack-pattern--00000000-0000-4000-8000-0000000000bb"
        )
        injected += 1

    out["objects"] = objs
    return out, injected


# ---------------------------------------------------------------------------


def load_real_bundles(qdrant_url: str, collection: str) -> list[dict[str, Any]]:
    """Bundles produced by real runs, from the long-term memory. Empty on any error —
    the injected arm still runs, and the report says how many were found."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"{qdrant_url}/collections/{collection}/points/scroll",
        data=json.dumps({"limit": 64, "with_payload": ["sample_id", "stix_bundle_json"]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - local service
            points = json.loads(resp.read())["result"]["points"]
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        print(f"WARN: long-term memory unreachable ({exc}); real-bundle arm skipped.")
        return []

    out = []
    for p in points:
        raw = (p.get("payload") or {}).get("stix_bundle_json")
        if not raw:
            continue
        try:
            bundle = json.loads(raw)
        except ValueError:
            continue
        if isinstance(bundle, dict) and bundle.get("objects"):
            bundle["_sample_id"] = (p.get("payload") or {}).get("sample_id", "?")
            out.append(bundle)
    return out


def _strip_private(bundle: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in bundle.items() if not k.startswith("_")}


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure the STIX integrity pass externally.")
    ap.add_argument("--qdrant-url", type=str, default="http://localhost:6333")
    ap.add_argument("--collection", type=str, default="maljan_cases_v2")
    ap.add_argument("--out", type=str, default="tests/evaluation/stix_integrity.json")
    args = ap.parse_args()

    assert_validator_usable()

    # Arm 0: what the *current* code emits. The stored bundles below predate the
    # 2026-08-08 spec_version fix, so grading only those would report a defect we have
    # since repaired. This arm builds a bundle straight from the production STIX models
    # and asks the validator about it — no LLM involved, and it is the arm that moves
    # when the emitter changes.
    from maljan.schemas.stix_models import (
        AttackPattern,
        Bundle,
        Indicator,
        Malware,
        Relationship,
    )

    _mal = Malware(name="probe")
    _ap = AttackPattern(name="Process Injection")
    emitted = json.loads(
        Bundle(
            objects=[
                _mal,
                _ap,
                Indicator(
                    pattern=_PROBE_PATTERN,
                    pattern_type="stix",
                ),
                Relationship(relationship_type="uses", source_ref=_mal.id, target_ref=_ap.id),
            ]
        ).model_dump_json()
    )
    v_emitted = validate(emitted)
    print(
        f"current emitter: clean={v_emitted['clean']} "
        f"errors={v_emitted['n_errors']} ref_warnings={v_emitted['n_ref_warnings']}",
        flush=True,
    )
    for _e in v_emitted["errors"][:3]:
        print(f"    ERR: {_e[:120]}", flush=True)

    bundles = load_real_bundles(args.qdrant_url, args.collection)
    print(f"real bundles from long-term memory: {len(bundles)}", flush=True)

    real_rows = []
    injected_rows = []

    for b in bundles:
        sid = b.get("_sample_id", "?")[:12]
        clean = _strip_private(b)

        off = shape(clean)
        v_off = validate(clean)
        on_bundle = apply_pass(clean)
        on = shape(on_bundle)
        v_on = validate(on_bundle)
        real_rows.append(
            {
                "sample": sid,
                "pass_off": {**off, "validator": v_off},
                "pass_on": {**on, "validator": v_on},
                "objects_removed": off["objects"] - on["objects"],
            }
        )
        print(
            f"  {sid}: off objects={off['objects']} clean={v_off['clean']} "
            f"| on objects={on['objects']} clean={v_on['clean']}",
            flush=True,
        )

        # Injected arm: repair versus rejection.
        broken, n_injected = inject_defects(clean)
        v_broken = validate(broken)
        repaired = apply_pass(broken)
        v_repaired = validate(repaired)
        s_broken, s_repaired = shape(broken), shape(repaired)
        injected_rows.append(
            {
                "sample": sid,
                "defects_injected": n_injected,
                "broken": {**s_broken, "validator": v_broken},
                "repaired": {**s_repaired, "validator": v_repaired},
                # The contribution, stated as a number: rejection would discard the whole
                # bundle, repair keeps the objects that were never at fault.
                "objects_rejection_would_discard": s_broken["objects"],
                "objects_repair_preserves": s_repaired["objects"],
            }
        )
        print(
            f"    injected {n_injected}: broken clean={v_broken['clean']} "
            f"({s_broken['objects']} obj) -> repaired clean={v_repaired['clean']} "
            f"({s_repaired['objects']} obj)",
            flush=True,
        )

    n = len(real_rows)
    result: dict[str, Any] = {
        "schema": "maljan-stix-integrity/v1",
        "instrument": "OASIS cti-stix-validator 3.3.1, STIX 2.1, enforce_refs=True",
        "note": (
            f"Real-bundle sample is small (n={n}) and every aggregate below should be read "
            "that way. They are authentic pipeline output, which is why they are used at "
            "all: the defect classes this pass exists for come from LLM generation and "
            "cannot be produced without it."
        ),
        "current_emitter": {
            "note": (
                "A bundle built directly from the production STIX models — the arm that "
                "moves when the emitter changes. The stored bundles below predate the "
                "2026-08-08 spec_version fix."
            ),
            "validator": v_emitted,
        },
        "real_bundles": {
            "n": n,
            "clean_without_pass": sum(1 for r in real_rows if r["pass_off"]["validator"]["clean"]),
            "clean_with_pass": sum(1 for r in real_rows if r["pass_on"]["validator"]["clean"]),
            "total_objects_removed": sum(r["objects_removed"] for r in real_rows),
            "per_bundle": real_rows,
        },
        "injected_defects": {
            "n": len(injected_rows),
            "clean_when_broken": sum(1 for r in injected_rows if r["broken"]["validator"]["clean"]),
            "clean_after_repair": sum(
                1 for r in injected_rows if r["repaired"]["validator"]["clean"]
            ),
            "objects_preserved_vs_rejection": sum(
                r["objects_repair_preserves"] for r in injected_rows
            ),
            "per_bundle": injected_rows,
        },
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print()
    print(json.dumps({k: v for k, v in result.items() if k != "real_bundles"}, indent=2)[:1500])
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
