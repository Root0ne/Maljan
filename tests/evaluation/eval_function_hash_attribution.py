"""B7: does the opcode-hash attribution tier ever fire, and on what?

C2 claims a two-tier attribution design. §3.12 measured the semantic tier and
found it works in isolation and is near-inert end to end. The opcode-hash tier
has no evaluation artifact at all, so this is its first measurement — and, per
the rule that keeps paying, it asks whether the mechanism *engages* before
asking what it is worth.

The corpus it queries turns out to hold **3 samples across 2 families**
(`dropper` 2,199 functions, `rat` 27), so the ceiling is already visible. This
harness measures what actually comes back on real cohort samples: how many of
each sample's functions clear the 8-instruction floor, how many find a match,
and what family the tier would assert.

Ghidra is restarted per sample — a read timeout leaves the JVM mid-analysis and
every later load is refused (§3.14), which is how a whole window of samples was
lost the first time this kind of sweep was run.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
import httpx

from maljan.analysis.function_hash_attribution import (
    aggregate_matches,
    build_attribution_hint,
    fetch_bulk_function_hashes,
)
from maljan.core.config import get_settings
from maljan.memory.function_hash_store import FunctionHashStore

CFG = get_settings()
G = CFG.mcp.ghidra
BASE = G.url.rstrip("/")
MIN_INSTR = CFG.preprocessing.function_hash_min_instructions
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("MALJAN_EVAL_OUT", ROOT / "logs")) / "b7_attribution.json"


def restart_ghidra() -> None:
    subprocess.run(["docker", "restart", "maljan-ghidra-mcp"], capture_output=True, timeout=180)
    hdr = {"Authorization": f"Bearer {G.auth_token}"} if G.auth_token else {}
    for _ in range(40):
        try:
            httpx.get(f"{BASE}/get_metadata", headers=hdr, timeout=5)
            return
        except Exception:
            time.sleep(3)


cohort = json.loads((ROOT / "tests/evaluation/dynamic_cohort_n100.json").read_text())
n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
samples = cohort["samples"][:n]

store = FunctionHashStore(url=CFG.memory.qdrant_url)
print(
    f"corpus points={store.count()}  min_instructions={MIN_INSTR}  samples={len(samples)}",
    flush=True,
)

state = json.loads(OUT.read_text()) if OUT.exists() else {"results": {}}
for i, s in enumerate(samples, 1):
    sha = s["sha256"]
    if sha in state["results"]:
        continue
    restart_ghidra()
    rec = {"year": s["year"], "family_label": s.get("signature")}
    t0 = time.time()
    try:
        funcs = fetch_bulk_function_hashes(
            base_url=BASE,
            auth_token=G.auth_token,
            file_path=f"/data/samples/{sha}.exe",
            min_instructions=MIN_INSTR,
            timeout=300.0,
        )
        rec["n_functions_kept"] = len(funcs)
        matches = store.match([h for _, h in funcs], exclude_sample_id=sha) if funcs else []
        rec["n_matches"] = len(matches)
        agg = aggregate_matches(matches)
        rec["families"] = [
            {"family": a.family, "n": a.match_count, "confidence": round(a.confidence, 4)}
            for a in agg
        ]
        rec["hint_chars"] = len(build_attribution_hint(agg))
        rec["fires"] = bool(agg)
    except Exception as e:  # noqa: BLE001 — a failed sample is data
        rec["error"] = f"{type(e).__name__}: {str(e)[:160]}"
    rec["seconds"] = round(time.time() - t0, 1)
    state["results"][sha] = rec
    OUT.write_text(json.dumps(state, indent=1))
    good = [v for v in state["results"].values() if "error" not in v]
    fired = [v for v in good if v.get("fires")]
    print(
        f"[{i}/{len(samples)}] {sha[:12]} funcs={rec.get('n_functions_kept', '-'):5} "
        f"matches={rec.get('n_matches', '-'):5} fires={rec.get('fires', 'ERR')} "
        f"{rec['seconds']:6.1f}s  fired={len(fired)}/{len(good)}",
        flush=True,
    )

good = [v for v in state["results"].values() if "error" not in v]
fired = [v for v in good if v.get("fires")]
print(f"\nRESULT analysed={len(good)} errors={len(state['results']) - len(good)}")
if good:
    print(f"  tier fires on {len(fired)}/{len(good)} = {len(fired) / len(good):.1%}")
    f = sorted(v["n_functions_kept"] for v in good)
    print(f"  functions kept per sample: min={f[0]} median={f[len(f) // 2]} max={f[-1]}")
    import collections

    fams = collections.Counter(d["family"] for v in fired for d in v["families"])
    print(f"  families asserted: {dict(fams)}")
