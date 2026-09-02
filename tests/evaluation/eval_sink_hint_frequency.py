"""B6, first half: how often does the sink-reachability hint actually fire?

The module returns "" for a binary with no named sink APIs and the analyst then
proceeds normally, so if that is the common case an on/off ablation showing "no
effect" is indistinguishable from "the feature never ran". Frequency before
effect.

Two failure modes are designed against, both met on the first attempt:

* **A load that did not happen.** `load_program` answers HTTP 200 with an
  `error` body when it refuses, so `raise_for_status()` passes and everything
  downstream describes whichever program is still current. The first run of this
  harness recorded 66 consecutive samples with a call graph of *identical*
  length before that was noticed. A load without a program name is now a
  recorded error, never a data point.
* **A server that degrades.** The container began refusing every load after
  roughly thirty in one lifetime, JVM at 5.15 GB. It is therefore restarted
  every RESTART_EVERY samples rather than trusted to last.

Replicates the production pre-pass exactly, including `format=json&limit=20000`,
and counts how often the edge list reaches that limit — a truncation site P6
has to report and nothing else currently counts.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
import httpx

from maljan.analysis.ghidra_program import SWITCH_PARAM, SWITCH_PATH, program_name_from_load
from maljan.analysis.sink_reachability import build_priority_hint
from maljan.core.config import get_settings

_CFG = get_settings().mcp.ghidra
BASE = _CFG.url.rstrip("/")
_HEADERS = {"Authorization": f"Bearer {_CFG.auth_token}"} if _CFG.auth_token else {}
CONTAINER_DIR = "/data/samples"
MAX_FUNCS = 12
LIMIT = 20000
RESTART_EVERY = 1
CALL_TIMEOUT = 300.0
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("MALJAN_EVAL_OUT", ROOT / "logs")) / "b6_hint_rate.json"


def restart_ghidra() -> None:
    subprocess.run(["docker", "restart", "maljan-ghidra-mcp"], capture_output=True, timeout=180)
    for _ in range(60):
        try:
            httpx.get(f"{BASE}/get_metadata", headers=_HEADERS, timeout=5)
            print("  (ghidra restarted)", flush=True)
            return
        except Exception:
            time.sleep(3)
    print("  (ghidra did not come back within 180s)", flush=True)


cohort = json.loads((ROOT / "tests/evaluation/dynamic_cohort_n100.json").read_text())
n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
samples = cohort["samples"][:n]

state = json.loads(OUT.read_text()) if OUT.exists() else {"results": {}}
todo = [s for s in samples if s["sha256"] not in state["results"]]
print(f"n={len(samples)} done={len(state['results'])} todo={len(todo)}", flush=True)

t0 = time.time()
for i, s in enumerate(todo, 1):
    if (i - 1) % RESTART_EVERY == 0:
        restart_ghidra()
    sha = s["sha256"]
    path = f"{CONTAINER_DIR}/{sha}.exe"
    rec = {"year": s["year"], "size": s["size"]}
    t1 = time.time()
    try:
        with httpx.Client(timeout=CALL_TIMEOUT, headers=_HEADERS) as http:
            loaded = http.post(f"{BASE}/load_program", json={"file": path})
            loaded.raise_for_status()
            name = program_name_from_load(loaded.text)
            if not name:
                # Not a miss and not an empty hint — a sample we failed to look
                # at. Counting it as either would be inventing a measurement.
                raise RuntimeError(f"load refused: {' '.join(loaded.text.split())[:160]}")
            http.post(f"{BASE}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={})
            http.post(f"{BASE}/run_analysis", json={}).raise_for_status()
            r = http.get(f"{BASE}/get_full_call_graph", params={"format": "json", "limit": LIMIT})
            r.raise_for_status()
            graph = r.text
        hint = build_priority_hint(graph, max_funcs=MAX_FUNCS)
        rec.update(
            program=name,
            graph_chars=len(graph),
            graph_lines=graph.count("\n") + 1,
            hit_limit=graph.count("\n") + 1 >= LIMIT,
            hint_chars=len(hint),
            hint_nonempty=bool(hint),
            seconds=round(time.time() - t1, 1),
        )
    except Exception as e:  # noqa: BLE001 — a bad sample is data, not a stop
        rec.update(error=f"{type(e).__name__}: {str(e)[:200]}", seconds=round(time.time() - t1, 1))
    state["results"][sha] = rec
    OUT.write_text(json.dumps(state, indent=1))
    good = [v for v in state["results"].values() if not v.get("error")]
    ok = [v for v in good if v.get("hint_nonempty")]
    print(
        f"[{i}/{len(todo)}] {time.time() - t0:6.0f}s {sha[:12]} {rec.get('seconds'):6}s "
        f"hint={rec.get('hint_chars', '-')}  nonempty={len(ok)}/{len(good)} "
        f"err={len(state['results']) - len(good)}",
        flush=True,
    )

res = list(state["results"].values())
good = [r for r in res if not r.get("error")]
ok = [r for r in good if r["hint_nonempty"]]
print(f"\nRESULT analysed={len(good)} errors={len(res) - len(good)}")
if good:
    print(f"  hint non-empty: {len(ok)}/{len(good)} = {len(ok) / len(good):.1%}")
    print(f"  hit the {LIMIT}-edge limit: {sum(1 for r in good if r['hit_limit'])}/{len(good)}")
    graphs = {r["graph_chars"] for r in good}
    print(f"  distinct call-graph sizes: {len(graphs)} across {len(good)} samples")
    if ok:
        h = sorted(r["hint_chars"] for r in ok)
        print(f"  hint chars: min={h[0]} median={h[len(h) // 2]} max={h[-1]}")
