"""B6, second half: does the sink-reachability hint change what the analyst finds?

Worth running only because §3.15 established the mechanism fires on 56.7% of
samples. Where it does not fire the two arms are identical by construction, so
the ablation runs on the **non-empty-hint** subset and says so; averaging a
feature over samples it never touched is how §3.11's cap produced an
uninterpretable null.

Paired by design: the same sample, the same binary, the same model at temp 0,
with `use_sink_reachability` the only thing that differs. Ghidra is restarted
between runs — a read timeout poisons the server and every later load is refused
(§3.14) — which also guarantees neither arm inherits the other's analysis.

Checkpointed per (sample, arm). E1 was withdrawn because its per-sample outputs
were not retained; this writes every arm's claimed technique IDs to disk as it
goes.
"""

import json
import os
import subprocess
import sys
import time

# Both arms get the same wall-clock bound. Concluding arms finish in
# 200-323 s (measured), so 600 s never truncates a working analysis; it only
# stops a failing one from burning 25 minutes, and it does so symmetrically,
# so the comparison between arms is untouched.
os.environ.setdefault("REACT_AGENT_TIMEOUT_OVERRIDES__static", "600")
from pathlib import Path

sys.path.insert(0, "/home/user/Belgeler/kingston/Projects/Maljan")
sys.path.insert(0, "/home/user/Belgeler/kingston/Projects/Maljan/src")
import httpx

ROOT = Path("/home/user/Belgeler/kingston/Projects/Maljan")
OUT = Path(
    "/tmp/claude-1000/-home-user-Belgeler-kingston-Projects-Maljan/"
    "797a8dd1-30c6-476b-be2d-9fe83a5a9f1e/scratchpad/b6_ablation.json"
)
CONTAINER_DIR = "/data/samples"


def restart_ghidra(base: str, token: str) -> None:
    subprocess.run(["docker", "restart", "maljan-ghidra-mcp"], capture_output=True, timeout=180)
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    for _ in range(40):
        try:
            httpx.get(f"{base}/get_metadata", headers=hdr, timeout=5)
            return
        except Exception:
            time.sleep(3)


def restart_llama() -> None:
    """Reclaim llama-server's cumulative KV growth between arms.

    It grows with cumulative requests rather than plateauing — 10.4 GB fresh,
    16.1 GB after one arm — so a long paired run drifts into the host's
    memory floor. temp 0 makes the restart measurement-neutral.
    """
    # Tell the guard this drop is declared, not runaway (see night_guard.sh).
    grace = "/home/user/Belgeler/kingston/Projects/Maljan/logs/night-job.grace"
    open(grace, "w").close()
    subprocess.run(["pkill", "-f", "llama-server"], capture_output=True)
    time.sleep(5)
    subprocess.Popen(
        [
            "/home/user/maljan-llm-build/ik_llama.cpp/build-cuda/bin/llama-server",
            "-m",
            "/home/user/Belgeler/kingston/Projects/Maljan/models/Qwen3.6-35B-A3B-IQ3_K_R4.gguf",
            "-c",
            "65536",
            "-t",
            "16",
            "-fa",
            "on",
            "-ctk",
            "q8_0",
            "-ctv",
            "q8_0",
            "-ngl",
            "999",
            "-ot",
            r"blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU",
            "--context-shift",
            "on",
            "--jinja",
            "--alias",
            "qwen3.6-35b-a3b",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            r = httpx.get("http://localhost:8080/health", timeout=5)
            if r.json().get("status") == "ok":
                os.path.exists(grace) and os.remove(grace)
                return
        except Exception:
            pass
        time.sleep(5)


def run_arm(sha: str, hint_on: bool) -> dict:
    """One analyst pass. Returns claimed technique ids and cost."""
    from maljan.core.config import get_settings
    from maljan.core.container import ServiceContainer

    cfg = get_settings()
    cfg.preprocessing.use_sink_reachability = hint_on  # the only difference
    restart_ghidra(cfg.mcp.ghidra.url.rstrip("/"), cfg.mcp.ghidra.auth_token)

    # Built through the container rather than by hand: the analyst it produces
    # is wired to the same LLM, ledgers and MCP toolkit production uses, and an
    # ablation on a hand-rolled analyst would be measuring a different object.
    container = ServiceContainer(config=cfg)
    agent = container.get_agent("static")
    agent._analysis_file_path = f"{CONTAINER_DIR}/{sha}.exe"
    payload = json.dumps(
        {
            "sample_hash": sha,
            "analysis_file_path": f"{CONTAINER_DIR}/{sha}.exe",
            "static": {"note": "binary available to Ghidra at analysis_file_path"},
        }
    )
    t0 = time.time()
    isr = agent.analyze_isr(payload)
    dt = time.time() - t0
    tids = sorted(
        {c.technique_id for c in getattr(isr, "claims", []) if getattr(c, "technique_id", None)}
    )
    return {
        "seconds": round(dt, 1),
        "n_claims": len(getattr(isr, "claims", [])),
        "technique_ids": tids,
        "hint_on": hint_on,
    }


def main() -> int:
    freq = json.loads((ROOT / "tests/evaluation/sink_hint_frequency.json").read_text())
    with_hint = [
        sha for sha, v in freq["results"].items() if not v.get("error") and v.get("hint_nonempty")
    ]
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    targets = sorted(with_hint)[:n]

    state = json.loads(OUT.read_text()) if OUT.exists() else {}
    print(f"non-empty-hint samples available={len(with_hint)}  running={len(targets)}", flush=True)

    for i, sha in enumerate(targets, 1):
        for arm in ("on", "off"):
            key = f"{sha}:{arm}"
            if key in state:
                continue
            restart_llama()
            try:
                state[key] = run_arm(sha, hint_on=(arm == "on"))
            except Exception as e:  # noqa: BLE001 — a failed arm is data
                state[key] = {
                    "error": f"{type(e).__name__}: {str(e)[:200]}",
                    "hint_on": arm == "on",
                }
            OUT.write_text(json.dumps(state, indent=1))
            r = state[key]
            print(
                f"[{i}/{len(targets)}] {sha[:12]} hint={arm:3s} "
                f"{r.get('seconds', '-'):>7}s claims={r.get('n_claims', 'ERR')} "
                f"tids={len(r.get('technique_ids', []))}",
                flush=True,
            )
    print("\nDONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
