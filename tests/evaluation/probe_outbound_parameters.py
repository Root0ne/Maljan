"""Does the model server act on the parameters we send it? — measured, one by one.

Two parameters were found on 2026-08-15 to be accepted and ignored: `enable_thinking`
on one hosted provider (§3.32) and `max_completion_tokens` on the local server
(§3.35). Both were discovered by accident — a result that made no sense, traced
back. The set of parameters this pipeline sends is small and enumerable, so
waiting for the next nonsensical result is a choice, not a necessity.

This probe enumerates what the provider actually puts on the wire and tests each
one that can be tested, against the running server, by observing behaviour rather
than by reading a response field. A server that ignores a parameter does not say
so; the only evidence is that the output does not change.

The full outbound set, and where each stands:

| parameter | how it is checked |
|---|---|
| `temperature` | greedy at 0.0 (identical repeats), varied at 2.0 |
| `extra_body.max_tokens` / `n_predict` | completion stops at the requested count |
| `max_completion_tokens` alone | **known ignored** — kept as a regression witness |
| `chat_template_kwargs.enable_thinking` | reasoning share of output |
| `request_timeout`, `max_retries` | verified 2026-08-09 (§ bind_eval_llm); not re-probed here |
| `model`, `stream` | trivially observable in the response |

**`temperature` is the one that mattered enough to write this.** E6's M5 argument
turns on it: *"a language model at temperature 0, asked 32 times, does not usually
agree with itself perfectly"* — the sentence that identified a constant as a
missed tell. If this server does not honour temperature, that reasoning is wrong,
and it had never been measured.

Needs llama-server on :8080. Costs a handful of short generations.

Run:  .venv/bin/python tests/evaluation/probe_outbound_parameters.py
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
OUT_JSON = _HERE / "outbound_parameter_probe.json"
OUT_MD = _HERE / "outbound_parameter_probe.md"

URL = "http://127.0.0.1:8080/v1/chat/completions"
MODEL = "qwen3.6-35b-a3b"


def ask(**body: Any) -> dict[str, Any]:
    payload = {"model": MODEL, "stream": False, **body}
    req = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer probe"},
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read().decode())


def content_of(out: dict[str, Any]) -> str:
    return str(((out.get("choices") or [{}])[0].get("message") or {}).get("content") or "")


def tokens_of(out: dict[str, Any]) -> int | None:
    usage = out.get("usage") or {}
    value = usage.get("completion_tokens")
    return int(value) if isinstance(value, int) else None


# Open-ended and long enough that sampling has somewhere to go. The first version
# of this probe asked for "three colours, comma separated" — a prompt so
# constrained that a peaked distribution could return the same answer at any
# temperature, which would have made "the parameter is ignored" unfalsifiable and
# the conclusion worthless. A continuation task at 64 tokens is the control the
# question actually needs.
_OPEN_PROMPT = (
    "Continue this description in two or three sentences, in your own words: "
    "a program writes a copy of itself into another directory and then runs it."
)
_TEMP_TOKENS = 64


def probe_temperature() -> dict[str, Any]:
    """Greedy at 0.0, varied at 2.0 — and the high arm is the one that matters.

    Identical repeats at 0.0 alone prove nothing: a server that ignores the
    parameter and decodes greedily looks exactly the same as one that honours a
    request for greedy decoding. The high setting is the discriminator. It is also
    where a weak prompt would produce a false negative, which is why the prompt is
    open-ended and the budget is 64 tokens rather than three words.

    A ``seed`` sweep runs alongside it: with sampling on, three different seeds at
    temperature 2.0 should not agree. If they do, the server is not sampling at
    all, and that is a claim about the deployment rather than about our request.
    """

    def gen(**kw: Any) -> str:
        return content_of(
            ask(
                messages=[{"role": "user", "content": _OPEN_PROMPT}],
                max_tokens=_TEMP_TOKENS,
                n_predict=_TEMP_TOKENS,
                # Without this the whole budget goes into ``reasoning_content``
                # and every arm returns an empty string (§3.6). The first run of
                # this probe omitted it and concluded "identical at every
                # temperature" from three empty answers compared against three
                # empty answers — a verdict about nothing at all.
                chat_template_kwargs={"enable_thinking": False},
                **kw,
            )
        )

    cold = [gen(temperature=0.0) for _ in range(3)]
    hot = [gen(temperature=2.0) for _ in range(3)]
    seeded = [gen(temperature=2.0, top_p=0.95, seed=s) for s in (1, 2, 3)]

    # An empty answer is not agreement. Comparing blanks is how the first run of
    # this probe produced a confident wrong verdict, so emptiness is checked
    # before anything is concluded and reported as its own outcome.
    produced_text = all(s.strip() for s in cold + hot + seeded)
    deterministic = len(set(cold)) == 1
    varies = len(set(hot)) > 1
    seed_varies = len(set(seeded)) > 1

    if not produced_text:
        verdict = "inconclusive-empty-output"
    elif deterministic and (varies or seed_varies):
        verdict = "honoured"
    elif deterministic:
        # Greedy-whatever-you-ask is *safe* for our purposes but is not the same
        # claim, so it gets its own verdict rather than a pass.
        verdict = "greedy-regardless"
    else:
        verdict = "not-deterministic-at-0"

    return {
        "parameter": "temperature",
        "prompt_style": "open-ended continuation, 64-token budget, thinking disabled",
        "all_arms_produced_text": produced_text,
        "deterministic_at_0": deterministic,
        "varies_at_2": varies,
        "varies_across_seeds_at_2": seed_varies,
        "distinct_at_0": len(set(cold)),
        "distinct_at_2": len(set(hot)),
        "distinct_across_seeds": len(set(seeded)),
        "cold_sample": cold[0][:200],
        "hot_sample": hot[0][:200],
        "honoured": verdict == "honoured",
        "verdict": verdict,
    }


def probe_output_cap() -> list[dict[str, Any]]:
    """The regression witness for §3.35, both spellings.

    Run this against a **small context with context-shift off** and an ignored cap
    announces itself twice over: the generation runs past the requested count, and
    then it exhausts the context and the server returns 500 *"context shift is
    disabled"*. That error is the measurement, not a probe failure — a request that
    stops at 48 tokens cannot exhaust 4,096 — so it is recorded rather than raised.
    """
    prompt = "Count upward from one, one number per line, and do not stop."
    cap = 48
    variants = (
        ("max_completion_tokens only", {"max_completion_tokens": cap}),
        (
            "+ max_tokens/n_predict",
            {"max_completion_tokens": cap, "max_tokens": cap, "n_predict": cap},
        ),
    )
    out = []
    for label, kwargs in variants:
        try:
            resp = ask(messages=[{"role": "user", "content": prompt}], **kwargs)
        except urllib.error.HTTPError as exc:
            out.append(
                {
                    "parameter": label,
                    "requested": cap,
                    "produced": None,
                    "honoured": False,
                    "note": f"ran to context exhaustion (HTTP {exc.code}) — the cap did not bind",
                }
            )
            continue
        produced = tokens_of(resp)
        out.append(
            {
                "parameter": label,
                "requested": cap,
                "produced": produced,
                "honoured": bool(produced) and produced <= cap + 2,
            }
        )
    return out


def probe_thinking() -> dict[str, Any]:
    """The flag is only meaningful if the answer is not empty when it is off."""
    prompt = "In one short sentence: what does a dropper do?"
    off = ask(
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=128,
        n_predict=128,
        chat_template_kwargs={"enable_thinking": False},
    )
    text = content_of(off)
    return {
        "parameter": "chat_template_kwargs.enable_thinking=False",
        "answer_chars": len(text),
        "answer_is_empty": not text.strip(),
        # §3.6: with thinking on, this server strips the whole answer into
        # reasoning_content and returns nothing. A non-empty answer is the
        # observable consequence of the flag being read.
        "honoured": bool(text.strip()),
    }


def main() -> int:
    try:
        results: dict[str, Any] = {
            "schema": "outbound-parameter-probe/v1",
            "temperature": probe_temperature(),
            "output_cap": probe_output_cap(),
            "thinking": probe_thinking(),
        }
    except urllib.error.URLError as exc:
        print(f"server unreachable at {URL} — {exc}")
        return 1

    t = results["temperature"]
    lines = [
        "# Does the server act on what we send it?",
        "",
        "Each parameter checked by behaviour, not by a response field — a server that",
        "ignores a parameter does not report having done so.",
        "",
        "| parameter | observation | verdict |",
        "|---|---|---|",
        f"| `temperature` | {t['distinct_at_0']} distinct of 3 at 0.0, "
        f"{t['distinct_at_2']} of 3 at 2.0 | **{t['verdict']}** |",
    ]
    for row in results["output_cap"]:
        seen = row.get("note") or f"{row['produced']} tokens for a cap of {row['requested']}"
        lines.append(
            f"| `{row['parameter']}` | {seen} | "
            f"**{'honoured' if row['honoured'] else 'IGNORED'}** |"
        )
    th = results["thinking"]
    lines.append(
        f"| `enable_thinking=False` | {th['answer_chars']}-char answer |"
        f" **{'honoured' if th['honoured'] else 'IGNORED'}** |"
    )

    lines += [
        "",
        "`temperature` is the one this probe was written for. E6's M5 argument turns on it:",
        "*a language model at temperature 0, asked 32 times, does not usually agree with itself*",
        "— the sentence that identified a constant as a missed tell. It had never been measured.",
    ]
    if t["verdict"] == "inconclusive-empty-output":
        lines += [
            "",
            "**Inconclusive: at least one arm returned an empty answer**, so the comparison was",
            "between blanks and says nothing about the parameter. Recorded rather than reported as",
            "a result — this is the exact shape of failure the probe exists to catch.",
        ]
    elif t["verdict"] == "greedy-regardless":
        lines += [
            "",
            "**The server is greedy whatever we ask.** Repeats at 0.0 are identical and so are",
            "repeats at 2.0, so the parameter is not being read — the determinism our arguments",
            "rely on is a property of this deployment rather than of the value we set. The",
            "conclusion in M5 survives (the output *is* deterministic), but the reason given for",
            "it does not, and a deployment that started honouring the parameter would silently",
            "invalidate it.",
        ]
    elif t["verdict"] == "not-deterministic-at-0":
        lines += [
            "",
            "**Repeats at temperature 0 are not identical.** Every argument in this project that",
            "treats a temperature-0 call as reproducible needs re-reading, starting with M5.",
        ]

    report = "\n".join(lines)
    print("\n" + report)
    OUT_MD.write_text(report + "\n")
    OUT_JSON.write_text(json.dumps(results, indent=1) + "\n")
    print(f"\nwrote {OUT_MD.name} and {OUT_JSON.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
