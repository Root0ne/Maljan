# The System, Briefly

*Draft for the paper, §3. Deliberately short. The system is the **setting** in which the
measurements were taken, not the contribution; describing it at length would misrepresent what this
paper claims. Each component is stated with the measurement that decided its fate, so a reader can
see immediately which parts of the design survived contact with evidence.*

## 3.1 Shape

The pipeline maps evidence about a malware sample to MITRE ATT&CK technique IDs and emits a STIX
bundle. Three analysts run over heterogeneous evidence channels, a judge synthesises a verdict, and
a deterministic layer adjudicates between them.

| component | what it does | verdict |
|---|---|---|
| **static analyst** | ReAct loop over a headless reverse-engineering server (decompilation, imports, strings, call graph), 20 tools from a curated allowlist | operational; its salvage path was defective (§6) |
| **dynamic analyst** | ReAct loop over a CAPEv2 sandbox via MCP | operational; only Windows PE is analysable on our instance |
| **network analyst** | local PCAP analysis over the sandbox's capture | operational; depends on the sandbox indirectly |
| **judge** | synthesises a verdict and emits STIX | operational |
| **corroboration cascade** | weights layers, marks a technique corroborated when ≥2 layers contribute | **measured: never reaches the artefact** (0/32), and its technique set *replaces* the judge's (80/80) |
| **confidence gating** | caps confidence for unsupported obfuscation/injection claims | **measured: fires on 0.82% of techniques** |
| **case-prior RAG** | retrieves similar past cases to prime mapping | **measured: loses to a label-frequency prior in production** |
| **family-feature RAG** | retrieves family fingerprints | **measured: +0.003 F1 end to end** |
| **opcode-hash attribution** | normalised function hashes matched against a corpus | **measured: fires on 0 of 18 samples** |
| **sink-reachability hint** | ranks functions reachable to sensitive APIs, injected as prompt steering | **fires on 56.7%**; measured: **ΔtechniqueIDs +0.5, CI [−3.3, +4.5]** |

Two design choices are worth stating because they are *not* what failed, and a reader should not
infer that everything did.

**Tool exposure is not tool availability.** The reverse-engineering server advertises ~165 tools.
Exposing the full catalogue to a 3B-active-parameter MoE is infeasible — the model's tool selection
degrades before the context does — so the analyst is given a curated 20. This is a deliberate
narrowing with a measurement behind it, and it held.

**The pipeline degrades rather than fails when a service is absent.** With the sandbox unreachable
the dynamic path is skipped and the run completes on static evidence, which is pinned by a test. This
mattered during the study: the sandbox was reachable only from one network, and every static-only
result in this paper was produced by that degradation working as designed.

## 3.2 What runs it

One local model — Qwen3.6-35B-A3B at IQ3_K_R4, served by ik_llama.cpp on a single RTX 5060 host with
hybrid MoE offload — plus a headless reverse-engineering container, a Qdrant vector store, and a
CAPEv2 sandbox on a separate machine. Exact identifiers are in the reproducibility appendix, and
their limits are not incidental: the model server's memory grows with cumulative requests, generation
rate varies eightfold with context length on this architecture, and the sandbox retains its reports
for days. Each of those shaped an experiment reported here.

## 3.3 Why the system is not the contribution

Of the four claims the architecture was built around — multi-agent consensus over heterogeneous
channels, a multi-layer corroboration cascade, two-tier attribution, and falsification-before-
confidence — **three are now measured and negative or near-null**, and the fourth awaits sandbox
access. The components are not broken; several work well in isolation and were built for sound
reasons. They simply do not move the end-to-end result, and we could not have known that without
measuring each mechanism's firing rate before its effect.

That outcome is the reason this paper is about measurement. A system whose parts individually
justify themselves and collectively change nothing is an ordinary result, and reporting it requires
only honesty. What required method was discovering that several of those measurements had been
wrong in the first place.
