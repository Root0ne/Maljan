# Benchmark

This page reports how the `default` team performs on a small set of real
samples, and how one of its reports compares, item by item, with a published
human analysis of the same sample. The benchmark ran four times between
2026-09-23 and 2026-09-24, with platform fixes between the runs. Every number
below comes from a single run on a laptop, with **nothing executed**: all runs
used the mock sandbox, so every finding is static.

In short:

- The verdict was right in every completed run: 4 of 4 samples on both models
  in iteration 1, and every sample in every later iteration.
- Against the human report, the best run (iteration 4) found 15 of 57 core
  items, partly found 25, missed 17 and got none wrong. Before decoded strings
  and VirusTotal labels reached the model, the same sample scored 3 / 7 / 46 / 1.
- What Maljan still misses is mostly control flow: the anti-analysis checks, the
  bot-ID derivation, the beacon interval and the command IDs. Strings alone
  cannot recover these, and a disassembler did not help in the one run that had
  one.
- On the benign control (signed PuTTY), the last run published no ATT&CK
  techniques and no detection drafts, but its report still carries four
  malicious-sounding sentences.

## Method

### Samples

| # | Sample | Kind | Human report |
| :-- | :-- | :-- | :-- |
| 1 | Latrodectus bot DLL, sha256 `6091f258…` | x86-64 Windows DLL, malware | Yes: the reference sample |
| 2 | Sample A (VirusTotal labels name Filisto) | Windows PE, malware | No |
| 3 | PuTTY, signed by its author | Windows PE, **benign**: the false-positive control | Not applicable |
| 4 | An ELF sample (VirusTotal labels name Snowlight) | Linux ELF, malware | No |

Iteration 1 ran all four samples on both models. Later iterations ran the
default model only, on the samples that the fixes in between were meant to
move: iteration 2 ran samples 1–3 and a second run of sample 1 with a
disassembler attached; iteration 3 ran samples 1 and 3; iteration 4 ran samples
1 and 3.

### Models

| | Default model | Small model |
| :-- | :-- | :-- |
| Model | Qwen3.6-35B-A3B (IQ3_K_R4 quantisation) | qwen3.8:27b |
| Server | ik_llama.cpp, through the OpenAI-compatible provider | Ollama, thinking disabled |
| Context | 32,768 tokens | 32,768 tokens |
| Placement | about 10.4 GB resident at load; the experts of blocks 10–39 on the CPU | 19 GB, 76% on the CPU and 24% on the GPU |
| Iterations | 1, 2, 3 and 4 | 1 only |

The small model was set as both the expert model and the judge model. Every
timeout and budget stayed as shipped for both models.

### Host, sandbox and profile

- **Host.** One laptop with an 8 GB GPU, shared with other desktop work. The
  benchmark stopped any run in which the host's available memory fell below
  6 GB; such a run was not counted.
- **Sandbox.** The local mock sandbox, which has no fixture for any of these
  samples. Nothing was executed, and the dynamic and network analysts were
  skipped in every run.
- **Team.** The `default` profile: the deterministic triage pack (including
  FLOSS decoded strings, capa and VirusTotal labels), the static analyst, the
  debate, the judge's verdict and the report. No setting was changed between
  runs of an iteration.
- **Model server.** From iteration 2 on, llama.cpp ran with a 1 GiB prompt cache
  instead of the 8 GiB default, to fit the host's memory. Iteration 4 also
  capped the per-slot context checkpoints at 8 instead of 32. Wall times are
  therefore not like for like across iterations.

### The human report and the scoring key

The reference sample is scored against
[Bitsight, *Latrodectus, are you coming back?* (João Batista, 2024-06-17)](https://www.bitsight.com/blog/latrodectus-are-you-coming-back),
which lists this sample's sha256 among the bot samples it analysed. Elastic's
and Proofpoint's public analyses of the family serve as corroboration. The
score files quote the human report only by section name.

From that report the key draws **57 core items** in ten groups:

| Group | Items | What it covers |
| :-- | --: | :-- |
| K1 identity | 5 | Family, class (loader), the IcedID link, x64 DLL with its architecture check, four exports at one address |
| K2 execution flow | 6 | API resolution by hash, abort on a failed check, the mutex, install then persist, register then command loop, the update file |
| K3 anti-analysis | 7 | Debugger check, process count, architecture, MAC check, PEB walk with CRC32 names, string encryption, self-deletion |
| K4 identifiers | 3 | Bot ID, group and its hash, the two encrypted C2s |
| K5 persistence | 3 | Install path, the `Updater` scheduled task at logon, the update file's purpose |
| K6 C2 | 7 | HTTPS POST to `/live/`, User-Agent, RC4 then base64, beacon interval, beacon format, beacon types, C2 instructions |
| K9 IOCs | 8 | The sample's hashes, `/live/`, the User-Agent, the mutex, the install folder and file name, the task, the update file |
| K7 commands | 11 | The C2 command set |
| K8 discovery | 1 | The discovery commands |
| K10 ATT&CK | 6 | The techniques the human analyses support |

K1–K6 and K9 form the **main** comparison (39 items); K7, K8 and K10 are
**depth** (18 items). Build-specific values (the C2 domains, the group name, the
RC4 key) are checked only for consistency with the human report's lists,
because that report describes the family across about 80 samples. Detection
drafts and later-stage items are not scored.

Each item gets one verdict, and each verdict quotes the report sentence it
rests on and names the human report section it is scored against:

- **Found**: the report body states the item, with its purpose right.
- **Partly**: split in two so a reader can discount the weaker kind.
    - **Partly (body)**: the report body states part of the item, or states it
      with the wrong purpose.
    - **Partly (appendix)**: the item's own value (an IOC, a format string, a
      command keyword) is printed only in the report's appendix of FLOSS
      strings, with no sentence about it.
- **Missed**: the report does not state the item. A behaviour that a string in
  the appendix only hints at counts as missed, not partly.
- **Wrong**: the report states the item in a way the human report contradicts.

Each score file also lists the **reverse direction**: claims in Maljan's report
that no human report supports, marked as contradicted, unsupported, or correct
but new.

## Results

### The default model across the iterations

Default model, default profile, one run per cell.

| | Iteration 1 | Iteration 2 | Iteration 3 | Iteration 4 |
| :-- | :-- | :-- | :-- | :-- |
| Tree | `dev` @ `9019db82` | `dev` @ `39b07c65` | `dev` @ `872ba234` | `dev` @ `1eb7312f` |
| Samples completed | Latrodectus, sample A, PuTTY, ELF | Latrodectus, sample A, PuTTY | PuTTY (Latrodectus stopped twice by the 6 GB memory rule) | Latrodectus, PuTTY |
| Verdicts right | 4 of 4 | 3 of 3 | 1 of 1 | 2 of 2 |
| Verdict stated in the judge's structured answer | 3 of 4 | 3 of 3 | 1 of 1 | 1 of 2 (Latrodectus: the answer overran its output cap twice and the verdict was read from text) |
| PuTTY (false-positive control): malicious sentences / techniques published / draft rules | 3 / 3 / 20 | 3 / 0 / 0 | 4 / 13 / 0 | 4 / **0** / 0 |
| PuTTY wall time | 10.5 min | 19.4 min ¹ | 15.4 min ¹ | 13.2 min ¹ |
| Model speed recorded | generation 34 tok/s (wall clock) | generation 26–40 tok/s (wall clock) | prompt 463, generation 56 tok/s (llama.cpp timings) | prompt 433–475, generation 55 tok/s (llama.cpp timings) |

¹ From iteration 2 on, llama.cpp ran with a 1 GiB prompt cache instead of the
8 GiB default, and iteration 4 also bounded the per-slot context checkpoints
(8 instead of 32). Times are therefore not like for like across iterations.

The verdicts per sample: Latrodectus Malware (family Latrodectus), sample A
Malware, PuTTY Benign (family PuTTY), the ELF Malware (family Snowlight). In
iteration 1 the default model's judge wrote non-JSON twice on sample A, so its
verdict carried no confidence, severity or family; in iteration 2 the judge was
asked again after its answer was cut and stated Malware, 0.95, High, Filisto.

### The small model (iteration 1 only)

qwen3.8:27b on Ollama, not re-run since:

- Verdicts right on 4 of 4 samples, each stated with a confidence, and the
  family named on all four (Filisto included).
- PuTTY: 1 malicious sentence, 0 techniques, 20 template detection drafts.
- Mean wall time 63.3 min over Latrodectus, sample A and PuTTY, against a mean
  of 545 s for the default model over its four runs.
- It ran 76% on the CPU with an 8 GB GPU. Every run on a Windows PE sample hit
  the static analyst's 1,500 s time cap, and on those three samples the analyst
  produced no claims; only the small ELF's analysis finished in time.

The small model scored almost as well as the default model against the human
report (10 found against 12) without a single analyst claim, because in
iteration 1 the triage pack did the work that mattered: FLOSS decoded the
Latrodectus strings, the VirusTotal labels named the family, and the judge and
report model of both models read the same pack.

### Against a human analyst

Latrodectus, 57 core items, found / partly / missed / wrong:

| Maljan report | Found | Partly | Missed | Wrong |
| :-- | --: | --: | --: | --: |
| Baseline, before decoded strings and VirusTotal labels reached the triage pack | 3 | 7 | 46 | 1 |
| Small model, iteration 1 | 10 | 28 | 19 | 0 |
| Default model, iteration 1 | 12 | 29 | 16 | 0 |
| Default model, iteration 2 | 12 | 25 | 20 | 0 |
| Default model, iteration 2, with the r2 disassembler | 11 | 24 | 21 | 1 |
| Default model, iteration 3 | not scored: the run was stopped by the memory rule on both attempts | | | |
| **Default model, iteration 4** | **15** | 25 | 17 | 0 |

The same scores by group:

| Group (items) | Baseline | Small, it. 1 | Default, it. 1 | Default, it. 2 | Default + r2, it. 2 | **Default, it. 4** |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| K1 identity (5) | 1/2/1/1 | 3/1/1/0 | 3/1/1/0 | 3/1/1/0 | 3/1/1/0 | 2/2/1/0 |
| K2 execution flow (6) | 0/1/5/0 | 0/4/2/0 | 0/4/2/0 | 0/4/2/0 | 0/3/2/1 | 0/4/2/0 |
| K3 anti-analysis (7) | 0/2/5/0 | 0/3/4/0 | 0/3/4/0 | 0/3/4/0 | 0/3/4/0 | 0/3/4/0 |
| K4 identifiers (3) | 0/1/2/0 | 1/2/0/0 | 1/2/0/0 | 1/2/0/0 | 1/2/0/0 | 1/2/0/0 |
| K5 persistence (3) | 0/0/3/0 | 0/3/0/0 | 0/3/0/0 | 0/3/0/0 | 0/3/0/0 | 1/2/0/0 |
| K6 C2 (7) | 0/1/6/0 | 2/3/2/0 | 2/3/2/0 | 3/2/2/0 | 2/3/2/0 | 3/2/2/0 |
| K9 IOCs (8) | 1/0/7/0 | 2/6/0/0 | 2/6/0/0 | 3/5/0/0 | 3/5/0/0 | 4/4/0/0 |
| **Main (39)** | 2/7/29/1 | 8/22/9/0 | 8/22/9/0 | 10/20/9/0 | 9/20/9/1 | **11/19/9/0** |
| K7 commands (11) | 0/0/11/0 | 0/6/5/0 | 0/6/5/0 | 0/4/7/0 | 0/3/8/0 | 0/6/5/0 |
| K8 discovery (1) | 0/0/1/0 | 1/0/0/0 | 1/0/0/0 | 1/0/0/0 | 1/0/0/0 | 1/0/0/0 |
| K10 ATT&CK (6) | 1/0/5/0 | 1/0/5/0 | 3/1/2/0 | 1/1/4/0 | 1/1/4/0 | 3/0/3/0 |
| **All core (57)** | **3/7/46/1** | **10/28/19/0** | **12/29/16/0** | **12/25/20/0** | **11/24/21/1** | **15/25/17/0** |

How much of "partly" sits only in the appendix, and the scores with those items
counted as missed:

| Run | Partly (body) | Partly (appendix) | Discounting appendix-only items |
| :-- | --: | --: | :-- |
| Small, iteration 1 | 20 | 8 | 10/20/27/0 |
| Default, iteration 1 | 20 | 9 | 12/20/25/0 |
| Default, iteration 2 | 20 | 5 | 12/20/25/0 |
| Default + r2, iteration 2 | 14 | 10 | 11/14/31/1 |
| Default, iteration 4 | 23 | 2 | 15/23/19/0 |

**Iteration 4 is the best-scored reference run**, with 15 found and 0 wrong
against 12 and 0 in iteration 2:

- A new host-identifier section put the mutex `runnung`, the `Custom_update`
  folder, the group `Littlehw`, the RC4 key `12345`, the C2 instruction keywords
  and the beacon format into the report body, so appendix-only items fell from
  5 to 2.
- The scheduled task was stated with its name (`Updater`) and its logon
  trigger, and T1053.005 and T1218.011 were published.
- The eight core IOC values are all stated in the body as values (iteration 2:
  5 of 8), 5 of 8 with a purpose.

The same run shows what is still weak:

- Most host identifiers were listed without their purpose. The mutex, for
  example, appears as "Unknown string, possibly part of a key or identifier",
  so those items moved from partly (appendix) to partly (body), not to found.
- The judge's structured answer overran its 8,192-token output cap twice. The
  verdict (Malware, Latrodectus) was then read from text, and the two decoded
  C2 domains were not published as indicators, as they had been in iteration 2.
  Only the sample's hashes (1 of the 8 core IOC values) were published.
- Five of the ten published techniques had no evidence behind them. One was
  T1003 OS Credential Dumping, attached to the debugger check's read of the PEB.
  In the reverse direction the report makes 10 contradicted or unsupported
  claims (iteration 2: 9).

Item by item, with the quoted sentence and the human report section for each:
[iteration 4](scores/latrodectus-iteration4-default.md),
[iteration 2](scores/latrodectus-iteration2-default.md),
[iteration 2 with r2](scores/latrodectus-iteration2-r2.md),
[iteration 1](scores/latrodectus-iteration1-default.md) and
[iteration 1, small model](scores/latrodectus-iteration1-small.md).

## What changed between iterations

**Before iteration 1.** The baseline report on the reference sample found 3
items. Three changes carried iteration 1 to 12 found and 16 missed:

1. FLOSS in the triage pack. It recovered 81 decoded strings: the C2 pair,
   `/live/`, the User-Agent, the beacon format, the mutex, the install folder
   and file name, the scheduled task, the RC4 key, the group, the command
   keywords and every discovery command. The IOC group went from 7 missed to 0.
2. VirusTotal labels in the triage pack, which put the family right.
3. Measured header facts in the report: compile time, an x86-64 DLL, the export
   name and the four exports sharing one address.

**Iteration 1 to iteration 2.** Fixes for what iteration 1 showed:

- The judge is asked once more when its answer is cut at the output cap
  (sample A then stated its verdict with a confidence and the family).
- Citations are checked against the evidence entry that holds the quoted
  value, not only for the id existing.
- Decoded C2 values are published in the report's IOC section and the IOC
  endpoint, not only in the STIX export.
- No template detection drafts are generated on a Benign verdict.
- An invalid STIX pattern is asked about instead of exported; no run since has
  a validator error.
- Report sections that had been dropped (the configuration section) came back,
  and a host-identifier section was added for decoded values.
- Wrong ATT&CK technique names in prose are asked about.
- A cancelled job stops its model calls.
- For a slow model: the closing summary after a time cap is sized to fit the
  context window, and an analyst with no claims is not run again from scratch.
  The small model was not re-run, so this is untested on it.

Result: the User-Agent and its IOC became found and the C2 domains were
published, but the new host-identifier section overran its 8,192-token budget
and was missing, and the analyst claimed different techniques. The total stayed
at 12 found.

**Iteration 2 to iteration 3.**

- The triage pack prints whole hashes instead of 16-character prefixes.
- A job is stored before it is queued, so a worker cannot pick up a job it
  cannot find.
- llama.cpp's own prompt and generation rates are recorded, and derived
  timeouts include reading the prompt.
- A report section cut at its output cap is asked once for a shorter answer.
- The capability check no longer flags negated sentences, and a sentence it
  flags that the retry keeps is marked where it stands.

Result: the reference run did not complete. Both attempts were stopped by the
memory rule in the report stage, with the model server grown to 13.4–14.2 GB,
so iteration 3 has no score. On PuTTY the analyst attached technique ids to
sentences such as "does not contain any obvious persistence … mechanisms", and
13 techniques were published on a benign file.

**Iteration 3 to iteration 4.**

- A claim whose technique id sits on a sentence that reads as absence is asked
  about. The claim is never edited, and a technique the analyst keeps is still
  published, with a note.
- A section answer with alike rows is asked once whether they are repeats.
- The STIX report for a Benign verdict is typed `threat-report` instead of
  `malware`.
- Host configuration: the model server keeps 8 context checkpoints per slot
  instead of 32, which kept its peak at 11.9–12.3 GB.

Result: both runs completed on the first attempt, the host-identifier section
reached a stored Latrodectus report (57 rows, all cited to the FLOSS entry that
holds them), and the score rose to 15 found. PuTTY published no techniques, but
the analyst made no absence claim with a technique id in this run, so the drop
comes from the analyst's different output, not from the new check.

## The disassembler finding

In iteration 2 the reference sample was run a second time with the r2
disassembler attached (`core.static.provider = "r2"`). This shows a model gap,
not a tool gap. The static analyst got 68 r2 tools and made nine decompiles
down the real start-up path, from the export through the start-up routine to
the API resolver (53 callers) and the string decoder (121 callers). But it spent
its 39 steps before reaching the anti-analysis checks, and its closing answer
was a repeated list of strings with no confidence, which the platform correctly
refused to read as claims.

It recovered none of the control-flow items: the anti-analysis checks, the
bot-ID derivation, the beacon interval and the command IDs. The report written
without analyst claims was worse than the default run's: four "does not"
sentences contradict the human report (no C2 commands, no persistence, no
payloads, and `runnung` as a registry key), one of them scored wrong. This is a
single run.

## The false-positive control

PuTTY is a signed, benign SSH client. Every run named it Benign with the family
PuTTY at 0.99, and no indicator was ever typed malicious. What varies is what
the report says around the verdict:

| Run | Malicious sentences | Techniques published | Detection drafts |
| :-- | --: | --: | --: |
| Default, iteration 1 | 3 | 3 | 20 |
| Small, iteration 1 | 1 | 0 | 20 |
| Default, iteration 2 | 3 | 0 | 0 |
| Default, iteration 3 | 4 | 13 | 0 |
| Default, iteration 4 | 4 | 0 | 0 |

- In iteration 1 both models produced the same 20 template Suricata drafts with
  the class `trojan-activity`, one of them titled as a C2 IP for `6.0.0.0`, and
  the default model's STIX export had 3 validator errors. Since iteration 2, a
  Benign verdict generates no drafts.
- Iteration 3's 13 techniques came from absence sentences carrying technique
  ids. They included T1014 Rootkit and T1555 Credentials from Password Stores.
- Iteration 4's four malicious sentences say that the sample performs
  keylogging and captures clipboard data, attempts to evade detection and
  debuggers, employs anti-debugging and evasion techniques, and may be a
  repacked binary. They rest on capa rule names. The report also says
  "verified clean by 75/75 AV engines" where 0 of 75 engines flag it.
- Iteration 4 printed four marks on sentences its capability check doubted, and
  none of them is right: two sit on sentences stating that persistence APIs are
  absent, and two on PuTTY's configuration path `/SSH/Auth/Credentials`. The
  four real over-claims are not marked.

## Limitations

- **One reference sample.** Its human report is family-level prose that names
  this hash among about 80 samples, so build-specific values are checked only
  for consistency.
- **The other samples have no human report**, and their false positives are
  judged against each run's own evidence.
- **One run per cell, no variance measured.** The static analyst's output
  changes shape from run to run (7 to 48 claims), and several movements between
  iterations are the model's rather than the tree's, such as T1053.005
  appearing and disappearing. A change of a few items is within what a rerun
  could produce.
- **The model server's settings changed** between iterations (prompt cache from
  iteration 2, checkpoint budget in iteration 4), so wall times are not like for
  like.
- **Nothing was executed** (mock sandbox). The dynamic and network analysts
  never ran.
- **The host is a laptop with an 8 GB GPU** shared with other work. Every
  counted run finished within about 1 GB of the 6 GB memory stop, and in
  iteration 3 two attempts crossed it.
- **The small model's numbers come from iteration 1 only**, and they reflect
  this host: a GPU that holds the whole model would change its time-cap
  outcome.

## Score files

| File | Run |
| :-- | :-- |
| [latrodectus-iteration4-default.md](scores/latrodectus-iteration4-default.md) | Default model, iteration 4 (`dev` @ `1eb7312f`) |
| [latrodectus-iteration2-default.md](scores/latrodectus-iteration2-default.md) | Default model, iteration 2 (`dev` @ `39b07c65`) |
| [latrodectus-iteration2-r2.md](scores/latrodectus-iteration2-r2.md) | Default model with the r2 disassembler, iteration 2 |
| [latrodectus-iteration1-default.md](scores/latrodectus-iteration1-default.md) | Default model, iteration 1 (`dev` @ `9019db82`) |
| [latrodectus-iteration1-small.md](scores/latrodectus-iteration1-small.md) | Small model, iteration 1 |
