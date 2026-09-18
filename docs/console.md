# The console

The web console in `apps/web`. It talks to the API in `apps/api` over
`/api/v1/...` and to one WebSocket per run at `/ws/analysis/{job_id}`.

## Navigation

```
/login, /register       Sign in, or ask for an account
/dashboard              Counts, verdict mix, the five latest runs, runtime banners
/samples                Upload a sample, browse samples, submit an analysis
/jobs                   Every analysis, filtered by status; cancel a running one
/analysis/{jobId}
  ├── SUMMARY           Severity, findings counts, executive summary, exports
  ├── CONVERSATION      The run as a group conversation, live and replayed
  ├── IDENTITY          Hashes, file metadata, signatures, reputation
  ├── STATIC            Binary structure, imports, strings, packers
  ├── DYNAMIC           Process tree, behaviour, sandbox findings
  ├── NETWORK           Domains, IPs, URLs, and their enrichment
  ├── PERSISTENCE       Autoruns, services, scheduled tasks
  ├── ATT&CK            The technique matrix for this sample
  ├── ATTRIBUTION       Family, campaign, and the evidence behind each
  ├── DETECTION         Rule matches, generated rules, the STIX bundle
  ├── DEFENSE           Recommended mitigations and hunts
  └── EVIDENCE          The ledger: every tool call the run made
/settings
  ├── Profile           Name, email, password
  ├── API keys          Issue and revoke keys
  ├── Setup guides      Admin: one wizard per thing a run needs
  └── Configuration     Admin: every setting, in five sections
/audit                  Admin: the audit trail
```

A report is a completed job, so there is one list of analyses rather than a
Jobs page and a Reports page that link to the same run. `/reports` lands on
that list with its status filter applied. The verdict of a finished run is a
column on its row; the search palette offers samples and analyses, each row a
link into the run rather than a second rendering of the list.

The analysis header carries the verdict, the sample, the job status and the
run's stages, and the stage strip is there and nowhere else, so the shape of
the run reads the same from every tab. The sample is the heading and is not
restated under it; the confidence is printed here, once, as a two-decimal
number, and a run whose judge never answered reads "not assessed" rather than
being scored zero.

**When the verdict and the severity disagree.** A judge can call a sample
Malicious and rate it Informational in the same run, and the console used to
present the two as unrelated facts two cards apart — a reader had no way to
know which to believe. Neither is overruled here: both are the judge's, and
picking a winner would be the console inventing a finding. Instead the header
says so, in one line — "Judge: Malicious 0.95 · Severity: Informational" —
with the sentence that names the disagreement under it. The band each verdict
implies is in `apps/web/src/lib/verdictHeader.ts`; a rating one band out is
not a disagreement. A stage names itself and its members by
the labels an operator gave them — the same names the conversation and the
per-agent results table use. One selector answers for all of them
(`apps/web/src/lib/rosterNames.ts`), reading the roster the job carries and
falling back to the published key where the roster names nobody.

**Only the tabs the run filled.** A tab is offered when the report carries
what it draws: a ledger section routed to it, or its own typed block
(`apps/web/src/components/analysis/analysisTabs.ts`). Where a tab's content
needs parsing before it is known to be drawable, the rule and the panel share
one reading — the rule for DETECTION is the rule-match parser itself
(`ruleMatches.ts`), and the rule for ATT&CK is the mapped techniques the
matrix is built from, never the corroboration it only decorates a card with. SUMMARY, CONVERSATION
and EVIDENCE are always offered — the first is where a run lands, the second
answers whatever state the job is in, and on the third "no call matches these
filters" is information rather than an apology. While a job is still running
those three are all there is, and the rest appear as the report fills them.
Inside a tab the same rule applies to every panel, so a run with no observed
traffic shows no empty Domains table.

Older analysis URLs still resolve, from the server: `/ttps` goes to ATT&CK,
`/rules`, `/signatures` and `/stix` to DETECTION, and `/live`, `/process`,
`/agents`, `/pipeline` and `/timeline` to CONVERSATION
(`apps/web/next.config.ts`).

## Conversation

One tab for a run that is happening and a run that happened. It draws the
participants, what each said, the tool calls they made, the corrections they
were shown, the questions the judge asked and the verdict that closed the run —
in the order the publisher numbered them.

**Participants.** Everyone the team declares, named by the label the operator
gave the agent rather than by its registry key, with an initial-avatar and a
colour that stays the same for one agent across runs. A specialist that no
stage names is shown with the agents that can task it. Each participant
carries what it has done — lines said, tool calls answered — and that count
appears here and nowhere else on the screen. Selecting a participant narrows
the conversation to that participant.

The run's own watchers are not participants. The mediator and the sycophancy
detector speak as the pipeline and name themselves in the line, so they are
drawn as notices to the room rather than as members of a team nobody composed
them into.

**Kinds.** A message is drawn as what it is: speech as a bubble; a tool call as
one monospaced line with the tool, whether it succeeded — in the icon's shape
and in words a screen reader can read — how long it took and a chip that opens
its row on the EVIDENCE tab; a validator correction and a cap notice as
centred notes; a judge's question and a delegated ask and answer as bubbles
with an arrow to the agent addressed; the verdict as a closing card.
Streamed text appends into the speaker's open bubble and is replaced by the
message that closes the turn.

**Grouping.** Stage, then round. A stage header says which stage it is, what
kind it is and whether it ran, finished or declined — a stage that declined
gives its reason there rather than leaving an unexplained gap.

**Following.** While a run is live the view follows the newest message as long
as the reader is at the bottom of the stream, and stops the moment they scroll
up; a "Jump to latest" button brings them back. The strip at the foot of the
stream says who is working right now. For an agent a stage names, that comes
from the `agent_progress` events the worker publishes; for a specialist a lead
reaches through `ask_<key>`, which no stage names and which therefore gets
none, it is inferred from the agent's own lines — so such a specialist is
`waiting` until it first speaks.

**Leaving and coming back.** The events, the roster and the socket live in a
run store keyed by job id (`apps/web/src/lib/runStore.ts`), not in the page.
Navigating away and back re-renders from what the store already holds, and the
socket outlives the page for a grace period rather than being redialled.

**A long run.** Frames are committed a batch at a time rather than one at a
time, the conversation is built by continuing the previous walk rather than
repeating it, and a line that has not changed keeps the object it was drawn
from — so a three-thousand-event replay draws the line that just arrived
instead of every line before it.

## How the console follows a run

One socket per job, opened by the store on the first reader. The store reads
the recorded feed from `GET /api/v1/jobs/{id}/events` first, then attaches the
socket with `?since=<the last seq it holds>`, so a resume costs the events it
missed rather than a re-read of the window. The access token travels as the
`maljan.v1.<token>` subprotocol and never in the URL.

What the conversation draws as prose — a message's text and its report, a
correction, a tool call's arguments and its result — is scrubbed by the
publisher before it reaches the socket, the stream or the stored transcript: a
credential shape is replaced, a URL keeps its scheme and host, a host path is
cut to its file name. The names it joins on are not: the agent, stage and tool
keys, the labels, the ids and the words it switches on are exempt by field
name, so what the console reads to place a line is always what the run called
it. The arguments and the output as they were are on the evidence ledger,
behind the report's ownership check.

Every event carries a job-wide `seq`, which is the ordering key, the dedupe
identity and the resume cursor. A run recorded before the numbering existed
keeps the order its events arrived in. A run whose feed has passed the
retention window replays from the conversation stored on its report instead —
only then, so stored rows can never be laid over a feed that still has
something to say. A stored row carries what its event carried, its kind and
its stage included, so a replay groups by stage and keeps the arrow between a
delegated ask and its answer. A run recorded before those were columns carries
neither, and the view derives what it can: such a replay is one unnamed stage
of plain lines.

## Reputation

A run asks one service about the sample's hash: `get_file_report` on
VirusTotal's own MCP server when it is configured, `check_hash` on the
threat-intel sidecar when it is not. The answer is drawn on IDENTITY, beside
the hashes, under the name of the service that gave it — its engine counts, the
labels the industry gives the file, and when it was first and last seen.

It is read from that service's ledger entry and from nothing else, so a
service that is configured and was never asked, or asked and answered nothing,
draws no section at all.

## A row that says nothing

Across the report tabs, a key/value row whose value is empty, `-` or an empty
list is not drawn, and a key/value section whose every row said nothing is not
drawn either — a heading over an empty table is the "No X yet" placeholder in
another shape. A table row is left alone, because its cells are positional.

A column says nothing in the same way. A column whose every row holds the same
value is stated once above the table and taken out of it, and one that is
empty on every row is dropped: the NETWORK indicator table spent two of its
four columns on one evidence id and forty dashes.

Machine names and machine values are read back before they are drawn
(`apps/web/src/lib/humanise.ts`). A section the console has no typed panel for
is drawn from its own declared shape, so its column headers are whatever key
the tool used, and a binary header table's values are the constants the file
format stores — `machine 34404`, `subsystem 2`, `timestamp 1566949827`. The
keys are read as sentences with an acronym list, and the header values as
their named constants, a human size, a UTC date and a hex entry point. A field
or a constant nothing knows is drawn as it arrived rather than guessed at.

IDENTITY applies it twice over. The `identity` section is the one that
overlaps the tab's own blocks, so it is split: its hashes go to the File
hashes block, which draws only the fingerprints a tool produced, and its
signing row is stated as a sentence rather than as `present=no`. A report
written before `signing_info` answered for one format carries three such rows,
of which all but one are the tool's untouched defaults; the tab keeps the one
for the format the run routed on and drops the rest.

## Settings

Anyone signed in has Profile and API keys. An administrator also has the setup
guides and, once a language model is connected, the configuration console —
until then the console's route only bounces back to the guides, so it is not
offered. A non-admin sees two entries rather than four, the two admin ones
having been drawn permanently disabled before.

Before a model is connected the hub lists the four guides a first analysis
needs — a model, a static analyser, a sandbox and a team — and opens the other
three once there is a model to test them against. Every setting is editable in
exactly one group of the console; a guide is the staged, step-by-step way into
the same keys, and each group header links to the guide that covers it.

## Width, contrast and the keyboard

The content column constrains its content rather than growing to it: `main` is
a flex item, so without `min-w-0` one wide `<pre>` takes it past the viewport
and the shell's `overflow:hidden` cuts the rest off with no scrollbar to reach
it. Every table and code block inside it has its own horizontal scroller, and
those only work once the column has a width to work against.

The base layout is the phone layout. A multi-column grid starts at one or two
columns and widens at `sm` / `md` / `lg`; `styleRules.test.ts` fails on an
unconditional `grid-cols-3` or wider, which is what the dashboard's four stat
columns at 375 px were.

Contrast is WCAG 2.1 AA on every text tier, on the surfaces that tier is used
on — which is not the same as on every surface, and the token comment in
`globals.css` says which. `--accent` is tuned for its own contrast against the
canvas and reaches only 3.10:1 behind white, so a filled button uses
`--accent-fill` (4.63:1, hover 6.47:1); `--accent` keeps borders, icons, the
focus ring and the /10 washes. A chip is painted on `--bg-elevated` (5.30:1 for
`--text-muted`) rather than on `--border` (4.12:1), which is the one surface
the text-tier analysis never covered.

`--text-tertiary` is the narrowest tier: 4.94:1 on `--bg-deep` and 4.51:1 on
`--bg-surface`, but 4.10:1 on `--bg-elevated` and `--bg-hover` and 3.97:1 on
`--bg-active`. It carries the least-important metadata on the two dark
surfaces — a message's time of day in the stream, a round divider, a
placeholder — and anything that can land on a lighter surface, including a
row that hovers onto one, uses `--text-secondary` instead. The disabled tier
is for disabled controls and for nothing else.

Every page begins with a "Skip to content" link and has an `h1`; every data
table's headers carry `scope="col"`; the file inputs are real controls hidden
with the visually-hidden pattern rather than `display:none`, behind a button
that says what it does in the console's own language.

## Style

No gradients, and no colour or background that eases from one value to
another: a hover state is a state, so it arrives when the pointer does. The
transitions that stay are the ones that move something — a rail widening, a
chevron turning. Icons are `lucide-react`, drawn in `currentColor` with
nothing filled behind them: 16 or 18 px everywhere except the conversation
components, whose icons sit inline with 11 px text and are sized to it. The
rules are held by
`apps/web/src/lib/__tests__/styleRules.test.ts`, which reads the tree rather
than the built CSS.

## Evidence

The ledger is one surface. Every citation elsewhere — a report section, a
claim, a tool call in the conversation — is a chip that opens the row it cites
with the call's arguments, its result and its duration.
