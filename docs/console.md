# The console

The web console in `apps/web`. It talks to the API in `apps/api` over
`/api/v1/...` and to one WebSocket per run at `/ws/analysis/{job_id}`.

## Navigation

```
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
the run reads the same from every tab. A stage names itself and its members by
the labels an operator gave them — the same names the conversation uses.

**Only the tabs the run filled.** A tab is offered when the report carries
what it draws: a ledger section routed to it, or its own typed block
(`apps/web/src/components/analysis/analysisTabs.ts`). SUMMARY, CONVERSATION
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
stream says who is working right now.

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

Every event carries a job-wide `seq`, which is the ordering key, the dedupe
identity and the resume cursor. A run recorded before the numbering existed
keeps the order its events arrived in. A run whose feed has passed the
retention window replays from the conversation stored on its report instead —
only then, so stored rows can never be laid over a feed that still has
something to say.

## Reputation

A run asks one service about the sample's hash: `get_file_report` on
VirusTotal's own MCP server when it is configured, `check_hash` on the
threat-intel sidecar when it is not. The answer is drawn on IDENTITY, beside
the hashes, under the name of the service that gave it — its engine counts, the
labels the industry gives the file, and when it was first and last seen.

It is read from that service's ledger entry and from nothing else, so a
service that is configured and was never asked, or asked and answered nothing,
draws no section at all.

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

## Style

No gradients, and no colour or background that eases from one value to
another: a hover state is a state, so it arrives when the pointer does. The
transitions that stay are the ones that move something — a rail widening, a
chevron turning. Icons are `lucide-react` at 16 or 18 px, drawn in
`currentColor` with nothing filled behind them. The rules are held by
`apps/web/src/lib/__tests__/styleRules.test.ts`, which reads the tree rather
than the built CSS.

## Evidence

The ledger is one surface. Every citation elsewhere — a report section, a
claim, a tool call in the conversation — is a chip that opens the row it cites
with the call's arguments, its result and its duration.
