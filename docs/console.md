# The console

The web console in `apps/web`. It talks to the API in `apps/api` over
`/api/v1/...` and to one WebSocket per run at `/ws/analysis/{job_id}`.

## Navigation

```
/dashboard              Counts, verdict mix, recent analyses, runtime banners
/samples                Upload a sample, browse samples, submit an analysis
/jobs                   Runs, filtered by status; cancel a running one
/reports                Finished reports
/analysis/{jobId}
  ├── SUMMARY           Verdict, severity, executive summary, exports
  ├── CONVERSATION      The run as a group conversation, live and replayed
  ├── IDENTITY          Hashes, file metadata, signatures
  ├── STATIC            PE structure, imports, strings, packers
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

The analysis header carries the verdict, the sample, the job status and the
run's stages. The stage strip is there and nowhere else, so the shape of the
run reads the same from every tab.

Older analysis URLs still resolve: `/ttps` goes to ATT&CK, `/rules`,
`/signatures` and `/stix` to DETECTION, and `/live`, `/process`, `/agents`,
`/pipeline` and `/timeline` to CONVERSATION.

## Conversation

One tab for a run that is happening and a run that happened. It draws the
participants, what each said, the tool calls they made, the corrections they
were shown, the questions the judge asked and the verdict that closed the run —
in the order the publisher numbered them.

**Participants.** Everyone the team declares, named by the label the operator
gave the agent rather than by its registry key, with an initial-avatar and a
colour that stays the same for one agent across runs. A specialist that no
stage names is shown with the agents that can task it. Selecting a participant
narrows the conversation to that participant.

**Kinds.** A message is drawn as what it is: speech as a bubble; a tool call as
one monospaced line with the tool, whether it succeeded, how long it took and a
chip that opens its row on the EVIDENCE tab; a validator correction and a cap
notice as centred notes; a judge's question and a delegated ask and answer as
bubbles with an arrow to the agent addressed; the verdict as a closing card.
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

## How the console follows a run

One socket per job, opened by the store on the first reader. The store reads
the recorded feed from `GET /api/v1/jobs/{id}/events` first, then attaches the
socket with `?since=<the last seq it holds>`, so a resume costs the events it
missed rather than a re-read of the window. The access token travels as the
`maljan.v1.<token>` subprotocol and never in the URL.

Every event carries a job-wide `seq`, which is the ordering key, the dedupe
identity and the resume cursor. A run recorded before the numbering existed
keeps the order its events arrived in, and a run whose feed has passed the
retention window replays from the conversation stored on its report.

## Evidence

The ledger is one surface. Every citation elsewhere — a report section, a
claim, a tool call in the conversation — is a chip that opens the row it cites
with the call's arguments, its result and its duration.
