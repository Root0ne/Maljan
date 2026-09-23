# The console

The web console in `apps/web`. It talks to the API in `apps/api` over
`/api/v1/...` and to one WebSocket per run at `/ws/analysis/{job_id}`.

## Navigation

```
/login, /register       Sign in, or ask for an account
/dashboard              Counts, verdict mix, the five latest runs and their verdicts,
                        the tools recent runs used, runtime banners
/samples                Upload a sample, browse samples, submit an analysis
/jobs                   Every analysis, filtered by status; cancel a running one
/analysis/{jobId}
  ├── SUMMARY           Severity, findings counts, time per stage, key findings, technical analysis, exports
  ├── CONVERSATION      The run as a group conversation, live and replayed
  ├── IDENTITY          Hashes, file metadata, signatures, reputation
  ├── STATIC            Binary structure, imports, strings, packers
  ├── DYNAMIC           Process tree, behaviour, sandbox findings
  ├── NETWORK           Domains, IPs, URLs, and their enrichment
  ├── PERSISTENCE       Autoruns, services, scheduled tasks
  ├── ATT&CK            The technique matrix for this sample
  ├── ATTRIBUTION       Family, campaign, and the evidence behind each
  ├── DETECTION         Rule matches, generated rules, the STIX bundle and its graph
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

Each row of that list copies its sample's SHA-256 and its job id in one press
each, the two values an operator pastes somewhere else. The buttons sit outside
the row's link, their names say which row's value they copy, and the
confirmation is read out from a live region rather than left to the button's
word changing under focus. The same control
(`apps/web/src/components/ui/CopyButton.tsx`) copies the IDENTITY hashes and
the DETECTION rule cards; its name stays the same under focus and holds the
word it shows, the "Copied" a sighted reader sees is not read a second time,
and each button is at least 24 px tall.

**The dashboard.** Each of the five latest runs carries its verdict as a chip,
in the verdict colours every surface shares (`apps/web/src/lib/verdict.ts`)
and in words; a run with no verdict yet — still running, failed, or a report
the page could not read — shows its status instead of an empty chip, and a run
that has a report but did not complete shows its status beside the chip. Under
them, "Tools used" lists the tools the caller's last 20 completed runs called,
most calls first, as flat bars with the count printed. It is read from each
run's own `run_summary.evidence.by_tool` by `GET /api/v1/dashboard/tools`, so
it counts what the ledger recorded rather than what the feed happened to
carry. Only runs whose report carries that per-tool record stand behind the
bars and the "N of M runs" each row speaks; a run written before the record
existed says nothing about which tools ran, so it is not counted as a run that
called none of them, and the heading says how many such runs it read. A long
tool name is cut on screen and whole on hover and to a screen reader, and the
section is absent while no run has called anything.

**Status colours.** A run's status — completed, running, pending, failed,
cancelled — is coloured by one map (`apps/web/src/lib/status.ts`), read by the
dashboard, the analyses list, the search palette and the analysis header, and
a stage's or a participant's running and done, and an analyst's or a
message's failed, take the same colours. The status word is always printed
beside it. `status.test.ts` fails, anywhere else, on a state word given a
status colour in a map and on a ternary that compares any value with a state
word and holds a status colour in either branch.

The analysis header carries the verdict, the sample, the job status and the
run's stages, and the stage strip is there and nowhere else, so the shape of
the run reads the same from every tab. The sample is the heading and is not
restated under it; the confidence is printed here, once, as a two-decimal
number, and a run whose judge never answered reads "not assessed" rather than
being scored zero.

**Time per stage.** SUMMARY lists each stage that took time with its duration
and a flat bar measured against the run's total elapsed, which is printed
beside them with the time the stages account for; the gap is queueing,
ingestion and the writing of the report. The rows are the ones the stage strip
draws, from the same run store and the same formatter
(`stageTiming` in `apps/web/src/components/analysis/stageTimeline.ts`), so the
Summary and the strip cannot print different durations for one stage. A stage
that declined has no row, and a run stored before stages were timed has no
card.

**When the verdict and the severity disagree.** A judge can call a sample
Malicious and rate it Informational in the same run, and the console used to
present the two as unrelated facts two cards apart — a reader had no way to
know which to believe. Neither is overruled here: both are the judge's, and
picking a winner would be the console inventing a finding. Instead the header
says so, in one line — "Judge: Malicious 0.95 · Severity: Informational" —
with the sentence that names the disagreement under it.

The rule is deliberately narrow (`apps/web/src/lib/verdictHeader.ts`). Two
shapes contradict: a malicious verdict over Informational, or over a severity
block the judge assessed no rating into; and a benign verdict over High or
Critical. Nothing else does. A malicious verdict at Low severity is what
adware, unwanted programs and riskware look like on a report that is not
contradicting itself, and telling that reader not to trust either number would
spend the trust this rule exists to protect. A Suspicious verdict sits between
the two by definition, a verdict the console does not recognise implies
nothing, and a run with no structured report yet has no severity to disagree
with. A stage names itself and its members by
the labels an operator gave them — the same names the conversation and the
per-agent results table use. One selector answers for all of them
(`apps/web/src/lib/rosterNames.ts`), reading the roster the job carries and
falling back to the published key where the roster names nobody.

**Only the tabs the run filled.** A tab is offered when the report carries
what it draws: a ledger section routed to it, or its own typed block
(`apps/web/src/components/analysis/analysisTabs.ts`). Where a tab's content
needs parsing before it is known to be drawable, the rule and the panel share
one reading — the rule for DETECTION is the rule-match reader itself
(`ruleMatches.ts`), and the rule for ATT&CK is the mapped techniques the
matrix is built from, never the corroboration it only decorates a card with. SUMMARY, CONVERSATION
and EVIDENCE are always offered — the first is where a run lands, the second
answers whatever state the job is in, and on the third "no call matches these
filters" is information rather than an apology. While a job is still running
those three are all there is, and the rest appear as the report fills them.
Inside a tab the same rule applies to every panel, so a run with no observed
traffic shows no empty Domains table.

**The report model's words, labelled as its words.** SUMMARY draws what the
report model wrote in the order the exported report prints it: the key
findings, each bullet with the ledger entries it cites (or *no evidence cited*),
then the summary paragraph; and a technical-analysis card with the execution
flow — each step carrying the model's own mark, *observed in sandbox* or
*assessed* — the configuration it recovered with how each value was obtained,
the commands the sample accepts and its C2 channels. Both cards say *Written by
the report model* beside their heading. A run whose report model wrote nothing
says why, in the words the report records, rather than showing a template: the
platform writes no prose of its own, and that line is labelled *Measured*, not
as the report model's. A step or a configuration item the validator kept a
finding on shows it beside the row (`report.flow_voice`,
`report.configuration_uncited`), as the exported report does, and a step marked
observed in a run with no sandbox observation says so. The console is a reading
surface, so the defanging rule applies to it: a C2 channel's endpoints are
written `hxxp://`, `[.]` and `[:]`; the machine surfaces keep them live. The
severity card's platform line reads *Platform (from the file format,
measured)*, since the builder reads it from the format and the judge did not
assess it. A report stored before key findings
existed shows its summary and the capability paragraphs it carried. IDENTITY
adds the header facts the format tool read — architecture, whether the image is
a DLL, the export directory's name and the version resource's internal name —
and STATIC lists the exports with their ordinal and address when the tool
reported them. ATTRIBUTION says who named the family: the judge, with the
entries it cited, or the sandbox's own classification when the judge named
none. None of it is drawn with a gradient.

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

## Severity

One ladder owns severity: Critical, High, Medium, Low, Informational, the
judge's five words, with one colour each (`apps/web/src/lib/severity.ts`).
The Summary's rating, the DYNAMIC signature badges and the header's
verdict-against-severity rule read it, and anything sorted by severity is
sorted by the ladder's rank, never by the label's alphabetical order — which
would put High before Informational before Low before Medium. A word that is
not a rung sorts last and is drawn in Informational's colour with its own word
beside it. The colour is never the only carrier: the rung's word is always
printed.

DETECTION's rule matches are the report sections the rule tools' ledger rows
build, each headed by the chips of the ledger entries it came from, as STATIC
drew them before: `yara_matches` and `sigma_matches`, whose Level column is
the level the Sigma rule's author declared. They are routed to DETECTION and to nowhere
else; STATIC says where they are and links there rather than drawing the same
table twice. A Sigma row shows its level labelled as the rule's level, sorted
and dotted by it on the same ladder (one dot per rung from Informational up);
a rule that declares none says "no level declared" and takes no part in the
sort. A run stored before those tools recorded its matches as the old
deterministic layers' claims instead, and only such a run is read from them:
its Sigma rows say "level not recorded", draw no dots, take no part in the
sort, and show the layer's confidence — set from the rule's maturity status —
as the number it is. Nothing reads a confidence as a severity.

A DYNAMIC signature's number is the sandbox's own, and its scale depends on
which sandbox produced it: a CAPEv2 signature declares 1 to 3 (low, medium,
high), and Hatching Triage writes its 1 to 10 signature score into the same
field (1 no malicious behaviour, 2–5 likely benign, 6–7 suspicious, 8–9 likely
malicious, 10 known bad). The console reads the provider the run recorded
(`sandbox.provider` in `run_summary.settings_snapshot`). On `cape2` and
`triage` a score inside the scale takes the rung it means and prints it in
words beside the number — "High, 8/10". On any other provider — an uploaded or
REST report can be on either scale — and for a number outside its scale, the
number is drawn in one neutral tone as it came, beside the word "unrated".

`severity.test.ts` fails, anywhere outside the ladder module, on a rung given a
status colour; on a rung compared by its spelling against a `severity`,
`rating`, `level` or `sev` value, either way round; on a `case` of a rung in a
switch; and on a severity sorted by `localeCompare` or by comparing two labels
with `<` or `>`.

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

**A server's tools.** Once a tool server has been tested, its Tools section is
a table: a search that narrows the rows by name, "Select all" and "Select
none" (which act on the rows a search left on screen, and say so), an
"enabled N of M" count that is announced politely once a search or a run of
ticks settles rather than at every keystroke, and — when the server offers a capability manifest —
each tool's standing on its host, with the manifest's reason, what the tool
still answers without the missing part and the remedy on the row of every tool
it marks unavailable. It edits the per-server tick list and nothing else. A
built-in's "every tool" becomes the explicit list on the first edit, as a
single tick always did, and a name on the list the manifest no longer offers
is kept.

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
another: a hover state is a state, so it arrives when the pointer does. That
holds for the charts and bars too: a bar is one flat fill, and an SVG
gradient, an arbitrary `transition-[…]` over a colour and an inline or
stylesheet `transition` over one are caught like the class names are.
Tailwind's bare `transition` class eases colours by default, and it is caught
as a whole token in two places: in any string inside a `className` or `class`
attribute, a ternary between the attribute's braces included; and in any
string that reads as a class list wherever it sits — a constant of any name, a
map of classes — meaning every token is lower-case and made of the characters
class names use, and at least one token holds `-` or `:`. A sentence, which
has capitals, punctuation or no such token, is not read as one. The
transitions that stay are the ones that move something — a rail widening, a
chevron turning. Icons are `lucide-react`, drawn in `currentColor` with
nothing filled behind them: 16 or 18 px everywhere except the conversation
components, whose icons sit inline with 11 px text and are sized to it. The
rules are held by
`apps/web/src/lib/__tests__/styleRules.test.ts`, which reads the tree rather
than the built CSS.

## The relationship graph

DETECTION's STIX section shows the exported bundle three ways: Graph, Table
and JSON. All three read the bundle `GET /api/v1/reports/{id}/stix` serves,
the one the Download button saves, and nothing is assembled beside it.

The graph draws the bundle and nothing else. A node is one of its objects
(malware, attack-pattern, indicator, tool, infrastructure, file, domain-name,
an address, a URL, a process and so on), an object no relationship names
included. An edge is one of its `relationship` objects, labelled with its
`relationship_type`, or a `sighting` drawn from what was sighted to each place
and observation it names. An edge prints a confidence only where the bundle
states one: `x_maljan_confidence` on its 0–1 scale, or the standard's
`confidence` as `n/100`. A word, a value off its scale or nothing prints
nothing, never a zero or a half. Colour says which STIX type a node is, from
the console's own tokens and flat, and the legend says the same in words;
nothing is coloured by severity and nothing is grouped. Where a node sits is
a deterministic layout, the same for the same bundle, and says nothing about
the object.

A report, note, opinion, grouping, identity or marking that no relationship
names is not drawn, and neither is a relationship whose end the bundle does
not hold; the table lists both under "In the bundle, not drawn" with the
reason, so the graph and the table account for every object. An object the
export declined is not in the bundle and so not in the graph; the run's
validation findings name it.

Selecting a node or an edge by pointer, or a node with Enter or Space, shows
its STIX JSON, its relationships, and the evidence-ledger ids it carries in
`x_maljan_evidence_refs` as links into EVIDENCE; the Relationships table lists
them too. Nodes take keyboard focus and edges do not: a selected node lists
each of its relationships as a button, which is how the keyboard reaches an
edge, and a bundle with hundreds of edges does not put hundreds of stops in
the tab order. The export writes that property from the run's record:
the sample's `uses` edge to a technique carries the entries that tie to it,
and an object the record ties to nothing says it carries none. A bundle stored
before the property existed has none anywhere. The table is in the page
under the graph for a screen reader, and is the view itself under Table. A
bundle of more than 300 objects opens on the table and says so, with the
graph one click away; 300 lays out in tens of milliseconds and edge labels
past 120 edges show only around the selected or focused node. Export SVG
saves the drawing with the page's colours written in, a legend of the types
above it and no selection or focus on it, and Export PNG saves the same at
twice its size. A second object under an id the bundle already used is listed
under "not drawn" with that reason.

## Comparing two runs

A finished analysis offers "Compare with another run" under its header. The
compare page first lists the other completed runs of the same sample, newest
first, and then any completed run by run id, file name or SHA-256; a whole
run id typed in can be compared even when it is not among the latest hundred.
Choosing one opens `/compare?a=<job>&b=<job>`, which reads
`GET /api/v1/reports/diff` and nothing else.

The header shows both runs — file name, run id, when it was analysed, SHA-256
— and says plainly whether they are the same file, different files, or not
known because a digest is not recorded. Two different samples are allowed:
a new build of a family is what the comparison is for. The page states what
each run's record says and never which run is right.

Sections follow in groups — Verdict, ATT&CK, Indicators, Findings, Detection,
STIX, Run — each with its counts in words, the key its rows are paired by
and any note about a record that holds nothing for it. A row's status is an
icon, a mark and a word together (Changed `~`, Added in B `+`, Removed in B
`−`, Only in A `A`, Only in B `B`, Unchanged `=`), so nothing depends on colour.
"Only in A" and "Only in B" are rows the record does not key stably, such as
a key finding reworded or a STIX report object, and are never paired by
guess. A changed row's badge names what changed ("Changed: level", "Changed:
who stated it") and the row lists every field, marking those equal in both
runs "(same in both)", so the value that did not change stays in view; the
evidence column links each run's cited ledger ids into that run's EVIDENCE
tab, and shows none where the record holds no id for the row. Ids a record
cites for a whole section, as the rule-match sections do, are listed under
the section heading as section evidence. Differences come first; "Show
unchanged rows" lists the rest, and a section longer than 200 rows offers
"Show all".

Every control is a link, a button or a checkbox, so the keyboard reaches
all of it, and the section list at the top jumps to each section. "Swap A and
B" reverses the comparison. Print hides the navigation and prints dark text
on white, a section at a time where it fits, with tables unclipped and run ids
in full. A section still capped at 200 rows prints "Showing 200 of N rows" and
says to choose Show all first; the rows past the cap are not drawn, in print
either, so a large bundle does not put every row in the page.

## Evidence

The ledger is one surface. Every citation elsewhere — a report section, a
claim, a tool call in the conversation — is a chip that opens the row it cites
with the call's arguments, its result and its duration.
