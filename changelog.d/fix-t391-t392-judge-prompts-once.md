### Fixed

- **The mediator, the verdict and the technique question read each analyst's answer in force, and read it once (T-392).** A revision round's report was the answer the revision wrote, whatever its validation turn did next. When the turn kept a retry, merged one by claim number, or settled what a kept retry left out or withdrew, the ISR held the claims in force while every later mediation, the verdict, the technique question and the peers' next revisions read the replaced answer. A stored run shows it: a first answer of 12 claims was the report while the ISR held a kept retry of 27 claims, with no text shared. When the turn left the answer as written, the prompts read it as written, as before. When the turn changed it, the prompts read:
  - the claims in force, rendered as a first answer's are and numbered as the mediator's ISR summaries number them, so a mediation's "claim N" names the claim the revision prompts relay;
  - each finding in force, with its words, techniques, evidence, confidence and category;
  - under "Written in this answer besides its claims:", what the revision wrote besides its claims (its disputes and rebuttals, what it accepted from peers, its other sections), never its replaced claims.

  The claims summary the platform put at the head of a report (recorded on the ISR as rendered) is rendered again from the ISR whenever a prompt is built, so a mark the platform set on a claim afterwards is shown; text the analyst wrote is never rendered again, whatever it opens with. A report whose answer in force a validation retry added claims to, after a revision that wrote none, is built the same way: the summary with every claim once, a line naming the added claims by number, then what the answer in force held besides its claims. The mediator reads each such analyst once: its ISR summary is no longer listed a second time. The run record keeps what was written. The reviser's transcript message carries the answer the revision wrote; when a retry is in force, the retry's own words come first, so they survive the message's length cut. A revision that wrote no claim keeps what it wrote, as before.

  The router's word-for-word test now compares the answer in force. A round whose kept retry rewrote a revision that was otherwise identical to the answer before it may now end as reworded where it ended as identical; no other stop reason changes.

  Live runs only; stored runs and their replays are unchanged.
- **The negotiation history is shown as text, each listed line once (T-391).** The mediator and the verdict read the history as the repr of its arguments. Each line a mediation listed stood in its finding and again in `contradictions`, `not_blocking` or `unread_marks`, and a ledger fact about a line quoted it once more: about 42 % of the history, 43.8 to 25.4 thousand characters in a stored run's verdict. Each entry is now:
  - the mediator's words;
  - every listed line once, with its standing said in words: `(standing: blocking)`, `(standing: not blocking)`, or `(standing: blocking, its mark was not read)`. The mediator's bracketed mark syntax is never used for this, so a line copied from the history is read by its own mark alone;
  - a ledger fact about a line under that line (the longest listed line the fact quotes);
  - the confidence, and the status, note and other facts where there are any.

  The mediator's words have run-state markers written out, as the reports do. Reading the lines is linear in the finding's length. Nothing the repr showed is left out.
- **The technique question shows a triage pack row once (T-391).** It showed the pack and, under EVIDENCE CITED, the stored outputs the same pack rows are rendered from: in a stored run, four rows of about 107 thousand characters, twice. A pack row whose entry's stored output is shown whole below now keeps its head and says the line's items are in that output:
  - a row of several lines keeps its first line;
  - a row of one line keeps the line its own renderer writes with no item listed (`triage_pack.pack_row_heads`), so every sentence the renderer adds, such as what the decoding schemes cannot see, stays;
  - the row stays whole when its entry is shortened, incomplete, a lower-cased search copy, a failed call or has no head to render, or when its output is shorter than the row;
  - the earlier run's block after the pack is untouched.

  Applied after the evidence is fitted, so it frees room and shortens nothing.
