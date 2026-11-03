### Changed

- **A named revision is shown, of each peer, the claims the contested lines cite, not the peer's whole report (T-364).** When the mediation names who revises, each named analyst still gets its own report whole. For each peer that a blocking line names, it now gets only the claims that line cites by number, numbered and quoted from the peer's answer in force (the one the mediator read), as the mediator's summary wrote them. Lists and ranges of up to 20 claims are read whole, for example "claims 32–34", "17 to 19", "3, 4, and 5" and "claim #3 and claim 4". After the claims come the peer's disputes, and the items it wrote besides its claims, that name the analyst by key, label or a short form ("STATIC R2 claim 11"). The excerpt is headed `STATIC REPORT (excerpt):` and its first line says which claims it quotes and that the whole report is not shown, so every prompt builder carries that sentence, the plain text revision included. The peer's whole report is shown as before, with a sentence on the round's record and in the log saying why, in any of these cases:
  - a line names the peer with no claim number for it;
  - a number is too long or past the claims of its answer in force;
  - a range is wider than 20 claims;
  - a line cites a claim without naming its analyst;
  - a quoted claim shares no ledger id or address with the clause of its blocking line that cites it (from the reference to the next one, a ";" or the end of the sentence, never a mark's reason), which catches a mediator citation error;
  - the peer's answer in force is not held.

  Each round's record, and `run_summary.efficiency.inputs.peer_reports`, count the excerpts and the whole reports with their character sizes. A round that asks every analyst, the merge by claim number, the system turn and the order of the prompt's blocks are unchanged, and a whole report is headed and passed byte for byte as before.
