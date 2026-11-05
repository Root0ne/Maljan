### Fixed

- **A blocking line's "its claim N" is read for its analyst, so withdraw-by-rule can act on it (T-563).** haiku11's round-4 mediation set an analyst's "Claim 27" against "its claim 40" and wrote "claim 27" again; the platform read both numbers for no analyst, logged two "reads no analyst" warnings, and no claim could be withdrawn by rule on the line. The analyst field itself was read: the cause was the pronoun.
  - On a line whose `[analysts: ...]` field names one analyst, "its claim N" (or "its own claim N") is read for that analyst when no other participant is named before it, as the newer reading reads a reference: withdrawn by rule only where its clause shares a ledger id or an address with the claim.
  - A bare "claim N" the line already names for that analyst is that claim written again, not an unplaced reference.
  - The claim-reference readers run in linear time on long lines: each clause's end is looked up among the line's clause ends found once, and the spans already read are kept as a byte map. A 270 KB line took 14 s and now takes 0.3 s.
  - Every claim reading of the stored mediations of haiku7 to haiku11 is pinned. Against the earlier reading the one difference is haiku11's round-4 line 1, and no mediation asks other analysts than before.
