# Construct validity, and the objections the work does not close

Supplement to *What a language model adds to deterministic malware analysis, and what it takes to measure it*. Section 3.11 of the paper states both in summary; the working is here. Numbers shown as `…` in this file are derived in `tests/evaluation/paper_facts.py` and printed in the paper.

## The two checks the pitfall survey does not include

Two checks the survey does not include, both described in the paper, caught errors
one level below what the nine pitfalls address. A scored component deriving its output from the same
source as the labels is scoring a tautology, so this was tested component by component. Ground truth
is the MITRE `malware uses attack-pattern` relationship set, which comes from nothing this
project produces; the Sigma layer reads its identifier from each rule's own community-authored
ATT&CK tag, so it shares ATT&CK's vocabulary with the labels and not their source; and the sandbox
baseline, which would have mattered most, takes its identifiers from class attributes hand-written
in each signature module and consults no family attribution, which is what makes it a baseline
rather than a second view of the answer. The retrieval corpora do not overlap the evaluation
cohorts, checked by digest: of the … cases in the ATT&CK case corpus, none
shares a SHA-256 digest with the …-sample dynamic cohort or the …-sample
drift manifest. Two construct problems survive and both are ours: the case corpus is labelled with
the technique identifiers the pipeline itself previously attributed, which is why that number is
relabelled as self-consistency in the paper, and the catalogue defining valid
identifiers is the same file that bounds the label universe.

## The three objections

Three objections remain that the work does not close. The first is that the judge findings rest on
four calls, the intercept requiring a live judge call per observation. On the working path the
finding is deductive rather than statistical: the reconciliation step restores the cascade's set by
construction, and the …-arm mechanism check confirms the bundle equals
that set on every arm, with the judge contributing one identifier of its own on
… of … samples, an upper bound of
… on the per-sample rate. On the failing path it is an existence
claim, demonstrated on four calls against an uncapped control whose raw text provably contains no
identifiers. Neither is a rate, and what would settle it is the same intercept over the
…-sample cohort. The second is that the detector's own evidence is retrospective: it
found four defects on batches we already had reason to distrust, and the prospective test, reporting
output cardinality beside every batch for a year and counting how often it is first to a defect, we
have not run. The third is that seven defects in one's own code is a post-mortem rather than a
result; we claim the setting and the price rather than the category, every mechanism having been
counter-searched in an adjacent field's vocabulary (the paper).
