"""What is left of the deterministic extractors.

Each module here used to own one section of the report and fill it by
re-reading the sample or the sandbox report. The report is assembled from the
evidence ledger now, so the section-building halves are gone and what remains
is the classification and scoring the rest of the pipeline still asks for:
format and platform detection, the packer and language signatures, the import
classifier, the DGA scorer, the capability matrix and the family attribution.

Graceful degradation stays the rule: a missing input means a ``None`` or an
empty list, never an exception.
"""
