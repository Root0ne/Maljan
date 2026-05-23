# Triage - Analysis types

Source: https://tria.ge/docs/analysis/
Mirrored: 2026-05-23

---

# Analysis types

Triage™ stages of analysis for submissions: static and behavioral.

## Static analysis

Static analysis is performed without executing the sample. Instead, the sample is analyzed using a variety of processing stages selected based on file type and content which **may** include (but is not limited to):

-
Extracting an archive or container format (e.g. Archives, disk images)

-
Running YARA rules on the sample (and unpacked artifacts)

-
Running heuristic signatures on the sample (and unpacked artifacts)

-
Extracting a malware configuration from the sample (if present and supported)

### Malware Configuration

In some cases, static analysis can extract the malware configuration and display it in the report.

When static analysis extracts a malware configuration and displays a score, additional behavioral analysis is unnecessary as the sample has been positively identified.

Malware configurations are parsed directly from the file(s) submitted, and do not pull data from external sources. The exact output and included data fields can and will change between families and versions.

**Note**: The malware configuration extracted in static analysis may not be present in the behavioral report, if for example the C2 was offline at the time of behavioral analysis.

## Behavioral Analysis

Behavioral analysis is performed by executing the sample and observing its behavior in a controlled environment.

Many samples employ encryption, obfuscation, or "packing" which makes it infeasible to analyze them statically. This can apply to both legitimate software and malware, and in both cases the aim is to increase the cost of reverse engineering of the sample to understand its function.

Behavioral analysis collects data about the sample during execution, such as: registry events, file operations (modify/write), network requests, and memory dumps.

Metadata and artifacts from behavioral analysis are analyzed to produce the Tactics, Techniques & Procedures (TTPs) and indicators present in the Triage™ report.
