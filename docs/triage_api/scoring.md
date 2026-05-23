# Triage - Scoring

Source: https://tria.ge/docs/scoring/
Mirrored: 2026-05-23

---

# Score meaning

Triage™ uses 1 - 10 scoring to reflect whether an analysis is malicious or not. The following is an explanation of what each score means and what can cause this score.

**Note**: it is important to look at the actual signatures that were triggered. The score is determined by these.

10

#### Known bad

**Examples:**

- A malware family was detected.

8-9

#### Likely malicious

One or more known damaging malware attack patterns were detected.

**Examples:**

- The deleting of shadow copies on Windows.

5-7

#### Shows suspicious behavior

One or more suspicious actions were detected. The detected actions can be malicious, but also have (common) benign uses.

**Examples:**

- Changing file permissions.
- Anti-VM behavior/trying to detect a VM.

2-4

#### Likely benign

One or more interesting behaviors were detected. The detected actions are interesting enough to be notified about, but are not directly malicious.

1

#### No (potentially) malicious behavior was detected.

N/A

#### Not available

The report is incomplete, or something went wrong.
