# OpenSSF Best Practices: passing-level answers

A copy-paste sheet for the passing form at <https://www.bestpractices.dev/>.
Each criterion has the answer that is true of the repository today, the
justification to paste, and the evidence URL. Where the answer is not *Met*,
it says what would make it so; nothing here claims a practice the repository
does not follow.

- Project name: Malspark
- Description: multi-agent malware analysis platform: LLM analyst agents drive
  static, dynamic and threat-intelligence tools and write an evidence-backed
  report.
- Project URL: <https://malspark.com>
- Repository URL: <https://github.com/Root0ne/Malspark>
- Licence: MIT

The evidence URLs point at `main`. Files added on `dev` (`RELEASING.md`,
`fuzz/`, `.clusterfuzzlite/`, the release and fuzzing workflows) resolve once
`dev` is promoted, so submit the form after that promotion.

## Basics

### `description_good` — Met
The README states what the platform does, what it analyses and how it is run.
Evidence: https://github.com/Root0ne/Malspark#readme

### `interact` — Met
The README and CONTRIBUTING.md say how to obtain the software, give feedback
(GitHub issues) and contribute (pull requests against `dev`).
Evidence: https://github.com/Root0ne/Malspark/blob/main/CONTRIBUTING.md

### `contribution` — Met
CONTRIBUTING.md describes the contribution process: branch from `dev`, focused
pull requests, local gates, tests and a changelog fragment.
Evidence: https://github.com/Root0ne/Malspark/blob/main/CONTRIBUTING.md

### `contribution_requirements` — Met
CONTRIBUTING.md states the coding and commit conventions and the checks a pull
request must pass; the pull request template lists them.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/pull_request_template.md

### `floss_license` — Met
The project is released under the MIT licence.
Evidence: https://github.com/Root0ne/Malspark/blob/main/LICENSE

### `floss_license_osi` — Met
MIT is an OSI-approved licence.
Evidence: https://github.com/Root0ne/Malspark/blob/main/LICENSE

### `license_location` — Met
The licence is in the standard location, `LICENSE` at the repository root.
Evidence: https://github.com/Root0ne/Malspark/blob/main/LICENSE

### `documentation_basics` — Met
The documentation (getting started, deployment, configuration, usage,
operations) is published at https://malspark.com/docs/ from the repository.
Evidence: https://github.com/Root0ne/Malspark/tree/main/apps/docs/content/docs

### `documentation_interface` — Met
The REST API, the WebSocket, the CLI and the configuration are documented; the
API page lists every router group and the OpenAPI schema is generated from the
code.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/docs/content/docs/api.mdx

### `sites_https` — Met
The repository (github.com), the documentation site (malspark.com) and the
image registry (ghcr.io) are served over HTTPS only.
Evidence: https://github.com/Root0ne/Malspark

### `discussion` — Met
GitHub issues and pull requests: searchable, addressable by URL, open to new
participants, and usable without proprietary client software.
Evidence: https://github.com/Root0ne/Malspark/issues

### `english` — Met
Documentation, issues and code review are in English.
Evidence: https://github.com/Root0ne/Malspark/blob/main/CONTRIBUTING.md

### `maintained` — Met
The project is actively maintained: changes merge to `dev` weekly and
Dependabot updates are handled continuously.
Evidence: https://github.com/Root0ne/Malspark/commits/dev

## Change control

### `repo_public` — Met
Public Git repository on GitHub.
Evidence: https://github.com/Root0ne/Malspark

### `repo_track` — Met
Git records every change, its author and its date.
Evidence: https://github.com/Root0ne/Malspark/commits/main

### `repo_interim` — Met
Interim work is public: every change lands on `dev` through a public pull
request before it is promoted to `main`.
Evidence: https://github.com/Root0ne/Malspark/pulls?q=is%3Apr

### `repo_distributed` — Met
Git, a distributed version control system.
Evidence: https://github.com/Root0ne/Malspark

### `version_unique` — Unmet until the first release
The version is declared once, in `pyproject.toml`, and a release is a `v*` tag
whose name the release workflow checks against it; no release has been tagged
yet. Met once the first tag is pushed (RELEASING.md).
Evidence: https://github.com/Root0ne/Malspark/blob/main/RELEASING.md

### `version_semver` (suggested) — Met once tagged
Releases are numbered `MAJOR.MINOR.PATCH` (`pyproject.toml` version, `v*`
tags).
Evidence: https://github.com/Root0ne/Malspark/blob/main/pyproject.toml

### `version_tags` (suggested) — Unmet until the first release
Each release is a `v*` Git tag; none exists yet.
Evidence: https://github.com/Root0ne/Malspark/tags

### `release_notes` — Unmet until the first release
CHANGELOG.md is a human-readable summary of changes, kept from changelog
fragments; it holds only an *Unreleased* section until the first version is
tagged. Each GitHub release carries the version's section (RELEASING.md).
Evidence: https://github.com/Root0ne/Malspark/blob/main/CHANGELOG.md

### `release_notes_vulns` — N/A
No CVE has been assigned to a vulnerability in the project itself. Fixed
dependency vulnerabilities are named with their CVE or GHSA identifier in
CHANGELOG.md.
Evidence: https://github.com/Root0ne/Malspark/blob/main/CHANGELOG.md

## Reporting

### `report_process` — Met
Bugs are reported through GitHub issues with a bug-report form.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/ISSUE_TEMPLATE/bug_report.yml

### `report_tracker` (suggested) — Met
GitHub issues are the tracker.
Evidence: https://github.com/Root0ne/Malspark/issues

### `report_responses` — Met (no reports filed)
No bug report has been filed by anyone outside the project in the last twelve
months; the maintainers respond to every issue. Confirm before submitting.
Evidence: https://github.com/Root0ne/Malspark/issues?q=is%3Aissue

### `enhancement_responses` — Met (no requests filed)
No enhancement request has been filed by anyone outside the project in the
last twelve months; a feature-request form is in place. Confirm before
submitting.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/ISSUE_TEMPLATE/feature_request.yml

### `report_archive` — Met
Issues and pull requests are a public, searchable archive.
Evidence: https://github.com/Root0ne/Malspark/issues?q=

### `vulnerability_report_process` — Met
SECURITY.md describes how to report a vulnerability and what to expect.
Evidence: https://github.com/Root0ne/Malspark/blob/main/SECURITY.md

### `vulnerability_report_private` — Met
Private vulnerability reporting is enabled on the repository; SECURITY.md
links its form and asks reporters not to open public issues.
Evidence: https://github.com/Root0ne/Malspark/security/advisories/new

### `vulnerability_report_response` — N/A
No vulnerability has been reported in the last six months. SECURITY.md commits
to an acknowledgement within 3 business days and an assessment within 10.
Evidence: https://github.com/Root0ne/Malspark/blob/main/SECURITY.md

## Quality

### `build` — Met
`uv sync` installs the locked environment, `make` runs the gates, and the
compose files build the images.
Evidence: https://github.com/Root0ne/Malspark/blob/main/Makefile

### `build_common_tools` (suggested) — Met
uv, make, npm and Docker.
Evidence: https://github.com/Root0ne/Malspark/blob/main/Makefile

### `build_floss_tools` — Met
Every build tool is free and open source (uv, hatchling, make, npm, Docker
Engine/Buildx).
Evidence: https://github.com/Root0ne/Malspark/blob/main/pyproject.toml

### `test` — Met
An automated suite: pytest for the Python packages, Vitest and Playwright for
the console; CONTRIBUTING.md says how to run it.
Evidence: https://github.com/Root0ne/Malspark/tree/main/tests

### `test_invocation` (suggested) — Met
`uv run pytest tests/` (or `make test`), and `npm run test:unit` and
`npm run test:e2e` in `apps/web`.
Evidence: https://github.com/Root0ne/Malspark/blob/main/CONTRIBUTING.md

### `test_most` (suggested) — Unknown
No coverage figure is measured. Answer *Met* only after measuring branch
coverage (for example `pytest --cov`); otherwise leave it unanswered.
Evidence: https://github.com/Root0ne/Malspark/tree/main/tests

### `test_continuous_integration` (suggested) — Met
Every pull request and push to `dev` and `main` runs the suite in GitHub
Actions; the jobs are required checks.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/ci.yml

### `test_policy` — Met
CONTRIBUTING.md requires tests for the behaviour a change adds or alters.
Evidence: https://github.com/Root0ne/Malspark/blob/main/CONTRIBUTING.md

### `tests_are_added` — Met
Recent changes add or update tests alongside the code (see the merged pull
requests).
Evidence: https://github.com/Root0ne/Malspark/pulls?q=is%3Apr+is%3Amerged

### `tests_documented_added` (suggested) — Met
CONTRIBUTING.md and the pull request template state the test requirement.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/pull_request_template.md

### `warnings` — Met
Ruff (lint and format), mypy, tsc and ESLint run on every change.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/ci.yml

### `warnings_fixed` — Met
Those jobs fail on any finding and are required checks, so warnings are fixed
before merge.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/ci.yml

### `warnings_strict` (suggested) — Met
mypy runs with `disallow_untyped_defs`, TypeScript with `strict: true`.
Evidence: https://github.com/Root0ne/Malspark/blob/main/pyproject.toml

## Security

### `know_secure_design` — owner's statement
This criterion is about the primary developer's knowledge and cannot be shown
by the repository. If true, describe the design principles the platform
applies (least privilege for every container and workflow, deny by default,
input treated as hostile, sandboxed execution), pointing at the security page.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/docs/content/docs/security.mdx

### `know_common_errors` — owner's statement
As above: the developer's own knowledge of common vulnerability classes and
their mitigations (injection, XSS, SSRF, deserialisation, path traversal),
which the code applies (raw HTML disabled in report rendering, defused XML,
RE2 for operator-supplied patterns, bounded archive reads).
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/docs/content/docs/security.mdx

### `crypto_published` — Met
Only published algorithms: Argon2 for passwords, HMAC-SHA256 JWTs, TLS from
the deployment's proxy.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/auth/password.py

### `crypto_call` — Met
Cryptography comes from libraries (argon2-cffi, PyJWT, cryptography); the
project implements none itself.
Evidence: https://github.com/Root0ne/Malspark/blob/main/pyproject.toml

### `crypto_floss` — Met
Those libraries are free and open source.
Evidence: https://github.com/Root0ne/Malspark/blob/main/uv.lock

### `crypto_keylength` — Met
The API refuses to start with a JWT secret shorter than 32 characters or a
known placeholder.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/bootstrap.py

### `crypto_working` — Met
No broken algorithm is used for security. MD5 and SHA-1 are computed only as
sample identifiers, the indicators analysts and threat-intelligence services
exchange, never to protect anything.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/api/v1/samples.py

### `crypto_weaknesses` (suggested) — Met
No algorithm or mode with known serious weaknesses is used for security.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/auth/password.py

### `crypto_pfs` (suggested) — N/A
The platform does not terminate TLS itself; every port binds to loopback by
default and an operator's reverse proxy provides TLS.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/docs/content/docs/security.mdx

### `crypto_password_storage` — Met
User passwords are stored as Argon2 hashes (argon2-cffi `PasswordHasher`).
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/auth/password.py

### `crypto_random` — Met
Keys, tokens and nonces come from Python's `secrets` module.
Evidence: https://github.com/Root0ne/Malspark/blob/main/apps/api/app/api/v1/audit.py

### `delivery_mitm` — Met
Source, releases and images are delivered over HTTPS (GitHub, ghcr.io);
release artefacts carry Sigstore signatures and SLSA provenance.
Evidence: https://github.com/Root0ne/Malspark/blob/main/RELEASING.md

### `delivery_unsigned` — Met
No hash is fetched over HTTP: every downloaded tool in the Dockerfiles is
checked against a SHA-256 held in the repository, base images are pinned by
digest and Actions by commit SHA.
Evidence: https://github.com/Root0ne/Malspark/blob/main/docker/Dockerfile.backend

### `vulnerabilities_fixed_60_days` — Unmet today
OpenSSF Scorecard reports open OSV advisories in the locked dependencies,
some of medium severity and older than 60 days. Answer *Met* only after the
dependency upgrades land and Scorecard's Vulnerabilities check reads 10, or
each remaining advisory is shown not to affect the project and recorded in an
`osv-scanner.toml` with the reason.
Evidence: https://scorecard.dev/viewer/?uri=github.com/Root0ne/Malspark

### `vulnerabilities_critical_fixed` (suggested) — answer with the above
Evidence: https://github.com/Root0ne/Malspark/security/dependabot

### `no_leaked_credentials` — Met
No valid credential is in the repository. GitHub secret scanning and push
protection are on, and credential-shaped test values are built at run time.
Evidence: https://github.com/Root0ne/Malspark/blob/main/tests/credential_shapes.py

## Analysis

### `static_analysis` — Met
CodeQL (Python, JavaScript/TypeScript, Actions; security-extended), Semgrep,
Ruff and mypy run on every pull request and push.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/codeql.yml

### `static_analysis_common_vulnerabilities` (suggested) — Met
CodeQL's security-extended suite and Semgrep's security-audit ruleset look
for common vulnerability classes.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/ci.yml

### `static_analysis_fixed` — Met
CodeQL and Semgrep are required checks; a finding is fixed, or dismissed with
a stated reason, before merge.
Evidence: https://github.com/Root0ne/Malspark/security/code-scanning

### `static_analysis_often` (suggested) — Met
On every commit to a pull request, `dev` and `main`, and weekly.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/codeql.yml

### `dynamic_analysis` (suggested) — Met
Atheris fuzz harnesses for the readers of untrusted input run under
ClusterFuzzLite on pull requests and nightly; the end-to-end suite drives the
running console.
Evidence: https://github.com/Root0ne/Malspark/blob/main/.github/workflows/cflite.yml

### `dynamic_analysis_unsafe` (suggested) — N/A
The project is written in Python and TypeScript, memory-safe languages.
Evidence: https://github.com/Root0ne/Malspark

### `dynamic_analysis_enable_assertions` (suggested) — Met
The fuzz harnesses and the test suite run with Python assertions enabled, and
each harness fails on any exception outside its reader's stated contract.
Evidence: https://github.com/Root0ne/Malspark/tree/main/fuzz

### `dynamic_analysis_fixed` — N/A
Fuzzing has not yet reported a medium or higher severity vulnerability; one it
reports is handled as any vulnerability (SECURITY.md).
Evidence: https://github.com/Root0ne/Malspark/blob/main/SECURITY.md
