### Security

- **Dependency security updates carried onto `dev`.** brotli 1.2.1 and brotlicffi 1.2.1.0 fix an out-of-bounds write (CVE-2026-111497). virtualenv 21.14.13 fixes GHSA-cx6f-vjhg-g3cc, and with it python-discovery moves to 1.6.4. filelock moves to 4.2.1 and opentelemetry-api to 1.45.1. Each version is the one Dependabot's security pull request against `main` chose; `main` gets them at the next promotion. The Qdrant server pin moves to v1.18.3 in both the compose file and the CI service, so the test that holds the two pins equal passes. No run changes.
