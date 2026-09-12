# Security policy

Maljan analyses live malware and holds credentials for the services that help
it do so. Vulnerabilities in it matter, and we want to hear about them.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/Root0ne/Maljan/security/advisories/new>. Do not open a
public issue or pull request for an unfixed vulnerability.

Include the version or commit, the configuration that reproduces the problem
(LLM provider, sandbox provider, tool servers, deployment mode), the steps, and
the impact you observed. Redact tokens, API keys and sample paths.

## What to expect

- Acknowledgement within 3 business days.
- An assessment and a plan within 10 business days; we will keep you informed
  as the fix progresses.
- Credit in the advisory and the changelog when the fix ships, unless you ask
  otherwise.

## Supported versions

Fixes land on `dev` and are promoted to `main`. Only the current `main` is
supported; deployments should track it.

## Scope

In scope: the API, the worker, the web console, the MCP sidecars under
`services/`, the compose stack, and the CI configuration. Out of scope: the
third-party tools Maljan drives (Ghidra, CAPEv2, radare2, the model servers)
except where Maljan's integration with them creates the exposure, and issues
that require an already-compromised host.

How authentication, roles, secret storage and exports work is described in
[docs/security.md](docs/security.md).
