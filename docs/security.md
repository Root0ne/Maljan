# Security

Maljan handles live malware and the credentials of the services that analyse
it. This document describes how callers are authenticated, what a role may do,
how secrets are stored, what leaves the system in an export, and how to report
a vulnerability.

## Authentication

Two credentials are accepted, and an explicit one wins.

- **JWT bearer** — `POST /api/v1/auth/login` returns a short-lived access token
  and sets an HttpOnly refresh cookie (`maljan_refresh`, scoped to path
  `/api/v1/auth`, `SameSite=Lax`, `Secure` per `COOKIE_SECURE`). Send
  the access token as `Authorization: Bearer <token>`. `POST /auth/refresh`
  exchanges the cookie for a new pair, `POST /auth/logout` clears it. Refresh
  tokens are registered and consumed by `jti`, so a used one cannot be
  replayed. Access-token and refresh-token lifetimes are settings
  (`jwt_access_token_expire_minutes`, `jwt_refresh_token_expire_days`).
- **API key** — `X-API-Key`. Keys are minted at `POST /api/v1/audit/api-keys`,
  stored only as a SHA-256 hash, and can carry an expiry. Unknown, revoked and
  expired keys are all refused with the same generic 401, so the header cannot
  be used as an oracle; `last_used_at` is stamped on every accepted call, which
  is how a stale or leaked key is spotted. A key is shown once, at creation.

If a request carries an `X-API-Key` header it is judged on that key rather than
falling through to the bearer path.

**Token signing and rotation.** Tokens are signed with `JWT_SECRET_KEY` under
`JWT_ALGORITHM`, carry the `JWT_ISSUER`/`JWT_AUDIENCE` claims, and are stamped
with the `kid` in `JWT_KEY_ID`. To rotate, move the old secret to
`JWT_PREVIOUS_SECRET_KEY` with its `JWT_PREVIOUS_KEY_ID` and set the new one;
both are accepted until every token carrying the old `kid` has expired, after
which the previous pair can be removed.

**The development bypass.** `AUTH_DISABLED` skips every token check and
attributes each request to a seeded admin user. It is refused at startup
whenever `DEBUG` is false, it is forced off under pytest, and the frontend's
`NEXT_PUBLIC_AUTH_DISABLED` defaults to secure and is excluded from the Docker
build context. Never enable it outside a trusted local environment.

**WebSocket.** `/ws/analysis/{job_id}` authenticates the same access token and
refuses anything that is not one, closing with code 1008 rather than serving
events.

## Roles

Three roles: `admin`, `analyst` (the role a registration gets) and `readonly`.
Admin gates the configuration surface — the settings schema, values, patches,
resets, export and import — plus the audit log and API-key management. A
refusal names the caller's actual role so the console can hide admin-only
navigation rather than guess. There is no endpoint that grants admin; the first
one is promoted in the database.

## Secret storage

Secret settings are encrypted with Fernet under `SETTINGS_ENCRYPTION_KEY` and
stored as `enc:v1:<token>`; the process refuses to start without a valid key,
so there is no read-only fallback mode in which secrets sit in plaintext. A
credential nested inside a composite setting — an MCP server's `auth_token`, a
frontier arm's `api_key` — is stored in its own encrypted row rather than
inside the composite, and a startup repair moves any that an older version left
inline.

Stored secrets are never echoed back. Values are returned to the console as a
mask plus a short hint, run summaries mask them, and DSNs are redacted before
they are shown in the read-only Deployment group.

## What an export leaves out

A JSON export is a file on an operator's disk, so it carries no credential at
all: secret entries are skipped, masked values nested inside composites are
stripped at any depth, and every value in an MCP server's `env` map is masked
while its variable names remain. Each omission is listed in `secrets_omitted`,
so the operator can see what must be re-entered on the other side. A mask that
comes back on import means "keep the stored value", never "set the literal
mask" — the failure mode that the old `.env` export had.

## Transport and browser surface

- **CORS** — `CORS_ORIGINS`, `CORS_ALLOW_METHODS` and `CORS_ALLOW_HEADERS`
  default to a local console. Credentials are allowed, so the origin list must
  be exact in production. `X-API-Key` is in the default header allowlist
  because a browser preflight would otherwise strip it.
- **Cookie** — the refresh cookie is HttpOnly and path-scoped, and its `Secure`
  flag follows `COOKIE_SECURE`, which defaults to the inverse of `DEBUG`. A
  deployment that leaves it false outside debug is warned about at startup.
- **Security headers** — `SecurityHeadersMiddleware` installs CSP,
  `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and
  `Permissions-Policy` on every response; HSTS is added outside debug.
- **OpenAPI** — `/docs`, `/redoc` and `/openapi.json` are served only when
  `DEBUG` is true, so a production deployment publishes no schema.
- **Exposure** — every compose port binds to `BIND_ADDRESS`, `127.0.0.1` by
  default. Widening it puts a malware-handling stack on the network; do it only
  behind a proxy or firewall you control.

## Handling samples

Uploaded samples are live malware. They are stored in MinIO and mirrored into
`SAMPLES_DIR`, which the Ghidra container mounts read-only. Keep both
directories excluded from on-access scanners, off shared storage and off
developer machines that are not meant to hold samples. Detonation happens in
whichever sandbox is configured, never on the Maljan host.

## Reporting a vulnerability

Report security issues privately through GitHub's security advisories on
[the repository](https://github.com/Root0ne/Maljan), or to the repository owner
directly. Please do not open a public issue for an unfixed vulnerability, and
include the version or commit, the configuration that reproduces it, and the
impact you observed.
