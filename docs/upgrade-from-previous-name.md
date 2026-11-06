# Upgrading a deployment from the previous name

Malspark was called Maljan before T-576. Every name an operator sees changed
with the rename; the data a deployment already holds did not move by itself.
This page carries an existing deployment across. Nothing here deletes the old
data: the old volumes stay until you remove them.

## Before you start

1. Let the analysis queue drain, then stop the old stack without removing its
   volumes: `docker compose -f docker/docker-compose.yml down` (no `-v`).
2. Pull the release and run the plan:

   ```bash
   scripts/upgrade/rename-volumes-and-env.sh --env-file docker/.env
   ```

   It lists every volume copy and every env key rename it would make, and
   prints the steps below with your names filled in. It prints key names only,
   never a value.

## Volumes

The compose file now names its project (`name: malspark`), so every volume is
`malspark_<volume>`. Before, compose named volumes after the project it was
started as: `docker_<volume>` by default (the directory of the first compose
file), or `maljan_<volume>` where `COMPOSE_PROJECT_NAME` or `-p` said so.

`--apply` copies each old volume into its new name with `docker run --rm`
(an `alpine` container; `--image` picks another), labelled as the compose
project's own. A target that already exists is never written into, and a
volume a running container still uses is skipped. If two old projects would
copy into the same target, the script refuses; name the one you use with
`--from-project`.

## Environment variables

Every variable that started with `MALJAN_` now starts with `MALSPARK_`
(`MALSPARK_UID`, `MALSPARK_GID`, `MALSPARK_STAGING_DIR`, ...). `--apply`
renames the keys in the env file in place and keeps a copy of the file as it
was beside it (`docker/.env.before-malspark`; it holds secrets, so remove it
once the new stack runs). A key whose new name is already set is left for you
to resolve. Variables set anywhere else (a shell profile, a systemd unit, a CI
secret) are yours to rename.

## Postgres

The copied `pgdata` still holds the database `maljan` owned by the role
`maljan`; the new defaults are `malspark`. Either keep them, by setting
`POSTGRES_DB=maljan` and `POSTGRES_USER=maljan` in `docker/.env`, or rename
them with only Postgres running; the script prints the exact commands. A
SCRAM password survives a role rename; an MD5 one is cleared and must be set
again. An audit anchor role (`maljan_anchor`) is renamed the same way, or kept
and named in `AUDIT_ANCHOR_DATABASE_URL` as it is.

## Qdrant

The memory collections keep their old names (`maljan_cases_v2`,
`maljan_function_hashes_v1`). Point `core.memory.qdrant.collection` and
`core.memory.qdrant.function_hash_collection` at them in the console, or keep
the new defaults and let memory start empty.

## MinIO

The stored samples are in the bucket `maljan-samples`; the API now uses
`malspark-samples` and creates it on start. The script prints a short command
that copies every object into the new bucket from inside the API container.

## What else changes for an operator

- Container names, images and networks: `malspark-*`.
- The command line entry point and the Python package: `malspark`.
- Plugins register under the `malspark.*` entry-point groups.
- Logger names and the WebSocket subprotocol use `malspark`; a log filter or
  a client of your own that names the old ones needs the new names.
- A Python environment that installed the previous distribution needs
  `uv sync` (or `pip install -e .`) once, so the `malspark` distribution and
  command are there.
- Signed-in sessions end once: the refresh cookie, the token issuer and
  audience changed. Sign in again.
- The console's stored preferences in the browser start fresh.
- Generated rule names start with `Malspark_AutoGen_`, downloads with
  `malspark-`, and the STIX custom properties with `x_malspark_`. A bundle
  stored before the upgrade is served under the new property names.
- Settings exports are written as `malspark-settings/3`; an export written
  before the upgrade still imports.
- Job packages are written as `malspark-job-package/2`; a package built before
  the upgrade still verifies.
- The FLOSS binary is installed under `~/.local/share/malspark/tools`; run
  `scripts/install_floss.sh` again, or move the old directory there.

Some values keep the old name on purpose, because data already written is
bound to them: the domain tags and key labels of the evidence ledger, audit
chain and job package signatures, and the capture directory an earlier
release left under the system temp directory. They are listed in
`src/malspark/core/previous_name.py`.
