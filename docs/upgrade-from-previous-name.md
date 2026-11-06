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
`maljan_function_hashes_v1`). With `--qdrant-url <url>` (and the API key read
from `QDRANT_API_KEY` in the env file, never printed), `--apply` creates the
new default names as aliases of them where the new names are free, so memory
reads what it held; without it the script prints the two requests. Or point
`core.memory.qdrant.collection` and `core.memory.qdrant.function_hash_collection`
at the old names in the console. Where neither was done, a store whose
default collection is absent and whose old twin holds data reads the twin and
says so in the log; it never creates an empty collection beside it. The
marker of the memory repair an earlier release finished is still found, so the
repair does not run again.

## MinIO

The stored samples, the spilled ledger parts and, with the object-store audit
anchor, the anchored audit heads (`audit-chain/head/`) are in the bucket
`maljan-samples`, under its object lock, retention, legal holds and versions.
Keep it: the compose file now passes `MINIO_BUCKET` to the API and the
workers (empty when unset, which names no bucket), and `--apply` sets
`MINIO_BUCKET=maljan-samples` in the env file when the copied MinIO data holds
that bucket.

If `MINIO_BUCKET` is not set, the default bucket is missing and
`maljan-samples` is there, the API uses `maljan-samples` and the log names
`MINIO_BUCKET`; it never creates an empty bucket beside it.

Do not let the API start on a new, empty bucket while an audit head is
anchored in the old one: the anchor would read empty beside the database's
head (`EMPTY_BESIDE_A_HEAD`), the next append would anchor afresh, and the
anchored record from before the upgrade would no longer be the one checked. A
copy into a new bucket also drops retention, legal holds and every version but
the latest, so the copy command the script prints refuses a bucket with an
object lock or any audit head.

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
- Job packages are written as `malspark-job-package/2` and signed under the key
  label `malspark-job-package-v1`; a package built and signed before the
  upgrade still verifies. An evidence bundle stored before still reads.
- The FLOSS binary is installed under `~/.local/share/malspark/tools`; run
  `scripts/install_floss.sh` again, or move the old directory there.

Some values keep the old name on purpose, because data already written is
bound to them: the domain tags of the evidence ledger, audit chain, stored
report seals and job package signatures, the ledger chain's key label, the
namespace MISP attribute uuids are derived in and the STIX producer identity's
id (so a MISP instance or a STIX consumer that holds earlier exports sees the
same attributes and the same producer), the prefix of the settings repair
markers in the database, the collection of the memory repair's markers, and
the capture directory and the staging base an earlier release left under the
system temp directory (both still swept on the staging TTL).

What an installed component still sends or declares under the old name is
read, and named in the log where it should move: a tool server's
`maljan/tool_facts` declaration, a plugin in a `maljan.*` entry-point group,
an environment variable still set as `MALJAN_*` (named at start, never its
value), and a stored server map's `MALJAN_*` environment names (renamed by the
migration in the clear map, and as they are read from an encrypted row). They are listed in
`src/malspark/core/previous_name.py`.
