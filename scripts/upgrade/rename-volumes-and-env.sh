#!/usr/bin/env bash
# Carry a deployment started under the product's previous name (maljan) across
# to Malspark: its docker volumes, its env file and, as printed steps, its
# Postgres database, Qdrant collections and MinIO bucket.
#
# By default it only prints the plan. --apply performs the volume copies and
# the env-file key renames; nothing old is deleted, so the previous stack can
# still be started from its own volumes until you remove them yourself.
#
# Volumes: compose named them under the project it was started as. Before the
# compose file named its project (name: malspark) that was the directory of the
# first compose file, "docker", unless COMPOSE_PROJECT_NAME or -p said
# otherwise (often "maljan"). Each <old project>_<volume> is copied into
# malspark_<volume> with `docker run --rm`; any other volume whose name carries
# the previous name is copied into the same name with the new one. A target
# that already exists is never written into.
#
# Env file: every key that starts with MALJAN_ becomes MALSPARK_ in place (a
# copy of the file is kept beside it first). Only key names are printed, never
# a value. A value that still names the old database, user or bucket is named
# by its key so you can decide; it is not changed. Where the copied MinIO data
# holds the old bucket, MINIO_BUCKET is set to it, so the API keeps reading its
# samples, spilled parts and audit heads (with their locks) where they are.
#
# Qdrant: with --qdrant-url, the new collection names are created as aliases of
# the old collections where the new names are free (the API key is read from
# the env file's QDRANT_API_KEY and never printed); without it, the requests
# are printed.
#
#   scripts/upgrade/rename-volumes-and-env.sh [--apply] [--env-file docker/.env]
#       [--from-project NAME]... [--image alpine:3.20] [--qdrant-url URL]
#
# Stop the old stack first (docker compose ... down, without -v).

set -euo pipefail
# Byte ranges in every pattern: in some locales [A-Za-z] leaves out a letter.
export LC_ALL=C

OLD=maljan
OLD_UPPER=MALJAN
NEW=malspark
NEW_UPPER=MALSPARK
VOLUMES=(pgdata redis_data qdrant_data minio_data ghidra_projects attck_cache)

apply=0
env_file=docker/.env
image=alpine:3.20
qdrant_url=
projects=()
old_bucket=0

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    --env-file) env_file="${2:?--env-file needs a path}"; shift ;;
    --from-project) projects+=("${2:?--from-project needs a name}"); shift ;;
    --image) image="${2:?--image needs an image}"; shift ;;
    --qdrant-url) qdrant_url="${2:?--qdrant-url needs a URL}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ ${#projects[@]} -gt 0 ] || projects=("$OLD" docker)

mode=plan
[ "$apply" -eq 1 ] && mode=apply
echo "== Malspark upgrade ($mode) =="

# ── Volumes ──────────────────────────────────────────────────────────

copy_volume() {
  local from="$1" to="$2" key="$3"
  if docker volume inspect "$to" >/dev/null 2>&1; then
    echo "  skip $from -> $to: $to already exists; nothing is written into it"
    return
  fi
  if [ -n "$(docker ps -q --filter "volume=$from")" ]; then
    echo "  skip $from -> $to: a running container uses $from; stop the old stack first"
    return
  fi
  if [ "$apply" -eq 0 ]; then
    echo "  copy $from -> $to"
    return
  fi
  local labels=()
  if [ -n "$key" ]; then
    labels=(--label "com.docker.compose.project=$NEW" --label "com.docker.compose.volume=$key")
  fi
  docker volume create ${labels[@]+"${labels[@]}"} "$to" >/dev/null
  docker run --rm -v "$from:/from:ro" -v "$to:/to" "$image" sh -c 'cd /from && cp -a . /to/'
  echo "  copied $from -> $to"
}

echo
echo "Volumes:"
if ! command -v docker >/dev/null 2>&1; then
  echo "  docker is not on PATH; skipping the volumes"
else
  existing="$(docker volume ls --format '{{.Name}}')"
  declare -A target_from=()
  for key in "${VOLUMES[@]}"; do
    for project in "${projects[@]}"; do
      from="${project}_${key}"
      grep -qxF -- "$from" <<<"$existing" || continue
      to="${NEW}_${key}"
      if [ -n "${target_from[$to]:-}" ]; then
        echo "  refuse: both ${target_from[$to]} and $from would become $to;" \
          "name the old project with --from-project" >&2
        exit 1
      fi
      target_from[$to]="$from"
      copy_volume "$from" "$to" "$key"
    done
  done
  # Any other volume that carries the previous name, outside the compose keys.
  while IFS= read -r from; do
    [ -n "$from" ] || continue
    covered=0
    for to in "${!target_from[@]}"; do
      [ "${target_from[$to]}" = "$from" ] && covered=1
    done
    [ "$covered" -eq 1 ] && continue
    to="${from//$OLD/$NEW}"
    to="${to//$OLD_UPPER/$NEW_UPPER}"
    [ "$to" = "$from" ] && continue
    copy_volume "$from" "$to" ""
  done < <(grep -i -- "$OLD" <<<"$existing" || true)
  [ ${#target_from[@]} -gt 0 ] || echo "  no volume of the projects ${projects[*]} found"
  echo "  The old volumes are kept. Once the new stack reads its data, remove them"
  echo "  with: docker volume rm <name>"
  # Does the MinIO data (the old volume, or the new one already there) hold
  # the old bucket?
  minio_volume="${target_from[${NEW}_minio_data]:-}"
  if [ -z "$minio_volume" ] && grep -qxF -- "${NEW}_minio_data" <<<"$existing"; then
    minio_volume="${NEW}_minio_data"
  fi
  if [ -n "$minio_volume" ] \
    && docker run --rm -v "$minio_volume:/data:ro" "$image" test -d "/data/$OLD-samples" 2>/dev/null; then
    old_bucket=1
    echo "  $minio_volume holds the bucket $OLD-samples: MINIO_BUCKET keeps it (see the env file)"
  fi
fi

# ── Env file ─────────────────────────────────────────────────────────

echo
echo "Env file ($env_file):"
if [ ! -f "$env_file" ]; then
  echo "  not found; pass --env-file <path> to rename its keys"
else
  # Keys only: the awk program prints key names, never what follows the "=".
  key_re="^[[:space:]]*(#[[:space:]]*)?(export[[:space:]]+)?${OLD_UPPER}_[A-Za-z0-9_]*="
  old_keys="$(grep -E -- "$key_re" "$env_file" | sed -E -e 's/=.*//' -e 's/^.*[[:space:]#]//' | sort -u || true)"
  if [ -z "$old_keys" ]; then
    echo "  no key starts with ${OLD_UPPER}_"
  else
    while IFS= read -r key; do
      new_key="${NEW_UPPER}_${key#"${OLD_UPPER}"_}"
      if grep -qE "^[[:space:]]*(export[[:space:]]+)?${new_key}=" "$env_file"; then
        echo "  keep $key: $new_key is already set; remove one of them yourself"
      else
        echo "  rename $key -> $new_key"
      fi
    done <<<"$old_keys"
    if [ "$apply" -eq 1 ]; then
      backup="${env_file}.before-${NEW}"
      # An earlier run's backup is never overwritten.
      [ -e "$backup" ] && backup="${backup}.$(date -u +%Y%m%dT%H%M%SZ)"
      cp -p -- "$env_file" "$backup"
      tmp="$(mktemp "${env_file}.XXXXXX")"
      chmod --reference="$env_file" "$tmp" 2>/dev/null || chmod 600 "$tmp"
      awk -v old="${OLD_UPPER}_" -v new="${NEW_UPPER}_" -v file="$env_file" '
        BEGIN {
          while ((getline line < file) > 0) {
            if (match(line, /^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=/)) {
              k = substr(line, 1, RLENGTH - 1); sub(/^[[:space:]]*(export[[:space:]]+)?/, "", k)
              set[k] = 1
            }
          }
          close(file)
        }
        {
          if (match($0, "^[[:space:]]*(#[[:space:]]*)?(export[[:space:]]+)?" old "[A-Za-z0-9_]*=")) {
            head = substr($0, 1, RLENGTH); rest = substr($0, RLENGTH + 1)
            i = index(head, old); k = substr(head, i, length(head) - i)
            nk = new substr(k, length(old) + 1)
            if (!(nk in set)) { head = substr(head, 1, i - 1) nk "=" }
            print head rest
          } else { print }
        }' "$env_file" >"$tmp"
      mv -- "$tmp" "$env_file"
      echo "  renamed in place; the file as it was is kept at $backup (it holds secrets)"
    fi
  fi
  # The old bucket stays the API's bucket (option a for Postgres, for MinIO).
  if [ "$old_bucket" -eq 1 ]; then
    if grep -qE '^[[:space:]]*(export[[:space:]]+)?MINIO_BUCKET=' "$env_file"; then
      echo "  keep MINIO_BUCKET: it is already set; it must name the bucket the data is in"
    elif [ "$apply" -eq 1 ]; then
      # A file whose last line has no newline gets one first.
      if [ -s "$env_file" ] && [ -n "$(tail -c 1 "$env_file")" ]; then
        printf '\n' >>"$env_file"
      fi
      printf 'MINIO_BUCKET=%s\n' "$OLD-samples" >>"$env_file"
      echo "  set MINIO_BUCKET to the bucket the copied data holds"
    else
      echo "  set MINIO_BUCKET to the bucket the copied data holds"
    fi
  fi
  # Values that still name the previous name: the key only.
  while IFS= read -r line; do
    key="$(sed -E -e 's/=.*//' -e 's/^.*[[:space:]]//' <<<"$line")"
    echo "  the value of $key names the previous name; it is left as it is (see below)"
  done < <(grep -E '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*=' "$env_file" \
    | awk -F= -v old="$OLD" '{ v = substr($0, index($0, "=") + 1); if (tolower(v) ~ old) print $1 "=" }' || true)
fi

# ── Qdrant ───────────────────────────────────────────────────────────

echo
echo "Qdrant:"
qdrant_pairs=("${NEW}_cases_v2 ${OLD}_cases_v2" "${NEW}_function_hashes_v1 ${OLD}_function_hashes_v1")
if [ -z "$qdrant_url" ] || ! command -v curl >/dev/null 2>&1; then
  for pair in "${qdrant_pairs[@]}"; do
    set -- $pair
    echo "  alias $1 -> $2 (pass --qdrant-url to create it): POST /collections/aliases"
    echo "    {\"actions\":[{\"create_alias\":{\"collection_name\":\"$2\",\"alias_name\":\"$1\"}}]}"
  done
else
  # The key goes to curl on its standard input, never on its command line.
  qdrant_key=
  if [ -f "$env_file" ]; then
    qdrant_key="$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?QDRANT_API_KEY=//p' "$env_file" | tail -1 || true)"
  fi
  qdrant() {
    printf 'header = "api-key: %s"\n' "$qdrant_key" \
      | curl -sS --fail -K - -H 'Content-Type: application/json' "$@"
  }
  names="$(qdrant "$qdrant_url/collections" | grep -oE '"name":"[^"]*"' | cut -d'"' -f4 || true)"
  aliases="$(qdrant "$qdrant_url/aliases" | grep -oE '"alias_name":"[^"]*"' | cut -d'"' -f4 || true)"
  for pair in "${qdrant_pairs[@]}"; do
    set -- $pair
    if grep -qxF -- "$1" <<<"$names" || grep -qxF -- "$1" <<<"$aliases"; then
      echo "  skip alias $1: the name is taken"
    elif ! grep -qxF -- "$2" <<<"$names"; then
      echo "  skip alias $1: there is no collection $2"
    elif [ "$apply" -eq 0 ]; then
      echo "  alias $1 -> $2"
    else
      qdrant -X POST "$qdrant_url/collections/aliases" \
        -d "{\"actions\":[{\"create_alias\":{\"collection_name\":\"$2\",\"alias_name\":\"$1\"}}]}" >/dev/null
      echo "  created alias $1 -> $2"
    fi
  done
  unset qdrant_key
fi

# ── What the script does not do ─────────────────────────────────────

cat <<EOF

Postgres: the copied pgdata still holds the database "$OLD", owned by the
role "$OLD". Either
  a) keep them: set POSTGRES_DB=$OLD and POSTGRES_USER=$OLD in docker/.env;
     every connection the stack makes is built from those two; or
  b) rename them, with only postgres running under the new project:
       docker compose -f docker/docker-compose.yml up -d postgres
       docker compose -f docker/docker-compose.yml exec postgres \\
         psql -U $OLD -d postgres -c 'CREATE ROLE ${NEW}_rename SUPERUSER LOGIN'
       docker compose -f docker/docker-compose.yml exec postgres \\
         psql -U ${NEW}_rename -d postgres \\
         -c 'ALTER DATABASE $OLD RENAME TO $NEW' -c 'ALTER ROLE $OLD RENAME TO $NEW'
       docker compose -f docker/docker-compose.yml exec postgres \\
         psql -U $NEW -d postgres -c 'DROP ROLE ${NEW}_rename'
     A SCRAM password survives the role rename; an MD5 one is cleared, so set
     it again (ALTER ROLE $NEW PASSWORD ...). An audit anchor role
     (${OLD}_anchor) is renamed the same way, or kept and named in
     AUDIT_ANCHOR_DATABASE_URL as it is.

Qdrant: the copied qdrant_data still holds the collections ${OLD}_cases_v2 and
${OLD}_function_hashes_v1. The aliases above let the new default names read
them; or point core.memory.qdrant.collection and
core.memory.qdrant.function_hash_collection at the old names in the console.

MinIO: the copied minio_data still holds the bucket $OLD-samples, with its
object lock, retention, legal holds and versions. Keep it: MINIO_BUCKET=$OLD-samples
in docker/.env (set above when the bucket was found). The object-store audit
anchor keeps its heads there under audit-chain/head/; a new, empty bucket would
read as empty beside the database's head and the next append would anchor anew.
Only a bucket with no object lock and no audit head may be copied instead; this
copy refuses any other (run it with the new stack up and MINIO_BUCKET unset):

docker compose -f docker/docker-compose.yml exec -T api python - <<'PY'
from minio.commonconfig import CopySource
from minio.error import S3Error
from app.config import settings
from app.services.object_store import client
store, old = client(), "$OLD-samples"
try:
    store.get_object_lock_config(old)
except S3Error as exc:
    if exc.code != "ObjectLockConfigurationNotFoundError":
        raise
else:
    raise SystemExit(f"{old} has object lock: keep it with MINIO_BUCKET={old}")
if any(True for _ in store.list_objects(old, prefix="audit-chain/head/", recursive=True)):
    raise SystemExit(f"{old} holds audit heads: keep it with MINIO_BUCKET={old}")
if not store.bucket_exists(settings.minio_bucket):
    raise SystemExit("start the API once so it creates its bucket")
for item in store.list_objects(old, recursive=True):
    store.copy_object(settings.minio_bucket, item.object_name, CopySource(old, item.object_name))
PY

Redis: queued jobs and job ownership keys carry the old prefix; let the old
queue drain before stopping it, or resubmit what was queued.

Settings exports: an export written before the rename still imports.
EOF
