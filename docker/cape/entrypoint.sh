#!/bin/bash
# CAPEv2 web container entrypoint.
#
# Steps:
#   1. Patch conf/cuckoo.conf to use the PostgreSQL service from docker-compose.
#   2. Patch conf/reporting.conf so the web app does NOT require MongoDB.
#   3. Patch conf/api.conf to expose the REST endpoints we need without auth
#      (a token is layered on top by the Maljan client in the .env).
#   4. Initialise the SQLAlchemy schema via Alembic.
#   5. Launch Django via runserver (development mode is fine for the
#      dev integration target; switch to uWSGI for production).
set -euo pipefail

CAPE_HOME=/opt/CAPEv2
cd "$CAPE_HOME"

POSTGRES_DSN=${CAPE_POSTGRES_DSN:-postgresql://cape:cape@cape-postgres:5432/cape}
WEB_HOST=${CAPE_WEB_HOST:-0.0.0.0}
WEB_PORT=${CAPE_WEB_PORT:-8000}
API_TOKEN=${CAPE_API_TOKEN:-}

echo "[cape-entrypoint] patching conf/cuckoo.conf"
python3 - <<PY
import re, pathlib
p = pathlib.Path('/opt/CAPEv2/conf/cuckoo.conf')
text = p.read_text()
text = re.sub(r'^connection\s*=.*$', 'connection = ${POSTGRES_DSN}', text, flags=re.MULTILINE)
p.write_text(text)
PY

echo "[cape-entrypoint] patching conf/reporting.conf to disable MongoDB"
python3 - <<'PY'
import re, pathlib
p = pathlib.Path('/opt/CAPEv2/conf/reporting.conf')
if p.exists():
    text = p.read_text()
    # Flip every "enabled = yes" under a [mongodb] / [elasticsearch] section to "no"
    # by replacing the first "enabled = yes" after those headers. A targeted replace
    # is safer than a global one — it leaves jsondump etc. intact.
    for section in ('mongodb', 'elasticsearchdb'):
        text = re.sub(
            rf'(\[{section}\][^[]*?enabled\s*=\s*)yes',
            r'\1no',
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
    p.write_text(text)
PY

echo "[cape-entrypoint] patching conf/web.conf"
python3 - <<'PY'
import re, pathlib
p = pathlib.Path('/opt/CAPEv2/conf/web.conf')
if p.exists():
    text = p.read_text()
    # Disable the recaptcha block — there's no token in the dev container.
    text = re.sub(r'^(\s*recaptcha\s*=\s*).*$', r'\1no', text, flags=re.MULTILINE)
    p.write_text(text)
PY

echo "[cape-entrypoint] ensuring per-endpoint 'enabled = yes'"
python3 - <<'PY'
import pathlib, re
for name in ('api.conf', 'apiv2.conf'):
    p = pathlib.Path(f'/opt/CAPEv2/conf/{name}')
    if not p.exists():
        continue
    text = p.read_text()
    # Match ``enabled = no`` at the start of an option line ONLY. This
    # preserves settings whose name happens to end in ``enabled`` (e.g.
    # ``token_auth_enabled``) which need to stay off in the dev stack.
    text = re.sub(r'^(\s*)enabled\s*=\s*no\s*$', r'\1enabled = yes', text, flags=re.MULTILINE)
    p.write_text(text)
PY

echo "[cape-entrypoint] leaving token_auth_enabled=no for dev (open API)"

# Wait for Postgres to accept connections.
echo "[cape-entrypoint] waiting for Postgres..."
PG_HOST=$(echo "$POSTGRES_DSN" | sed -E 's|.*@([^:/]+).*|\1|')
PG_PORT=$(echo "$POSTGRES_DSN" | sed -E 's|.*:([0-9]+)/.*|\1|')
for _ in $(seq 1 60); do
    if nc -z "$PG_HOST" "$PG_PORT" 2>/dev/null; then
        echo "[cape-entrypoint] Postgres reachable on ${PG_HOST}:${PG_PORT}"
        break
    fi
    sleep 1
done

# Initialise the SQLAlchemy schema.
echo "[cape-entrypoint] running alembic upgrade"
cd "$CAPE_HOME/utils/db_migration"
python3 -m alembic upgrade head || {
    echo "[cape-entrypoint] alembic upgrade failed — continuing so the web UI still boots"
}
cd "$CAPE_HOME"

# Django apps (auth, sessions, allauth, etc.) maintain their own schema via
# Django migrations rather than the alembic chain above. Without this the
# /admin/, account, and token endpoints all 500 with "no such table".
echo "[cape-entrypoint] running Django migrate"
cd "$CAPE_HOME/web"
python3 manage.py migrate --noinput || \
    echo "[cape-entrypoint] django migrate failed — continuing so the API still boots"

case "${1:-web}" in
    web)
        echo "[cape-entrypoint] launching Django webserver on ${WEB_HOST}:${WEB_PORT}"
        cd "$CAPE_HOME/web"
        exec python3 manage.py runserver "${WEB_HOST}:${WEB_PORT}" --noreload
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        exec "$@"
        ;;
esac
