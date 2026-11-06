#!/usr/bin/env bash
#
# Drop, recreate and migrate one database of the local federation stack.
#
#   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
#     ./scripts/reset-dev-db.sh postgresql://catbird:catbird_dev_password@localhost:5433/catbird
#
# The URL must name a loopback host, port 5433 (ds1) or 5434 (ds2) and the
# database catbird of docker-compose.federation.yml. Production's database is
# also named catbird (migration 20250101000000 grants on it), so the name proves
# nothing: before anything is dropped, the live server must report database
# catbird and the cluster_name the compose file gives that port's container
# (catbird-federation-ds1 or catbird-federation-ds2). The target allowlist lives
# only in this file: there is no override, no Doppler and no .env lookup. After
# migration, the supported Compose peer-fixtures service restores both homes'
# allowlist rows. Restart the reset home afterwards so it re-initializes its chat
# fence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ACTIVATION_GUC_VALUE=handlers-and-legacy-apis-sealed

refuse() {
    echo "reset-dev-db: refusing: $*" >&2
    exit 1
}

url="${1:-}"
[ -n "$url" ] || refuse "usage: $0 postgresql://USER[:PASSWORD]@localhost:PORT/DATABASE"

# scheme://[userinfo@]host[:port]/database and nothing else: a query string,
# socket path or host list could point libpq somewhere other than the parsed host.
re='^(postgres|postgresql)://([^@/?#]*@)?([^:/?#,@]+)(:([0-9]+))?/([a-z0-9_]+)$'
[[ "$url" =~ $re ]] \
    || refuse "expected postgresql://USER[:PASSWORD]@localhost:PORT/DATABASE without a query string"
scheme="${BASH_REMATCH[1]}"
userinfo="${BASH_REMATCH[2]}"
host="${BASH_REMATCH[3]}"
port="${BASH_REMATCH[5]:-5432}"
database="${BASH_REMATCH[6]}"

case "$host" in
    localhost|127.0.0.1) ;;
    *) refuse "host $host is not loopback" ;;
esac
case "$port" in
    5433) cluster=catbird-federation-ds1 ;;
    5434) cluster=catbird-federation-ds2 ;;
    *) refuse "port $port is not a local federation stack port (5433 ds1, 5434 ds2)" ;;
esac
[ "$database" = catbird ] \
    || refuse "$database is not the local federation stack database (catbird)"
[ "${CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED:-}" = "$ACTIVATION_GUC_VALUE" ] \
    || refuse "set CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=$ACTIVATION_GUC_VALUE: the fresh database must apply migration 20260728000004 (see ../migrations/README.md)"

# Every connection below names the same explicit host and port. libpq would
# otherwise let these variables redirect it.
unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGPORT
target_url="$scheme://$userinfo$host:$port/$database"

live="$(psql "$target_url" -X -Atqc "SELECT current_database() || ' ' || current_setting('cluster_name')")" \
    || refuse "cannot connect to $host:$port/$database"
[ "$live" = "$database $cluster" ] \
    || refuse "server reports '$live', expected '$database $cluster' (a docker-compose.federation.yml container)"

echo "Resetting $host:$port/$database ..."
psql "$scheme://$userinfo$host:$port/postgres" -X -q -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS $database WITH (FORCE)" \
    -c "CREATE DATABASE $database"
"$SCRIPT_DIR/run-migrations.sh" "$target_url"
docker compose -f "$REPO_DIR/docker-compose.federation.yml" \
    run --rm --no-deps peer-fixtures
