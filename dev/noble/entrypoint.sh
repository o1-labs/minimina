#!/usr/bin/env bash
# Starts postgres on $PGPORT (default 5433, so it does not clash with a host
# postgres when the container uses the host network), then runs CMD as `dev`.
set -euo pipefail

PGPORT="${PGPORT:-5433}"
PGDATA=/var/lib/postgresql/16/minimina

if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
  install -d -o postgres -g postgres "$PGDATA"
  su postgres -c "/usr/lib/postgresql/16/bin/initdb -D $PGDATA -U postgres --auth=md5 --pwfile=<(echo postgres)" >/dev/null
fi
su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PGDATA -l $PGDATA/server.log -w \
  -o '-p $PGPORT -c listen_addresses=localhost -c unix_socket_directories=/tmp' start" >/dev/null

exec setpriv --reuid=dev --regid=dev --init-groups env HOME=/home/dev "$@"
