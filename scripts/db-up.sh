#!/usr/bin/env bash
# Local dev MySQL for mcp-firewall: own datadir (./.mysql), loopback only, UTC.
# Usage: ./scripts/db-up.sh            (foreground)
#        nohup ./scripts/db-up.sh &    (background)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${MYSQL_PORT:-3307}"
DATA="$PWD/.mysql/data"; RUN="$PWD/.mysql/run"
mkdir -p "$RUN"
if [ ! -d "$DATA/mysql" ]; then
  mkdir -p "$DATA"
  mysqld --initialize-insecure --datadir="$DATA" --user="$(whoami)" --log-error="$RUN/init.log"
fi
exec mysqld --datadir="$DATA" --port="$PORT" --bind-address=127.0.0.1 \
  --socket="$RUN/mysql.sock" --mysqlx=OFF --pid-file="$RUN/mysqld.pid" \
  --default-time-zone=+00:00 --log-error="$RUN/error.log" --user="$(whoami)"
