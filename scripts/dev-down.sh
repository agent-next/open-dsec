#!/usr/bin/env bash
# Stop only the PIDs this worktree's dev-up.sh started (never by name).
set -u
DSEC_HOME="${DSEC_HOME:-/tmp/dsec-dev}"
[[ -f "$DSEC_HOME/pids" ]] || { echo "no pid file at $DSEC_HOME/pids"; exit 0; }
while read -r pid; do
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null && echo "stopped $pid"
  fi
done < "$DSEC_HOME/pids"
rm -f "$DSEC_HOME/pids"
docker ps -aq --filter label=open-dsec | xargs -r docker rm -f >/dev/null 2>&1 || true
echo "dev stack down"
