#!/usr/bin/env bash
# Start the one-host open-dsec control plane (M1): iam, watcher, placement,
# apiserver, edge — plus the aether binary containers bind-mount. Reads the
# host's resources for the edge's admission capacity. Idempotent-ish: refuses
# to double-start. State, sockets and PIDs live in DSEC_HOME (default
# /tmp/dsec-dev). Usage: scripts/dev-up.sh; stop with scripts/dev-down.sh.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
DSEC_HOME="${DSEC_HOME:-/tmp/dsec-dev}"
API_PORT="${DSEC_API_PORT:-9100}"
IAM_PORT="${DSEC_IAM_PORT:-9101}"
WATCHER_PORT="${DSEC_WATCHER_PORT:-9102}"
PLACEMENT_PORT="${DSEC_PLACEMENT_PORT:-9103}"
EDGE_PORT="${DSEC_EDGE_PORT:-9104}"
EDGE_ID="${DSEC_EDGE_ID:-edge-1}"

if [[ -f "$DSEC_HOME/pids" ]] && kill -0 "$(head -1 "$DSEC_HOME/pids")" 2>/dev/null; then
  echo "dev stack already running ($DSEC_HOME/pids); run scripts/dev-down.sh first" >&2
  exit 1
fi

BIN="$ROOT/target/debug"
for b in dsec-iam dsec-watcher dsec-placement dsec-apiserver dsec-edge dsec-aether; do
  [[ -x "$BIN/$b" ]] || { echo "missing $BIN/$b — run: cargo build" >&2; exit 1; }
done

# Edge admission capacity: this host's CPUs, half its RAM, a sane sandbox cap.
CPU_MC=$(( $(nproc) * 1000 ))
MEM_MB=$(( $(awk '/MemTotal/ {print int($2/2048)}' /proc/meminfo) ))
SBX_MAX="${DSEC_SBX_MAX:-512}"

if ! docker info >/dev/null 2>&1; then
  echo "warning: docker unreachable — the edge will create nothing until it is" >&2
fi
docker image inspect debian:12-slim >/dev/null 2>&1 || docker pull debian:12-slim

mkdir -p "$DSEC_HOME/edge"
: > "$DSEC_HOME/pids"

start() { # name cmd...
  local name="$1"; shift
  "$@" >>"$DSEC_HOME/$name.log" 2>&1 &
  local pid=$!
  echo "$pid" >> "$DSEC_HOME/pids"
  echo "started $name (pid $pid, log $DSEC_HOME/$name.log)"
}

start iam    "$BIN/dsec-iam" --listen "tcp://127.0.0.1:$IAM_PORT" --state "$DSEC_HOME/iam.json"
start watcher "$BIN/dsec-watcher" --listen "tcp://127.0.0.1:$WATCHER_PORT" --edge "$EDGE_ID=tcp://127.0.0.1:$EDGE_PORT"
start placement "$BIN/dsec-placement" --listen "tcp://127.0.0.1:$PLACEMENT_PORT" --watcher "tcp://127.0.0.1:$WATCHER_PORT"
start edge   "$BIN/dsec-edge" --listen "tcp://127.0.0.1:$EDGE_PORT" --id "$EDGE_ID" \
             --data-dir "$DSEC_HOME/edge" --aether-bin "$BIN/dsec-aether" \
             --iam "tcp://127.0.0.1:$IAM_PORT" --cpu-mc "$CPU_MC" --mem-mb "$MEM_MB" --sandboxes "$SBX_MAX"
start api    "$BIN/dsec-apiserver" --listen "tcp://127.0.0.1:$API_PORT" \
             --iam "tcp://127.0.0.1:$IAM_PORT" --placement "tcp://127.0.0.1:$PLACEMENT_PORT" \
             --watcher "tcp://127.0.0.1:$WATCHER_PORT"

# Readiness: the apiserver accepts TCP and iam answers.
for i in $(seq 1 50); do
  if (echo > /dev/tcp/127.0.0.1/"$API_PORT") >/dev/null 2>&1; then break; fi
  sleep 0.2
done

DEV_TOKEN=$(python3 - "$DSEC_HOME/iam.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    st = json.load(f)
print(next(p["token"] for p in st["principals"].values() if p["id"] == "dev"))
PY
)
cat <<EOF

open-dsec dev stack up (edge capacity: ${CPU_MC}mc / ${MEM_MB}MiB / ${SBX_MAX} sandboxes)

  from libdsec import Client
  c = Client("127.0.0.1:$API_PORT", token="$DEV_TOKEN")
  sb = c.create(image="debian:12-slim", cpu=0.5, memory=256, ttl=600,
                network={"pypi": True, "npm": False})
  sb.exec("echo hello")
  sb.release()

Stop: scripts/dev-down.sh
EOF
