#!/usr/bin/env bash
# Measures container lifecycle latency with the release binary.
# Usage: sudo scripts/bench.sh [iterations]
set -euo pipefail
N=${1:-30}
cd "$(dirname "$0")/.."
cargo build --release -q
B=$PWD/target/release/hull
export HULL_ROOT=/var/lib/hull-bench
$B pull bench --busybox >/dev/null 2>&1

ms() { date +%s%N; }
report() { awk -v n="$2" -v t="$3" -v name="$1" 'BEGIN{printf "%-38s %8.2f ms/op  (%d ops)\n", name, t/n/1e6, n}'; }

t0=$(ms); for _ in $(seq "$N"); do /bin/true; done; t1=$(ms)
report "baseline: fork+exec /bin/true" "$N" $((t1-t0))

t0=$(ms); for _ in $(seq "$N"); do $B run bench true >/dev/null; done; t1=$(ms)
report "hull run (all namespaces) true" "$N" $((t1-t0))

t0=$(ms); for _ in $(seq "$N"); do $B run --memory 64m --cpus 1 --pids 64 bench true >/dev/null; done; t1=$(ms)
report "hull run + cgroup limits true" "$N" $((t1-t0))

id=$($B run -d bench sleep 600)
t0=$(ms); for _ in $(seq "$N"); do $B exec "$id" true; done; t1=$(ms)
report "hull exec (setns) true" "$N" $((t1-t0))
t0=$(ms); $B stop -t 5 "$id" >/dev/null; t1=$(ms)
report "hull stop (SIGTERM via init)" 1 $((t1-t0))

ids=$($B ps -a | awk 'NR>1{print $1}')
t0=$(ms); for c in $ids; do $B rm -f "$c" >/dev/null; done; t1=$(ms)
report "hull rm" "$(echo "$ids" | wc -w)" $((t1-t0))
