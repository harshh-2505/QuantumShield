#!/usr/bin/env bash
# Docker-free version of the demo. Needs Python 3.15+ linked against OpenSSL 3.5+
# (e.g. Debian trixie / Ubuntu 25.10+, or `uv python install 3.15`) and the
# `openssl` 3.5 CLI, with quantumshield installed (`pip install -e .`).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
QS="python -m quantumshield"
ITER="${QS_BENCH_ITERATIONS:-100}"
step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

$QS info
python - <<'PY'
from quantumshield import tlsutil
if not (tlsutil.HAS_GROUP_API and tlsutil.OPENSSL_HAS_MLKEM):
    raise SystemExit("This demo needs Python 3.15+ with OpenSSL 3.5+; use ../run-demo.sh (Docker) instead.")
PY

wait_port() { python - "$1" <<'PY'
import socket, sys, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close(); break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit(f"port {sys.argv[1]} did not open")
PY
}

step "0. Classical PKI and three classical services"
rm -rf pki out && mkdir -p out
$QS pki init --dir pki/legacy --alg rsa2048 --name "Acme Legacy CA" >/dev/null
$QS pki issue orders inventory --dir pki/legacy --alg rsa2048 --days 825 >/dev/null
$QS pki issue payments --dir pki/legacy --alg ecdsa-p256 --days 365 >/dev/null
python services.py --pki pki/legacy & PIDS+=($!)
for p in 9441 9442 9443; do wait_port $p; done
$QS get https://127.0.0.1:9441/api/payments/

step "1-3. Scan, inventory (CBOM) and migration plan"
$QS scan -e orders=127.0.0.1:9441 -e payments=127.0.0.1:9442 -e inventory=127.0.0.1:9443 \
  -c ../legacy-configs -o out/before
$QS migrate out/before/inventory.json -o out/migration
$QS bench net -n "$ITER" -o out/bench.json -t "orders (classical)=127.0.0.1:9441" >/dev/null

step "4. Hybrid post-quantum sidecars"
$QS pki init --dir pki/pqc --alg mldsa65 >/dev/null
$QS pki issue orders payments inventory scanner --dir pki/pqc --alg mldsa65
$QS proxy --config sidecars.json --admin 127.0.0.1:9900 > out/proxy.log & PIDS+=($!)
for p in 10441 10442 10443 9001 9002 9900; do wait_port $p; done
# Re-point orders' outbound calls at its egress listeners (plain HTTP on loopback).
kill "${PIDS[0]}"; sleep 0.5
python services.py --pki pki/legacy --payments-url http://127.0.0.1:9001 \
  --inventory-url http://127.0.0.1:9002 & PIDS[0]=$!
wait_port 9441
$QS get https://127.0.0.1:10441/api/payments/
grep '"payments-ingress"' out/proxy.log | grep handshake | tail -1

step "5. Connection time, CPU and message size"
$QS bench local -n "$ITER" -o out/bench.json --merge >/dev/null
$QS bench net -n "$ITER" -o out/bench.json --merge \
  -t "orders via PQC proxy=127.0.0.1:10441,group=X25519MLKEM768,admin=http://127.0.0.1:9900/stats"
cat out/bench.md

step "6. Re-scan and dashboard"
$QS scan -e orders=127.0.0.1:10441 -e payments=127.0.0.1:10442 -e inventory=127.0.0.1:10443 \
  --client-cert pki/pqc/scanner.crt --client-key pki/pqc/scanner.key -o out/after
$QS compare out/before/inventory.json out/after/inventory.json
$QS dashboard --before out/before/inventory.json --after out/after/inventory.json \
  --bench out/bench.json --plan out/migration/plan.json -o out/dashboard.html
