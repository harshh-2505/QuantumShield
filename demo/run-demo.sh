#!/usr/bin/env bash
# QuantumShield end-to-end demo.
#
#   ./run-demo.sh          run every step
#   ./run-demo.sh down     stop and remove the demo containers
#
# Steps
#   0. Build the image, create a classical PKI, start three nginx services
#   1. Scan certificates, TLS endpoints and config files
#   2. Show the cryptographic inventory (CBOM)
#   3. Identify the services that need migration and plan it
#   4. Deploy hybrid post-quantum sidecars (X25519MLKEM768 + ML-DSA-65 mTLS)
#   5. Compare connection time, CPU and message size
#   6. Zero-trust checks: legacy client, unknown identity, rotation, revocation
#   7. Re-scan and build the before/after dashboard
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
cd "$DIR"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
QS=("${COMPOSE[@]}" run --rm -T qs)
ITER="${QS_BENCH_ITERATIONS:-200}"

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
note() { printf '\033[2m%s\033[0m\n' "$*"; }

if [[ "${1:-}" == "down" ]]; then
  "${COMPOSE[@]}" --profile pqc --profile tools down -v --remove-orphans
  exit 0
fi

# ------------------------------------------------------------------ 0. setup
step "0. Build QuantumShield and start three classical services"
if [[ -z "${QS_SKIP_BUILD:-}" ]]; then
  docker build -q -t quantumshield:latest "$ROOT" ${QS_BUILD_ARGS:-} >/dev/null
fi
"${COMPOSE[@]}" --profile pqc --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf pki runtime out && mkdir -p pki runtime/{orders,payments,inventory} out

note "Classical PKI: RSA-2048 CA; orders RSA-2048 (825 days), payments ECDSA P-256, inventory RSA-2048 (825 days)"
"${QS[@]}" pki init --dir pki/legacy --alg rsa2048 --name "Acme Legacy CA" >/dev/null
"${QS[@]}" pki issue orders    --dir pki/legacy --alg rsa2048    --days 825 >/dev/null
"${QS[@]}" pki issue payments  --dir pki/legacy --alg ecdsa-p256 --days 365 >/dev/null
"${QS[@]}" pki issue inventory --dir pki/legacy --alg rsa2048    --days 825 >/dev/null

for s in orders payments inventory; do
  cp "services/$s/listen.classical.conf" "runtime/$s/listen.conf"
done
cp services/orders/routes.classical.conf runtime/orders/routes.conf
touch runtime/payments/routes.conf runtime/inventory/routes.conf
"${COMPOSE[@]}" up -d --wait orders payments inventory

"${QS[@]}" get https://orders:443/api/payments/ | sed 's/^/  /'

# ------------------------------------------------------------------ 1-3. scan
step "1-3. Scan certificates, TLS endpoints and configuration files"
"${QS[@]}" scan \
  -e orders=orders:443 -e payments=payments:443 -e inventory=inventory:443 \
  -c orders=services/orders/nginx.conf \
  -c payments=services/payments/nginx.conf \
  -c inventory=services/inventory/nginx.conf \
  -c legacy-configs -c legacy-pki=pki/legacy \
  -o out/before

step "2. Cryptographic inventory (CycloneDX 1.6 CBOM)"
docker run --rm -i -v "$DIR/out:/out" --entrypoint python quantumshield:latest - <<'PY'
import json
bom = json.load(open("/out/before/cbom.json"))
kinds = {}
for c in bom["components"]:
    t = c["cryptoProperties"]["assetType"]
    kinds[t] = kinds.get(t, 0) + 1
print("  components:", ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
for c in bom["components"]:
    if c["cryptoProperties"]["assetType"] == "algorithm":
        status = next(p["value"] for p in c["properties"] if p["name"].endswith("quantum-status"))
        print(f"  {c['name']:<22} {status}")
PY

step "3. Services requiring migration, and the plan"
"${QS[@]}" migrate out/before/inventory.json -o out/migration

note "Baseline: live connections to the classical services"
"${QS[@]}" bench net -n "$ITER" -o out/bench.json \
  -t "orders nginx (classical)=orders:443" \
  -t "payments nginx (classical)=payments:443"

# ------------------------------------------------------------------ 4. migrate
step "4. Deploy hybrid post-quantum sidecars (no change to the services' code)"
note "Post-quantum PKI: ML-DSA-65 CA and 30-day workload certificates with SPIFFE IDs"
"${QS[@]}" pki init --dir pki/pqc --alg mldsa65 >/dev/null
"${QS[@]}" pki issue orders payments inventory scanner --dir pki/pqc --alg mldsa65 --days 30
note "Benchmark-only ECDSA PKI (classical baseline through the same proxy)"
"${QS[@]}" pki init --dir pki/bench-ecdsa --alg ecdsa-p256 --name "Bench ECDSA CA" >/dev/null
"${QS[@]}" pki issue payments bench-client --dir pki/bench-ecdsa --alg ecdsa-p256 >/dev/null

note "Moving each service's legacy TLS listener to loopback and routing its outbound calls via the sidecar"
for s in orders payments inventory; do
  cp "services/$s/listen.pqc.conf" "runtime/$s/listen.conf"
done
cp services/orders/routes.pqc.conf runtime/orders/routes.conf
"${COMPOSE[@]}" restart payments inventory orders >/dev/null 2>&1
"${COMPOSE[@]}" up -d --wait orders payments inventory >/dev/null 2>&1
"${COMPOSE[@]}" --profile pqc up -d orders-pqc payments-pqc inventory-pqc
"${COMPOSE[@]}" run --rm -T --entrypoint python qs - <<'PY'
import socket, time
for host in ("orders", "payments", "inventory"):
    for _ in range(100):
        try:
            socket.create_connection((host, 9900), timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        raise SystemExit(f"sidecar for {host} did not start")
PY

note "Client -> orders (hybrid, edge) -> payments and inventory (hybrid mTLS, ML-DSA identities)"
"${QS[@]}" get https://orders:8443/api/payments/ | sed 's/^/  /'
"${QS[@]}" get https://orders:8443/api/inventory/ | sed 's/^/  /'
note "payments sidecar log (the orders -> payments hop):"
"${COMPOSE[@]}" logs --no-log-prefix payments-pqc | grep '"handshake"' | tail -1 | sed 's/^/  /' || true
note "Legacy port is no longer reachable from the network:"
"${QS[@]}" get https://payments:443/health 2>&1 | sed 's/^/  /' || true

# ------------------------------------------------------------------ 5. bench
step "5. Compare connection time, CPU use and message size"
"${QS[@]}" bench local -n "$ITER" -o out/bench.json --merge >/dev/null
"${QS[@]}" bench net -n "$ITER" -o out/bench.json --merge \
  -t "proxy classical: X25519 + ECDSA=payments:7443,group=X25519,cert=pki/bench-ecdsa/bench-client.crt,key=pki/bench-ecdsa/bench-client.key,admin=http://payments:9900/stats" \
  -t "proxy hybrid: X25519MLKEM768 + ECDSA=payments:7444,group=X25519MLKEM768,cert=pki/bench-ecdsa/bench-client.crt,key=pki/bench-ecdsa/bench-client.key,admin=http://payments:9900/stats" \
  -t "proxy hybrid: X25519MLKEM768 + ML-DSA-65=payments:8443,group=X25519MLKEM768,cert=pki/pqc/scanner.crt,key=pki/pqc/scanner.key,admin=http://payments:9900/stats" \
  >/dev/null || true
# The first net run (classical nginx) is merged with the post-migration runs.
docker run --rm -i -v "$DIR/out:/out" --entrypoint python quantumshield:latest - <<'PY'
import json
from quantumshield import bench
d = json.load(open("/out/bench.json"))
print(bench.to_markdown([bench.Result(**r) for r in d["local"]],
                        [bench.NetResult(**r) for r in d["network"]]))
PY

# ------------------------------------------------------------------ 6. zero trust
step "6. Zero-trust controls"
note "a) A classical-only client is refused by the strict payments sidecar:"
"${QS[@]}" get https://payments:8443/api/payments/ --groups X25519 \
  --cert pki/pqc/scanner.crt --key pki/pqc/scanner.key 2>&1 | sed 's/^/  /' || true
note "b) A valid certificate with an identity that is not allowed:"
"${QS[@]}" pki issue intruder --dir pki/pqc --alg mldsa65 >/dev/null
"${QS[@]}" get https://payments:8443/api/payments/ \
  --cert pki/pqc/intruder.crt --key pki/pqc/intruder.key 2>&1 | sed 's/^/  /' || true
note "c) Key rotation: re-issue payments' certificate; the sidecar reloads it without a restart:"
"${QS[@]}" pki issue payments --dir pki/pqc --alg mldsa65 --days 30 | sed 's/^/  /'
sleep 1.5
"${QS[@]}" get https://orders:8443/api/payments/ | sed 's/^/  /'
"${COMPOSE[@]}" logs --no-log-prefix payments-pqc | grep context-reloaded | tail -1 | sed 's/^/  /' || true

# ------------------------------------------------------------------ 7. re-scan
step "7. Re-scan after migration"
"${QS[@]}" scan \
  -e orders=orders:8443 -e payments=payments:8443 -e inventory=inventory:8443 \
  --client-cert pki/pqc/scanner.crt --client-key pki/pqc/scanner.key \
  -o out/after
"${QS[@]}" compare out/before/inventory.json out/after/inventory.json

note "d) Revocation: revoke the scanner's certificate; its next connection is refused:"
"${QS[@]}" pki revoke pki/pqc/scanner.crt --dir pki/pqc | sed 's/^/  /'
"${QS[@]}" get https://payments:8443/api/payments/ \
  --cert pki/pqc/scanner.crt --key pki/pqc/scanner.key 2>&1 | sed 's/^/  /' || true
"${COMPOSE[@]}" logs --no-log-prefix payments-pqc | grep '"rejected"' | tail -2 | sed 's/^/  /' || true

"${QS[@]}" dashboard --before out/before/inventory.json --after out/after/inventory.json \
  --bench out/bench.json --plan out/migration/plan.json -o out/dashboard.html

step "Done"
echo "  Inventory + CBOM:  demo/out/before/{inventory,cbom}.json, report.md"
echo "  Migration plan:    demo/out/migration/plan.md (patched configs in patched/)"
echo "  Benchmarks:        demo/out/bench.md"
echo "  Dashboard:         demo/out/dashboard.html"
echo "  Try it:            curl -k https://localhost:9443/... is gone; the PQC edge is https://localhost:10443"
echo "  Stop:              ./run-demo.sh down"
