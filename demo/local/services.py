"""Three tiny HTTPS services with deliberately classical TLS (Docker-free demo).

    python services.py --pki ./pki/legacy [--payments-url URL] [--inventory-url URL]

orders     127.0.0.1:9441  TLS 1.2-1.3, X25519/P-256 only, RSA-2048 cert
payments   127.0.0.1:9442  TLS 1.2 only, P-256, ECDSA cert
inventory  127.0.0.1:9443  TLS 1.2 only, static-RSA suites allowed, RSA-2048 cert
"""

import argparse
import json
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from quantumshield import tlsutil

SERVICES = {
    "orders": dict(port=9441, max=ssl.TLSVersion.TLSv1_3, groups="X25519:secp256r1",
                   ciphers="ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"),
    "payments": dict(port=9442, max=ssl.TLSVersion.TLSv1_2, groups="secp256r1",
                     ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA"),
    "inventory": dict(port=9443, max=ssl.TLSVersion.TLSv1_2, groups="secp256r1:secp384r1",
                      ciphers="AES128-GCM-SHA256:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256"),
}
BODIES = {
    "orders": {"service": "orders", "orders": [{"id": 1001, "sku": "QS-42", "qty": 3}]},
    "payments": {"service": "payments", "status": "authorised", "amount": 129.99},
    "inventory": {"service": "inventory", "sku": "QS-42", "on_hand": 118},
}


def make_handler(name, routes):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = BODIES[name]
            for prefix, url in routes.items():
                if self.path.startswith(prefix):
                    ctx = ssl._create_unverified_context()
                    with urllib.request.urlopen(url + self.path, context=ctx, timeout=5) as r:
                        body = json.loads(r.read())
            data = (json.dumps(body) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return H


def serve(name, cfg, pki, routes):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = cfg["max"]
    ctx.set_ciphers(cfg["ciphers"])
    tlsutil.set_groups(ctx, cfg["groups"])
    ctx.load_cert_chain(f"{pki}/{name}.crt", f"{pki}/{name}.key")
    srv = ThreadingHTTPServer(("127.0.0.1", cfg["port"]), make_handler(name, routes))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"{name} listening on https://127.0.0.1:{cfg['port']}", flush=True)
    srv.serve_forever()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pki", required=True)
    p.add_argument("--payments-url", default="https://127.0.0.1:9442")
    p.add_argument("--inventory-url", default="https://127.0.0.1:9443")
    a = p.parse_args()
    routes = {"/api/payments/": a.payments_url, "/api/inventory/": a.inventory_url}
    threads = []
    for name, cfg in SERVICES.items():
        t = threading.Thread(target=serve, args=(name, cfg, a.pki,
                                                 routes if name == "orders" else {}),
                             daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
