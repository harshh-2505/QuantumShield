### Handshake cost (in-process, TLS 1.3, mutual TLS, n=200)

| Scenario | Group | Certs | Wall ms (p50) | Client CPU ms | Server CPU ms | Client→Server B | Server→Client B | Total B | vs. baseline |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ECDHE P-256 + RSA-2048 (legacy) | secp256r1 | rsa2048 | 2.161 | 1.108 | 1.007 | 2,431 | 2,483 | 4,914 | 1.00x bytes |
| X25519 + ECDSA P-256 | x25519 | ecdsa-p256 | 1.634 | 0.824 | 0.756 | 1,158 | 1,483 | 2,641 | 0.54x bytes |
| X25519MLKEM768 + ECDSA P-256 | X25519MLKEM768 | ecdsa-p256 | 1.821 | 0.957 | 0.827 | 2,334 | 2,570 | 4,904 | 1.00x bytes |
| X25519MLKEM768 + ML-DSA-65 | X25519MLKEM768 | mldsa65 | 5.146 | 2.391 | 2.172 | 15,856 | 16,049 | 31,905 | 6.49x bytes |
| ML-KEM-768 + ML-DSA-65 (pure PQC) | MLKEM768 | mldsa65 | 4.619 | 2.222 | 2.008 | 15,824 | 16,017 | 31,841 | 6.48x bytes |
| SecP384r1MLKEM1024 + ML-DSA-87 (CNSA 2.0 level) | SecP384r1MLKEM1024 | mldsa87 | 7.699 | 3.878 | 3.474 | 21,558 | 21,828 | 43,386 | 8.83x bytes |

### Live connections (TCP + TLS)

| Path | Group | Connect ms (p50) | p95 | TLS ms | Client CPU ms | Proxy CPU ms/conn | Total bytes | Errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| orders nginx (classical) | x25519 | 2.270 | 2.800 | 1.787 | 1.091 | - | 3,112 | 0 |
| payments nginx (classical) | secp256r1 | 2.202 | 2.806 | 1.710 | 1.259 | - | 2,912 | 0 |
| proxy classical: X25519 + ECDSA | x25519 | 3.921 | 5.274 | 3.358 | 1.366 | 3.697 | 2,697 | 0 |
| proxy hybrid: X25519MLKEM768 + ECDSA | X25519MLKEM768 | 4.274 | 6.769 | 3.690 | 1.563 | 3.870 | 4,734 | 0 |
| proxy hybrid: X25519MLKEM768 + ML-DSA-65 | X25519MLKEM768 | 7.002 | 11.818 | 6.446 | 3.016 | 5.690 | 26,649 | 0 |
