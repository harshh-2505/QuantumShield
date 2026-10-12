### Handshake cost (in-process, TLS 1.3, mutual TLS, n=200)

| Scenario | Group | Certs | Wall ms (p50) | Client CPU ms | Server CPU ms | Client→Server B | Server→Client B | Total B | vs. baseline |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ECDHE P-256 + RSA-2048 (legacy) | secp256r1 | rsa2048 | 2.132 | 1.098 | 1.003 | 2,430 | 2,483 | 4,913 | 1.00x bytes |
| X25519 + ECDSA P-256 | x25519 | ecdsa-p256 | 1.592 | 0.817 | 0.759 | 1,162 | 1,482 | 2,644 | 0.54x bytes |
| X25519MLKEM768 + ECDSA P-256 | X25519MLKEM768 | ecdsa-p256 | 1.871 | 1.004 | 0.860 | 2,339 | 2,569 | 4,908 | 1.00x bytes |
| X25519MLKEM768 + ML-DSA-65 | X25519MLKEM768 | mldsa65 | 5.234 | 2.536 | 2.311 | 15,842 | 16,049 | 31,891 | 6.49x bytes |
| ML-KEM-768 + ML-DSA-65 (pure PQC) | MLKEM768 | mldsa65 | 4.427 | 2.230 | 1.868 | 15,810 | 16,017 | 31,827 | 6.48x bytes |
| SecP384r1MLKEM1024 + ML-DSA-87 (CNSA 2.0 level) | SecP384r1MLKEM1024 | mldsa87 | 7.876 | 3.790 | 3.486 | 21,531 | 21,828 | 43,359 | 8.83x bytes |

### Live connections (TCP + TLS)

| Path | Group | Connect ms (p50) | p95 | TLS ms | Client CPU ms | Proxy CPU ms/conn | Total bytes | Errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| orders nginx (classical) | x25519 | 2.447 | 3.064 | 1.586 | 1.411 | - | 3,112 | 0 |
| payments nginx (classical) | secp256r1 | 2.154 | 2.860 | 1.619 | 1.287 | - | 2,912 | 0 |
| proxy classical: X25519 + ECDSA | x25519 | 3.660 | 4.905 | 3.042 | 1.446 | 3.506 | 2,695 | 0 |
| proxy hybrid: X25519MLKEM768 + ECDSA | X25519MLKEM768 | 3.645 | 4.656 | 3.131 | 1.399 | 3.478 | 4,733 | 0 |
| proxy hybrid: X25519MLKEM768 + ML-DSA-65 | X25519MLKEM768 | 6.324 | 9.944 | 5.835 | 2.533 | 5.351 | 26,601 | 0 |
