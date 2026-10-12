# QuantumShield cryptographic inventory

Generated: 2026-10-12T13:46:42+00:00  
Scanner TLS runtime: OpenSSL 3.5.7 9 Jun 2026; ML-KEM available; group control

## Migration readiness

| Service | Status | Risk score | Key exchange | Certificate key | Findings |
|---|---|---:|---|---|---|
| orders | **quantum-safe** | 0 | X25519MLKEM768 | ML-DSA-65 | 1 info |
| payments | **quantum-safe** | 0 | X25519MLKEM768 | ML-DSA-65 |  |
| inventory | **quantum-safe** | 0 | X25519MLKEM768 | ML-DSA-65 |  |

## TLS endpoints

| Service | Endpoint | Protocols | Negotiated | Group | PQC groups accepted | TLS 1.2 suites | mTLS |
|---|---|---|---|---|---|---|---|
| orders | orders:8443 | TLSv1.3 | TLSv1.3 TLS_AES_256_GCM_SHA384 | X25519MLKEM768 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | 0 | no |
| payments | payments:8443 | TLSv1.3 | TLSv1.3 TLS_AES_256_GCM_SHA384 | X25519MLKEM768 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | 0 | required |
| inventory | inventory:8443 | TLSv1.3 | TLSv1.3 TLS_AES_256_GCM_SHA384 | X25519MLKEM768 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | 0 | required |

## Certificates

| Subject | Key | Signature | Expires | Seen at |
|---|---|---|---|---|
| CN=inventory,O=QuantumShield | ML-DSA-65 | ML-DSA-65 | 2026-11-11 | tls://inventory:8443 |
| CN=QuantumShield Root CA,O=QuantumShield | ML-DSA-65 | ML-DSA-65 | 2036-10-09 | tls://inventory:8443<br>tls://payments:8443<br>tls://orders:8443 |
| CN=payments,O=QuantumShield | ML-DSA-65 | ML-DSA-65 | 2026-11-11 | tls://payments:8443 |
| CN=orders,O=QuantumShield | ML-DSA-65 | ML-DSA-65 | 2026-11-11 | tls://orders:8443 |

## Findings

| Severity | Rule | Service | Asset | Finding | Evidence | Recommendation |
|---|---|---|---|---|---|---|
| info | QS-ZT-001 | orders | orders:8443 | No workload identity required (no mutual TLS) | The endpoint accepts anonymous clients | For service-to-service traffic, require mTLS with short-lived workload certificates (the QuantumShield proxy does this). |
