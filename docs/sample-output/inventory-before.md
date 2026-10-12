# QuantumShield cryptographic inventory

Generated: 2026-10-12T13:46:00+00:00  
Scanner TLS runtime: OpenSSL 3.5.7 9 Jun 2026; ML-KEM available; group control

## Migration readiness

| Service | Status | Risk score | Key exchange | Certificate key | Findings |
|---|---|---:|---|---|---|
| inventory | **vulnerable** | 212 | secp256r1 | RSA-2048 | 2 critical, 6 high, 1 medium, 2 low, 1 info |
| legacy-configs | **vulnerable** | 200 | - | - | 2 critical, 5 high, 2 medium, 2 low |
| payments | **vulnerable** | 82 | secp256r1 | secp256r1 | 4 high, 1 low, 1 info |
| reports.internal | **vulnerable** | 60 | - | - | 1 critical, 1 high, 1 info |
| orders | **vulnerable** | 40 | x25519 | RSA-2048 | 2 high, 1 info |
| legacy-pki | **review** | 34 | - | - | 3 medium, 5 low |

## TLS endpoints

| Service | Endpoint | Protocols | Negotiated | Group | PQC groups accepted | TLS 1.2 suites | mTLS |
|---|---|---|---|---|---|---|---|
| orders | orders:443 | TLSv1.2, TLSv1.3 | TLSv1.3 TLS_AES_256_GCM_SHA384 | x25519 | none | 2 | no |
| payments | payments:443 | TLSv1.2 | TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256 | secp256r1 | none | 2 | no |
| inventory | inventory:443 | TLSv1.0, TLSv1.1, TLSv1.2 | TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 | secp256r1 | none | 3 | no |

## Certificates

| Subject | Key | Signature | Expires | Seen at |
|---|---|---|---|---|
| CN=inventory,O=QuantumShield | RSA-2048 | RSA/SHA-256 | 2029-01-14 | tls://inventory:443<br>file://pki/legacy/inventory.crt |
| CN=orders,O=QuantumShield | RSA-2048 | RSA/SHA-256 | 2029-01-14 | tls://orders:443<br>file://pki/legacy/orders.crt |
| CN=payments,O=QuantumShield | secp256r1 | RSA/SHA-256 | 2027-10-12 | tls://payments:443<br>file://pki/legacy/payments.crt |
| CN=Acme Legacy CA,O=QuantumShield | RSA-2048 | RSA/SHA-256 | 2036-10-09 | file://pki/legacy/ca.crt |

## Configuration and source files

| File | Kind | Service | Crypto settings |
|---|---|---|---|
| services/orders/nginx.conf | nginx | orders | 4 |
| services/payments/nginx.conf | nginx | payments | 4 |
| services/inventory/nginx.conf | nginx | inventory | 4 |
| legacy-configs/apache-ssl.conf | apache | reports.internal | 3 |
| legacy-configs/billing_client.py | source | legacy-configs | 2 |
| legacy-configs/haproxy.cfg | haproxy | legacy-configs | 4 |
| legacy-configs/openssl.cnf | openssl | legacy-configs | 3 |
| legacy-configs/sshd_config | sshd | legacy-configs | 5 |
| pki/legacy/ca.crt | pem | legacy-pki | 0 |
| pki/legacy/ca.key | pem | legacy-pki | 1 |
| pki/legacy/inventory.crt | pem | legacy-pki | 0 |
| pki/legacy/inventory.key | pem | legacy-pki | 1 |
| pki/legacy/orders.crt | pem | legacy-pki | 0 |
| pki/legacy/orders.key | pem | legacy-pki | 1 |
| pki/legacy/payments.crt | pem | legacy-pki | 0 |
| pki/legacy/payments.key | pem | legacy-pki | 1 |

## Algorithms referenced in configuration

| Algorithm | Quantum status | Occurrences | Replace with |
|---|---|---:|---|
| ECDH-P256 | quantum-broken | 6 | X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203) |
| AES-128-GCM | quantum-weakened | 6 | AES-256-GCM |
| AES-256-CBC | quantum-resistant | 5 | AES-256-GCM (AEAD) |
| RSA | quantum-broken | 5 | ML-DSA-65 (FIPS 204), or a hybrid/composite certificate during transition |
| X25519 | quantum-broken | 4 | X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203) |
| AES-256-GCM | quantum-resistant | 4 | - |
| RSA-KEX | quantum-broken | 4 | X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203) over TLS 1.3 (also restores forward secrecy) |
| AES-128-CBC | quantum-weakened | 3 | AES-256-GCM |
| ECDH-P384 | quantum-broken | 2 | SecP384r1MLKEM1024 or X25519MLKEM768 |
| ChaCha20-Poly1305 | quantum-resistant | 2 | - |
| ECDSA | quantum-broken | 2 | ML-DSA-65 (FIPS 204), or a hybrid/composite certificate during transition |
| MD5 | insecure | 1 | SHA-256 or SHA-384 |
| DH-1024 | insecure | 1 | X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203) |
| 3DES | insecure | 1 | AES-256-GCM |
| SHA-256 | quantum-resistant | 1 | - |
| SHA-1 | insecure | 1 | SHA-256 or SHA-384 |

## Findings

| Severity | Rule | Service | Asset | Finding | Evidence | Recommendation |
|---|---|---|---|---|---|---|
| critical (HNDL) | QS-CFG-CIPH-003 | inventory | services/inventory/nginx.conf:14 | Static RSA key-exchange suites allowed | ssl_ciphers AES128-GCM-SHA256:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:@SECLEVEL=0 | Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20. |
| critical (HNDL) | QS-TLS-KEX-003 | inventory | inventory:443 | Static RSA key exchange accepted (no forward secrecy) | Accepts AES128-GCM-SHA256, AES256-SHA | Remove kRSA suites. Anyone who records traffic and later obtains or breaks the RSA key decrypts every session. |
| critical (HNDL) | QS-CFG-CIPH-003 | legacy-configs | legacy-configs/haproxy.cfg:2 | Static RSA key-exchange suites allowed | ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA256 | Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20. |
| critical (HNDL) | QS-CFG-CIPH-003 | legacy-configs | legacy-configs/openssl.cnf:11 | Static RSA key-exchange suites allowed | CipherString DEFAULT:@SECLEVEL=2 | Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20. |
| critical (HNDL) | QS-CFG-CIPH-003 | reports.internal | legacy-configs/apache-ssl.conf:5 | Static RSA key-exchange suites allowed | SSLCipherSuite HIGH:!aNULL:!MD5 | Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20. |
| high (HNDL) | QS-CFG-KEX-001 | inventory | services/inventory/nginx.conf:13 | Only classical key-exchange groups configured | ssl_ecdh_curve prime256v1:secp384r1 | Add X25519MLKEM768 first, keeping X25519 for older clients. |
| high (HNDL) | QS-CFG-PROTO-001 | inventory | services/inventory/nginx.conf:12 | TLS 1.3 not enabled | ssl_protocols TLSv1 TLSv1.1 TLSv1.2 | Enable TLSv1.3; hybrid ML-KEM requires it. |
| high | QS-CFG-PROTO-002 | inventory | services/inventory/nginx.conf:12 | Legacy TLS versions enabled | ssl_protocols TLSv1 TLSv1.1 TLSv1.2 | Allow only TLS 1.2 and 1.3. |
| high (HNDL) | QS-TLS-KEX-001 | inventory | inventory:443 | Key exchange is not quantum-safe (harvest-now-decrypt-later) | Negotiated secp256r1; no hybrid ML-KEM group accepted | Enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+) or front the service with the QuantumShield hybrid proxy. |
| high (HNDL) | QS-TLS-PROTO-001 | inventory | inventory:443 | TLS 1.3 not supported | Highest protocol: TLSv1.2 | Hybrid ML-KEM key exchange is only defined for TLS 1.3. Upgrade the TLS stack or deploy the QuantumShield proxy. |
| high | QS-TLS-PROTO-002 | inventory | inventory:443 | Legacy TLS versions accepted | TLSv1.0, TLSv1.1 | Disable TLS 1.0 and 1.1. |
| high (HNDL) | QS-CFG-KEX-001 | legacy-configs | legacy-configs/haproxy.cfg:6 | Only classical key-exchange groups configured | curves P-256:X25519 | Add X25519MLKEM768 first, keeping X25519 for older clients. |
| high (HNDL) | QS-CFG-KEX-001 | legacy-configs | legacy-configs/openssl.cnf:12 | Only classical key-exchange groups configured | Groups X25519:secp256r1:secp384r1 | Add X25519MLKEM768 first, keeping X25519 for older clients. |
| high | QS-SSH-CIPH-001 | legacy-configs | legacy-configs/sshd_config:6 | SSH allows insecure ciphers | Ciphers aes128-ctr,aes256-gcm@openssh.com,3des-cbc | Use chacha20-poly1305 and aes256-gcm. |
| high (HNDL) | QS-SSH-KEX-001 | legacy-configs | legacy-configs/sshd_config:5 | SSH key exchange is not quantum-safe | KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1 | Put mlkem768x25519-sha256 (OpenSSH 9.9+) and sntrup761x25519-sha512 first. |
| high | QS-SSH-KEX-002 | legacy-configs | legacy-configs/sshd_config:5 | SSH allows broken key exchange | KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1 | Remove SHA-1 / 1024-bit Diffie-Hellman groups. |
| high (HNDL) | QS-CFG-KEX-001 | orders | services/orders/nginx.conf:13 | Only classical key-exchange groups configured | ssl_ecdh_curve X25519:prime256v1 | Add X25519MLKEM768 first, keeping X25519 for older clients. |
| high (HNDL) | QS-TLS-KEX-001 | orders | orders:443 | Key exchange is not quantum-safe (harvest-now-decrypt-later) | Negotiated x25519; no hybrid ML-KEM group accepted | Enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+) or front the service with the QuantumShield hybrid proxy. |
| high (HNDL) | QS-CFG-KEX-001 | payments | services/payments/nginx.conf:13 | Only classical key-exchange groups configured | ssl_ecdh_curve prime256v1 | Add X25519MLKEM768 first, keeping X25519 for older clients. |
| high (HNDL) | QS-CFG-PROTO-001 | payments | services/payments/nginx.conf:12 | TLS 1.3 not enabled | ssl_protocols TLSv1.2 | Enable TLSv1.3; hybrid ML-KEM requires it. |
| high (HNDL) | QS-TLS-KEX-001 | payments | payments:443 | Key exchange is not quantum-safe (harvest-now-decrypt-later) | Negotiated secp256r1; no hybrid ML-KEM group accepted | Enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+) or front the service with the QuantumShield hybrid proxy. |
| high (HNDL) | QS-TLS-PROTO-001 | payments | payments:443 | TLS 1.3 not supported | Highest protocol: TLSv1.2 | Hybrid ML-KEM key exchange is only defined for TLS 1.3. Upgrade the TLS stack or deploy the QuantumShield proxy. |
| high | QS-CFG-PROTO-002 | reports.internal | legacy-configs/apache-ssl.conf:4 | Legacy TLS versions enabled | SSLProtocol all -SSLv3 | Allow only TLS 1.2 and 1.3. |
| medium | QS-CERT-SIG-001 | inventory, legacy-pki | cert:9525e604be21ac95 (CN=inventory,O=QuantumShield) | Certificate key is quantum-vulnerable | RSA-2048 public key, signed with RSA/SHA-256 | Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). Authentication is not exposed to harvest-now-decrypt-later, so this follows key exchange in priority. |
| medium | QS-CODE-001 | legacy-configs | legacy-configs/billing_client.py:8 | Hard-coded quantum-vulnerable algorithm in source | code return rsa.generate_private_key(public_exponent=65537, key_size=2048) | Route RSA through a crypto-agility layer (config-selected algorithm) so it can be swapped for ML-KEM / ML-DSA. |
| medium | QS-CODE-002 | legacy-configs | legacy-configs/billing_client.py:12 | Broken hash function used in source | code return hashlib.md5(data).hexdigest() | Use SHA-256 or stronger (fine for non-security checksums, but verify). |
| medium | QS-CERT-SIG-001 | legacy-pki | cert:687c3c41bbb9873a (CN=Acme Legacy CA,O=QuantumShield) | Certificate key is quantum-vulnerable | RSA-2048 public key, signed with RSA/SHA-256 | Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). Authentication is not exposed to harvest-now-decrypt-later, so this follows key exchange in priority. |
| medium | QS-CERT-SIG-001 | legacy-pki, orders | cert:68bfdce459df8021 (CN=orders,O=QuantumShield) | Certificate key is quantum-vulnerable | RSA-2048 public key, signed with RSA/SHA-256 | Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). Authentication is not exposed to harvest-now-decrypt-later, so this follows key exchange in priority. |
| medium | QS-CERT-SIG-001 | legacy-pki, payments | cert:ea7279e7018d8155 (CN=payments,O=QuantumShield) | Certificate key is quantum-vulnerable | secp256r1 public key, signed with RSA/SHA-256 | Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). Authentication is not exposed to harvest-now-decrypt-later, so this follows key exchange in priority. |
| low | QS-TLS-CIPH-002 | inventory | inventory:443 | 128-bit symmetric cipher preferred | Negotiated ECDHE-RSA-AES128-GCM-SHA256 (Grover's algorithm halves its strength) | Prefer AES-256-GCM or ChaCha20-Poly1305 for long-lived secrets. |
| low | QS-CERT-ROT-001 | inventory, legacy-pki | cert:9525e604be21ac95 (CN=inventory,O=QuantumShield) | Long-lived certificate | Valid for 825 days | Use short-lived workload certificates so rotation and algorithm changes are routine. |
| low | QS-SSH-HK-001 | legacy-configs | legacy-configs/sshd_config:3 | SSH host key is quantum-vulnerable | HostKey /etc/ssh/ssh_host_rsa_key | Track OpenSSH's ML-DSA host-key support; keep keys rotatable. |
| low | QS-SSH-HK-001 | legacy-configs | legacy-configs/sshd_config:4 | SSH host key is quantum-vulnerable | HostKey /etc/ssh/ssh_host_ecdsa_key | Track OpenSSH's ML-DSA host-key support; keep keys rotatable. |
| low | QS-KEY-001 | legacy-pki | pki/legacy/ca.key:1 | Quantum-vulnerable private key on disk | private-key RSA-2048 | Replace with ML-DSA keys when the certificate is re-issued; keep keys out of source trees. |
| low | QS-KEY-001 | legacy-pki | pki/legacy/inventory.key:1 | Quantum-vulnerable private key on disk | private-key RSA-2048 | Replace with ML-DSA keys when the certificate is re-issued; keep keys out of source trees. |
| low | QS-KEY-001 | legacy-pki | pki/legacy/orders.key:1 | Quantum-vulnerable private key on disk | private-key RSA-2048 | Replace with ML-DSA keys when the certificate is re-issued; keep keys out of source trees. |
| low | QS-KEY-001 | legacy-pki | pki/legacy/payments.key:1 | Quantum-vulnerable private key on disk | private-key ECDSA | Replace with ML-DSA keys when the certificate is re-issued; keep keys out of source trees. |
| low | QS-CERT-ROT-001 | legacy-pki, orders | cert:68bfdce459df8021 (CN=orders,O=QuantumShield) | Long-lived certificate | Valid for 825 days | Use short-lived workload certificates so rotation and algorithm changes are routine. |
| low | QS-TLS-CIPH-002 | payments | payments:443 | 128-bit symmetric cipher preferred | Negotiated ECDHE-ECDSA-AES128-GCM-SHA256 (Grover's algorithm halves its strength) | Prefer AES-256-GCM or ChaCha20-Poly1305 for long-lived secrets. |
| info | QS-ZT-001 | inventory | inventory:443 | No workload identity required (no mutual TLS) | The endpoint accepts anonymous clients | For service-to-service traffic, require mTLS with short-lived workload certificates (the QuantumShield proxy does this). |
| info | QS-ZT-001 | orders | orders:443 | No workload identity required (no mutual TLS) | The endpoint accepts anonymous clients | For service-to-service traffic, require mTLS with short-lived workload certificates (the QuantumShield proxy does this). |
| info | QS-ZT-001 | payments | payments:443 | No workload identity required (no mutual TLS) | The endpoint accepts anonymous clients | For service-to-service traffic, require mTLS with short-lived workload certificates (the QuantumShield proxy does this). |
| info | QS-CFG-KEX-000 | reports.internal | legacy-configs/apache-ssl.conf | Key-exchange groups left to library defaults | No ssl_ecdh_curve / Groups directive | Defaults are hybrid only with OpenSSL 3.5+. Pin X25519MLKEM768:X25519 explicitly. |
