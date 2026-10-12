# QuantumShield migration plan

Generated 2026-10-12T16:02:13+00:00

## inventory  (vulnerable, risk score 212)

**Phase 1: stop harvest-now-decrypt-later (key exchange)**

- [critical] Remove static-RSA key-exchange cipher suites
  - services/inventory/nginx.conf:14: ssl_ciphers AES128-GCM-SHA256:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:@SECLEVEL=0
  - inventory:443: Accepts AES128-GCM-SHA256, AES256-SHA
- [high] Offer hybrid ML-KEM key exchange (X25519MLKEM768) first
  - services/inventory/nginx.conf:13: ssl_ecdh_curve prime256v1:secp384r1
  - inventory:443: Negotiated secp256r1; no hybrid ML-KEM group accepted
- [high] Enable TLS 1.3 (required for hybrid ML-KEM)
  - services/inventory/nginx.conf:12: ssl_protocols TLSv1 TLSv1.1 TLSv1.2
  - inventory:443: Highest protocol: TLSv1.2

**Phase 2: harden transport and add workload identity**

- [high] Disable TLS 1.0 / 1.1
  - services/inventory/nginx.conf:12: ssl_protocols TLSv1 TLSv1.1 TLSv1.2
  - inventory:443: TLSv1.0, TLSv1.1
- [info] Front the service with a QuantumShield hybrid-PQC mTLS proxy
  - inventory:443: The endpoint accepts anonymous clients

**Phase 3: post-quantum authentication and agility**

- [medium] Re-issue certificates with ML-DSA-65 (or composite) keys
  - cert:31e523e607ed6c61 (CN=inventory,O=QuantumShield): RSA-2048 public key, signed with RSA/SHA-256
- [low] Move to short-lived, centrally issued certificates
  - cert:31e523e607ed6c61 (CN=inventory,O=QuantumShield): Valid for 825 days

**Phase 4: clean-up**

- [low] Prefer 256-bit symmetric ciphers
  - inventory:443: Negotiated ECDHE-RSA-AES128-GCM-SHA256 (Grover's algorithm halves its strength)

## legacy-configs  (vulnerable, risk score 200)

**Phase 1: stop harvest-now-decrypt-later (key exchange)**

- [critical] Remove static-RSA key-exchange cipher suites
  - legacy-configs/haproxy.cfg:2: ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA256
  - legacy-configs/openssl.cnf:11: CipherString DEFAULT:@SECLEVEL=2
- [high] Offer hybrid ML-KEM key exchange (X25519MLKEM768) first
  - legacy-configs/haproxy.cfg:6: curves P-256:X25519
  - legacy-configs/openssl.cnf:12: Groups X25519:secp256r1:secp384r1
- [high] Use mlkem768x25519-sha256 / sntrup761x25519 SSH key exchange
  - legacy-configs/sshd_config:5: KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1

**Phase 2: harden transport and add workload identity**

- [high] Remove insecure ciphers
  - legacy-configs/sshd_config:6: Ciphers aes128-ctr,aes256-gcm@openssh.com,3des-cbc

**Phase 3: post-quantum authentication and agility**

- [medium] Route hard-coded crypto through a configurable (agile) layer
  - legacy-configs/billing_client.py:8: code return rsa.generate_private_key(public_exponent=65537, key_size=2048)
  - legacy-configs/billing_client.py:12: code return hashlib.md5(data).hexdigest()

**Phase 4: clean-up**

- [low] Plan SSH host-key migration
  - legacy-configs/sshd_config:3: HostKey /etc/ssh/ssh_host_rsa_key
  - legacy-configs/sshd_config:4: HostKey /etc/ssh/ssh_host_ecdsa_key

## payments  (vulnerable, risk score 82)

**Phase 1: stop harvest-now-decrypt-later (key exchange)**

- [high] Offer hybrid ML-KEM key exchange (X25519MLKEM768) first
  - services/payments/nginx.conf:13: ssl_ecdh_curve prime256v1
  - payments:443: Negotiated secp256r1; no hybrid ML-KEM group accepted
- [high] Enable TLS 1.3 (required for hybrid ML-KEM)
  - services/payments/nginx.conf:12: ssl_protocols TLSv1.2
  - payments:443: Highest protocol: TLSv1.2

**Phase 2: harden transport and add workload identity**

- [info] Front the service with a QuantumShield hybrid-PQC mTLS proxy
  - payments:443: The endpoint accepts anonymous clients

**Phase 3: post-quantum authentication and agility**

- [medium] Re-issue certificates with ML-DSA-65 (or composite) keys
  - cert:db8ce0cf4f4c293b (CN=payments,O=QuantumShield): secp256r1 public key, signed with RSA/SHA-256

**Phase 4: clean-up**

- [low] Prefer 256-bit symmetric ciphers
  - payments:443: Negotiated ECDHE-ECDSA-AES128-GCM-SHA256 (Grover's algorithm halves its strength)

## reports.internal  (vulnerable, risk score 60)

**Phase 1: stop harvest-now-decrypt-later (key exchange)**

- [critical] Remove static-RSA key-exchange cipher suites
  - legacy-configs/apache-ssl.conf:5: SSLCipherSuite HIGH:!aNULL:!MD5

**Phase 2: harden transport and add workload identity**

- [high] Disable TLS 1.0 / 1.1
  - legacy-configs/apache-ssl.conf:4: SSLProtocol all -SSLv3

## orders  (vulnerable, risk score 40)

**Phase 1: stop harvest-now-decrypt-later (key exchange)**

- [high] Offer hybrid ML-KEM key exchange (X25519MLKEM768) first
  - services/orders/nginx.conf:13: ssl_ecdh_curve X25519:prime256v1
  - orders:443: Negotiated x25519; no hybrid ML-KEM group accepted

**Phase 2: harden transport and add workload identity**

- [info] Front the service with a QuantumShield hybrid-PQC mTLS proxy
  - orders:443: The endpoint accepts anonymous clients

**Phase 3: post-quantum authentication and agility**

- [medium] Re-issue certificates with ML-DSA-65 (or composite) keys
  - cert:5d3a1bf4064a786b (CN=orders,O=QuantumShield): RSA-2048 public key, signed with RSA/SHA-256
- [low] Move to short-lived, centrally issued certificates
  - cert:5d3a1bf4064a786b (CN=orders,O=QuantumShield): Valid for 825 days

## legacy-pki  (review, risk score 34)

**Phase 3: post-quantum authentication and agility**

- [medium] Re-issue certificates with ML-DSA-65 (or composite) keys
  - cert:31e523e607ed6c61 (CN=inventory,O=QuantumShield): RSA-2048 public key, signed with RSA/SHA-256
  - cert:a6e27d189bdb9916 (CN=Acme Legacy CA,O=QuantumShield): RSA-2048 public key, signed with RSA/SHA-256
  - cert:5d3a1bf4064a786b (CN=orders,O=QuantumShield): RSA-2048 public key, signed with RSA/SHA-256
- [low] Move to short-lived, centrally issued certificates
  - cert:31e523e607ed6c61 (CN=inventory,O=QuantumShield): Valid for 825 days
  - cert:5d3a1bf4064a786b (CN=orders,O=QuantumShield): Valid for 825 days

## Config patches

### services/orders/nginx.conf

```diff
--- services/orders/nginx.conf
+++ services/orders/nginx.conf (migrated)
@@ -9,9 +9,9 @@
 
         ssl_certificate     /etc/nginx/pki/orders.crt;
         ssl_certificate_key /etc/nginx/pki/orders.key;
-        ssl_protocols       TLSv1.2 TLSv1.3;
-        ssl_ecdh_curve      X25519:prime256v1;
-        ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
+        ssl_protocols TLSv1.2 TLSv1.3;
+        ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;  # quantumshield: hybrid ML-KEM
+        ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;
         ssl_prefer_server_ciphers on;
 
         default_type application/json;
```

### services/payments/nginx.conf

```diff
--- services/payments/nginx.conf
+++ services/payments/nginx.conf (migrated)
@@ -9,9 +9,9 @@
 
         ssl_certificate     /etc/nginx/pki/payments.crt;
         ssl_certificate_key /etc/nginx/pki/payments.key;
-        ssl_protocols       TLSv1.2;
-        ssl_ecdh_curve      prime256v1;
-        ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA;
+        ssl_protocols TLSv1.2 TLSv1.3;
+        ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;  # quantumshield: hybrid ML-KEM
+        ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;
 
         default_type application/json;
         location = /health       { return 200 '{"service":"payments","ok":true}\n'; }
```

### services/inventory/nginx.conf

```diff
--- services/inventory/nginx.conf
+++ services/inventory/nginx.conf (migrated)
@@ -9,9 +9,9 @@
 
         ssl_certificate     /etc/nginx/pki/inventory.crt;
         ssl_certificate_key /etc/nginx/pki/inventory.key;
-        ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
-        ssl_ecdh_curve      prime256v1:secp384r1;
-        ssl_ciphers         AES128-GCM-SHA256:AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:@SECLEVEL=0;
+        ssl_protocols TLSv1.2 TLSv1.3;
+        ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;  # quantumshield: hybrid ML-KEM
+        ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;
 
         default_type application/json;
         location = /health        { return 200 '{"service":"inventory","ok":true}\n'; }
```

### legacy-configs/apache-ssl.conf

```diff
--- legacy-configs/apache-ssl.conf
+++ legacy-configs/apache-ssl.conf (migrated)
@@ -1,7 +1,7 @@
 <VirtualHost *:443>
     ServerName reports.internal
     SSLEngine on
-    SSLProtocol all -SSLv3
-    SSLCipherSuite HIGH:!aNULL:!MD5
+    SSLProtocol -all +TLSv1.2 +TLSv1.3
+    SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20
     SSLCertificateFile /etc/ssl/reports.crt
 </VirtualHost>
```

### legacy-configs/haproxy.cfg

```diff
--- legacy-configs/haproxy.cfg
+++ legacy-configs/haproxy.cfg (migrated)
@@ -1,9 +1,10 @@
 global
-    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA256
-    ssl-default-bind-options ssl-min-ver TLSv1.1
+    ssl-default-bind-curves X25519MLKEM768:X25519:P-256
+    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20
+    ssl-default-bind-options ssl-min-ver TLSv1.2
 
 frontend public
-    bind :443 ssl crt /etc/haproxy/certs/edge.pem curves P-256:X25519
+    bind :443 ssl crt /etc/haproxy/certs/edge.pem curves X25519MLKEM768:X25519:P-256
     default_backend orders
 
 backend orders
```

### legacy-configs/openssl.cnf

```diff
--- legacy-configs/openssl.cnf
+++ legacy-configs/openssl.cnf (migrated)
@@ -9,4 +9,4 @@
 [system_default_sect]
 MinProtocol = TLSv1.2
 CipherString = DEFAULT:@SECLEVEL=2
-Groups = X25519:secp256r1:secp384r1
+Groups = X25519MLKEM768:X25519:prime256v1
```

### legacy-configs/sshd_config

```diff
--- legacy-configs/sshd_config
+++ legacy-configs/sshd_config (migrated)
@@ -2,7 +2,7 @@
 Port 22
 HostKey /etc/ssh/ssh_host_rsa_key
 HostKey /etc/ssh/ssh_host_ecdsa_key
-KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1
-Ciphers aes128-ctr,aes256-gcm@openssh.com,3des-cbc
+KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256
+Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
 MACs hmac-sha2-256,hmac-sha1
 PermitRootLogin no
```

## Sidecar proxies (no change to the service)

```json
{
  "proxies": [
    {
      "name": "orders-pqc",
      "mode": "ingress",
      "listen": "0.0.0.0:8443",
      "upstream": "orders:443",
      "upstream_tls": true,
      "policy": "strict",
      "cert": "pki/orders.crt",
      "key": "pki/orders.key",
      "ca": "pki/ca.crt",
      "require_client_cert": true
    },
    {
      "name": "payments-pqc",
      "mode": "ingress",
      "listen": "0.0.0.0:8444",
      "upstream": "payments:443",
      "upstream_tls": true,
      "policy": "strict",
      "cert": "pki/payments.crt",
      "key": "pki/payments.key",
      "ca": "pki/ca.crt",
      "require_client_cert": true
    },
    {
      "name": "inventory-pqc",
      "mode": "ingress",
      "listen": "0.0.0.0:8445",
      "upstream": "inventory:443",
      "upstream_tls": true,
      "policy": "strict",
      "cert": "pki/inventory.crt",
      "key": "pki/inventory.key",
      "ca": "pki/ca.crt",
      "require_client_cert": true
    }
  ]
}
```

