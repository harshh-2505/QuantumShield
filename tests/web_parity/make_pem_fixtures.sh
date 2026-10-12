#!/bin/sh
# Recreate the PEM fixtures in tests/web_parity/fixtures/pem with the OpenSSL 3.5
# CLI from the project image (run from the repository root):
#
#   docker run --rm -i --user "$(id -u)" -v "$PWD/tests/web_parity/fixtures/pem:/out" \
#       --entrypoint sh quantumshield:latest -s < tests/web_parity/make_pem_fixtures.sh
#
# Validity dates are fixed, and tests/test_web_analyzer.py evaluates the expiry
# rules at 2026-10-12T00:00:00Z, so every certificate rule keeps firing (or not)
# the same way regardless of when the test runs.  Keys are throwaway test keys.
set -eu
cd /out
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat > "$T/min.cnf" <<'EOF'
[req]
distinguished_name = dn
string_mask = utf8only
[dn]
EOF
cat > "$T/t61.cnf" <<'EOF'
[req]
distinguished_name = dn
string_mask = default
[dn]
EOF
LEAF='-addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature'
CA='-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign'

key() { openssl genpkey "$@" 2>/dev/null; }
selfsigned() {  # key subject not_before not_after extra-args...
    k=$1 s=$2 nb=$3 na=$4; shift 4
    openssl req -config "$T/min.cnf" -new -x509 -key "$k" -subj "$s" \
        -not_before "$nb" -not_after "$na" "$@"
}
issue() {  # key subject ca-cert ca-key not_before not_after extfile
    openssl req -config "$T/min.cnf" -new -key "$1" -subj "$2" -out "$T/req.csr"
    openssl x509 -req -in "$T/req.csr" -CA "$3" -CAkey "$4" -set_serial "$5" \
        -not_before "$6" -not_after "$7" -extfile "$8"
}

# RSA-2048 self-signed leaf, 825 days: quantum-vulnerable, long-lived, self-signed.
key -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/rsa2048.key"
selfsigned "$T/rsa2048.key" "/C=US/O=Legacy Corp/CN=legacy.example.com" \
    20260101000000Z 20280405000000Z $LEAF \
    -addext "subjectAltName=DNS:legacy.example.com,DNS:www.legacy.example.com,IP:10.0.0.7" \
    > rsa2048-selfsigned.pem

# RSA-1024 signed with SHA-1, expired: short key, broken hash, expired, and a
# notBefore in the 1900s (UTCTime "99..." means 1999).
key -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$T/rsa1024.key"
selfsigned "$T/rsa1024.key" "/O=Old Bank/OU=Mainframe/CN=old.bank.internal" \
    19991231235959Z 20250101000000Z -sha1 $LEAF > rsa1024-sha1-expired.crt

# ECDSA P-384 CA + P-256 leaf that expires 8 days after the test clock.
key -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$T/ec-ca.key"
selfsigned "$T/ec-ca.key" "/O=QuantumShield Test/CN=Test ECDSA Root" \
    20250101000000Z 20350101000000Z $CA > "$T/ec-ca.crt"
key -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ecdsa-p256.key
cat > "$T/ec-leaf.ext" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:payments.internal,DNS:localhost,URI:spiffe://quantumshield.local/payments,IP:127.0.0.1,IP:::1,IP:2001:db8:0:0:1:0:0:1,IP:2001:db8:0:1:1:1:1:1,IP:fe80:1::
EOF
issue ecdsa-p256.key "/O=QuantumShield Test/CN=payments" "$T/ec-ca.crt" "$T/ec-ca.key" \
    0x1F00000000000000000000000000000000000001 20260901000000Z 20261020000000Z "$T/ec-leaf.ext" \
    > "$T/ec-leaf.crt"
cat "$T/ec-leaf.crt" "$T/ec-ca.crt" > ecdsa-p256-chain.pem
# The same chain with the leaf repeated: one certificate, reported once.
cat "$T/ec-leaf.crt" "$T/ec-ca.crt" "$T/ec-leaf.crt" > fullchain-repeated.pem

# ML-DSA-65 CA + ML-DSA-65 leaf (post-quantum: no signature finding).
key -algorithm ML-DSA-65 -out "$T/mldsa-ca.key"
selfsigned "$T/mldsa-ca.key" "/O=QuantumShield/CN=QuantumShield Root CA" \
    20260101000000Z 20360101000000Z $CA > mldsa65-ca.crt
key -algorithm ML-DSA-65 -out mldsa65.key
cat > "$T/ml-leaf.ext" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectAltName = DNS:orders,URI:spiffe://quantumshield.local/orders
EOF
issue mldsa65.key "/O=QuantumShield/CN=orders" mldsa65-ca.crt "$T/mldsa-ca.key" \
    4242 20261001000000Z 20261031000000Z "$T/ml-leaf.ext" > "$T/ml-leaf.crt"
cat "$T/ml-leaf.crt" mldsa65-ca.crt > mldsa65-chain.pem

# Ed25519 leaf valid for ten years: long-lived, self-signed.
key -algorithm ED25519 -out ed25519.key
selfsigned ed25519.key "/CN=build-agent-07" 20240101000000Z 20340101000000Z $LEAF \
    > ed25519-longlived.crt

# DSA-2048 CA (signature algorithm dsa-with-sha256, not in catalog.SIG_OIDS), valid
# until 2050, which X.509 encodes as GeneralizedTime.
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out "$T/dsa.param" 2>/dev/null
openssl genpkey -paramfile "$T/dsa.param" -out dsa.key
selfsigned dsa.key "/O=Legacy Corp/CN=DSA Signing CA" 20200101000000Z 20500101000000Z $CA \
    > dsa2048-ca.crt

# RSA key, RSASSA-PSS signature; plus RFC 4514 escaping and multi-valued RDNs.
selfsigned "$T/rsa2048.key" \
    "/C=DE/ST=Berlin/O=Müller, Schmidt & Söhne+OU=R&D \"Lab\"/CN=#1 test <svc>;x /emailAddress=ops@example.com" \
    20260301000000Z 20270301000000Z -utf8 -sigopt rsa_padding_mode:pss -sha384 $LEAF \
    > rsa-pss-names.crt

# Latin-1 subject stored as a T61String (string_mask=default).
openssl req -config "$T/t61.cnf" -new -x509 -key "$T/rsa2048.key" -utf8 \
    -subj "/O=Caf$(printf '\303\251') Ltd/CN=t61.example" \
    -not_before 20260101000000Z -not_after 20270101000000Z $LEAF > t61-subject.crt

# PrintableString subject with a character PrintableString does not allow: the
# certificate is patched after signing, and cryptography refuses to load it.
openssl req -config "$T/t61.cnf" -new -x509 -key "$T/rsa2048.key" \
    -subj "/O=Printable Test/CN=printable-XX.example" \
    -not_before 20260101000000Z -not_after 20270101000000Z $LEAF -outform DER |
    LC_ALL=C sed "s/printable-XX/printable-@@/g" > "$T/bad-printable.der"
{ echo "-----BEGIN CERTIFICATE-----"; base64 -w 64 "$T/bad-printable.der"
  echo "-----END CERTIFICATE-----"; } > bad-printable-subject.crt

# Private keys in every container format the scanner recognises.
cp "$T/rsa2048.key" rsa2048-pkcs8.key
openssl pkey -in "$T/rsa1024.key" -traditional -out rsa1024-traditional.key
openssl pkey -in "$T/ec-ca.key" -traditional -out ecdsa-p384-sec1.key
key -algorithm ML-KEM-768 -out mlkem768.key
key -algorithm X25519 -out x25519.key
openssl pkey -in ecdsa-p256.key -aes256 -passout pass:fixture -out encrypted-pkcs8.key
openssl pkey -in "$T/rsa1024.key" -traditional -aes256 -passout pass:fixture \
    -out encrypted-traditional.key

# A typical server bundle: certificate followed by its private key.
cat rsa2048-selfsigned.pem rsa2048-pkcs8.key > server-bundle.pem
