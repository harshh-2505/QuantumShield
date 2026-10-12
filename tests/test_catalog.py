from quantumshield.catalog import QuantumStatus, classify_group, lookup, parse_cipher_suite


def test_lookup_aliases_and_oids():
    assert lookup("prime256v1").name == "ECDH-P256"
    assert lookup("2.16.840.1.101.3.4.3.18").name == "ML-DSA-65"
    assert lookup("ssh-ed25519").status is QuantumStatus.BROKEN
    assert lookup("nonexistent") is None


def test_groups():
    assert classify_group("X25519MLKEM768").status is QuantumStatus.HYBRID
    assert classify_group("MLKEM768").status is QuantumStatus.RESISTANT
    assert classify_group("x25519").quantum_safe is False


def test_cipher_suites():
    rsa = parse_cipher_suite("AES256-SHA")
    assert rsa.kex == "RSA" and not rsa.forward_secrecy
    assert rsa.cipher.name == "AES-256-CBC"
    ecdhe = parse_cipher_suite("ECDHE-ECDSA-AES128-GCM-SHA256")
    assert (ecdhe.kex, ecdhe.auth, ecdhe.cipher.name) == ("ECDHE", "ECDSA", "AES-128-GCM")
    tls13 = parse_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert tls13.kex == "TLS13" and tls13.cipher.name == "AES-256-GCM"
    assert parse_cipher_suite("DES-CBC3-SHA").cipher.status is QuantumStatus.INSECURE
