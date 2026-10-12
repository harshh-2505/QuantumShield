/*
 * QuantumShield analyzer for the browser.
 *
 * A dependency-free port of the Python configuration scanner and its rules:
 * quantumshield/config_scanner.py (parsers and detect_kind), catalog.py,
 * certs.py (certificate fields), the config / certificate / key / source rules
 * of analyzer.py, and cbom.py for a config-only inventory.  It lets the site
 * analyze a pasted config, key or certificate without uploading it.
 *
 * tests/test_web_analyzer.py keeps this file in sync with the Python code: it
 * runs both on the same fixtures and requires the same findings.  When a rule
 * changes in Python, change it here too.
 *
 * Parsing and lookup only: nothing here implements cryptography.  OpenSSL
 * cipher strings ("HIGH:!aNULL") are expanded from a table that
 * scripts/gen_cipher_table.py probed from OpenSSL 3.5.  Certificate
 * fingerprints use the platform's SHA-256 (Node's crypto module, or WebCrypto
 * through analyzeAsync()).
 *
 *   QSAnalyzer.analyze(filename, text, {now, service, sha256})  -> result
 *   QSAnalyzer.analyzeAsync(filename, text, opts)               -> Promise<result>
 *   QSAnalyzer.cbom(results, {timestamp, serialNumber})         -> CycloneDX 1.6 CBOM
 *   QSAnalyzer.catalog                                          -> algorithm table
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.QSAnalyzer = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var VERSION = "0.1.0"; // quantumshield.__version__ (checked by the parity test)

  // ======================================================== Python string semantics
  // The rules compare strings the way Python does, so whitespace, splitting and
  // word boundaries follow Python's definitions rather than JavaScript's.

  // Characters for which Python's str.isspace() is true (also what \s matches).
  var WS = "\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
  var WORD = "\\p{L}\\p{N}_"; // Python's Unicode \w
  var RE_WS_CHAR = new RegExp("^[" + WS + "]$", "u");
  var RE_LINE_BREAK = /\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]/;
  var RE_LINE_END = /(?:\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029])$/;

  function isWS(ch) { return RE_WS_CHAR.test(ch); }

  function strip(s, chars) { return rstrip(lstrip(s, chars), chars); }

  function lstrip(s, chars) {
    var i = 0;
    while (i < s.length && (chars === undefined ? isWS(s[i]) : chars.indexOf(s[i]) >= 0)) i++;
    return s.slice(i);
  }

  function rstrip(s, chars) {
    var j = s.length;
    while (j > 0 && (chars === undefined ? isWS(s[j - 1]) : chars.indexOf(s[j - 1]) >= 0)) j--;
    return s.slice(0, j);
  }

  // str.split() / str.split(None, maxsplit)
  function split(s, maxsplit) {
    var out = [], i = 0, n = s.length;
    for (;;) {
      while (i < n && isWS(s[i])) i++;
      if (i >= n) break;
      if (maxsplit !== undefined && out.length === maxsplit) { out.push(s.slice(i)); break; }
      var j = i;
      while (j < n && !isWS(s[j])) j++;
      out.push(s.slice(i, j));
      i = j;
    }
    return out;
  }

  // str.splitlines()
  function splitlines(s) {
    if (!s) return [];
    var parts = s.split(RE_LINE_BREAK);
    if (RE_LINE_END.test(s)) parts.pop();
    return parts;
  }

  // str.partition(sep)
  function partition(s, sep) {
    var i = s.indexOf(sep);
    return i < 0 ? [s, "", ""] : [s.slice(0, i), sep, s.slice(i + sep.length)];
  }

  function startsWithAny(s, prefixes) {
    for (var i = 0; i < prefixes.length; i++) if (s.startsWith(prefixes[i])) return true;
    return false;
  }

  function endsWithAny(s, suffixes) {
    for (var i = 0; i < suffixes.length; i++) if (s.endsWith(suffixes[i])) return true;
    return false;
  }

  // Python indexes strings by code point, JavaScript by UTF-16 unit.
  function cpLength(s) {
    if (!/[\ud800-\udfff]/.test(s)) return s.length;
    return Array.from(s).length;
  }

  function cpSlice(s, start, end) {
    if (!/[\ud800-\udfff]/.test(s)) return s.slice(start, end);
    return Array.from(s).slice(start, end).join("");
  }

  // Python's ordering of str (by code point).
  function cpCompare(a, b) {
    var i = 0, j = 0;
    while (i < a.length && j < b.length) {
      var x = a.codePointAt(i), y = b.codePointAt(j);
      if (x !== y) return x < y ? -1 : 1;
      i += x > 0xffff ? 2 : 1;
      j += y > 0xffff ? 2 : 1;
    }
    if (i < a.length) return 1;
    if (j < b.length) return -1;
    return 0;
  }

  // list(dict.fromkeys(items))
  function unique(items) {
    var seen = new Set(), out = [];
    items.forEach(function (x) { if (!seen.has(x)) { seen.add(x); out.push(x); } });
    return out;
  }

  // PurePosixPath(path).name / .parent.name / .suffix
  function pathParts(path) {
    return String(path).split("/").filter(function (p) { return p && p !== "."; });
  }

  function baseName(path) { var p = pathParts(path); return p.length ? p[p.length - 1] : ""; }

  function parentName(path) { var p = pathParts(path); return p.length > 1 ? p[p.length - 2] : ""; }

  function suffix(name) {
    var i = name.lastIndexOf(".");
    return i > 0 && i < name.length - 1 ? name.slice(i) : "";
  }

  // ======================================================== catalog (catalog.py)

  var BROKEN = "quantum-broken", WEAKENED = "quantum-weakened", RESISTANT = "quantum-resistant",
    HYBRID = "hybrid", INSECURE = "insecure";
  var KEM = "kem", KEY_AGREE = "key-agree", SIGNATURE = "signature", PKE = "pke",
    BLOCK_CIPHER = "block-cipher", STREAM_CIPHER = "stream-cipher", AE = "ae", HASH = "hash";

  var KEX_REPLACEMENT = "X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203)";
  var SIG_REPLACEMENT = "ML-DSA-65 (FIPS 204), or a hybrid/composite certificate during transition";

  // [name, primitive, status, classical bits, quantum bits, NIST level, OID, replacement, aliases]
  var ALGORITHM_ROWS = [
    // Key establishment: post-quantum and hybrid (TLS 1.3 named groups)
    ["X25519MLKEM768", KEM, HYBRID, 128, 192, 3, null, "",
      ["x25519_mlkem768", "mlkem768x25519", "mlkem768x25519-sha256"]],
    ["SecP256r1MLKEM768", KEM, HYBRID, 128, 192, 3, null, "", ["secp256r1mlkem768", "p256_mlkem768"]],
    ["SecP384r1MLKEM1024", KEM, HYBRID, 192, 256, 5, null, "", ["secp384r1mlkem1024", "p384_mlkem1024"]],
    ["X25519Kyber768Draft00", KEM, HYBRID, 128, 192, 3, null,
      "X25519MLKEM768 (the pre-standard Kyber draft is obsolete)", ["x25519kyber768draft00", "x25519kyber768"]],
    ["sntrup761x25519-sha512", KEM, HYBRID, 128, 128, 1, null, "", ["sntrup761x25519-sha512@openssh.com"]],
    ["ML-KEM-512", KEM, RESISTANT, 128, 128, 1, "2.16.840.1.101.3.4.4.1", "", ["mlkem512"]],
    ["ML-KEM-768", KEM, RESISTANT, 192, 192, 3, "2.16.840.1.101.3.4.4.2", "", ["mlkem768"]],
    ["ML-KEM-1024", KEM, RESISTANT, 256, 256, 5, "2.16.840.1.101.3.4.4.3", "", ["mlkem1024"]],
    // Key establishment: classical (harvest-now-decrypt-later exposure)
    ["X25519", KEY_AGREE, BROKEN, 128, 0, 0, "1.3.101.110", KEX_REPLACEMENT,
      ["curve25519", "curve25519-sha256", "curve25519-sha256@libssh.org"]],
    ["X448", KEY_AGREE, BROKEN, 224, 0, 0, "1.3.101.111", KEX_REPLACEMENT, []],
    ["ECDH-P256", KEY_AGREE, BROKEN, 128, 0, 0, null, KEX_REPLACEMENT,
      ["secp256r1", "prime256v1", "p-256", "ecdh-sha2-nistp256"]],
    ["ECDH-P384", KEY_AGREE, BROKEN, 192, 0, 0, null, "SecP384r1MLKEM1024 or X25519MLKEM768",
      ["secp384r1", "p-384", "ecdh-sha2-nistp384"]],
    ["ECDH-P521", KEY_AGREE, BROKEN, 256, 0, 0, null, "SecP384r1MLKEM1024",
      ["secp521r1", "p-521", "ecdh-sha2-nistp521"]],
    ["FFDHE", KEY_AGREE, BROKEN, 112, 0, 0, null, KEX_REPLACEMENT,
      ["ffdhe2048", "ffdhe3072", "ffdhe4096", "dhe", "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256"]],
    ["DH-1024", KEY_AGREE, INSECURE, 80, 0, 0, null, KEX_REPLACEMENT,
      ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]],
    ["RSA-KEX", PKE, BROKEN, 112, 0, 0, null,
      KEX_REPLACEMENT + " over TLS 1.3 (also restores forward secrecy)", ["rsa key exchange", "kRSA"]],
    // Signatures: post-quantum
    ["ML-DSA-44", SIGNATURE, RESISTANT, 128, 128, 2, "2.16.840.1.101.3.4.3.17", "", ["mldsa44"]],
    ["ML-DSA-65", SIGNATURE, RESISTANT, 192, 192, 3, "2.16.840.1.101.3.4.3.18", "", ["mldsa65"]],
    ["ML-DSA-87", SIGNATURE, RESISTANT, 256, 256, 5, "2.16.840.1.101.3.4.3.19", "", ["mldsa87"]],
    ["SLH-DSA-SHA2-128s", SIGNATURE, RESISTANT, 128, 128, 1, "2.16.840.1.101.3.4.3.20", "",
      ["slh-dsa-sha2-128s", "slhdsa"]],
    // Signatures: classical
    ["RSA", SIGNATURE, BROKEN, 112, 0, 0, "1.2.840.113549.1.1.1", SIG_REPLACEMENT,
      ["rsaencryption", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "rsassa-pss",
        "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "rsa-pss"]],
    ["ECDSA", SIGNATURE, BROKEN, 128, 0, 0, "1.2.840.10045.2.1", SIG_REPLACEMENT,
      ["ec", "id-ecpublickey", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
        "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384"]],
    ["Ed25519", SIGNATURE, BROKEN, 128, 0, 0, "1.3.101.112", SIG_REPLACEMENT, ["ssh-ed25519", "ed25519"]],
    ["Ed448", SIGNATURE, BROKEN, 224, 0, 0, "1.3.101.113", SIG_REPLACEMENT, []],
    ["DSA", SIGNATURE, INSECURE, 80, 0, 0, "1.2.840.10040.4.1", SIG_REPLACEMENT, ["ssh-dss"]],
    // Symmetric ciphers
    ["AES-256-GCM", AE, RESISTANT, 256, 128, 5, null, "",
      ["aes256-gcm", "aes256-gcm@openssh.com", "tls_aes_256_gcm_sha384"]],
    ["AES-128-GCM", AE, WEAKENED, 128, 64, 1, null, "AES-256-GCM",
      ["aes128-gcm", "aes128-gcm@openssh.com", "tls_aes_128_gcm_sha256"]],
    ["ChaCha20-Poly1305", AE, RESISTANT, 256, 128, 5, null, "",
      ["chacha20", "chacha20-poly1305@openssh.com", "tls_chacha20_poly1305_sha256"]],
    ["AES-256-CBC", BLOCK_CIPHER, RESISTANT, 256, 128, 5, null, "AES-256-GCM (AEAD)",
      ["aes256-cbc", "aes256", "aes256-ctr"]],
    ["AES-128-CBC", BLOCK_CIPHER, WEAKENED, 128, 64, 1, null, "AES-256-GCM", ["aes128-cbc", "aes128", "aes128-ctr"]],
    ["3DES", BLOCK_CIPHER, INSECURE, 112, 56, 0, null, "AES-256-GCM",
      ["des-cbc3", "des-ede3", "3des-cbc", "tripledes"]],
    ["DES", BLOCK_CIPHER, INSECURE, 56, 28, 0, null, "AES-256-GCM", []],
    ["RC4", STREAM_CIPHER, INSECURE, 0, 0, 0, null, "AES-256-GCM or ChaCha20-Poly1305", ["arcfour"]],
    // Hashes / MACs
    ["SHA-512", HASH, RESISTANT, 256, 256, 5, null, "", ["sha512"]],
    ["SHA-384", HASH, RESISTANT, 192, 192, 4, null, "", ["sha384"]],
    ["SHA-256", HASH, RESISTANT, 128, 128, 2, null, "", ["sha256", "hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"]],
    ["SHA-1", HASH, INSECURE, 63, 0, 0, null, "SHA-256 or SHA-384", ["sha1", "hmac-sha1"]],
    ["MD5", HASH, INSECURE, 18, 0, 0, null, "SHA-256 or SHA-384", ["hmac-md5"]],
  ];

  var CATALOG = ALGORITHM_ROWS.map(function (r) {
    return {
      name: r[0], primitive: r[1], status: r[2], classical_bits: r[3], quantum_bits: r[4],
      nist_level: r[5], oid: r[6], replacement: r[7], aliases: r[8].slice(),
      quantum_safe: r[2] === RESISTANT || r[2] === HYBRID,
    };
  });

  var INDEX = new Map();
  CATALOG.forEach(function (alg) {
    [alg.name].concat(alg.aliases, alg.oid ? [alg.oid] : []).forEach(function (key) {
      INDEX.set(key.toLowerCase(), alg);
    });
  });

  // Find an algorithm by canonical name, alias or OID (case-insensitive).
  function lookup(name) {
    if (!name) return null;
    return INDEX.get(strip(String(name)).toLowerCase()) || null;
  }

  function classifyGroup(group) {
    if (!group) return null;
    var g = strip(String(group));
    var alg = lookup(g);
    if (alg) return alg;
    if (g.toLowerCase().startsWith("mlkem")) return lookup("ML-KEM-" + g.slice(5));
    return null;
  }

  var CIPHER_PATTERNS = [
    [/AES[_-]?256[_-]GCM/, "AES-256-GCM"],
    [/AES[_-]?128[_-]GCM/, "AES-128-GCM"],
    [/CHACHA20/, "ChaCha20-Poly1305"],
    [/AES[_-]?256/, "AES-256-CBC"],
    [/AES[_-]?128/, "AES-128-CBC"],
    [/(3DES|DES[_-]CBC3|DES-EDE3)/, "3DES"],
    [/RC4/, "RC4"],
    [/(^|[_-])DES([_-]|$)/, "DES"],
  ];

  // Decompose an OpenSSL or IANA cipher-suite name into its components.
  function parseCipherSuite(name) {
    var n = String(name).toUpperCase();
    var cipher = null;
    for (var i = 0; i < CIPHER_PATTERNS.length; i++) {
      if (CIPHER_PATTERNS[i][0].test(n)) { cipher = lookup(CIPHER_PATTERNS[i][1]); break; }
    }
    if (n.startsWith("TLS_") && n.indexOf("_WITH_") < 0) {
      // TLS 1.3 suites only name the AEAD; key exchange is a separate group.
      return { name: name, kex: "TLS13", auth: "TLS13", cipher: cipher, mac: "AEAD", forward_secrecy: true };
    }
    var kex = n.indexOf("ECDHE") >= 0 ? "ECDHE"
      : n.indexOf("DHE") >= 0 || n.indexOf("EDH") >= 0 ? "DHE"
        : startsWithAny(n, ["PSK", "TLS_PSK"]) ? "PSK" : "RSA";
    var auth = n.indexOf("ECDSA") >= 0 ? "ECDSA" : n.indexOf("PSK") >= 0 ? "PSK" : "RSA";
    var mac = n.indexOf("GCM") >= 0 || n.indexOf("CHACHA") >= 0 || n.indexOf("CCM") >= 0 ? "AEAD"
      : n.endsWith("SHA384") ? "SHA-384" : n.endsWith("SHA256") ? "SHA-256"
        : n.endsWith("MD5") ? "MD5" : "SHA-1";
    return { name: name, kex: kex, auth: auth, cipher: cipher, mac: mac,
      forward_secrecy: kex === "ECDHE" || kex === "DHE" };
  }

  var SIG_OIDS = {
    "1.2.840.113549.1.1.5": ["RSA", "SHA-1"],
    "1.2.840.113549.1.1.4": ["RSA", "MD5"],
    "1.2.840.113549.1.1.11": ["RSA", "SHA-256"],
    "1.2.840.113549.1.1.12": ["RSA", "SHA-384"],
    "1.2.840.113549.1.1.13": ["RSA", "SHA-512"],
    "1.2.840.113549.1.1.10": ["RSA", "SHA-256"], // RSASSA-PSS (hash in params)
    "1.2.840.10045.4.1": ["ECDSA", "SHA-1"],
    "1.2.840.10045.4.3.2": ["ECDSA", "SHA-256"],
    "1.2.840.10045.4.3.3": ["ECDSA", "SHA-384"],
    "1.2.840.10045.4.3.4": ["ECDSA", "SHA-512"],
    "1.3.101.112": ["Ed25519", null],
    "1.3.101.113": ["Ed448", null],
    "2.16.840.1.101.3.4.3.17": ["ML-DSA-44", null],
    "2.16.840.1.101.3.4.3.18": ["ML-DSA-65", null],
    "2.16.840.1.101.3.4.3.19": ["ML-DSA-87", null],
  };

  // ======================================================== OpenSSL cipher strings
  //
  // config_scanner.ciphers_to_algs() asks the local OpenSSL to expand a cipher
  // string (SSL_CTX_set_cipher_list).  This replays that function over a table
  // probed from OpenSSL 3.5: the list of suites starts in OpenSSL's default
  // order, all inactive; each item of the string adds (plain), deletes (-),
  // moves to the end (+) or permanently removes (!) the suites it selects, and
  // "A+B" selects the suites in both A and B.

  // ---- BEGIN GENERATED CIPHER TABLE (scripts/gen_cipher_table.py; do not edit by hand) ----
  // Probed from OpenSSL 3.5.7 9 Jun 2026.
  var CIPHER_TABLE = {
    openssl: "OpenSSL 3.5.7 9 Jun 2026",
    // What a cipher string starting with DEFAULT expands to first.
    defaultRules: "ALL:!COMPLEMENTOFDEFAULT:!eNULL",
    // Every TLS <= 1.2 suite in OpenSSL's default preference order:
    // [OpenSSL name, IANA name, strength bits, protocol, aliases selecting it]
    suites: [
      ["ECDHE-ECDSA-AES256-GCM-SHA384"  , "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS AES256 ECDH kECDHE kEECDH ECDHE EECDH AESGCM aECDSA ECDSA"],
      ["ECDHE-RSA-AES256-GCM-SHA384"    , "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES256 ECDH kECDHE kEECDH ECDHE EECDH AESGCM"],
      ["DHE-DSS-AES256-GCM-SHA384"      , "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT FIPS AES256 DH kDHE kEDH DHE EDH AESGCM aDSS DSS"],
      ["DHE-RSA-AES256-GCM-SHA384"      , "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES256 DH kDHE kEDH DHE EDH AESGCM"],
      ["ECDHE-ECDSA-CHACHA20-POLY1305"  , "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 ECDH kECDHE kEECDH ECDHE EECDH aECDSA ECDSA CHACHA20"],
      ["ECDHE-RSA-CHACHA20-POLY1305"    , "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 aRSA ECDH kECDHE kEECDH ECDHE EECDH CHACHA20"],
      ["DHE-RSA-CHACHA20-POLY1305"      , "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 aRSA DH kDHE kEDH DHE EDH CHACHA20"],
      ["ECDHE-ECDSA-AES256-CCM"         , "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT AES256 ECDH kECDHE kEECDH ECDHE EECDH AESCCM aECDSA ECDSA"],
      ["DHE-RSA-AES256-CCM"             , "TLS_DHE_RSA_WITH_AES_256_CCM", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES256 DH kDHE kEDH DHE EDH AESCCM"],
      ["ECDHE-ECDSA-ARIA256-GCM-SHA384" , "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT ECDH kECDHE kEECDH ECDHE EECDH aECDSA ARIA ARIAGCM ECDSA ARIA256"],
      ["ECDHE-ARIA256-GCM-SHA384"       , "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA ECDH kECDHE kEECDH ECDHE EECDH ARIA ARIAGCM ARIA256"],
      ["DHE-DSS-ARIA256-GCM-SHA384"     , "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT DH kDHE kEDH DHE EDH ARIA ARIAGCM aDSS DSS ARIA256"],
      ["DHE-RSA-ARIA256-GCM-SHA384"     , "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA DH kDHE kEDH DHE EDH ARIA ARIAGCM ARIA256"],
      ["ADH-AES256-GCM-SHA384"          , "TLS_DH_anon_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT FIPS AES256 DH kDHE kEDH AESGCM aNULL ADH"],
      ["ECDHE-ECDSA-AES128-GCM-SHA256"  , "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS AES128 ECDH kECDHE kEECDH ECDHE EECDH AESGCM aECDSA ECDSA"],
      ["ECDHE-RSA-AES128-GCM-SHA256"    , "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES128 ECDH kECDHE kEECDH ECDHE EECDH AESGCM"],
      ["DHE-DSS-AES128-GCM-SHA256"      , "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT FIPS AES128 DH kDHE kEDH DHE EDH AESGCM aDSS DSS"],
      ["DHE-RSA-AES128-GCM-SHA256"      , "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES128 DH kDHE kEDH DHE EDH AESGCM"],
      ["ECDHE-ECDSA-AES128-CCM"         , "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT AES128 ECDH kECDHE kEECDH ECDHE EECDH AESCCM aECDSA ECDSA"],
      ["DHE-RSA-AES128-CCM"             , "TLS_DHE_RSA_WITH_AES_128_CCM", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES128 DH kDHE kEDH DHE EDH AESCCM"],
      ["ECDHE-ECDSA-ARIA128-GCM-SHA256" , "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT ECDH kECDHE kEECDH ECDHE EECDH aECDSA ARIA ARIAGCM ECDSA ARIA128"],
      ["ECDHE-ARIA128-GCM-SHA256"       , "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA ECDH kECDHE kEECDH ECDHE EECDH ARIA ARIAGCM ARIA128"],
      ["DHE-DSS-ARIA128-GCM-SHA256"     , "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT DH kDHE kEDH DHE EDH ARIA ARIAGCM aDSS DSS ARIA128"],
      ["DHE-RSA-ARIA128-GCM-SHA256"     , "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA DH kDHE kEDH DHE EDH ARIA ARIAGCM ARIA128"],
      ["ADH-AES128-GCM-SHA256"          , "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT FIPS AES128 DH kDHE kEDH AESGCM aNULL ADH"],
      ["ECDHE-ECDSA-AES256-CCM8"        , "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT AES256 ECDH kECDHE kEECDH ECDHE EECDH AESCCM aECDSA ECDSA AESCCM8 MEDIUM"],
      ["ECDHE-ECDSA-AES128-CCM8"        , "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT AES128 ECDH kECDHE kEECDH ECDHE EECDH AESCCM aECDSA ECDSA AESCCM8 MEDIUM"],
      ["DHE-RSA-AES256-CCM8"            , "TLS_DHE_RSA_WITH_AES_256_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES256 DH kDHE kEDH DHE EDH AESCCM AESCCM8 MEDIUM"],
      ["DHE-RSA-AES128-CCM8"            , "TLS_DHE_RSA_WITH_AES_128_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES128 DH kDHE kEDH DHE EDH AESCCM AESCCM8 MEDIUM"],
      ["ECDHE-ECDSA-AES256-SHA384"      , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC FIPS AES256 ECDH kECDHE kEECDH ECDHE EECDH aECDSA ECDSA SHA384"],
      ["ECDHE-RSA-AES256-SHA384"        , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES256 ECDH kECDHE kEECDH ECDHE EECDH SHA384"],
      ["DHE-RSA-AES256-SHA256"          , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES256 DH kDHE kEDH SHA256 DHE EDH"],
      ["DHE-DSS-AES256-SHA256"          , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT CBC FIPS AES256 DH kDHE kEDH SHA256 DHE EDH aDSS DSS"],
      ["ECDHE-ECDSA-CAMELLIA256-SHA384" , "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC ECDH kECDHE kEECDH CAMELLIA ECDHE EECDH aECDSA ECDSA SHA384 CAMELLIA256"],
      ["ECDHE-RSA-CAMELLIA256-SHA384"   , "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA ECDH kECDHE kEECDH CAMELLIA ECDHE EECDH SHA384 CAMELLIA256"],
      ["DHE-RSA-CAMELLIA256-SHA256"     , "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA DH kDHE kEDH SHA256 DHE EDH CAMELLIA CAMELLIA256"],
      ["DHE-DSS-CAMELLIA256-SHA256"     , "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC DH kDHE kEDH SHA256 DHE EDH CAMELLIA aDSS CAMELLIA256 DSS"],
      ["ADH-AES256-SHA256"              , "TLS_DH_anon_WITH_AES_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT CBC FIPS AES256 DH kDHE kEDH SHA256 aNULL ADH"],
      ["ADH-CAMELLIA256-SHA256"         , "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC DH kDHE kEDH SHA256 CAMELLIA CAMELLIA256 aNULL ADH"],
      ["ECDHE-ECDSA-AES128-SHA256"      , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC FIPS AES128 SHA256 ECDH kECDHE kEECDH ECDHE EECDH aECDSA ECDSA"],
      ["ECDHE-RSA-AES128-SHA256"        , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES128 SHA256 ECDH kECDHE kEECDH ECDHE EECDH"],
      ["DHE-RSA-AES128-SHA256"          , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES128 DH kDHE kEDH SHA256 DHE EDH"],
      ["DHE-DSS-AES128-SHA256"          , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT CBC FIPS AES128 DH kDHE kEDH SHA256 DHE EDH aDSS DSS"],
      ["ECDHE-ECDSA-CAMELLIA128-SHA256" , "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC SHA256 ECDH kECDHE kEECDH CAMELLIA ECDHE EECDH aECDSA ECDSA CAMELLIA128"],
      ["ECDHE-RSA-CAMELLIA128-SHA256"   , "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA SHA256 ECDH kECDHE kEECDH CAMELLIA ECDHE EECDH CAMELLIA128"],
      ["DHE-RSA-CAMELLIA128-SHA256"     , "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA DH kDHE kEDH SHA256 DHE EDH CAMELLIA CAMELLIA128"],
      ["DHE-DSS-CAMELLIA128-SHA256"     , "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC DH kDHE kEDH SHA256 DHE EDH CAMELLIA aDSS CAMELLIA128 DSS"],
      ["ADH-AES128-SHA256"              , "TLS_DH_anon_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT CBC FIPS AES128 DH kDHE kEDH SHA256 aNULL ADH"],
      ["ADH-CAMELLIA128-SHA256"         , "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC DH kDHE kEDH SHA256 CAMELLIA CAMELLIA128 aNULL ADH"],
      ["ECDHE-ECDSA-AES256-SHA"         , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 256, "TLSv1.0", "ALL HIGH AES CBC FIPS SHA SHA1 AES256 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH aECDSA ECDSA"],
      ["ECDHE-RSA-AES256-SHA"           , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256, "TLSv1.0", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES256 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH"],
      ["DHE-RSA-AES256-SHA"             , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES256 DH kDHE kEDH SSLv3 DHE EDH"],
      ["DHE-DSS-AES256-SHA"             , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES256 DH kDHE kEDH SSLv3 DHE EDH aDSS DSS"],
      ["DHE-RSA-CAMELLIA256-SHA"        , "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 256, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA SHA SHA1 DH kDHE kEDH SSLv3 DHE EDH CAMELLIA CAMELLIA256"],
      ["DHE-DSS-CAMELLIA256-SHA"        , "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 256, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC SHA SHA1 DH kDHE kEDH SSLv3 DHE EDH CAMELLIA aDSS CAMELLIA256 DSS"],
      ["AECDH-AES256-SHA"               , "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 256, "TLSv1.0", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES256 TLSv1 TLSv1.0 ECDH kECDHE kEECDH aNULL AECDH"],
      ["ADH-AES256-SHA"                 , "TLS_DH_anon_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES256 DH kDHE kEDH SSLv3 aNULL ADH"],
      ["ADH-CAMELLIA256-SHA"            , "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", 256, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC SHA SHA1 DH kDHE kEDH SSLv3 CAMELLIA CAMELLIA256 aNULL ADH"],
      ["ECDHE-ECDSA-AES128-SHA"         , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 128, "TLSv1.0", "ALL HIGH AES CBC FIPS SHA SHA1 AES128 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH aECDSA ECDSA"],
      ["ECDHE-RSA-AES128-SHA"           , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128, "TLSv1.0", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES128 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH"],
      ["DHE-RSA-AES128-SHA"             , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES128 DH kDHE kEDH SSLv3 DHE EDH"],
      ["DHE-DSS-AES128-SHA"             , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES128 DH kDHE kEDH SSLv3 DHE EDH aDSS DSS"],
      ["DHE-RSA-CAMELLIA128-SHA"        , "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 128, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA SHA SHA1 DH kDHE kEDH SSLv3 DHE EDH CAMELLIA CAMELLIA128"],
      ["DHE-DSS-CAMELLIA128-SHA"        , "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 128, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC SHA SHA1 DH kDHE kEDH SSLv3 DHE EDH CAMELLIA aDSS CAMELLIA128 DSS"],
      ["AECDH-AES128-SHA"               , "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 128, "TLSv1.0", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES128 TLSv1 TLSv1.0 ECDH kECDHE kEECDH aNULL AECDH"],
      ["ADH-AES128-SHA"                 , "TLS_DH_anon_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC FIPS SHA SHA1 AES128 DH kDHE kEDH SSLv3 aNULL ADH"],
      ["ADH-CAMELLIA128-SHA"            , "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", 128, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC SHA SHA1 DH kDHE kEDH SSLv3 CAMELLIA CAMELLIA128 aNULL ADH"],
      ["ECDHE-ECDSA-NULL-SHA"           , "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0, "TLSv1.0", "SHA SHA1 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH COMPLEMENTOFALL eNULL NULL aECDSA ECDSA"],
      ["ECDHE-RSA-NULL-SHA"             , "TLS_ECDHE_RSA_WITH_NULL_SHA", 0, "TLSv1.0", "aRSA SHA SHA1 TLSv1 TLSv1.0 ECDH kECDHE kEECDH ECDHE EECDH COMPLEMENTOFALL eNULL NULL"],
      ["RSA-PSK-AES256-GCM-SHA384"      , "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS PSK AES256 AESGCM kRSAPSK"],
      ["DHE-PSK-AES256-GCM-SHA384"      , "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS PSK aPSK AES256 AESGCM kDHEPSK"],
      ["RSA-PSK-CHACHA20-POLY1305"      , "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 aRSA PSK kRSAPSK CHACHA20"],
      ["DHE-PSK-CHACHA20-POLY1305"      , "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 PSK aPSK kDHEPSK CHACHA20"],
      ["ECDHE-PSK-CHACHA20-POLY1305"    , "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 PSK aPSK kECDHEPSK CHACHA20"],
      ["DHE-PSK-AES256-CCM"             , "TLS_DHE_PSK_WITH_AES_256_CCM", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES256 AESCCM kDHEPSK"],
      ["RSA-PSK-ARIA256-GCM-SHA384"     , "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA PSK ARIA ARIAGCM kRSAPSK ARIA256"],
      ["DHE-PSK-ARIA256-GCM-SHA384"     , "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK kDHEPSK ARIA ARIAGCM ARIA256"],
      ["AES256-GCM-SHA384"              , "TLS_RSA_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES256 kRSA RSA AESGCM"],
      ["AES256-CCM"                     , "TLS_RSA_WITH_AES_256_CCM", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES256 AESCCM kRSA RSA"],
      ["ARIA256-GCM-SHA384"             , "TLS_RSA_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA kRSA RSA ARIA ARIAGCM ARIA256"],
      ["PSK-AES256-GCM-SHA384"          , "TLS_PSK_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS PSK aPSK AES256 AESGCM kPSK"],
      ["PSK-CHACHA20-POLY1305"          , "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 PSK aPSK kPSK CHACHA20"],
      ["PSK-AES256-CCM"                 , "TLS_PSK_WITH_AES_256_CCM", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES256 AESCCM kPSK"],
      ["PSK-ARIA256-GCM-SHA384"         , "TLS_PSK_WITH_ARIA_256_GCM_SHA384", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK kPSK ARIA ARIAGCM ARIA256"],
      ["RSA-PSK-AES128-GCM-SHA256"      , "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS PSK AES128 AESGCM kRSAPSK"],
      ["DHE-PSK-AES128-GCM-SHA256"      , "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS PSK aPSK AES128 AESGCM kDHEPSK"],
      ["DHE-PSK-AES128-CCM"             , "TLS_DHE_PSK_WITH_AES_128_CCM", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES128 AESCCM kDHEPSK"],
      ["RSA-PSK-ARIA128-GCM-SHA256"     , "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA PSK ARIA ARIAGCM kRSAPSK ARIA128"],
      ["DHE-PSK-ARIA128-GCM-SHA256"     , "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK kDHEPSK ARIA ARIAGCM ARIA128"],
      ["AES128-GCM-SHA256"              , "TLS_RSA_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 aRSA FIPS AES128 kRSA RSA AESGCM"],
      ["AES128-CCM"                     , "TLS_RSA_WITH_AES_128_CCM", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES128 AESCCM kRSA RSA"],
      ["ARIA128-GCM-SHA256"             , "TLS_RSA_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT aRSA kRSA RSA ARIA ARIAGCM ARIA128"],
      ["PSK-AES128-GCM-SHA256"          , "TLS_PSK_WITH_AES_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 FIPS PSK aPSK AES128 AESGCM kPSK"],
      ["PSK-AES128-CCM"                 , "TLS_PSK_WITH_AES_128_CCM", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES128 AESCCM kPSK"],
      ["PSK-ARIA128-GCM-SHA256"         , "TLS_PSK_WITH_ARIA_128_GCM_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK kPSK ARIA ARIAGCM ARIA128"],
      ["DHE-PSK-AES256-CCM8"            , "TLS_PSK_DHE_WITH_AES_256_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES256 AESCCM kDHEPSK AESCCM8 MEDIUM"],
      ["DHE-PSK-AES128-CCM8"            , "TLS_PSK_DHE_WITH_AES_128_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES128 AESCCM kDHEPSK AESCCM8 MEDIUM"],
      ["AES256-CCM8"                    , "TLS_RSA_WITH_AES_256_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES256 AESCCM kRSA RSA AESCCM8 MEDIUM"],
      ["AES128-CCM8"                    , "TLS_RSA_WITH_AES_128_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT aRSA AES128 AESCCM kRSA RSA AESCCM8 MEDIUM"],
      ["PSK-AES256-CCM8"                , "TLS_PSK_WITH_AES_256_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES256 AESCCM kPSK AESCCM8 MEDIUM"],
      ["PSK-AES128-CCM8"                , "TLS_PSK_WITH_AES_128_CCM_8", 64, "TLSv1.2", "ALL AES TLSv1.2 COMPLEMENTOFDEFAULT PSK aPSK AES128 AESCCM kPSK AESCCM8 MEDIUM"],
      ["AES256-SHA256"                  , "TLS_RSA_WITH_AES_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES256 SHA256 kRSA RSA"],
      ["CAMELLIA256-SHA256"             , "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", 256, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA SHA256 CAMELLIA kRSA RSA CAMELLIA256"],
      ["AES128-SHA256"                  , "TLS_RSA_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH AES TLSv1.2 CBC aRSA FIPS AES128 SHA256 kRSA RSA"],
      ["CAMELLIA128-SHA256"             , "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.2", "ALL HIGH TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA SHA256 CAMELLIA kRSA RSA CAMELLIA128"],
      ["AECDH-NULL-SHA"                 , "TLS_ECDH_anon_WITH_NULL_SHA", 0, "TLSv1.0", "SHA SHA1 TLSv1 TLSv1.0 ECDH kECDHE kEECDH COMPLEMENTOFALL eNULL NULL aNULL AECDH"],
      ["ECDHE-PSK-AES256-CBC-SHA384"    , "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES256 TLSv1 TLSv1.0 SHA384 kECDHEPSK"],
      ["ECDHE-PSK-AES256-CBC-SHA"       , "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", 256, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES256 TLSv1 TLSv1.0 kECDHEPSK"],
      ["SRP-DSS-AES-256-CBC-SHA"        , "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC SHA SHA1 AES256 SSLv3 aDSS DSS kSRP SRP"],
      ["NULL-SHA256"                    , "TLS_RSA_WITH_NULL_SHA256", 0, "TLSv1.2", "TLSv1.2 aRSA SHA256 kRSA RSA COMPLEMENTOFALL eNULL NULL"],
      ["SRP-RSA-AES-256-CBC-SHA"        , "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC aRSA SHA SHA1 AES256 SSLv3 kSRP SRP"],
      ["SRP-AES-256-CBC-SHA"            , "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC SHA SHA1 AES256 SSLv3 kSRP SRP aSRP"],
      ["RSA-PSK-AES256-CBC-SHA384"      , "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH AES CBC aRSA FIPS PSK AES256 TLSv1 TLSv1.0 SHA384 kRSAPSK"],
      ["DHE-PSK-AES256-CBC-SHA384"      , "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES256 TLSv1 TLSv1.0 kDHEPSK SHA384"],
      ["RSA-PSK-AES256-CBC-SHA"         , "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC aRSA FIPS PSK SHA SHA1 AES256 SSLv3 kRSAPSK"],
      ["DHE-PSK-AES256-CBC-SHA"         , "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES256 SSLv3 kDHEPSK"],
      ["ECDHE-PSK-CAMELLIA256-SHA384"   , "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 CAMELLIA SHA384 CAMELLIA256 kECDHEPSK"],
      ["RSA-PSK-CAMELLIA256-SHA384"     , "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA PSK TLSv1 TLSv1.0 CAMELLIA SHA384 CAMELLIA256 kRSAPSK"],
      ["DHE-PSK-CAMELLIA256-SHA384"     , "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 CAMELLIA kDHEPSK SHA384 CAMELLIA256"],
      ["AES256-SHA"                     , "TLS_RSA_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES256 SSLv3 kRSA RSA"],
      ["CAMELLIA256-SHA"                , "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 256, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA SHA SHA1 SSLv3 CAMELLIA kRSA RSA CAMELLIA256"],
      ["PSK-AES256-CBC-SHA384"          , "TLS_PSK_WITH_AES_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES256 TLSv1 TLSv1.0 kPSK SHA384"],
      ["PSK-AES256-CBC-SHA"             , "TLS_PSK_WITH_AES_256_CBC_SHA", 256, "SSLv3", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES256 SSLv3 kPSK"],
      ["PSK-CAMELLIA256-SHA384"         , "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", 256, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 CAMELLIA kPSK SHA384 CAMELLIA256"],
      ["ECDHE-PSK-AES128-CBC-SHA256"    , "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES128 TLSv1 TLSv1.0 SHA256 kECDHEPSK"],
      ["ECDHE-PSK-AES128-CBC-SHA"       , "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 128, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES128 TLSv1 TLSv1.0 kECDHEPSK"],
      ["SRP-DSS-AES-128-CBC-SHA"        , "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES COMPLEMENTOFDEFAULT CBC SHA SHA1 AES128 SSLv3 aDSS DSS kSRP SRP"],
      ["SRP-RSA-AES-128-CBC-SHA"        , "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC aRSA SHA SHA1 AES128 SSLv3 kSRP SRP"],
      ["SRP-AES-128-CBC-SHA"            , "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC SHA SHA1 AES128 SSLv3 kSRP SRP aSRP"],
      ["RSA-PSK-AES128-CBC-SHA256"      , "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH AES CBC aRSA FIPS PSK AES128 TLSv1 TLSv1.0 SHA256 kRSAPSK"],
      ["DHE-PSK-AES128-CBC-SHA256"      , "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES128 TLSv1 TLSv1.0 SHA256 kDHEPSK"],
      ["RSA-PSK-AES128-CBC-SHA"         , "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC aRSA FIPS PSK SHA SHA1 AES128 SSLv3 kRSAPSK"],
      ["DHE-PSK-AES128-CBC-SHA"         , "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES128 SSLv3 kDHEPSK"],
      ["ECDHE-PSK-CAMELLIA128-SHA256"   , "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 SHA256 CAMELLIA CAMELLIA128 kECDHEPSK"],
      ["RSA-PSK-CAMELLIA128-SHA256"     , "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA PSK TLSv1 TLSv1.0 SHA256 CAMELLIA CAMELLIA128 kRSAPSK"],
      ["DHE-PSK-CAMELLIA128-SHA256"     , "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 SHA256 CAMELLIA kDHEPSK CAMELLIA128"],
      ["AES128-SHA"                     , "TLS_RSA_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC aRSA FIPS SHA SHA1 AES128 SSLv3 kRSA RSA"],
      ["CAMELLIA128-SHA"                , "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 128, "SSLv3", "ALL HIGH COMPLEMENTOFDEFAULT CBC aRSA SHA SHA1 SSLv3 CAMELLIA kRSA RSA CAMELLIA128"],
      ["PSK-AES128-CBC-SHA256"          , "TLS_PSK_WITH_AES_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH AES CBC FIPS PSK aPSK AES128 TLSv1 TLSv1.0 SHA256 kPSK"],
      ["PSK-AES128-CBC-SHA"             , "TLS_PSK_WITH_AES_128_CBC_SHA", 128, "SSLv3", "ALL HIGH AES CBC FIPS PSK aPSK SHA SHA1 AES128 SSLv3 kPSK"],
      ["PSK-CAMELLIA128-SHA256"         , "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", 128, "TLSv1.0", "ALL HIGH COMPLEMENTOFDEFAULT CBC PSK aPSK TLSv1 TLSv1.0 SHA256 CAMELLIA kPSK CAMELLIA128"],
      ["ECDHE-PSK-NULL-SHA384"          , "TLS_ECDHE_PSK_WITH_NULL_SHA384", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 COMPLEMENTOFALL eNULL NULL SHA384 kECDHEPSK"],
      ["ECDHE-PSK-NULL-SHA256"          , "TLS_ECDHE_PSK_WITH_NULL_SHA256", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 SHA256 COMPLEMENTOFALL eNULL NULL kECDHEPSK"],
      ["ECDHE-PSK-NULL-SHA"             , "TLS_ECDHE_PSK_WITH_NULL_SHA", 0, "TLSv1.0", "PSK aPSK SHA SHA1 TLSv1 TLSv1.0 COMPLEMENTOFALL eNULL NULL kECDHEPSK"],
      ["RSA-PSK-NULL-SHA384"            , "TLS_RSA_PSK_WITH_NULL_SHA384", 0, "TLSv1.0", "aRSA PSK TLSv1 TLSv1.0 COMPLEMENTOFALL eNULL NULL SHA384 kRSAPSK"],
      ["RSA-PSK-NULL-SHA256"            , "TLS_RSA_PSK_WITH_NULL_SHA256", 0, "TLSv1.0", "aRSA PSK TLSv1 TLSv1.0 SHA256 COMPLEMENTOFALL eNULL NULL kRSAPSK"],
      ["DHE-PSK-NULL-SHA384"            , "TLS_DHE_PSK_WITH_NULL_SHA384", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 COMPLEMENTOFALL eNULL kDHEPSK NULL SHA384"],
      ["DHE-PSK-NULL-SHA256"            , "TLS_DHE_PSK_WITH_NULL_SHA256", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 SHA256 COMPLEMENTOFALL eNULL kDHEPSK NULL"],
      ["RSA-PSK-NULL-SHA"               , "TLS_RSA_PSK_WITH_NULL_SHA", 0, "SSLv3", "aRSA PSK SHA SHA1 SSLv3 COMPLEMENTOFALL eNULL NULL kRSAPSK"],
      ["DHE-PSK-NULL-SHA"               , "TLS_DHE_PSK_WITH_NULL_SHA", 0, "SSLv3", "PSK aPSK SHA SHA1 SSLv3 COMPLEMENTOFALL eNULL kDHEPSK NULL"],
      ["NULL-SHA"                       , "TLS_RSA_WITH_NULL_SHA", 0, "SSLv3", "aRSA SHA SHA1 SSLv3 kRSA RSA COMPLEMENTOFALL eNULL NULL"],
      ["NULL-MD5"                       , "TLS_RSA_WITH_NULL_MD5", 0, "SSLv3", "aRSA SSLv3 kRSA RSA COMPLEMENTOFALL eNULL NULL MD5"],
      ["PSK-NULL-SHA384"                , "TLS_PSK_WITH_NULL_SHA384", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 COMPLEMENTOFALL eNULL kPSK NULL SHA384"],
      ["PSK-NULL-SHA256"                , "TLS_PSK_WITH_NULL_SHA256", 0, "TLSv1.0", "PSK aPSK TLSv1 TLSv1.0 SHA256 COMPLEMENTOFALL eNULL kPSK NULL"],
      ["PSK-NULL-SHA"                   , "TLS_PSK_WITH_NULL_SHA", 0, "SSLv3", "PSK aPSK SHA SHA1 SSLv3 COMPLEMENTOFALL eNULL kPSK NULL"],
    ],
    // "A+B" where B contradicts A selects nothing and OpenSSL skips the rest
    // of that item.  Hex bitmap over the alias list, in this order:
    aliases: "ALL HIGH AES TLSv1.2 COMPLEMENTOFDEFAULT CBC aRSA FIPS PSK aPSK SHA SHA1 AES128 AES256 DH kDHE kEDH TLSv1 TLSv1.0 SHA256 SSLv3 ECDH kECDHE kEECDH DHE EDH CAMELLIA ECDHE EECDH AESCCM kRSA RSA AESGCM COMPLEMENTOFALL eNULL kDHEPSK kPSK NULL aECDSA ARIA ARIAGCM ECDSA SHA384 aDSS CAMELLIA128 CAMELLIA256 DSS kRSAPSK aNULL ADH AESCCM8 kECDHEPSK MEDIUM ARIA128 ARIA256 CHACHA20 kSRP SRP AECDH aSRP MD5 EDH-DSS-DES-CBC3-SHA EDH-RSA-DES-CBC3-SHA LOW",
    contradicts: {
      "ALL"                   : "0000002600000000",
      "HIGH"                  : "8010000000000080",
      "AES"                   : "60e031a604000000",
      "TLSv1.2"               : "0000000000160000",
      "COMPLEMENTOFDEFAULT"   : "0000000000000000",
      "CBC"                   : "00e401a720000000",
      "aRSA"                  : "2c034a4000000200",
      "FIPS"                  : "8010002600000002",
      "PSK"                   : "67020000dbe1c000",
      "aPSK"                  : "6c034a4080000040",
      "SHA"                   : "1000040000080000",
      "SHA1"                  : "1000040000080000",
      "AES128"                : "60e031a604002000",
      "AES256"                : "60e031a604001000",
      "DH"                    : "07088018d8e00100",
      "kDHE"                  : "07088018d8e00100",
      "kEDH"                  : "07088018d8e00100",
      "TLSv1"                 : "0000000000100008",
      "TLSv1.0"               : "0000000000100008",
      "SHA256"                : "7000040000000c00",
      "SSLv3"                 : "0000000000060008",
      "ECDH"                  : "630a8018c301c100",
      "kECDHE"                : "630a8018c301c100",
      "kEECDH"                : "630a8018c301c100",
      "DHE"                   : "070b8018d8e00100",
      "EDH"                   : "070b8018d8e00100",
      "CAMELLIA"              : "60e401a720003004",
      "ECDHE"                 : "670b8018c301c100",
      "EECDH"                 : "670b8018c301c100",
      "AESCCM"                : "60e031a704000020",
      "kRSA"                  : "670a80181be1c100",
      "RSA"                   : "6f0bca581be1c300",
      "AESGCM"                : "60e431a624000020",
      "COMPLEMENTOFALL"       : "60e43181240030a5",
      "eNULL"                 : "60e43181240030a5",
      "kDHEPSK"               : "670a8010dbe1c000",
      "kPSK"                  : "670a8008dbe1c000",
      "NULL"                  : "60e43181240030a5",
      "aECDSA"                : "6c03480080000240",
      "ARIA"                  : "6084302724003024",
      "ARIAGCM"               : "6084302724003024",
      "ECDSA"                 : "6c03480080000240",
      "SHA384"                : "7000000000080c00",
      "aDSS"                  : "4c03024080000240",
      "CAMELLIA128"           : "60e421a720003004",
      "CAMELLIA256"           : "60e411a720003004",
      "DSS"                   : "4c03024080000240",
      "kRSAPSK"               : "670a0018dbe1c000",
      "aNULL"                 : "68004a409b000240",
      "ADH"                   : "6f08ca58dbe00340",
      "AESCCM8"               : "60e031a704000020",
      "kECDHEPSK"             : "67028018dbe1c000",
      "MEDIUM"                : "e000000000000082",
      "ARIA128"               : "60c4302724003024",
      "ARIA256"               : "60a4302724003024",
      "CHACHA20"              : "606431a724003024",
      "kSRP"                  : "640a8018dbe1c100",
      "SRP"                   : "640a8018dbe1c100",
      "AECDH"                 : "6b0aca58db01c340",
      "aSRP"                  : "64034a4080000240",
      "MD5"                   : "6000040000080c00",
      "EDH-DSS-DES-CBC3-SHA"  : "dfffb7fffce83344",
      "EDH-RSA-DES-CBC3-SHA"  : "bffffffffce83304",
      "LOW"                   : "6010000000000082",
    },
    // Aliases that set OpenSSL's strength mask; the first one in an item
    // replaces (rather than narrows) an earlier COMPLEMENTOFDEFAULT.
    strength: "HIGH FIPS MEDIUM LOW",
    notDefault: "COMPLEMENTOFDEFAULT",
    // Aliases that never contradict an explicit suite name in "NAME+ALIAS".
    nameTransparent: "TLSv1.2 COMPLEMENTOFDEFAULT TLSv1 TLSv1.0 SSLv3",
    // Pairs of different suite names that do not contradict in "N1+N2".
    namePairs: [],
  };
  // ---- END GENERATED CIPHER TABLE ----

  var SUITES = [], SUITE_BY_NAME = new Map(), ALIASES = new Map();
  var STRENGTH = new Set(), NAME_TRANSPARENT = new Set(), NAME_PAIRS = new Set(), NOT_DEFAULT = null;

  (function loadCipherTable() {
    var aliasNames = CIPHER_TABLE.aliases.split(" ");
    aliasNames.forEach(function (a, i) {
      ALIASES.set(a, { name: a, index: i, members: new Set(), contradicts: new Set() });
    });
    CIPHER_TABLE.suites.forEach(function (row, i) {
      var suite = { index: i, name: row[0], stdname: row[1], strength: row[2], protocol: row[3],
        aliases: row[4] ? row[4].split(" ") : [] };
      SUITES.push(suite);
      SUITE_BY_NAME.set(suite.name, suite);
      if (suite.stdname) SUITE_BY_NAME.set(suite.stdname, suite);
      suite.aliases.forEach(function (a) { ALIASES.get(a).members.add(i); });
    });
    aliasNames.forEach(function (a) {
      var hex = CIPHER_TABLE.contradicts[a], set = ALIASES.get(a).contradicts;
      for (var d = 0; d < hex.length; d++) {
        var nibble = parseInt(hex[hex.length - 1 - d], 16);
        for (var b = 0; b < 4; b++) if (nibble & (1 << b)) set.add(aliasNames[d * 4 + b]);
      }
    });
    CIPHER_TABLE.strength.split(" ").forEach(function (a) { STRENGTH.add(a); });
    CIPHER_TABLE.nameTransparent.split(" ").forEach(function (a) { NAME_TRANSPARENT.add(a); });
    CIPHER_TABLE.namePairs.forEach(function (p) { NAME_PAIRS.add(p[0] + " " + p[1]); });
    NOT_DEFAULT = CIPHER_TABLE.notDefault;
    // OpenSSL's strength mask: every suite has a bit (eNULL suites have
    // STRONG_NONE, which no alias names).
    SUITES.forEach(function (s) {
      s.strong = new Set(s.aliases.filter(function (a) { return STRENGTH.has(a); }));
      if (!s.strong.size) s.strong.add("NONE");
      s.notDefault = s.aliases.indexOf(NOT_DEFAULT) >= 0;
    });
  })();

  var ADD = 1, KILL = 2, DEL = 3, ORD = 4, SPECIAL = 5;

  function isSeparator(ch) { return ch === ":" || ch === " " || ch === ";" || ch === ","; }

  function isNameChar(ch) { return /^[A-Za-z0-9\-_.=]$/.test(ch); }

  function intersects(a, b) {
    var hit = false;
    a.forEach(function (x) { if (b.has(x)) hit = true; });
    return hit;
  }

  // One "+"-joined item.  OpenSSL ANDs bit masks per category; this keeps the
  // equivalent sets.  Returns false where OpenSSL gives up on the rule.
  function addComponent(item, word) {
    var suite = SUITE_BY_NAME.get(word);
    var alias = suite ? null : ALIASES.get(word);
    if (!suite && !alias) return false; // unknown name: the rule is ignored
    for (var i = 0; i < item.parts.length; i++) {
      var q = item.parts[i];
      var contradiction;
      if (suite && q.suite) {
        contradiction = q.suite !== suite && !NAME_PAIRS.has(q.suite.name + " " + suite.name);
      } else if (suite || q.suite) {
        var s = suite || q.suite, a = alias || q.alias;
        contradiction = !NAME_TRANSPARENT.has(a.name) && !a.members.has(s.index);
      } else {
        contradiction = q.alias.contradicts.has(alias.name);
      }
      if (contradiction) return false;
    }
    item.parts.push({ suite: suite, alias: alias });
    var bits = suite ? suite.strong : STRENGTH.has(alias.name) ? new Set([alias.name]) : null;
    if (bits) {
      if (item.strong === null) {
        // OpenSSL assigns the strength mask here, dropping an earlier NOT_DEFAULT.
        item.strong = new Set(bits);
        item.notDefault = false;
      } else {
        item.strong = new Set(Array.from(item.strong).filter(function (b) { return bits.has(b); }));
      }
    }
    if (suite) {
      item.suite = suite.index;
      if (suite.notDefault) item.notDefault = true;
    } else if (alias.name === NOT_DEFAULT) {
      item.notDefault = true;
    } else {
      var m = alias.members;
      item.set = item.set === null ? new Set(m) : new Set(Array.from(item.set).filter(function (x) { return m.has(x); }));
    }
    return true;
  }

  function matcher(item) {
    return function (i) {
      var s = SUITES[i];
      return (item.set === null || item.set.has(i)) && (item.suite === null || item.suite === i) &&
        (item.strong === null || intersects(item.strong, s.strong)) && (!item.notDefault || s.notDefault);
    };
  }

  function applyRule(state, match, rule) {
    var hit = state.order.filter(function (i) {
      return match(i) && (rule === KILL || (rule === ADD ? !state.active[i] : state.active[i]));
    });
    if (!hit.length) return;
    var moved = new Set(hit);
    var rest = state.order.filter(function (i) { return !moved.has(i); });
    if (rule === ADD) {
      hit.forEach(function (i) { state.active[i] = true; });
      state.order = rest.concat(hit); // newly added suites go to the end
    } else if (rule === ORD) {
      state.order = rest.concat(hit); // "+": move to the end
    } else if (rule === DEL) {
      hit.forEach(function (i) { state.active[i] = false; });
      state.order = hit.concat(rest); // "-": deleted suites move to the front
    } else {
      hit.forEach(function (i) { state.active[i] = false; });
      state.order = rest; // "!": gone for good
    }
  }

  // "@STRENGTH": stable sort of the active suites by descending strength.
  function strengthSort(state) {
    var max = 0;
    state.order.forEach(function (i) { if (state.active[i]) max = Math.max(max, SUITES[i].strength); });
    for (var bits = max; bits >= 0; bits--) {
      applyRule(state, function (i) { return SUITES[i].strength === bits; }, ORD);
    }
  }

  // ssl_cipher_process_rulestr(): false where OpenSSL reports an error.
  function processRules(s, state) {
    var l = 0, ok = true, n = s.length;
    var at = function (k) { return k < n ? s[k] : "\0"; };
    for (;;) {
      var ch = at(l);
      if (ch === "\0") break;
      var rule = ADD;
      if (ch === "-") { rule = DEL; l++; }
      else if (ch === "+") { rule = ORD; l++; }
      else if (ch === "!") { rule = KILL; l++; }
      else if (ch === "@") { rule = SPECIAL; l++; }
      if (isSeparator(ch)) { l++; continue; }
      var item = { parts: [], set: null, suite: null, strong: null, notDefault: false };
      var found = false, word = "";
      for (;;) {
        var start = l;
        while (isNameChar(at(l))) l++;
        word = s.slice(start, l);
        if (!word) return false; // "invalid command"
        if (rule === SPECIAL) break;
        var multi = at(l) === "+";
        if (multi) l++;
        found = addComponent(item, word);
        if (!found || !multi) break;
      }
      if (rule === SPECIAL) {
        if (word === "STRENGTH") strengthSort(state);
        else if (!(word.length === 10 && word.startsWith("SECLEVEL=") && /[0-5]/.test(word[9]))) ok = false;
        while (at(l) !== "\0" && !isSeparator(at(l))) l++;
      } else if (found) {
        applyRule(state, matcher(item), rule);
      } else {
        while (at(l) !== "\0" && !isSeparator(at(l))) l++;
      }
      if (at(l) === "\0") break;
    }
    return ok;
  }

  // The TLS <= 1.2 suites OpenSSL selects for a cipher string, in preference
  // order, or null where SSL_CTX_set_cipher_list() fails.
  function expandCipherString(str) {
    var s = String(str);
    var nul = s.indexOf("\0");
    if (nul >= 0) s = s.slice(0, nul);
    // check_suiteb_cipher_list(): Suite B prefixes replace the whole string.
    if (s.startsWith("SUITEB128ONLY")) s = "ECDHE-ECDSA-AES128-GCM-SHA256";
    else if (s.startsWith("SUITEB128C2")) s = "ECDHE-ECDSA-AES256-GCM-SHA384";
    else if (s.startsWith("SUITEB128")) s = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
    else if (s.startsWith("SUITEB192")) s = "ECDHE-ECDSA-AES256-GCM-SHA384";
    var state = { order: SUITES.map(function (x) { return x.index; }), active: SUITES.map(function () { return false; }) };
    var ok = true;
    if (s.startsWith("DEFAULT")) {
      ok = processRules(CIPHER_TABLE.defaultRules, state);
      s = s.slice(7);
      if (s[0] === ":") s = s.slice(1);
    }
    if (ok && s) ok = processRules(s, state);
    if (!ok) return null;
    var out = state.order.filter(function (i) { return state.active[i]; })
      .map(function (i) { return SUITES[i].name; });
    return out.length ? out : null;
  }

  // ======================================================== scanner helpers

  var RE_SPLIT_LIST = new RegExp("[" + WS + ":,]+", "u");

  function splitList(value) {
    return strip(strip(value), "\"';").split(RE_SPLIT_LIST).filter(Boolean);
  }

  function groupsToAlgs(value) {
    var out = [];
    splitList(value).forEach(function (g) {
      g = lstrip(g, "*?-");
      var low = g.toLowerCase();
      if (low === "auto" || low === "default") return;
      var alg = classifyGroup(g);
      out.push(alg ? alg.name : g);
    });
    return unique(out);
  }

  // Expand an OpenSSL cipher string (as the local library would), then list suites.
  function ciphersToSuites(value) {
    var v = strip(strip(String(value)), "\"';");
    var names = expandCipherString(v + ":@SECLEVEL=0");
    if (names === null) {
      names = splitList(v).filter(function (c) { return !startsWithAny(c, ["!", "-", "+", "@"]); });
    }
    return unique(names);
  }

  function cipherComponents(suites) {
    var algs = [];
    suites.forEach(function (s) {
      var info = parseCipherSuite(s);
      if (info.kex === "RSA") algs.push("RSA-KEX");
      if (info.cipher) algs.push(info.cipher.name);
      if (info.mac === "MD5") algs.push(info.mac); // HMAC-SHA1 in TLS record protection is not broken
    });
    return unique(algs);
  }

  function cipherAlgs(value) { return cipherComponents(ciphersToSuites(value)); }

  function sshAlgs(value) {
    var out = [];
    value.split(",").forEach(function (a) {
      a = lstrip(strip(a), "+-^");
      var alg = lookup(a);
      if (alg) out.push(alg.name);
      else if (a.toLowerCase().indexOf("mlkem") >= 0) out.push("X25519MLKEM768");
      else if (a) out.push(a);
    });
    return unique(out);
  }

  function newScan(path, kind) {
    return { path: path, kind: kind, service: null, items: [], certificates: [] };
  }

  function addItem(scan, directive, value, line, category, algorithms) {
    scan.items.push({ directive: directive, value: strip(value), line: line, category: category,
      algorithms: algorithms || [] });
  }

  // ======================================================== parsers

  // Referenced certificate files (ssl_certificate, SSLCertificateFile, crt ...)
  // are listed as items; the browser cannot open them, so unlike the CLI their
  // contents are not analyzed.  Paste the certificate itself to check it.

  var RE_NGINX = new RegExp("^((?:proxy_|grpc_)?ssl_[a-z_]+)[" + WS + "]+(.+?);", "su");
  var RE_SERVER_NAME = new RegExp("^server_name[" + WS + "]+(.+?);", "su");

  function parseNginx(path, text) {
    var scan = newScan(path, "nginx");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var m = RE_NGINX.exec(line);
      if (!m) {
        var m2 = RE_SERVER_NAME.exec(line);
        if (m2 && !scan.service) scan.service = split(m2[1])[0] || null;
        return;
      }
      var d = m[1], v = m[2];
      var base = d.slice(d.indexOf("ssl_") + 4);
      if (base === "protocols") addItem(scan, d, v, n, "tls-protocol", split(v));
      else if (base === "ciphers") addItem(scan, d, v, n, "tls-cipher", cipherAlgs(v));
      else if (base === "ecdh_curve") addItem(scan, d, v, n, "tls-kex", groupsToAlgs(v));
      else if (base === "conf_command") {
        var kv = partition(v, " "), key = kv[0].toLowerCase();
        if (key === "groups" || key === "curves") addItem(scan, d, v, n, "tls-kex", groupsToAlgs(kv[2]));
        else if (key === "signaturealgorithms") addItem(scan, d, v, n, "tls-sigalg", splitList(kv[2]));
      } else if (base === "certificate" || base === "trusted_certificate" || base === "client_certificate") {
        addItem(scan, d, v, n, "certificate");
      } else if (base === "verify_client") addItem(scan, d, v, n, "mtls");
    });
    return scan;
  }

  var RE_APACHE = new RegExp("^(SSL[" + WORD + "]+|ServerName)[" + WS + "]+(.+)", "isu");

  function parseApache(path, text) {
    var scan = newScan(path, "apache");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var m = RE_APACHE.exec(line);
      if (!m) return;
      var d = m[1], v = m[2], dl = d.toLowerCase();
      if (dl === "servername" && !scan.service) scan.service = split(v)[0];
      else if (dl === "sslprotocol" || dl === "sslproxyprotocol") addItem(scan, d, v, n, "tls-protocol", split(v));
      else if (dl === "sslciphersuite" || dl === "sslproxyciphersuite") {
        if (strip(v).toUpperCase().startsWith("TLSV1.3")) return;
        addItem(scan, d, v, n, "tls-cipher", cipherAlgs(v));
      } else if (dl === "sslopensslconfcmd") {
        var kv = partition(v, " "), key = kv[0].toLowerCase();
        if (key === "curves" || key === "groups") addItem(scan, d, v, n, "tls-kex", groupsToAlgs(kv[2]));
      } else if (dl === "sslcertificatefile" || dl === "sslcacertificatefile") {
        addItem(scan, d, v, n, "certificate");
      }
    });
    return scan;
  }

  var RE_HAPROXY = new RegExp(
    "^(ssl-default-(?:bind|server)-(?:ciphers|ciphersuites|options|curves))[" + WS + "]+(.+)", "su");

  function wordArg(key) { // Python: \bkey\s+(\S+)
    return new RegExp("(?:^|[^" + WORD + "])" + key + "[" + WS + "]+([^" + WS + "]+)", "u");
  }

  var HAPROXY_ARGS = [["curves", "tls-kex", wordArg("curves")], ["ciphers", "tls-cipher", wordArg("ciphers")],
    ["crt", "certificate", wordArg("crt")]];
  var RE_MIN_VER = wordArg("ssl-min-ver");

  function parseHaproxy(path, text) {
    var scan = newScan(path, "haproxy");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var m = RE_HAPROXY.exec(line);
      if (m) {
        var d = m[1], v = m[2];
        if (d.endsWith("-ciphers")) addItem(scan, d, v, n, "tls-cipher", cipherAlgs(v));
        else if (d.endsWith("-curves")) addItem(scan, d, v, n, "tls-kex", groupsToAlgs(v));
        else if (d.endsWith("-options")) {
          addItem(scan, d, v, n, "tls-protocol", split(v).filter(function (o) {
            return startsWithAny(o, ["ssl-min-ver", "no-tls", "no-ssl"]);
          }));
        }
        return;
      }
      if (startsWithAny(line, ["bind ", "server "]) && (" " + line).indexOf(" ssl") >= 0) {
        HAPROXY_ARGS.forEach(function (spec) {
          var mm = spec[2].exec(line);
          if (!mm) return;
          var val = mm[1];
          if (spec[1] === "tls-kex") addItem(scan, spec[0], val, n, spec[1], groupsToAlgs(val));
          else if (spec[1] === "tls-cipher") addItem(scan, spec[0], val, n, spec[1], cipherAlgs(val));
          else addItem(scan, spec[0], val, n, spec[1]);
        });
        var mv = RE_MIN_VER.exec(line);
        if (mv) addItem(scan, "ssl-min-ver", mv[1], n, "tls-protocol", [mv[1]]);
      }
    });
    return scan;
  }

  var RE_ENVOY = new RegExp("^-?[" + WS + "]*(ecdh_curves|cipher_suites|tls_minimum_protocol_version|" +
    "tls_maximum_protocol_version|filename)[" + WS + "]*:[" + WS + "]*(.*)", "su");

  function parseEnvoy(path, text) {
    var scan = newScan(path, "envoy");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var m = RE_ENVOY.exec(line);
      if (!m) return;
      var d = m[1], v = strip(strip(m[2]), "[]\"'");
      if (d === "ecdh_curves" && v) addItem(scan, d, v, n, "tls-kex", groupsToAlgs(v));
      else if (d === "cipher_suites" && v) addItem(scan, d, v, n, "tls-cipher", cipherAlgs(v));
      else if (d.startsWith("tls_m")) addItem(scan, d, v, n, "tls-protocol", [v.split("TLSv1_").join("TLSv1.")]);
      else if (d === "filename" && endsWithAny(v, [".crt", ".pem"])) addItem(scan, d, v, n, "certificate");
    });
    return scan;
  }

  var RE_OPENSSL_CNF = new RegExp("^(Groups|Curves|MinProtocol|MaxProtocol|CipherString|Ciphersuites|" +
    "SignatureAlgorithms)[" + WS + "]*=[" + WS + "]*(.+)", "isu");

  function parseOpensslCnf(path, text) {
    var scan = newScan(path, "openssl");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var m = RE_OPENSSL_CNF.exec(line);
      if (!m) return;
      var d = m[1], v = m[2], dl = d.toLowerCase();
      if (dl === "groups" || dl === "curves") addItem(scan, d, v, n, "tls-kex", groupsToAlgs(v));
      else if (dl === "minprotocol" || dl === "maxprotocol") addItem(scan, d, v, n, "tls-protocol", [strip(v)]);
      else if (dl === "cipherstring") addItem(scan, d, v, n, "tls-cipher", cipherAlgs(v));
      else if (dl === "signaturealgorithms") addItem(scan, d, v, n, "tls-sigalg", splitList(v));
    });
    return scan;
  }

  var SSH_CATEGORIES = { kexalgorithms: "ssh-kex", hostkeyalgorithms: "ssh-hostkey",
    pubkeyacceptedalgorithms: "ssh-hostkey", ciphers: "ssh-cipher", macs: "ssh-mac" };

  function parseSsh(path, text) {
    var scan = newScan(path, baseName(path).indexOf("sshd") >= 0 ? "sshd" : "ssh");
    splitlines(text).forEach(function (raw, idx) {
      var n = idx + 1, line = strip(raw.split("#")[0]);
      var parts = split(line, 1);
      if (parts.length !== 2) return;
      var d = parts[0], v = parts[1], dl = d.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(SSH_CATEGORIES, dl)) {
        addItem(scan, d, v, n, SSH_CATEGORIES[dl], sshAlgs(v));
      } else if (dl === "hostkey") {
        var alg = v.indexOf("rsa") >= 0 ? "RSA" : v.indexOf("ecdsa") >= 0 ? "ECDSA"
          : v.indexOf("ed25519") >= 0 ? "Ed25519" : v.indexOf("dsa") >= 0 ? "DSA" : "unknown";
        addItem(scan, d, v, n, "ssh-hostkey", [alg]);
      }
    });
    return scan;
  }

  var SOURCE_PATTERNS = [
    [new RegExp("rsa\\.generate_private_key|RSA\\.generate\\(|rsa\\.GenerateKey|" +
      "KeyPairGenerator\\.getInstance\\(\"RSA\"|generateKeyPair(Sync)?\\([" + WS + "]*['\"]rsa", "u"),
    "RSA", "code-asymmetric"],
    [new RegExp("ec\\.generate_private_key|ecdsa\\.GenerateKey|KeyPairGenerator\\.getInstance\\(\"EC\"|" +
      "generateKeyPair(Sync)?\\([" + WS + "]*['\"]ec['\"]|ec\\.SECP256R1|elliptic\\.P256\\(\\)", "u"),
    "ECDSA", "code-asymmetric"],
    [/ECDH|X25519PrivateKey|ecdh\.X25519\(\)|createECDH\(/, "X25519", "code-kex"],
    [new RegExp("hashlib\\.md5|createHash\\([" + WS + "]*['\"]md5|MessageDigest\\.getInstance\\(\"MD5\"|" +
      "md5\\.New\\(\\)", "u"), "MD5", "code-hash"],
    [new RegExp("hashlib\\.sha1|createHash\\([" + WS + "]*['\"]sha1|MessageDigest\\.getInstance\\(\"SHA-?1\"|" +
      "sha1\\.New\\(\\)", "u"), "SHA-1", "code-hash"],
    [/DES3|TripleDES|DESede|des\.NewTripleDESCipher/, "3DES", "code-cipher"],
    [new RegExp("(?:^|[^" + WORD + "])(?:ARC4|RC4)(?![" + WORD + "])|rc4\\.NewCipher", "u"), "RC4", "code-cipher"],
    [new RegExp("PROTOCOL_TLSv1(?![" + WORD + "])|TLSv1_METHOD|tls\\.VersionTLS10|" +
      "minVersion:[" + WS + "]*['\"]TLSv1['\"]", "u"), "TLSv1.0", "code-protocol"],
    [/CurvePreferences|set_ecdh_curve|ecdhCurve/, "configured-curves", "code-kex"],
    [/ML-?KEM|MLKEM|X25519MLKEM768|mlkem768/, "ML-KEM-768", "code-pqc"],
    [/ML-?DSA|MLDSA|mldsa65/, "ML-DSA-65", "code-pqc"],
  ];
  var SOURCE_EXT = [".py", ".go", ".java", ".js", ".ts", ".mjs", ".kt", ".rb", ".rs", ".cs"];

  function parseSource(path, text) {
    var scan = newScan(path, "source");
    splitlines(text).forEach(function (line, idx) {
      if (line.length > 1000 && cpLength(line) > 1000) return;
      SOURCE_PATTERNS.forEach(function (p) {
        if (p[0].test(line)) addItem(scan, "code", cpSlice(strip(line), 0, 160), idx + 1, p[2], [p[1]]);
      });
    });
    return scan.items.length ? scan : null;
  }

  var RE_DETECT_NGINX = new RegExp("(?:^|[^" + WORD + "])ssl_(?:certificate|protocols|ciphers)(?![" + WORD + "])", "u");
  var RE_DETECT_APACHE = new RegExp("(?:^|\\n)[" + WS + "]*SSL(?:Engine|Protocol|CertificateFile)(?![" + WORD + "])", "u");

  // detect_kind(): which parser applies, from the file name and the first 20000 characters.
  function detectKind(path, head) {
    var name = baseName(path).toLowerCase();
    head = head || "";
    if (name === "sshd_config" || name === "ssh_config" || endsWithAny(name, [".sshd_config", "sshd_config.conf"])) {
      return "ssh";
    }
    if (name === "openssl.cnf" || name.endsWith(".cnf")) return "openssl";
    if (name.startsWith("haproxy") || (name.endsWith(".cfg") && head.indexOf("frontend") >= 0)) return "haproxy";
    if (endsWithAny(name, [".pem", ".crt", ".cer", ".key"]) || cpSlice(head, 0, 2000).indexOf("-----BEGIN ") >= 0) {
      return "pem";
    }
    if (SOURCE_EXT.indexOf(suffix(baseName(path))) >= 0) return "source";
    if (endsWithAny(name, [".yaml", ".yml"]) && (head.indexOf("ecdh_curves") >= 0 || head.indexOf("tls_params") >= 0)) {
      return "envoy";
    }
    if (name.indexOf("nginx") >= 0 || RE_DETECT_NGINX.test(head)) return "nginx";
    if (RE_DETECT_APACHE.test(head) || name === "httpd.conf" || name === "ssl.conf" || name === "apache2.conf") {
      return "apache";
    }
    return null;
  }

  var PARSERS = { nginx: parseNginx, apache: parseApache, haproxy: parseHaproxy, envoy: parseEnvoy,
    openssl: parseOpensslCnf, ssh: parseSsh, source: parseSource };

  // ======================================================== DER / PEM (certs.py)

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var B64_INDEX = {};
  for (var b64i = 0; b64i < 64; b64i++) B64_INDEX[B64[b64i]] = b64i;

  // Strict standard base64 (the PEM body of a certificate), or null.
  function base64Strict(s) {
    s = s.replace(/[ \t\n\r\f\v]+/g, "");
    if (s.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
    return base64Lenient(s);
  }

  // binascii.a2b_base64(s, strict_mode=False), as base64.b64decode() uses it;
  // null where Python raises.
  function base64Lenient(s) {
    var out = [], quad = 0, left = 0, pads = 0;
    for (var i = 0; i < s.length; i++) {
      var ch = s[i];
      if (ch === "=") {
        if (quad >= 2 && quad + ++pads >= 4) return new Uint8Array(out);
        continue;
      }
      var v = B64_INDEX[ch];
      if (v === undefined) continue;
      pads = 0;
      if (quad === 0) { left = v; quad = 1; }
      else if (quad === 1) { out.push(((left << 2) | (v >> 4)) & 0xff); left = v & 0x0f; quad = 2; }
      else if (quad === 2) { out.push(((left << 4) | (v >> 2)) & 0xff); left = v & 0x03; quad = 3; }
      else { out.push(((left << 6) | v) & 0xff); left = 0; quad = 0; }
    }
    return quad === 0 ? new Uint8Array(out) : null;
  }

  function hex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    return s;
  }

  function fail() { throw new Error("malformed DER"); }

  // One DER TLV: {tag, start, end} with start/end bounding the contents.
  function tlv(b, pos, end) {
    if (pos >= end) fail();
    var tag = b[pos++];
    if ((tag & 0x1f) === 0x1f) { // high tag number: keep the first octet, skip the rest
      while (pos < end && (b[pos] & 0x80)) pos++;
      pos++;
    }
    if (pos >= end) fail();
    var len = b[pos++];
    if (len & 0x80) {
      var k = len & 0x7f;
      if (k === 0 || k > 4) fail();
      len = 0;
      while (k--) { if (pos >= end) fail(); len = len * 256 + b[pos++]; }
    }
    if (pos + len > end) fail();
    return { tag: tag, start: pos, end: pos + len };
  }

  function children(b, node) {
    var out = [], pos = node.start;
    while (pos < node.end) { var c = tlv(b, pos, node.end); out.push(c); pos = c.end; }
    return out;
  }

  function expect(node, tag) { if (!node || node.tag !== tag) fail(); return node; }

  function oidString(b, node) {
    expect(node, 0x06);
    var arcs = [], v = 0n, first = true;
    for (var i = node.start; i < node.end; i++) {
      v = (v << 7n) | BigInt(b[i] & 0x7f);
      if (!(b[i] & 0x80)) {
        if (first) {
          if (v < 40n) arcs.push("0", String(v));
          else if (v < 80n) arcs.push("1", String(v - 40n));
          else arcs.push("2", String(v - 80n));
          first = false;
        } else arcs.push(String(v));
        v = 0n;
      }
    }
    if (node.start === node.end || b[node.end - 1] & 0x80) fail();
    return arcs.join(".");
  }

  function integerBig(b, node) {
    expect(node, 0x02);
    if (node.start === node.end) fail();
    var v = 0n;
    for (var i = node.start; i < node.end; i++) v = (v << 8n) | BigInt(b[i]);
    if (b[node.start] & 0x80) v -= 1n << BigInt(8 * (node.end - node.start));
    return v;
  }

  function bitLength(v) { return v <= 0n ? 0 : v.toString(2).length; }

  function utf8(bytes) { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }

  function codeUnits(bytes, width) { // UTF-16BE (2) or UTF-32BE (4), strictly
    if (bytes.length % width) fail();
    var cps = [];
    for (var i = 0; i < bytes.length; i += width) {
      var c = width === 2 ? (bytes[i] << 8) | bytes[i + 1]
        : ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
      cps.push(c);
    }
    var out = "";
    for (var j = 0; j < cps.length; j++) {
      var cp = cps[j];
      if (width === 2 && cp >= 0xd800 && cp <= 0xdbff) {
        var lo = cps[++j];
        if (lo === undefined || lo < 0xdc00 || lo > 0xdfff) fail();
        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      } else if ((cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) fail();
      out += String.fromCodePoint(cp);
    }
    return out;
  }

  var RE_PRINTABLE = /^[A-Za-z0-9 '()+,\-./:=?]*$/;

  // Attribute values as cryptography decodes them (str, or bytes for BIT STRING).
  function nameValue(b, node) {
    var data = b.subarray(node.start, node.end);
    if (node.tag === 0x03) return { bytes: hex(data.subarray(1)) };
    if (node.tag === 0x1e) return codeUnits(data, 2);
    if (node.tag === 0x1c) return codeUnits(data, 4);
    var s = utf8(data);
    if (node.tag === 0x13 && !RE_PRINTABLE.test(s)) fail();
    return s;
  }

  var NAME_ATTRS = { "2.5.4.3": "CN", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.6": "C", "2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID" };

  // cryptography's _escape_dn_value()
  function escapeDn(val) {
    if (typeof val !== "string") return "#" + val.bytes;
    if (!val) return "";
    val = val.replace(/\\/g, "\\\\").replace(/"/g, "\\\"").replace(/\+/g, "\\+").replace(/,/g, "\\,")
      .replace(/;/g, "\\;").replace(/</g, "\\<").replace(/>/g, "\\>").replace(/\0/g, "\\00");
    if (val[0] === "#" || (val[0] === " " && val.length > 1)) val = "\\" + val;
    if (val[val.length - 1] === " ") val = val.slice(0, -1) + "\\ ";
    return val;
  }

  // Name -> [[{oid, value}, ...] per RDN]
  function parseName(b, node) {
    expect(node, 0x30);
    return children(b, node).map(function (rdn) {
      expect(rdn, 0x31);
      return children(b, rdn).map(function (atv) {
        var kids = children(b, expect(atv, 0x30));
        if (kids.length !== 2) fail();
        return { oid: oidString(b, kids[0]), value: nameValue(b, kids[1]) };
      });
    });
  }

  function rfc4514(name) {
    return name.slice().reverse().map(function (rdn) {
      return rdn.map(function (a) { return (NAME_ATTRS[a.oid] || a.oid) + "=" + escapeDn(a.value); }).join("+");
    }).join(",");
  }

  function nameKey(name) { // Name equality: RDNs in order, attributes as a set
    return JSON.stringify(name.map(function (rdn) {
      return unique(rdn.map(function (a) { return JSON.stringify([a.oid, a.value]); })).sort();
    }));
  }

  function daysFromCivil(y, m, d) {
    y -= m <= 2 ? 1 : 0;
    var era = Math.floor(y / 400), yoe = y - era * 400;
    var doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    return era * 146097 + yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy - 719468;
  }

  function parseTime(b, node) {
    var s = String.fromCharCode.apply(null, Array.from(b.subarray(node.start, node.end)));
    var m = node.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s)
      : node.tag === 0x18 ? /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s) : null;
    if (!m) fail();
    var year = Number(m[1]);
    if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000;
    var mo = Number(m[2]), d = Number(m[3]), hh = Number(m[4]), mi = Number(m[5]), ss = Number(m[6]);
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mi > 59 || ss > 59) fail();
    var pad = function (x, w) { return String(x).padStart(w, "0"); };
    return pad(year, 4) + "-" + pad(mo, 2) + "-" + pad(d, 2) + "T" + pad(hh, 2) + ":" + pad(mi, 2) + ":" +
      pad(ss, 2) + "+00:00";
  }

  // Seconds since the epoch for the isoformat() strings above.
  function isoSeconds(iso) {
    var m = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)\+00:00$/.exec(iso);
    if (!m) return null;
    return daysFromCivil(+m[1], +m[2], +m[3]) * 86400 + (+m[4]) * 3600 + (+m[5]) * 60 + (+m[6]);
  }

  // Python's str(ipaddress.ip_address(packed))
  function ipString(bytes) {
    if (bytes.length === 4) return Array.from(bytes).join(".");
    if (bytes.length !== 16) fail();
    var words = [];
    for (var i = 0; i < 16; i += 2) words.push((bytes[i] << 8) | bytes[i + 1]);
    if (words.slice(0, 5).every(function (w) { return w === 0; }) && words[5] === 0xffff) {
      return "::ffff:" + Array.from(bytes.subarray(12)).join(".");
    }
    var hextets = words.map(function (w) { return w.toString(16); });
    var bestStart = -1, bestLen = 0, start = -1, len = 0;
    hextets.forEach(function (h, k) {
      if (h === "0") {
        len++;
        if (start === -1) start = k;
        if (len > bestLen) { bestLen = len; bestStart = start; }
      } else { len = 0; start = -1; }
    });
    if (bestLen > 1) {
      var end = bestStart + bestLen;
      if (end === hextets.length) hextets.push("");
      hextets.splice(bestStart, bestLen, "");
      if (bestStart === 0) hextets.unshift("");
    }
    return hextets.join(":");
  }

  var EC_CURVES = { // cryptography's named curves: OID -> [name, key_size]
    "1.2.840.10045.3.1.1": ["secp192r1", 192], "1.3.132.0.33": ["secp224r1", 224],
    "1.3.132.0.10": ["secp256k1", 256], "1.2.840.10045.3.1.7": ["secp256r1", 256],
    "1.3.132.0.34": ["secp384r1", 384], "1.3.132.0.35": ["secp521r1", 521],
    "1.3.36.3.3.2.8.1.1.7": ["brainpoolP256r1", 256], "1.3.36.3.3.2.8.1.1.11": ["brainpoolP384r1", 384],
    "1.3.36.3.3.2.8.1.1.13": ["brainpoolP512r1", 512],
  };

  // Names cryptography gives signature OIDs that catalog.SIG_OIDS does not cover.
  var OID_NAMES = {
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption", "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10040.4.3": "dsa-with-sha1", "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256", "1.2.643.2.2.3": "GOST R 34.11-94 with GOST R 34.10-2001",
    "1.2.643.7.1.1.3.2": "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
    "1.2.643.7.1.1.3.3": "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)",
    "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
  };

  // certs._key_info(): (algorithm, size, detail) from SubjectPublicKeyInfo.
  function keyInfo(b, spki) {
    var kids = children(b, expect(spki, 0x30));
    var algId = children(b, expect(kids[0], 0x30));
    var oid = oidString(b, algId[0]);
    var params = algId[1];
    var key = expect(kids[1], 0x03);
    try {
      if (oid === "1.2.840.113549.1.1.1") {
        var rsa = children(b, expect(tlv(b, key.start + 1, key.end), 0x30));
        var n = integerBig(b, rsa[0]);
        if (n <= 0n) fail();
        return ["RSA", bitLength(n), "RSA-" + bitLength(n)];
      }
      if (oid === "1.2.840.10045.2.1" && params && params.tag === 0x06) {
        var curve = EC_CURVES[oidString(b, params)];
        if (curve) return ["ECDSA", curve[1], curve[0]];
      }
      if (oid === "1.3.101.112") return ["Ed25519", 256, "Ed25519"];
      if (oid === "1.3.101.113") return ["Ed448", 456, "Ed448"];
      if (oid === "1.2.840.10040.4.1" && params && params.tag === 0x30) {
        var p = integerBig(b, children(b, params)[0]);
        return ["DSA", bitLength(p), "DSA-" + bitLength(p)];
      }
    } catch (e) { /* unusable key: fall back to the OID like certs.py does */ }
    var alg = lookup(oid);
    if (alg) return [alg.name, null, alg.name];
    return [oid, null, null];
  }

  function sigInfo(oid) {
    if (SIG_OIDS[oid]) return SIG_OIDS[oid];
    var alg = lookup(oid);
    if (alg) return [alg.name, null];
    return [OID_NAMES[oid] || "Unknown OID", null];
  }

  // certs.cert_info() for one DER certificate; throws where cryptography raises.
  function parseCertificate(der, fingerprint) {
    var root = expect(tlv(der, 0, der.length), 0x30);
    if (root.end !== der.length) fail();
    var top = children(der, root);
    if (top.length !== 3) fail();
    var tbs = children(der, expect(top[0], 0x30));
    var i = tbs[0] && tbs[0].tag === 0xa0 ? 1 : 0;
    var serial = integerBig(der, tbs[i]);
    expect(tbs[i + 1], 0x30);
    var issuer = parseName(der, tbs[i + 2]);
    var validity = children(der, expect(tbs[i + 3], 0x30));
    var subject = parseName(der, tbs[i + 4]);
    var key = keyInfo(der, tbs[i + 5]);
    var sig = sigInfo(oidString(der, children(der, expect(top[1], 0x30))[0]));
    var sans = { dns: [], uri: [], ip: [] }, isCa = false;
    tbs.slice(i + 6).forEach(function (field) {
      if (field.tag !== 0xa3) return;
      children(der, expect(children(der, field)[0], 0x30)).forEach(function (ext) {
        var parts = children(der, expect(ext, 0x30));
        var extOid = oidString(der, parts[0]);
        var value = expect(parts[parts.length - 1], 0x04);
        var inner = tlv(der, value.start, value.end);
        if (extOid === "2.5.29.17") {
          children(der, expect(inner, 0x30)).forEach(function (gn) {
            var data = der.subarray(gn.start, gn.end);
            if (gn.tag === 0x82 || gn.tag === 0x86) {
              if (data.some(function (x) { return x > 0x7f; })) fail();
              (gn.tag === 0x82 ? sans.dns : sans.uri).push(String.fromCharCode.apply(null, Array.from(data)));
            } else if (gn.tag === 0x87) sans.ip.push(ipString(data));
          });
        } else if (extOid === "2.5.29.19") {
          var bc = children(der, expect(inner, 0x30));
          isCa = bc.length > 0 && bc[0].tag === 0x01 && der[bc[0].start] !== 0;
        }
      });
    });
    var serialHex = serial < 0n ? "-" + (-serial).toString(16) : serial.toString(16);
    return {
      fingerprint_sha256: fingerprint,
      subject: rfc4514(subject),
      issuer: rfc4514(issuer),
      serial: serialHex,
      not_before: parseTime(der, validity[0]),
      not_after: parseTime(der, validity[1]),
      public_key_algorithm: key[0],
      public_key_size: key[1],
      public_key_detail: key[2],
      signature_algorithm: sig[0],
      signature_hash: sig[1],
      subject_alt_names: sans.dns.map(function (s) { return "DNS:" + s; })
        .concat(sans.uri.map(function (s) { return "URI:" + s; }), sans.ip.map(function (s) { return "IP:" + s; })),
      self_signed: nameKey(subject) === nameKey(issuer),
      is_ca: isCa,
      sources: [],
    };
  }

  var RE_PEM_CERT = /-----BEGIN CERTIFICATE-----[ \t\n\r\f\v]+[\s\S]*?-----END CERTIFICATE-----/g;

  function certificateDers(text) {
    var out = [], m;
    RE_PEM_CERT.lastIndex = 0;
    while ((m = RE_PEM_CERT.exec(text))) {
      var body = m[0].slice("-----BEGIN CERTIFICATE-----".length, -"-----END CERTIFICATE-----".length);
      out.push(base64Strict(body));
    }
    return out;
  }

  function bytesKey(der) { return der.length + ":" + hex(der); }

  // DER-encoded OIDs of PQC algorithms inside PKCS#8 (config_scanner._PQ_KEY_OIDS).
  var PQ_KEY_OIDS = [["0609608648016503040311", "ML-DSA-44"], ["0609608648016503040312", "ML-DSA-65"],
    ["0609608648016503040313", "ML-DSA-87"], ["0609608648016503040401", "ML-KEM-512"],
    ["0609608648016503040402", "ML-KEM-768"], ["0609608648016503040403", "ML-KEM-1024"]];

  function rsaKeyBits(b, node) { // RSAPrivateKey: version, modulus, ...
    var n = integerBig(b, children(b, expect(node, 0x30))[1]);
    if (n <= 0n) fail();
    return bitLength(n);
  }

  function ecKeyBits(b, node, params) { // ECPrivateKey: version, key, [0] curve, [1] public key
    var kids = children(b, expect(node, 0x30));
    kids.slice(2).forEach(function (k) { if (k.tag === 0xa0) params = tlv(b, k.start, k.end); });
    var curve = params && params.tag === 0x06 ? EC_CURVES[oidString(b, params)] : null;
    if (!curve) fail();
    return curve[1];
  }

  // What serialization.load_pem_private_key(pem, None) yields, as [alg, size],
  // or null where it fails or gives a type _key_alg() does not report.
  function loadPrivateKey(label, body) {
    if (/Proc-Type:/.test(body)) return null; // legacy encrypted PEM: password required
    var der = base64Strict(body);
    if (!der) return null;
    try {
      var root = tlv(der, 0, der.length);
      if (label === "RSA PRIVATE KEY") return ["RSA", rsaKeyBits(der, root)];
      if (label === "EC PRIVATE KEY") return ["ECDSA", ecKeyBits(der, root, null)];
      if (label !== "PRIVATE KEY") return null;
      var kids = children(der, expect(root, 0x30));
      var algId = children(der, expect(kids[1], 0x30));
      var oid = oidString(der, algId[0]);
      var inner = expect(kids[2], 0x04);
      if (oid === "1.2.840.113549.1.1.1") return ["RSA", rsaKeyBits(der, tlv(der, inner.start, inner.end))];
      if (oid === "1.2.840.10045.2.1") return ["ECDSA", ecKeyBits(der, tlv(der, inner.start, inner.end), algId[1])];
      if (oid === "1.3.101.112") return ["Ed25519", 256];
    } catch (e) { /* not loadable */ }
    return null;
  }

  // config_scanner._key_alg()
  function keyAlg(pem, label) {
    var bodyText = pem.slice(pem.indexOf("-----", 11) + 5, pem.lastIndexOf("-----END"));
    var loaded = loadPrivateKey(label, bodyText);
    if (loaded) return loaded;
    var body = /-----BEGIN [A-Z ]*PRIVATE KEY-----([\s\S]+?)-----END/.exec(pem);
    if (body) {
      var der = base64Lenient(body[1].replace(/[ \t\n\r\f\v]+/g, "")) || new Uint8Array(0);
      var derHex = hex(der);
      for (var i = 0; i < PQ_KEY_OIDS.length; i++) {
        var at = derHex.indexOf(PQ_KEY_OIDS[i][0]);
        while (at >= 0 && at % 2) at = derHex.indexOf(PQ_KEY_OIDS[i][0], at + 1);
        if (at >= 0) return [PQ_KEY_OIDS[i][1], null];
      }
    }
    if (pem.indexOf("ENCRYPTED") >= 0) return ["encrypted", null];
    return ["unknown", null];
  }

  var RE_PEM_KEY = /-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]+?-----END \1-----/g;

  function parsePem(path, text, digest) {
    var scan = newScan(path, "pem");
    certificateDers(text).forEach(function (der) {
      if (!der) return;
      try {
        scan.certificates.push({ der: der, info: parseCertificate(der, digest(der)) });
      } catch (e) { /* cryptography raises ValueError: certs.parse_pem_bundle skips it */ }
    });
    var m, n = 0;
    RE_PEM_KEY.lastIndex = 0;
    while ((m = RE_PEM_KEY.exec(text))) {
      n++;
      var ka = keyAlg(m[0], m[1]);
      var label = ka[1] && ka[0] === "RSA" ? ka[0] + "-" + ka[1] : ka[0];
      addItem(scan, "private-key", label, n, "private-key", [ka[0]]);
    }
    return scan;
  }

  // ======================================================== rules (analyzer.py)

  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var QUANTUM_BROKEN_SIG = ["RSA", "ECDSA", "Ed25519", "Ed448", "DSA"];

  function status(name) {
    var alg = lookup(name) || classifyGroup(name);
    return alg ? alg.status : null;
  }

  function finding(rule, title, severity, asset, service, evidence, recommendation, hndl, migration) {
    return { rule_id: rule, title: title, severity: severity, asset: asset, service: service,
      evidence: evidence, recommendation: recommendation, hndl: !!hndl,
      migration: migration === undefined ? null : migration };
  }

  function configFindings(cfg) {
    var f = [], svc = cfg.service;
    function add(it, rule, title, sev, rec, hndl, migration) {
      f.push(finding(rule, title, sev, cfg.path + ":" + it.line, svc, it.directive + " " + it.value, rec,
        hndl, migration));
    }
    var hasKex = false, hasTls = false;
    cfg.items.forEach(function (it) {
      var algs = it.algorithms, cat = it.category, dir = it.directive.toLowerCase();
      if (cat === "tls-kex") {
        hasKex = true;
        if (algs.length && !algs.some(function (a) { var s = status(a); return s === HYBRID || s === RESISTANT; })) {
          add(it, "QS-CFG-KEX-001", "Only classical key-exchange groups configured", "high",
            "Add X25519MLKEM768 first, keeping X25519 for older clients.", true, "set-hybrid-groups");
        }
      } else if (cat === "tls-protocol") {
        hasTls = true;
        var joined = algs.join(" ").toLowerCase();
        var tokens = new Set(split(joined.split("_").join(".")).map(function (t) { return lstrip(t, "+"); }));
        var legacy = ["tlsv1", "tlsv1.0", "tlsv1.1", "sslv3", "sslv2"].some(function (t) { return tokens.has(t); });
        if (tokens.has("all") && !(tokens.has("-tlsv1") && tokens.has("-tlsv1.1"))) legacy = true;
        if (legacy && dir !== "maxprotocol") {
          add(it, "QS-CFG-PROTO-002", "Legacy TLS versions enabled", "high",
            "Allow only TLS 1.2 and 1.3.", false, "disable-legacy-tls");
        }
        if ((dir === "ssl_protocols" || dir === "proxy_ssl_protocols" || dir === "sslprotocol") &&
            joined.indexOf("tlsv1.3") < 0 && joined.indexOf("all") < 0) {
          add(it, "QS-CFG-PROTO-001", "TLS 1.3 not enabled", "high",
            "Enable TLSv1.3; hybrid ML-KEM requires it.", true, "enable-tls13");
        }
        if (dir === "maxprotocol" && joined.indexOf("1.3") < 0) {
          add(it, "QS-CFG-PROTO-001", "TLS 1.3 not enabled", "high",
            "Raise MaxProtocol to TLSv1.3.", true, "enable-tls13");
        }
      } else if (cat === "tls-cipher") {
        hasTls = true;
        if (algs.indexOf("RSA-KEX") >= 0) {
          add(it, "QS-CFG-CIPH-003", "Static RSA key-exchange suites allowed", "critical",
            "Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20.", true, "remove-rsa-kex");
        }
        var bad = algs.filter(function (a) { return status(a) === INSECURE; });
        if (bad.length) {
          add(it, "QS-CFG-CIPH-001", "Insecure ciphers allowed", "high",
            "Remove " + bad.join(", ") + ".", false, "remove-weak-ciphers");
        }
      } else if (cat === "certificate") {
        hasTls = true;
      } else if (cat === "ssh-kex") {
        if (!algs.some(function (a) { return status(a) === HYBRID; })) {
          add(it, "QS-SSH-KEX-001", "SSH key exchange is not quantum-safe", "high",
            "Put mlkem768x25519-sha256 (OpenSSH 9.9+) and sntrup761x25519-sha512 first.", true, "ssh-hybrid-kex");
        }
        if (algs.some(function (a) { return status(a) === INSECURE; })) {
          add(it, "QS-SSH-KEX-002", "SSH allows broken key exchange", "high",
            "Remove SHA-1 / 1024-bit Diffie-Hellman groups.", false, "ssh-hybrid-kex");
        }
      } else if (cat === "ssh-hostkey") {
        if (algs.indexOf("DSA") >= 0) {
          add(it, "QS-SSH-HK-002", "DSA host key", "high", "Remove DSA host keys.", false, "ssh-hostkey");
        } else if (algs.some(function (a) { return QUANTUM_BROKEN_SIG.indexOf(a) >= 0; })) {
          add(it, "QS-SSH-HK-001", "SSH host key is quantum-vulnerable", "low",
            "Track OpenSSH's ML-DSA host-key support; keep keys rotatable.", false, "ssh-hostkey");
        }
      } else if (cat === "ssh-cipher") {
        if (algs.some(function (a) { return status(a) === INSECURE; })) {
          add(it, "QS-SSH-CIPH-001", "SSH allows insecure ciphers", "high",
            "Use chacha20-poly1305 and aes256-gcm.", false, "remove-weak-ciphers");
        }
      } else if (cat === "private-key") {
        if (algs.some(function (a) { return QUANTUM_BROKEN_SIG.indexOf(a) >= 0; })) {
          add(it, "QS-KEY-001", "Quantum-vulnerable private key on disk", "low",
            "Replace with ML-DSA keys when the certificate is re-issued; keep keys out of source trees.",
            false, "reissue-mldsa");
        }
      } else if (cat === "code-asymmetric" || cat === "code-kex") {
        add(it, "QS-CODE-001", "Hard-coded quantum-vulnerable algorithm in source", "medium",
          "Route " + algs.join(", ") + " through a crypto-agility layer (config-selected algorithm) so it " +
          "can be swapped for ML-KEM / ML-DSA.", false, "refactor-code");
      } else if (cat === "code-hash") {
        add(it, "QS-CODE-002", "Broken hash function used in source", "medium",
          "Use SHA-256 or stronger (fine for non-security checksums, but verify).", false, "refactor-code");
      } else if (cat === "code-cipher" || cat === "code-protocol") {
        add(it, "QS-CODE-003", "Insecure cipher or protocol in source", "high",
          "Replace with AES-256-GCM / TLS 1.3.", false, "refactor-code");
      } else if (cat === "code-pqc") {
        add(it, "QS-CODE-PQC", "Post-quantum algorithm in use", "info",
          "Good: confirm it comes from a validated library.", false, null);
      }
    });
    if ((cfg.kind === "nginx" || cfg.kind === "apache" || cfg.kind === "haproxy") && hasTls && !hasKex) {
      f.push(finding("QS-CFG-KEX-000", "Key-exchange groups left to library defaults", "info", cfg.path, svc,
        "No ssl_ecdh_curve / Groups directive",
        "Defaults are hybrid only with OpenSSL 3.5+. Pin X25519MLKEM768:X25519 explicitly.", false,
        "set-hybrid-groups"));
    }
    return f;
  }

  var US = 1000000n, DAY_US = 86400n * US;

  function floorDiv(a, b) {
    var q = a / b;
    if (a % b !== 0n && (a < 0n) !== (b < 0n)) q -= 1n;
    return q;
  }

  function divideAndRound(a, b) { // timedelta / int: round half to even
    var q = floorDiv(a, b), r = (a - q * b) * 2n;
    if ((b > 0n ? r > b : r < b) || (r === b && q % 2n !== 0n)) q += 1n;
    return q;
  }

  function certFindings(cert, services, nowUs) {
    var f = [];
    var asset = "cert:" + (cert.fingerprint_sha256 ? cert.fingerprint_sha256.slice(0, 16) : "serial-" + cert.serial) +
      " (" + cert.subject + ")";
    var svc = unique(services).sort(cpCompare).join(", ") || null;
    function add(rule, title, sev, evidence, rec, migration) {
      f.push(finding(rule, title, sev, asset, svc, evidence, rec, false, migration));
    }
    var key = cert.public_key_algorithm;
    if (QUANTUM_BROKEN_SIG.indexOf(key) >= 0) {
      add("QS-CERT-SIG-001", "Certificate key is quantum-vulnerable", "medium",
        (cert.public_key_detail || key) + " public key, signed with " + cert.signature_algorithm +
        (cert.signature_hash ? "/" + cert.signature_hash : ""),
        "Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). Authentication is " +
        "not exposed to harvest-now-decrypt-later, so this follows key exchange in priority.", "reissue-mldsa");
    }
    if (key === "RSA" && cert.public_key_size && cert.public_key_size < 2048) {
      add("QS-CERT-KEY-001", "RSA key shorter than 2048 bits", "high", "RSA-" + cert.public_key_size,
        "Re-issue immediately.", "reissue-mldsa");
    }
    if (cert.signature_hash === "SHA-1" || cert.signature_hash === "MD5") {
      add("QS-CERT-HASH-001", "Certificate signed with a broken hash", "high",
        cert.signature_algorithm + " with " + cert.signature_hash, "Re-issue with SHA-256+ or ML-DSA.", "reissue-mldsa");
    }
    var nbS = isoSeconds(cert.not_before), naS = isoSeconds(cert.not_after);
    if (nbS === null || naS === null) return f;
    var nb = BigInt(nbS) * US, na = BigInt(naS) * US, life = na - nb;
    if (na < nowUs) {
      add("QS-CERT-EXP-001", "Certificate expired", "high", "Expired " + cert.not_after.slice(0, 10),
        "Rotate the certificate.", "rotate-cert");
    } else {
      var third = divideAndRound(life, 3n), limit = 30n * DAY_US < third ? 30n * DAY_US : third;
      if (na - nowUs < limit) {
        add("QS-CERT-EXP-002", "Certificate expires within 30 days", "medium", "Expires " + cert.not_after.slice(0, 10),
          "Rotate the certificate.", "rotate-cert");
      }
    }
    if (!cert.is_ca && life > 398n * DAY_US) {
      add("QS-CERT-ROT-001", "Long-lived certificate", "low", "Valid for " + floorDiv(life, DAY_US) + " days",
        "Use short-lived workload certificates so rotation and algorithm changes are routine.", "rotate-cert");
    }
    if (cert.self_signed && !cert.is_ca) {
      add("QS-CERT-TRUST-001", "Self-signed leaf certificate", "low", cert.subject,
        "Issue from an internal CA so certificates can be revoked and rotated centrally.", "rotate-cert");
    }
    return f;
  }

  function sortFindings(findings) {
    return findings.map(function (x, i) { return [x, i]; }).sort(function (a, b) {
      var x = a[0], y = b[0];
      return (SEVERITY_ORDER[x.severity] - SEVERITY_ORDER[y.severity]) ||
        cpCompare(x.service || "", y.service || "") || cpCompare(x.rule_id, y.rule_id) || a[1] - b[1];
    }).map(function (p) { return p[0]; });
  }

  // ======================================================== entry points

  function nowMicros(now) {
    if (now === undefined || now === null) now = Date.now();
    if (now instanceof Date) now = now.getTime();
    if (typeof now === "string") now = Date.parse(now);
    if (typeof now !== "number" || !isFinite(now)) throw new TypeError("opts.now must be a Date, ISO string or epoch ms");
    return BigInt(Math.round(now * 1000));
  }

  function nodeSha256() {
    try {
      // eslint-disable-next-line no-undef
      var nodeCrypto = typeof require === "function" ? require("crypto") : null;
      if (nodeCrypto && nodeCrypto.createHash) {
        return function (der) { return nodeCrypto.createHash("sha256").update(der).digest("hex"); };
      }
    } catch (e) { /* not Node */ }
    return null;
  }

  function algorithmView(name) {
    var alg = lookup(name) || classifyGroup(name);
    return { name: name, status: alg ? alg.status : null, primitive: alg ? alg.primitive : null };
  }

  // Analyze one file.  Mirrors config_scanner.scan_file() followed by
  // analyzer.analyze() on an inventory holding just that file.
  //   opts.now      Date / epoch ms / ISO string for the expiry rules (default: now)
  //   opts.service  service name, like "name=path" on the command line
  //   opts.sha256   function(Uint8Array) -> hex, for certificate fingerprints
  // Without opts.sha256 it uses Node's crypto module.  In a browser call
  // analyzeAsync() instead: with no SHA-256 at hand, fingerprint_sha256 is null and
  // certificates are named by serial number ("cert:serial-<hex>") instead.
  function analyze(filename, text, opts) {
    opts = opts || {};
    var path = String(filename === undefined || filename === null ? "" : filename);
    text = String(text === undefined || text === null ? "" : text);
    var result = { path: path, kind: null, scan_kind: null, service: null, items: [], certificates: [], findings: [] };
    var head = text.length > 20000 ? cpSlice(text, 0, 20000) : text;
    var kind = detectKind(path, head);
    result.kind = kind;
    if (!kind) return result;
    var digest = opts.sha256 || nodeSha256() || function () { return null; };
    var scan = kind === "pem" ? parsePem(path, text, digest) : PARSERS[kind](path, text);
    if (!scan || (!scan.items.length && !scan.certificates.length)) return result;
    scan.service = opts.service || scan.service || parentName(path);

    // Inventory.add_cert(): one entry per certificate, however often it appears.
    var certs = [], seen = new Map();
    scan.certificates.forEach(function (c) {
      var key = c.info.fingerprint_sha256 || bytesKey(c.der);
      if (!seen.has(key)) {
        c.info.sources = ["file://" + path];
        seen.set(key, c.info);
        certs.push(c.info);
      }
    });
    var findings = configFindings(scan);
    var nowUs = nowMicros(opts.now);
    certs.forEach(function (cert) {
      findings = findings.concat(certFindings(cert, [scan.service || path], nowUs));
    });

    result.scan_kind = scan.kind;
    result.service = scan.service;
    result.items = scan.items.map(function (it) {
      return { directive: it.directive, value: it.value, line: it.line, category: it.category,
        algorithms: it.algorithms.map(algorithmView) };
    });
    result.certificates = certs;
    result.findings = sortFindings(findings);
    return result;
  }

  // analyze(), with certificate fingerprints from WebCrypto (browsers have no
  // synchronous SHA-256).
  function analyzeAsync(filename, text, opts) {
    opts = Object.assign({}, opts || {});
    var subtle = typeof crypto !== "undefined" && crypto && crypto.subtle;
    if (opts.sha256 || !subtle) return Promise.resolve().then(function () { return analyze(filename, text, opts); });
    var ders = certificateDers(String(text === undefined || text === null ? "" : text)).filter(Boolean);
    return Promise.all(ders.map(function (der) { return subtle.digest("SHA-256", der); })).then(function (hashes) {
      var byDer = new Map();
      ders.forEach(function (der, i) { byDer.set(bytesKey(der), hex(new Uint8Array(hashes[i]))); });
      opts.sha256 = function (der) { return byDer.get(bytesKey(der)) || null; };
      return analyze(filename, text, opts);
    });
  }

  // ======================================================== CBOM (cbom.py)

  var FUNCS = { kem: ["encapsulate", "decapsulate", "keygen"], "key-agree": ["keygen"],
    signature: ["sign", "verify", "keygen"], pke: ["encrypt", "decrypt"], ae: ["encrypt", "decrypt"],
    "block-cipher": ["encrypt", "decrypt"], "stream-cipher": ["encrypt", "decrypt"], hash: ["digest"] };

  function randomUuid() {
    var c = typeof crypto !== "undefined" ? crypto : null;
    if (c && c.randomUUID) return c.randomUUID();
    var b = new Uint8Array(16);
    if (c && c.getRandomValues) c.getRandomValues(b);
    else for (var i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = hex(b);
    return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
  }

  function certRef(cert) {
    return "crypto/certificate/" + (cert.fingerprint_sha256 ? cert.fingerprint_sha256.slice(0, 16) : "serial-" + cert.serial);
  }

  // A CycloneDX 1.6 CBOM for one or more analyze() results, shaped like
  // cbom.build_cbom() for an inventory of those files.
  function cbom(results, opts) {
    opts = opts || {};
    results = Array.isArray(results) ? results : [results];
    var components = new Map(), deps = new Map(), services = new Map();

    function algorithm(name) {
      var alg = lookup(name) || classifyGroup(name);
      var cname = alg ? alg.name : name, ref = "crypto/algorithm/" + cname;
      if (components.has(ref)) return ref;
      var props = { assetType: "algorithm" };
      if (alg) {
        props.algorithmProperties = {
          primitive: alg.status === HYBRID ? "combiner" : alg.primitive,
          parameterSetIdentifier: cname,
          executionEnvironment: "software-plain-ram",
          cryptoFunctions: (FUNCS[alg.primitive] || []).slice(),
          classicalSecurityLevel: alg.classical_bits,
          nistQuantumSecurityLevel: alg.nist_level,
        };
        if (alg.oid) props.oid = alg.oid;
      }
      var comp = { type: "cryptographic-asset", "bom-ref": ref, name: cname, cryptoProperties: props,
        properties: [{ name: "quantumshield:quantum-status", value: alg ? alg.status : "unknown" }] };
      if (alg && alg.replacement) {
        comp.properties.push({ name: "quantumshield:recommended-replacement", value: alg.replacement });
      }
      components.set(ref, comp);
      return ref;
    }

    function dep(src) {
      if (!deps.has(src)) deps.set(src, new Set());
      for (var i = 1; i < arguments.length; i++) if (arguments[i]) deps.get(src).add(arguments[i]);
    }

    function service(name) {
      var ref = "service/" + name;
      if (!services.has(ref)) services.set(ref, { "bom-ref": ref, name: name, endpoints: [] });
      return ref;
    }

    var scanned = results.filter(function (r) { return r && r.kind && (r.items.length || r.certificates.length); });

    // Certificates (Inventory.certificates: first appearance wins, sources merged)
    var certs = new Map();
    scanned.forEach(function (r) {
      r.certificates.forEach(function (c) {
        var ref = certRef(c);
        if (!certs.has(ref)) certs.set(ref, Object.assign({}, c, { sources: c.sources.slice() }));
        else c.sources.forEach(function (s) { if (certs.get(ref).sources.indexOf(s) < 0) certs.get(ref).sources.push(s); });
      });
    });
    certs.forEach(function (c, ref) {
      var keyRef = algorithm(c.public_key_algorithm), sigRef = algorithm(c.signature_algorithm);
      if (c.signature_hash) dep(sigRef, algorithm(c.signature_hash));
      components.set(ref, {
        type: "cryptographic-asset", "bom-ref": ref, name: c.subject,
        cryptoProperties: {
          assetType: "certificate",
          certificateProperties: {
            subjectName: c.subject, issuerName: c.issuer, notValidBefore: c.not_before, notValidAfter: c.not_after,
            signatureAlgorithmRef: sigRef, subjectPublicKeyRef: keyRef, certificateFormat: "X.509",
            certificateExtension: "crt",
          },
        },
        properties: (c.fingerprint_sha256 ? [{ name: "quantumshield:fingerprint-sha256", value: c.fingerprint_sha256 }] : [])
          .concat([{ name: "quantumshield:public-key", value: c.public_key_detail || c.public_key_algorithm }],c.subject_alt_names.map(function (s) { return { name: "quantumshield:san", value: s }; }),
            c.sources.map(function (s) { return { name: "quantumshield:source", value: s }; })),
      });
      dep(ref, keyRef, sigRef);
    });

    // Configuration files
    scanned.forEach(function (r) {
      var sref = service(r.service || r.path), refs = [];
      r.items.forEach(function (it) {
        var algs = it.algorithms.map(function (a) { return typeof a === "string" ? a : a.name; });
        if (it.category === "private-key") {
          var kref = "crypto/key/" + r.path + "#" + it.line;
          components.set(kref, {
            type: "cryptographic-asset", "bom-ref": kref, name: "private key (" + it.value + ")",
            cryptoProperties: { assetType: "related-crypto-material",
              relatedCryptoMaterialProperties: { type: "private-key", algorithmRef: algs.length ? algorithm(algs[0]) : null } },
            evidence: { occurrences: [{ location: r.path, line: it.line }] },
          });
          refs.push(kref);
          return;
        }
        if (it.category === "tls-protocol" || it.category === "certificate" || it.category === "mtls") return;
        algs.forEach(function (a) {
          if (a.startsWith("configured-")) return;
          var ref = algorithm(a), comp = components.get(ref);
          comp.evidence = comp.evidence || {};
          var occ = comp.evidence.occurrences = comp.evidence.occurrences || [];
          if (occ.length < 50) {
            occ.push({ location: r.path, line: it.line, additionalContext: cpSlice(it.directive + " " + it.value, 0, 200) });
          }
          refs.push(ref);
        });
      });
      r.certificates.forEach(function (c) { refs.push(certRef(c)); });
      dep.apply(null, [sref].concat(refs));
    });

    var byRef = function (a, b) { return cpCompare(a["bom-ref"], b["bom-ref"]); };
    return {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: opts.serialNumber || "urn:uuid:" + randomUuid(),
      version: 1,
      metadata: {
        timestamp: opts.timestamp || new Date().toISOString(),
        tools: { components: [{ type: "application", name: "quantumshield", version: VERSION }] },
        properties: [{ name: "quantumshield:tls-library",
          value: opts.tlsLibrary || "browser (cipher table from " + CIPHER_TABLE.openssl + ")" }],
      },
      components: Array.from(components.values()).sort(byRef),
      services: Array.from(services.values()),
      dependencies: Array.from(deps.keys()).sort(cpCompare).map(function (k) {
        return { ref: k, dependsOn: Array.from(deps.get(k)).sort(cpCompare) };
      }),
    };
  }

  return {
    version: VERSION,
    analyze: analyze,
    analyzeAsync: analyzeAsync,
    cbom: cbom,
    catalog: CATALOG,
    lookup: lookup,
    classifyGroup: classifyGroup,
    parseCipherSuite: parseCipherSuite,
    detectKind: detectKind,
    expandCipherString: expandCipherString,
    ciphersToSuites: ciphersToSuites,
    cipherTable: { openssl: CIPHER_TABLE.openssl, suites: SUITES.length, aliases: ALIASES.size },
  };
});
