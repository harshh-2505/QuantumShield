"""Generate the OpenSSL cipher-string table embedded in web/assets/analyzer.js.

config_scanner.ciphers_to_algs() expands cipher strings such as
"HIGH:!aNULL:!MD5" with the local OpenSSL.  The browser port cannot call
OpenSSL, so this script asks OpenSSL (through Python's ssl module) for
everything the JavaScript needs to replay ``SSL_CTX_set_cipher_list``:

  * every TLS <= 1.2 suite, with its IANA name and strength bits, in OpenSSL's
    default preference order (the order in which a single alias expands);
  * every alias (ALL, HIGH, kRSA, AESGCM, ...) and the suites it selects;
  * which ``A+B`` combinations OpenSSL rejects as contradictory (it compares
    bit masks, so e.g. ``HIGH+FIPS`` selects nothing although both sets
    overlap);
  * a set of check vectors (cipher string -> expanded suites) that
    tests/test_web_analyzer.py replays against the JavaScript engine.

It only probes; it never generates keys or does any cryptography.

Regenerate from the repository root (needs the OpenSSL 3.5 image):

    docker run --rm -i --entrypoint python quantumshield:latest - \\
        < scripts/gen_cipher_table.py > /tmp/cipher-table.json
    python3 scripts/gen_cipher_table.py --embed /tmp/cipher-table.json

``--embed`` rewrites the block between the GENERATED CIPHER TABLE markers in
web/assets/analyzer.js and writes tests/web_parity/cipher_vectors.json.
"""

from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent if "__file__" in globals() else Path.cwd()
JS_PATH = Path("web/assets/analyzer.js")
VECTORS_PATH = Path("tests/web_parity/cipher_vectors.json")
BEGIN = "// ---- BEGIN GENERATED CIPHER TABLE"
END = "// ---- END GENERATED CIPHER TABLE ----"

# Aliases documented in ciphers(1) / ssl_ciph.c.  Strings mined from libssl add
# anything newer; names OpenSSL does not know simply expand to nothing.
KNOWN_ALIASES = """
ALL COMPLEMENTOFALL COMPLEMENTOFDEFAULT DEFAULT HIGH MEDIUM LOW EXP EXPORT EXPORT40
EXPORT56 FIPS eNULL NULL aNULL kRSA aRSA RSA kDHr kDHd kDH kDHE kEDH DH DHE EDH ADH
kECDHr kECDHe kECDH kEECDH kECDHE ECDH ECDHE EECDH AECDH aDSS DSS aDH aECDH aECDSA ECDSA
TLSv1.2 TLSv1.0 TLSv1.1 TLSv1 SSLv3 SSLv2 AES128 AES256 AES AESGCM AESCCM AESCCM8
ARIA128 ARIA256 ARIA ARIAGCM CAMELLIA128 CAMELLIA256 CAMELLIA CHACHA20 3DES DES RC4 RC2
IDEA SEED MD5 SHA1 SHA SHA256 SHA384 CBC AEAD aGOST aGOST01 aGOST12 kGOST kGOST18 GOST94
GOST89MAC GOST12 GOST89 MAGMA KUZNYECHIK PSK kPSK kECDHEPSK kDHEPSK kRSAPSK aPSK SRP
kSRP aSRP SUITEB128 SUITEB128ONLY SUITEB128C2 SUITEB192 KRB5 kKRB5 aKRB5 FZA kFZA aFZA
eFZA
""".split()

# OpenSSL treats these as prefixes of the whole cipher string, not as aliases
# (ssl_ciph.c: check_suiteb_cipher_list() and the "DEFAULT" special case).
PREFIX_RULES = ("DEFAULT", "SUITEB128ONLY", "SUITEB128C2", "SUITEB128", "SUITEB192")
ANCHOR = "AES128-SHA"   # a suite every OpenSSL 3.x build offers
# Aliases that set OpenSSL's strength mask (SSL_STRONG_MASK in ssl_local.h).
STRENGTH_ALIASES = {"HIGH", "MEDIUM", "LOW", "FIPS", "EXP", "EXPORT", "EXPORT40", "EXPORT56"}


# --------------------------------------------------------------------------- probing

def _ctx():
    import ssl
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def expand(rule: str) -> list[str] | None:
    """Exactly what config_scanner.ciphers_to_algs asks OpenSSL (None = SSLError)."""
    import ssl
    ctx = _ctx()
    try:
        ctx.set_ciphers(rule)
    except ssl.SSLError:
        return None
    return [c["name"] for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"]


def _libssl_strings() -> set[str]:
    """Every token-like string (and each of its suffixes) in the loaded libssl."""
    import ssl  # noqa: F401 - loads libssl into this process
    out: set[str] = set()
    try:
        maps = Path("/proc/self/maps").read_text()
    except OSError:
        return out
    libs = sorted({line.split()[-1] for line in maps.splitlines() if "libssl" in line})
    for lib in libs:
        data = Path(lib).read_bytes()
        for m in re.findall(rb"[A-Za-z0-9._=-]{2,64}", data):
            s = m.decode()
            # The linker merges strings that are suffixes of others ("ECDHE"
            # lives inside "kECDHE"), so try every suffix that starts a word.
            for i in range(len(s) - 1):
                t = s[i:]
                if t[0].isalpha():
                    out.add(t)
    return out


def _merge_order(chains: list[list[str]], universe: list[str]) -> list[str]:
    """One total order consistent with every alias expansion (Kahn's algorithm)."""
    pos_hint = {n: i for i, n in enumerate(universe)}
    succ: dict[str, set[str]] = {n: set() for n in universe}
    indeg = {n: 0 for n in universe}
    for chain in chains:
        for a, b in zip(chain, chain[1:]):
            if b not in succ[a]:
                succ[a].add(b)
                indeg[b] += 1
    ready = sorted((n for n in universe if indeg[n] == 0), key=pos_hint.get)
    out: list[str] = []
    while ready:
        n = ready.pop(0)
        out.append(n)
        for m in sorted(succ[n], key=pos_hint.get):
            indeg[m] -= 1
            if indeg[m] == 0:
                ready.append(m)
        ready.sort(key=pos_hint.get)
    if len(out) != len(universe):
        raise SystemExit("alias expansions are not consistent with a single order")
    return out


def _vectors(suites, stdnames, aliases, seed=20261012) -> list[str]:
    """Cipher strings whose OpenSSL expansion the JavaScript engine must reproduce."""
    rnd = random.Random(seed)
    names = [s["name"] for s in suites]
    out = [
        "", "DEFAULT", "DEFAULT:!kRSA", "DEFAULT,eNULL", "DEFAULTS", "DEFAULT:@STRENGTH",
        "HIGH:DEFAULT", "AES128-SHA:DEFAULT", "SUITEB128", "SUITEB128:HIGH", "SUITEB128ONLY",
        "SUITEB128C2", "SUITEB192", "SUITEB192XYZ:RSA", "HIGH:!aNULL:!MD5",
        "HIGH:!aNULL:!MD5:@SECLEVEL=0", "ALL:@STRENGTH", "ALL:-HIGH:HIGH",
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM", "kRSA:+AES256:!SHA256", "HIGH+FIPS",
        "MEDIUM+FIPS", "FIPS+HIGH:AES128-SHA", "kRSA+kECDHE+!:AES128-SHA", "kRSA+aECDSA+!:AES",
        "AES128-SHA+kRSA", "AES128-SHA+aECDSA", "AES128-SHA+TLSv1.2:AES256-SHA",
        "AES128-SHA+AES256-SHA:CAMELLIA", "HIGH+", "HIGH++AES", "+HIGH", "-HIGH:HIGH",
        "!HIGH:HIGH:MEDIUM", "HIGH|AES", "FOO|BAR:AES", "FOO+|x:AES", "HIGH:@FOO",
        "HIGH:@SECLEVEL=9", "HIGH:@SECLEVEL=10", "HIGH:@SECLEVEL=x", "HIGH:@STRENGTH+X",
        "@STRENGTH", "HIGH;MEDIUM", "HIGH MEDIUM", "HIGH\tMEDIUM", "high", "TLSv1.2:+SHA384",
        "RC4-SHA:DES-CBC3-SHA", "AES256-SHA:RC4", "COMPLEMENTOFDEFAULT", "COMPLEMENTOFALL:ALL",
        "eNULL:ALL:@STRENGTH", "ALL:COMPLEMENTOFALL:+aNULL:+eNULL", "TLS_RSA_WITH_AES_128_CBC_SHA",
        "kRSA+COMPLEMENTOFDEFAULT", "AES128-SHA+COMPLEMENTOFDEFAULT:AES256-SHA",
        "COMPLEMENTOFDEFAULT+AES128-SHA:AES256-SHA", "SSLv3+TLSv1.2:AES128-SHA",
        "--HIGH:AES", "AES128-SHA,,AES256-SHA", "AES128-SHA:@SECLEVEL=0:AES256-SHA",
        # "-" moves suites to the front, so re-adding them orders them before the rest
        "ECDHE+AESGCM:-aECDSA:AESGCM:!PSK:!aNULL", "ALL:-AES256:AES", "AES128:-SHA:AES256:SHA",
        "kRSA:-AES:+CAMELLIA:AES:@STRENGTH", "ALL:+AES128:-AES128:AES128", "!AES128:AES128:AES",
        "HIGH:-ECDSA:+SHA:ECDSA:@STRENGTH:-CHACHA20:CHACHA20",
    ]
    tokens = list(aliases) + names[:: 3] + [stdnames[n] for n in names[1::9] if n in stdnames] + [
        "FOO", "TLS_AES_128_GCM_SHA256", "DEFAULT", "SUITEB128", "high"]
    for _ in range(420):
        parts = []
        for _ in range(rnd.randint(1, 6)):
            item = "+".join(rnd.choice(tokens) for _ in range(rnd.choice([1, 1, 1, 2, 2, 3])))
            item = rnd.choice(["", "", "", "!", "-", "+"]) + item
            if rnd.random() < 0.06:
                item = rnd.choice(["@STRENGTH", "@SECLEVEL=1", "@SECLEVEL=0"])
            parts.append(item)
        sep = rnd.choice([":", ":", ":", ",", " ", ";"])
        out.append(sep.join(parts))
    for _ in range(60):   # malformed input
        s = rnd.choice(out[60:])
        i = rnd.randrange(len(s) + 1)
        out.append(s[:i] + rnd.choice("|[]()*&$#\"'!+:") + s[i:])
    return list(dict.fromkeys(out))


def probe() -> dict:
    import ssl

    ctx = _ctx()
    ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    details = {c["name"]: c for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"}
    names = list(details)
    name_set = set(names)

    candidates = set(KNOWN_ALIASES) | _libssl_strings()
    stdnames: dict[str, str] = {}
    alias_sets: dict[str, list[str]] = {}
    for cand in sorted(candidates):
        if cand in name_set or not cand[0].isalpha() or cand.startswith(PREFIX_RULES):
            continue
        r = expand(cand)
        if cand.startswith("TLS_") and r and len(r) == 1:
            if r[0] in stdnames:
                raise SystemExit(f"two IANA names for {r[0]}")
            stdnames[r[0]] = cand
        elif r:
            alias_sets[cand] = r
        elif expand(f"{cand}+!:{ANCHOR}") is None:
            # Known to OpenSSL but selects nothing here (LOW, ...).  Still matters:
            # "LOW+X" is parsed on, an unknown name ends the item.
            alias_sets[cand] = []

    base = _merge_order([alias_sets[a] for a in sorted(alias_sets)], names)
    rank = {n: i for i, n in enumerate(base)}
    for a, members in alias_sets.items():
        if sorted(members, key=rank.get) != members:
            raise SystemExit(f"alias {a} does not expand in base order")
    aliases = sorted(alias_sets, key=lambda a: (-len(alias_sets[a]), a.lower(), a))
    sets = {a: set(alias_sets[a]) for a in aliases}

    # "A+B": OpenSSL ANDs the bit masks of A and B; when that leaves nothing it
    # drops the whole rule ("found = 0") and skips the rest of the item.  Probe
    # with a trailing "+!": if OpenSSL is still parsing after B, '!' is a syntax
    # error; if it gave up, the item is skipped and the anchor suite survives.
    def contradicts(a: str, b: str) -> bool:
        return expand(f"{a}+{b}+!:{ANCHOR}") == [ANCHOR]

    contra: dict[str, list[str]] = {a: [b for b in aliases if contradicts(a, b)]
                                    for a in aliases}
    for a in aliases:
        for b in contra[a]:
            if a not in contra[b]:
                raise SystemExit(f"asymmetric contradiction {a}/{b}")

    # A suite name N in "N+A" never contradicts some aliases (protocol versions,
    # COMPLEMENTOFDEFAULT); for every other alias it contradicts exactly when N
    # is not selected by A.
    name_transparent = []
    for a in aliases:
        z = {n for n in names if contradicts(n, a)}
        if z != {n for n in names if contradicts(a, n)}:
            raise SystemExit(f"asymmetric name contradiction for {a}")
        if not z:
            name_transparent.append(a)
        elif z != name_set - sets[a]:
            raise SystemExit(f"alias {a}: name contradictions follow no rule")
    # Two different suite names normally contradict; record any that do not.
    name_pairs = [[n, m] for n in names for m in names if n != m and not contradicts(n, m)]

    # Strength aliases (HIGH, MEDIUM, FIPS, ...) are kept in a separate mask that
    # OpenSSL *assigns* rather than ANDs the first time it sees one, which wipes
    # an earlier COMPLEMENTOFDEFAULT: "COMPLEMENTOFDEFAULT+HIGH" selects all of
    # HIGH while "HIGH+COMPLEMENTOFDEFAULT" selects the intersection.
    not_default = "COMPLEMENTOFDEFAULT"
    strength = [a for a in aliases if a in STRENGTH_ALIASES or (
        a != not_default and expand(f"{not_default}+{a}") == alias_sets[a]
        and expand(f"{a}+{not_default}") != alias_sets[a])]
    # Every suite carries a strength bit (eNULL suites carry STRONG_NONE, which
    # no alias names), so a suite name in "+" also replaces that mask.
    strong_bits = {n: {a for a in strength if n in sets[a]} or {"NONE"} for n in names}
    for n in names:
        if n not in sets[not_default] and expand(f"{not_default}+{n}") != [n]:
            raise SystemExit(f"{n} does not reset COMPLEMENTOFDEFAULT")

    def model(parts: list[str]) -> list[str] | None:
        """The rule semantics analyzer.js implements, for one "+"-joined item."""
        cat = strong = name = None
        dflt = False
        for i, p in enumerate(parts):
            for q in parts[:i]:
                if q in name_set and p in name_set:
                    bad = q != p and [q, p] not in name_pairs
                elif q in name_set or p in name_set:
                    n, a = (q, p) if q in name_set else (p, q)
                    bad = a not in name_transparent and n not in sets[a]
                else:
                    bad = p in contra[q]
                if bad:
                    return None
            bits = strong_bits[p] if p in name_set else {p} if p in strength else set()
            if bits:
                if strong is None:
                    strong, dflt = set(bits), False
                else:
                    strong &= bits
            if p in name_set:
                name = p
                dflt = dflt or p in sets[not_default]
            elif p == not_default:
                dflt = True
            else:
                cat = sets[p] if cat is None else cat & sets[p]
        out = [n for n in base if (cat is None or n in cat) and (name is None or n == name)
               and (strong is None or strong & strong_bits[n])
               and (not dflt or n in sets[not_default])]
        return out or None

    for a in aliases:
        for b in aliases + names:
            for parts in ([a, b], [b, a]):
                if expand("+".join(parts)) != model(parts):
                    raise SystemExit(f"{'+'.join(parts)} does not match the model")
    rnd = random.Random(1)
    for _ in range(3000):
        parts = [rnd.choice(aliases + names) for _ in range(rnd.choice([2, 3, 3, 4]))]
        if expand("+".join(parts)) != model(parts):
            raise SystemExit(f"{'+'.join(parts)} does not match the model")

    default_rules = "ALL:!COMPLEMENTOFDEFAULT:!eNULL"
    if expand("DEFAULT") != expand(default_rules):
        raise SystemExit("DEFAULT no longer means " + default_rules)

    suites = [{"name": n, "stdname": stdnames.get(n, ""),
               "strength_bits": details[n]["strength_bits"], "protocol": details[n]["protocol"],
               "aliases": [a for a in aliases if n in sets[a]]} for n in base]
    vectors = [[s, expand(s)] for s in _vectors(suites, stdnames, aliases)]
    return {
        "openssl": ssl.OPENSSL_VERSION,
        "default_rules": default_rules,
        "aliases": aliases,
        "suites": suites,
        "contradicts": contra,
        "strength": strength,
        "not_default": not_default,
        "name_transparent": name_transparent,
        "name_pairs": name_pairs,
        "vectors": vectors,
    }


# --------------------------------------------------------------------------- embedding

def _js_string(s: str) -> str:
    return json.dumps(s)


def render_js(t: dict) -> str:
    aliases = t["aliases"]
    idx = {a: i for i, a in enumerate(aliases)}
    w = max(len(s["name"]) for s in t["suites"]) + 3
    lines = [
        f"{BEGIN} (scripts/gen_cipher_table.py; do not edit by hand) ----",
        "  // Probed from " + t["openssl"] + ".",
        "  var CIPHER_TABLE = {",
        "    openssl: " + _js_string(t["openssl"]) + ",",
        "    // What a cipher string starting with DEFAULT expands to first.",
        "    defaultRules: " + _js_string(t["default_rules"]) + ",",
        "    // Every TLS <= 1.2 suite in OpenSSL's default preference order:",
        "    // [OpenSSL name, IANA name, strength bits, protocol, aliases selecting it]",
        "    suites: [",
    ]
    for s in t["suites"]:
        row = ", ".join([_js_string(s["name"]).ljust(w), _js_string(s["stdname"]),
                         str(s["strength_bits"]), _js_string(s["protocol"]),
                         _js_string(" ".join(s["aliases"]))])
        lines.append(f"      [{row}],")
    lines += [
        "    ],",
        "    // \"A+B\" where B contradicts A selects nothing and OpenSSL skips the rest",
        "    // of that item.  Hex bitmap over the alias list, in this order:",
        "    aliases: " + _js_string(" ".join(aliases)) + ",",
        "    contradicts: {",
    ]
    for a in aliases:
        bits = 0
        for b in t["contradicts"][a]:
            bits |= 1 << idx[b]
        hexbits = format(bits, "x").rjust((len(aliases) + 3) // 4, "0")
        lines.append(f"      {_js_string(a).ljust(24)}: \"{hexbits}\",")
    lines += [
        "    },",
        "    // Aliases that set OpenSSL's strength mask; the first one in an item",
        "    // replaces (rather than narrows) an earlier " + t["not_default"] + ".",
        "    strength: " + _js_string(" ".join(t["strength"])) + ",",
        "    notDefault: " + _js_string(t["not_default"]) + ",",
        "    // Aliases that never contradict an explicit suite name in \"NAME+ALIAS\".",
        "    nameTransparent: " + _js_string(" ".join(t["name_transparent"])) + ",",
        "    // Pairs of different suite names that do not contradict in \"N1+N2\".",
        "    namePairs: " + json.dumps(t["name_pairs"]) + ",",
        "  };",
        "  " + END,
    ]
    return "\n".join(lines)


def embed(table_path: str) -> None:
    raw = sys.stdin.read() if table_path == "-" else Path(table_path).read_text()
    t = json.loads(raw)
    js_file = ROOT / JS_PATH
    src = js_file.read_text()
    start = src.index(BEGIN)
    start = src.rindex("\n", 0, start) + 1
    stop = src.index(END) + len(END)
    js_file.write_text(src[:start] + "  " + render_js(t) + src[stop:])
    names = [s["name"] for s in t["suites"]]
    pos = {n: i for i, n in enumerate(names)}
    rows = ",\n".join(json.dumps([s, None if r is None else " ".join(str(pos[n]) for n in r)])
                       for s, r in t["vectors"])
    (ROOT / VECTORS_PATH).write_text(
        "{\n" f'"openssl": {json.dumps(t["openssl"])},\n'
        '"note": "Generated by scripts/gen_cipher_table.py. Each vector is [cipher string, '
        'OpenSSL\'s expansion as indices into suites (null = SSL_CTX_set_cipher_list fails)].",\n'
        f'"suites": {json.dumps(names)},\n'
        f'"vectors": [\n{rows}\n]\n}}\n')
    print(f"embedded {len(t['suites'])} suites, {len(t['aliases'])} aliases and "
          f"{len(t['vectors'])} check vectors from {t['openssl']}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--embed":
        embed(sys.argv[2])
    else:
        json.dump(probe(), sys.stdout, indent=1)
        sys.stdout.write("\n")
