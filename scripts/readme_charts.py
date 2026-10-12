#!/usr/bin/env python3
"""Draw the README benchmark charts from a QuantumShield benchmark run.

Reads ``docs/sample-output/bench.json`` (written by ``qs bench ... -o``) and writes
to-scale SVG bar charts to ``docs/assets/``:

  bench-handshake.svg   wall time and client + server CPU per handshake (local scenarios)
  bench-bytes.svg       bytes on the wire per handshake, client->server / server->client
  bench-network.svg     TCP + TLS connect time (p50, with p95 whisker) for each live path

Each chart is written twice: ``<name>.svg`` on the dark "cryostat" card and
``<name>-light.svg`` on the light card, so the README can switch with
``<picture>`` / ``prefers-color-scheme``. Both carry their own background, so
either one reads on GitHub's light and dark themes.

Every bar in a chart shares one linear scale that starts at zero, and every bar
is labelled with its measured value.

If fontTools (and brotli) are installed, the IBM Plex fonts in web/assets/fonts are
subset to the glyphs used and embedded, so the charts look the same everywhere;
otherwise the SVGs fall back to the system monospace / sans-serif stack.

    python3 scripts/readme_charts.py [--bench docs/sample-output/bench.json] [--out docs/assets]
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = ROOT / "web" / "assets" / "fonts"

# Colour tokens: web/assets/tokens.css, plus three chart series tones checked for
# lightness band, colour-blind separation and contrast against each card surface.
THEMES = {
    "dark": dict(bg="#090d16", deck="#0f1522", line="#222b3e", ink="#e9edf5", dim="#8c95ab",
                 faint="#5a6378", gold="#e6c27a", safe="#5fd8bc", bad="#ff5c72",
                 time="#b08636", client="#3e52cc", server="#7a8aee",
                 on_client="#ffffff", on_server="#090d16"),
    "light": dict(bg="#f3f5f9", deck="#ffffff", line="#d8dee9", ink="#0d1321", dim="#556079",
                  faint="#8790a5", gold="#8f6413", safe="#0b8a6c", bad="#d02d48",
                  time="#9a6c12", client="#3a4fc9", server="#7c8ef0",
                  on_client="#ffffff", on_server="#0d1321"),
}
MONO = ('"QS Mono", "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, '
        '"Liberation Mono", monospace')
SANS = '"QS Sans", "IBM Plex Sans", "Segoe UI", "Helvetica Neue", Arial, sans-serif'
FONT_FILES = {("mono", 400): "plex-mono-400.woff2", ("mono", 500): "plex-mono-500.woff2",
              ("sans", 600): "plex-sans-600.woff2"}

W = 960
LABEL_X, BAR_X0, BAR_X1 = 40, 318, 812     # label column, bar area


def mono_w(text: str, size: float) -> float:
    return len(text) * 0.6 * size           # IBM Plex Mono: 600/1000 em advance


def nice_max(v: float) -> tuple[float, float]:
    """Axis maximum and tick step: the smallest 'nice' bound >= v."""
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 1.25, 2, 2.5, 4, 5, 8, 10):
        top = m * exp
        if top >= v:
            break
    step = {1: .2, 1.25: .25, 2: .5, 2.5: .5, 4: 1, 5: 1, 8: 2, 10: 2}[m] * exp
    return top, step


def fmt_ms(v: float) -> str:
    return f"{v:.2f}"


def fmt_b(v: int) -> str:
    return f"{v:,}"


def kex_safe(group: str | None) -> bool:
    return bool(group) and "MLKEM" in group.upper()


class Chart:
    def __init__(self, theme: str, height: int):
        self.t = THEMES[theme]
        self.h = height
        self.parts: list[str] = []
        self.used: dict[tuple[str, int], set[str]] = defaultdict(set)

    def text(self, x, y, s, size=13, family="mono", weight=400, fill="ink", anchor="start",
             spacing=0.0, spans=None):
        spans = spans or [(s, None)]
        body = ""
        for txt, col in spans:
            self.used[(family, weight)].update(txt)
            body += (f'<tspan fill="{self.t[col]}">{escape(txt)}</tspan>' if col
                     else escape(txt))
        fam = MONO if family == "mono" else SANS
        extra = f' text-anchor="{anchor}"' if anchor != "start" else ""
        extra += f' letter-spacing="{spacing}"' if spacing else ""
        self.parts.append(f'<text x="{x:.1f}" y="{y:.1f}" font-family=\'{fam}\' '
                          f'font-size="{size}" font-weight="{weight}" fill="{self.t[fill]}"'
                          f'{extra}>{body}</text>')

    def rect(self, x, y, w, h, fill, rx=0, **kw):
        a = "".join(f' {k.replace("_", "-")}="{v}"' for k, v in kw.items())
        self.parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
                          f'rx="{rx}" fill="{self.t.get(fill, fill)}"{a}/>')

    def line(self, x1, y1, x2, y2, stroke, width=1.0, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                          f'stroke="{self.t[stroke]}" stroke-width="{width}"{d}/>')

    def bar(self, x, y, w, h, fill, round_end=True):
        """A bar anchored on the left with a 4px rounded data end."""
        r = min(4.0, w / 2, h / 2) if round_end else 0
        if w <= 0:
            return
        self.parts.append(
            f'<path d="M{x:.1f} {y:.1f} H{x + w - r:.1f} Q{x + w:.1f} {y:.1f} {x + w:.1f} '
            f'{y + r:.1f} V{y + h - r:.1f} Q{x + w:.1f} {y + h:.1f} {x + w - r:.1f} {y + h:.1f} '
            f'H{x:.1f} Z" fill="{self.t[fill]}"/>')

    def dot(self, x, y, fill, r=4.0):
        self.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{self.t[fill]}"/>')

    def frame(self, fig: str, title: str, note: str):
        t = self.t
        self.parts.insert(0, f'<rect x="1" y="1" width="{W - 2}" height="{self.h - 2}" rx="18" '
                             f'fill="{t["bg"]}" stroke="{t["line"]}" stroke-width="1.5"/>')
        self.text(40, 50, fig, 13, "mono", 500, "gold", spacing=1.8)
        self.text(40 + mono_w(fig, 13) + 1.8 * len(fig) + 14, 50, title, 18, "sans", 600, "ink")
        self.text(W - 40, 50, note, 13, "mono", 400, "dim", "end")

    def legend(self, y, series, status=True):
        x = 40
        for label, col in series:
            self.rect(x, y - 10, 14, 10, col, rx=2)
            self.text(x + 22, y, label, 13, "mono", 400, "dim")
            x += 22 + mono_w(label, 13) + 26
        if status:
            x = W - 40 - mono_w("quantum-vulnerable", 13) - mono_w("post-quantum / hybrid", 13) - 70
            for label, col in (("quantum-vulnerable", "bad"), ("post-quantum / hybrid", "safe")):
                self.dot(x + 4, y - 4.5, col)
                self.text(x + 14, y, label, 13, "mono", 400, "dim")
                x += 14 + mono_w(label, 13) + 28

    def axis(self, y_top, y_bottom, top, step, unit, fmt):
        n = round(top / step)
        for i in range(n + 1):
            v = i * step
            x = BAR_X0 + (BAR_X1 - BAR_X0) * v / top
            self.line(x, y_top, x, y_bottom, "line", 1, None if i == 0 else "2 4")
            self.text(x, y_top - 8, fmt(v) + (f" {unit}" if i == n else ""), 12, "mono", 400,
                      "faint", "middle")

    def footer(self, y, spans):
        self.text(40, y, "", 13.5, "mono", 400, "dim", spans=spans)

    def render(self, title: str, desc: str) -> str:
        css = font_css(self.used)
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{self.h}" '
                f'viewBox="0 0 {W} {self.h}" role="img" aria-labelledby="t d">\n'
                f'<title id="t">{escape(title)}</title>\n<desc id="d">{escape(desc)}</desc>\n'
                f'<style>{css}</style>\n' + "\n".join(self.parts) + "\n</svg>\n")


def font_css(used) -> str:
    try:
        from fontTools import subset
        from fontTools.ttLib import TTFont
    except ImportError:
        return ""
    if importlib.util.find_spec("brotli") is None:   # woff2 output needs brotli
        return ""
    rules = []
    for (family, weight), chars in sorted(used.items()):
        path = FONT_DIR / FONT_FILES[(family, weight)]
        if not chars or not path.exists():
            continue
        font = TTFont(str(path))
        opts = subset.Options()
        opts.flavor, opts.layout_features = "woff2", ["kern"]
        opts.name_IDs, opts.name_legacy = [0, 13, 14], False
        sub = subset.Subsetter(opts)
        sub.populate(text="".join(sorted(chars)) + " ")
        sub.subset(font)
        name = "QS Mono" if family == "mono" else "QS Sans"
        for nid, val in ((1, name), (2, "Regular"), (4, name), (6, name.replace(" ", "") + "-Subset")):
            font["name"].setName(val, nid, 3, 1, 0x409)
        buf = io.BytesIO()
        font.flavor = "woff2"
        font.save(buf)
        b64 = base64.b64encode(buf.getvalue()).decode()
        rules.append(f'@font-face{{font-family:"{name}";font-weight:{weight};'
                     f'src:url(data:font/woff2;base64,{b64}) format("woff2")}}')
    return "\n".join(rules)


def split_label(label: str) -> tuple[str, str]:
    head, sep, tail = label.partition(" + ")
    return (head, "+ " + tail) if sep else (label, "")


def scale(v: float, top: float) -> float:
    return (BAR_X1 - BAR_X0) * v / top


# ------------------------------------------------------------------ charts

def handshake_chart(theme: str, local: list[dict], runtime: str) -> str:
    row_h, y0 = 64, 150
    h = y0 + row_h * len(local) + 70
    c = Chart(theme, h)
    top, step = nice_max(max(max(r["wall_ms_median"], r["client_cpu_ms"] + r["server_cpu_ms"])
                             for r in local))
    n = local[0]["iterations"]
    c.frame("FIG. 4", "Handshake cost, in-process",
            f"TLS 1.3 mTLS · median of {n} · {runtime}")
    c.legend(88, [("wall time (p50)", "time"), ("client CPU", "client"),
                  ("server CPU", "server")])
    c.axis(y0 - 18, y0 + row_h * len(local) - 6, top, step, "ms", lambda v: f"{v:g}")
    for i, r in enumerate(local):
        y = y0 + i * row_h
        l1, l2 = split_label(r["label"])
        c.dot(LABEL_X + 4, y + 16.5, "safe" if kex_safe(r["group"]) else "bad")
        c.text(LABEL_X + 14, y + 21, l1, 14, "mono", 500, "ink")
        if l2:
            c.dot(LABEL_X + 4, y + 38.5, "safe" if r["cert_alg"].startswith("mldsa") else "bad")
            c.text(LABEL_X + 14, y + 43, l2, 13, "mono", 400, "dim")
        # wall time
        wall = r["wall_ms_median"]
        ww = scale(wall, top)
        c.bar(BAR_X0, y + 8, ww, 15, "time")
        c.text(BAR_X0 + ww + 8, y + 20, f"{fmt_ms(wall)} ms", 13, "mono", 500, "ink")
        # CPU, client + server, stacked with a 2px gap
        cw, sw = scale(r["client_cpu_ms"], top), scale(r["server_cpu_ms"], top)
        c.bar(BAR_X0, y + 27, cw - 1, 15, "client", round_end=False)
        c.bar(BAR_X0 + cw + 1, y + 27, sw - 1, 15, "server")
        for x, w, v, ink in ((BAR_X0, cw - 1, r["client_cpu_ms"], "on_client"),
                             (BAR_X0 + cw + 1, sw - 1, r["server_cpu_ms"], "on_server")):
            if w >= mono_w(fmt_ms(v), 11) + 8:
                c.text(x + w / 2, y + 38.5, fmt_ms(v), 11, "mono", 500, ink, "middle")
        cpu = r["client_cpu_ms"] + r["server_cpu_ms"]
        c.text(BAR_X0 + cw + sw + 8, y + 39, f"{fmt_ms(cpu)} ms CPU", 13, "mono", 400, "dim")
    by = {r["scenario"]: r for r in local}
    spans = []
    if {"classical-ecdsa", "hybrid-ecdsa", "hybrid-mldsa"} <= by.keys():
        a, b, m = by["classical-ecdsa"], by["hybrid-ecdsa"], by["hybrid-mldsa"]
        dwall = b["wall_ms_median"] - a["wall_ms_median"]
        dcpu = (b["client_cpu_ms"] + b["server_cpu_ms"]) - (a["client_cpu_ms"] + a["server_cpu_ms"])
        spans = [("hybrid key exchange ", None), (f"+{dwall:.2f} ms", "ink"),
                 (" wall, ", None), (f"+{dcpu:.2f} ms", "ink"), (" CPU · ML-DSA-65 certs ", None),
                 (f"{m['wall_ms_median'] / b['wall_ms_median']:.1f}x", "ink"),
                 (" the wall time", None)]
    c.footer(h - 32, spans)
    desc = "; ".join(f"{r['label']}: wall {fmt_ms(r['wall_ms_median'])} ms, client CPU "
                     f"{fmt_ms(r['client_cpu_ms'])} ms, server CPU {fmt_ms(r['server_cpu_ms'])} ms"
                     for r in local)
    return c.render("Handshake cost per scenario", desc)


def bytes_chart(theme: str, local: list[dict]) -> str:
    row_h, y0 = 54, 150
    h = y0 + row_h * len(local) + 62
    c = Chart(theme, h)
    top, step = nice_max(max(r["bytes_total"] for r in local))
    base = local[0]
    c.frame("FIG. 5", "Bytes on the wire per handshake",
            "TLS 1.3 mTLS · leaf + CA cert each side")
    c.legend(88, [("client to server", "client"), ("server to client", "server")])
    c.axis(y0 - 18, y0 + row_h * len(local) - 6, top, step, "B",
           lambda v: f"{v / 1000:g}k" if v else "0")
    for i, r in enumerate(local):
        y = y0 + i * row_h
        l1, l2 = split_label(r["label"])
        c.dot(LABEL_X + 4, y + 12.5, "safe" if kex_safe(r["group"]) else "bad")
        c.text(LABEL_X + 14, y + 17, l1, 14, "mono", 500, "ink")
        if l2:
            c.dot(LABEL_X + 4, y + 33.5, "safe" if r["cert_alg"].startswith("mldsa") else "bad")
            c.text(LABEL_X + 14, y + 38, l2, 13, "mono", 400, "dim")
        cw = scale(r["bytes_client_to_server"], top)
        sw = scale(r["bytes_server_to_client"], top)
        c.bar(BAR_X0, y + 12, cw - 1, 20, "client", round_end=False)
        c.bar(BAR_X0 + cw + 1, y + 12, sw - 1, 20, "server")
        for x, w, v, ink in ((BAR_X0, cw - 1, r["bytes_client_to_server"], "on_client"),
                             (BAR_X0 + cw + 1, sw - 1, r["bytes_server_to_client"], "on_server")):
            if w >= mono_w(fmt_b(v), 11.5) + 10:
                c.text(x + w / 2, y + 26, fmt_b(v), 11.5, "mono", 500, ink, "middle")
        c.text(BAR_X0 + cw + sw + 8, y + 27, "", 13, "mono", 500, "ink",
               spans=[(f"{fmt_b(r['bytes_total'])} B", None),
                      (f"  {r['bytes_total'] / base['bytes_total']:.2f}x", "dim")])
    by = {r["scenario"]: r for r in local}
    spans = [(f"multiples are relative to {base['label']}", None)]
    if {"classical-ecdsa", "hybrid-ecdsa", "hybrid-mldsa"} <= by.keys():
        a, b, m = by["classical-ecdsa"], by["hybrid-ecdsa"], by["hybrid-mldsa"]
        spans = [("hybrid key share ", None),
                 (f"+{fmt_b(b['bytes_total'] - a['bytes_total'])} B", "ink"),
                 (" · ML-DSA-65 chains ", None),
                 (f"+{fmt_b(m['bytes_total'] - b['bytes_total'])} B", "ink"),
                 (f" · multiples vs. {split_label(base['label'])[0]} + RSA", None)]
    c.footer(h - 30, spans)
    desc = "; ".join(f"{r['label']}: {fmt_b(r['bytes_client_to_server'])} B client to server, "
                     f"{fmt_b(r['bytes_server_to_client'])} B server to client, "
                     f"{fmt_b(r['bytes_total'])} B total" for r in local)
    return c.render("Bytes on the wire per handshake", desc)


def network_chart(theme: str, net: list[dict]) -> str:
    row_h, y0 = 56, 150
    h = y0 + row_h * len(net) + 62
    c = Chart(theme, h)
    top, step = nice_max(max(r["connect_ms_p95"] for r in net))
    n = net[0]["iterations"]
    c.frame("FIG. 6", "Live connections, through the proxy",
            f"TCP + TLS connect · n={n} · Docker bridge")
    c.legend(88, [("connect time (p50)", "time")], status=False)
    x = 40 + 22 + mono_w("connect time (p50)", 13) + 26
    c.line(x, 84, x + 16, 84, "dim", 1.6)
    c.line(x + 16, 79, x + 16, 89, "dim", 1.6)
    c.text(x + 24, 88, "p95", 13, "mono", 400, "dim")
    x = W - 40 - mono_w("quantum-vulnerable", 13) - mono_w("post-quantum / hybrid", 13) - 70
    for label, col in (("quantum-vulnerable", "bad"), ("post-quantum / hybrid", "safe")):
        c.dot(x + 4, 83.5, col)
        c.text(x + 14, 88, label, 13, "mono", 400, "dim")
        x += 14 + mono_w(label, 13) + 28
    c.axis(y0 - 18, y0 + row_h * len(net) - 6, top, step, "ms", lambda v: f"{v:g}")
    for i, r in enumerate(net):
        y = y0 + i * row_h
        m = re.match(r"(.*?)\s*\((.*)\)$", r["name"])
        head, tail = (r["name"].split(": ", 1) if ": " in r["name"]
                      else ((m.group(1), m.group(2)) if m else (r["name"], "")))
        c.dot(LABEL_X + 4, y + 12.5, "safe" if kex_safe(r["negotiated_group"]) else "bad")
        c.text(LABEL_X + 14, y + 17, "", 13.5, "mono", 500, "ink",
               spans=[(head, None), (f"  {r['address']}", "faint")])
        c.text(LABEL_X + 14, y + 37, f"{tail} · {r['negotiated_group']}"
               if r["negotiated_group"] and r["negotiated_group"].lower() not in tail.lower() else tail,
               13, "mono", 400, "dim")
        p50, p95 = r["connect_ms_median"], r["connect_ms_p95"]
        w50, w95 = scale(p50, top), scale(p95, top)
        c.bar(BAR_X0, y + 12, w50, 20, "time")
        c.line(BAR_X0 + w50, y + 22, BAR_X0 + w95, y + 22, "dim", 1.6)
        c.line(BAR_X0 + w95, y + 16, BAR_X0 + w95, y + 28, "dim", 1.6)
        c.text(BAR_X0 + w95 + 8, y + 27, "", 13, "mono", 500, "ink",
               spans=[(f"{fmt_ms(p50)} ms", None), (f"  p95 {fmt_ms(p95)}", "dim")])
    by = {r["name"]: r for r in net}
    cl = next((r for k, r in by.items() if k.startswith("proxy classical")), None)
    hy = next((r for k, r in by.items() if k.startswith("proxy hybrid") and "ML-DSA" not in k), None)
    md = next((r for k, r in by.items() if k.startswith("proxy hybrid") and "ML-DSA" in k), None)
    spans = []
    if cl and hy and md:
        spans = [("through the proxy: hybrid KEX ", None),
                 (f"{fmt_ms(hy['connect_ms_median'])} ms", "ink"), (" vs classical ", None),
                 (f"{fmt_ms(cl['connect_ms_median'])} ms", "ink"), (" · ML-DSA-65 identities ", None),
                 (f"+{md['connect_ms_median'] - hy['connect_ms_median']:.2f} ms", "ink")]
    c.footer(h - 30, spans)
    desc = "; ".join(f"{r['name']} ({r['address']}, {r['negotiated_group']}): connect p50 "
                     f"{fmt_ms(r['connect_ms_median'])} ms, p95 {fmt_ms(r['connect_ms_p95'])} ms"
                     for r in net)
    return c.render("Live connection time per path", desc)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bench", default=str(ROOT / "docs" / "sample-output" / "bench.json"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "assets"))
    a = ap.parse_args()
    data = json.loads(Path(a.bench).read_text())
    m = re.search(r"OpenSSL [\d.]+", data.get("runtime", ""))
    runtime = m.group(0) if m else "OpenSSL"
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        sfx = "" if theme == "dark" else "-light"
        charts = {}
        if data.get("local"):
            charts["bench-handshake"] = handshake_chart(theme, data["local"], runtime)
            charts["bench-bytes"] = bytes_chart(theme, data["local"])
        if data.get("network"):
            charts["bench-network"] = network_chart(theme, data["network"])
        for name, svg in charts.items():
            p = out / f"{name}{sfx}.svg"
            p.write_text(svg)
            print(f"wrote {p.relative_to(ROOT) if p.is_relative_to(ROOT) else p}")


if __name__ == "__main__":
    main()
