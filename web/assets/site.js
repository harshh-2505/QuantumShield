/* QuantumShield site: lattice hero, Mosca calculator, demo results, benchmarks, analyzer. */
(function () {
  "use strict";
  const D = window.QS_DEMO || {};
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (n, d = 0) => Number(n).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const PQC = new Set(["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024"]);
  const SEV = ["critical", "high", "medium", "low", "info"];
  const SEV_COLOR = { critical: "var(--bad)", high: "color-mix(in srgb, var(--bad) 62%, var(--warn))", medium: "var(--warn)", low: "var(--info)", info: "var(--faint)" };
  const SEV_CHIP = { critical: "c-bad", high: "c-bad", medium: "c-warn", low: "c-info", info: "c-dim" };
  const STATUS_CHIP = { "quantum-safe": "c-safe", partial: "c-warn", vulnerable: "c-bad", review: "c-info" };
  const QSTATUS_CHIP = { "quantum-broken": "c-bad", insecure: "c-bad", "quantum-weakened": "c-warn", "quantum-resistant": "c-safe", hybrid: "c-safe" };
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  /* ------------------------------------------------------------ theme toggle */
  const themeBtn = $("#theme");
  function effectiveTheme() {
    const t = document.documentElement.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  const themeListeners = [];
  themeBtn.addEventListener("click", () => {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("qs-theme", next); } catch (e) { /* not persisted */ }
    themeListeners.forEach((f) => f());
  });
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => themeListeners.forEach((f) => f()));

  /* ------------------------------------------------------------ lattice hero */
  (function lattice() {
    const canvas = $("#lattice");
    const hero = canvas.parentElement;
    const ctx = canvas.getContext("2d");
    let W = 0, H = 0, dpr = 1, colors = {}, running = true, visible = true;
    const target = { x: 0, y: 0 }, want = { x: 0, y: 0 };
    let pointer = null, t0 = performance.now(), first = true;

    function rgba(hex, a) {
      const m = /^#?([0-9a-f]{6})$/i.exec(hex);
      if (!m) return hex;
      const n = parseInt(m[1], 16);
      return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
    }
    function readColors() {
      colors = { dim: css("--dim"), gold: css("--gold"), faint: css("--faint"), safe: css("--safe"), ink: css("--ink") };
    }
    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = hero.clientWidth; H = hero.clientHeight;
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (first) { const a = anchor(); target.x = want.x = a.x + 40; target.y = want.y = a.y - 30; first = false; }
      if (!running) draw(performance.now());
    }
    function anchor() { return { x: W > 820 ? W * 0.72 : W * 0.5, y: H * (W > 820 ? 0.42 : 0.3) }; }
    function basis(t) {
      const s = W < 600 ? 34 : 46;
      const th = 0.22 + (reduced ? 0 : (t - t0) * 0.000012);
      const c = Math.cos(th), si = Math.sin(th);
      const rot = (x, y) => [x * c - y * si, x * si + y * c];
      return { b1: rot(s, 0), b2: rot(s * 0.38, s * 0.9) };
    }
    function draw(now) {
      const { b1, b2 } = basis(now);
      const o = anchor();
      if (!pointer) {
        const k = reduced ? 0 : (now - t0);
        want.x = o.x + Math.cos(k * 0.00023) * Math.min(W * 0.2, 220) + Math.sin(k * 0.00071) * 18;
        want.y = o.y + Math.sin(k * 0.00031) * Math.min(H * 0.22, 140);
      }
      target.x += (want.x - target.x) * (reduced ? 1 : 0.12);
      target.y += (want.y - target.y) * (reduced ? 1 : 0.12);

      ctx.clearRect(0, 0, W, H);
      const det = b1[0] * b2[1] - b2[0] * b1[1];
      const toLat = (x, y) => { const dx = x - o.x, dy = y - o.y; return [(dx * b2[1] - dy * b2[0]) / det, (b1[0] * dy - b1[1] * dx) / det]; };
      const corners = [toLat(0, 0), toLat(W, 0), toLat(0, H), toLat(W, H)];
      const iMin = Math.floor(Math.min(...corners.map((c) => c[0]))) - 1, iMax = Math.ceil(Math.max(...corners.map((c) => c[0]))) + 1;
      const jMin = Math.floor(Math.min(...corners.map((c) => c[1]))) - 1, jMax = Math.ceil(Math.max(...corners.map((c) => c[1]))) + 1;
      const R = Math.hypot(...b1) * 3.2;

      for (let i = iMin; i <= iMax; i++) {
        for (let j = jMin; j <= jMax; j++) {
          const x = o.x + i * b1[0] + j * b2[0], y = o.y + i * b1[1] + j * b2[1];
          if (x < -4 || y < -4 || x > W + 4 || y > H + 4) continue;
          const d = Math.hypot(x - target.x, y - target.y);
          const near = Math.max(0, 1 - d / R);
          ctx.fillStyle = near > 0 ? rgba(colors.gold, 0.3 + near * 0.6) : rgba(colors.dim, 0.42);
          ctx.beginPath(); ctx.arc(x, y, 1.6 + near * 1.4, 0, Math.PI * 2); ctx.fill();
        }
      }
      // basis vectors at the anchor
      ctx.strokeStyle = rgba(colors.gold, 0.45); ctx.fillStyle = rgba(colors.gold, 0.6); ctx.lineWidth = 1.2;
      [[b1, "b₁"], [b2, "b₂"]].forEach(([b, name]) => {
        ctx.beginPath(); ctx.moveTo(o.x, o.y); ctx.lineTo(o.x + b[0], o.y + b[1]); ctx.stroke();
        const a = Math.atan2(b[1], b[0]), ex = o.x + b[0], ey = o.y + b[1];
        ctx.beginPath(); ctx.moveTo(ex, ey);
        ctx.lineTo(ex - 7 * Math.cos(a - 0.4), ey - 7 * Math.sin(a - 0.4));
        ctx.lineTo(ex - 7 * Math.cos(a + 0.4), ey - 7 * Math.sin(a + 0.4)); ctx.fill();
        ctx.font = "11px " + css("--mono"); ctx.fillText(name, ex + 6, ey + 4);
      });
      // closest vector: Babai rounding, then check the neighbours
      const c = toLat(target.x, target.y);
      let best = null;
      for (let di = -1; di <= 1; di++) for (let dj = -1; dj <= 1; dj++) {
        const i = Math.round(c[0]) + di, j = Math.round(c[1]) + dj;
        const x = o.x + i * b1[0] + j * b2[0], y = o.y + i * b1[1] + j * b2[1];
        const d = Math.hypot(x - target.x, y - target.y);
        if (!best || d < best.d) best = { i, j, x, y, d };
      }
      const g = ctx.createRadialGradient(target.x, target.y, 0, target.x, target.y, 48);
      g.addColorStop(0, rgba(colors.gold, 0.22)); g.addColorStop(1, rgba(colors.gold, 0));
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(target.x, target.y, 48, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = rgba(colors.gold, 0.9); ctx.lineWidth = 1.4; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(best.x, best.y); ctx.lineTo(target.x, target.y); ctx.stroke(); ctx.setLineDash([]);
      ctx.beginPath(); ctx.arc(best.x, best.y, 9, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = colors.gold; ctx.beginPath(); ctx.arc(target.x, target.y, 3.6, 0, Math.PI * 2); ctx.fill();
      ctx.font = "11px " + css("--mono"); ctx.fillStyle = rgba(colors.dim, 0.95);
      const sign = best.j < 0 ? "−" : "+";
      ctx.fillText(`${best.i}·b₁ ${sign} ${Math.abs(best.j)}·b₂`, best.x + 14, best.y - 12);
      ctx.fillStyle = rgba(colors.gold, 0.85);
      ctx.fillText("e", (best.x + target.x) / 2 + 6, (best.y + target.y) / 2 + 12);
    }
    function loop(now) {
      if (!running) return;
      if (visible && !document.hidden) draw(now);
      requestAnimationFrame(loop);
    }
    hero.addEventListener("pointermove", (e) => {
      const r = canvas.getBoundingClientRect();
      pointer = { x: e.clientX - r.left, y: e.clientY - r.top };
      want.x = pointer.x; want.y = pointer.y;
      if (!running) draw(performance.now());
    });
    hero.addEventListener("pointerleave", () => { pointer = null; if (!running) draw(performance.now()); });
    new IntersectionObserver((es) => { visible = es[0].isIntersecting; }).observe(hero);
    window.addEventListener("resize", resize);
    themeListeners.push(() => { readColors(); if (!running) draw(performance.now()); });
    readColors();
    if (reduced) { running = false; resize(); } else { resize(); requestAnimationFrame(loop); }
    document.fonts && document.fonts.ready.then(() => { if (!running) draw(performance.now()); });
  })();

  /* ------------------------------------------------------------ hero read-out */
  (function readout() {
    const before = D.before || {}, after = D.after || {};
    const migrated = (after.services || []).filter((s) => s.endpoint && PQC.has(s.endpoint.negotiated_group)).length;
    const total = (after.services || []).length;
    const ch = (o) => (o.critical || 0) + (o.high || 0);
    const local = (D.bench && D.bench.local) || [];
    const by = Object.fromEntries(local.map((r) => [r.scenario, r]));
    const dt = by["hybrid-ecdsa"] && by["classical-ecdsa"] ? by["hybrid-ecdsa"].wall_ms_median - by["classical-ecdsa"].wall_ms_median : null;
    const cells = [
      [`${migrated}<span class="u">/ ${total}</span>`, "demo services moved to hybrid ML-KEM key exchange", "safe"],
      [`${ch(before.severity_demo || {})} <span class="u">→</span> <span class="safe">${ch(after.severity_demo || {})}</span>`, "critical and high findings on those services, before and after", ""],
      [dt == null ? "n/a" : `+${fmt(dt, 2)}<span class="u">ms</span>`, "per handshake for hybrid key exchange, same certificate", ""],
      [`${(D.cbom && D.cbom.components) || 0}`, `components in the CycloneDX ${esc((D.cbom && D.cbom.spec) || "1.6")} CBOM of the starting point`, ""],
    ];
    $("#readout").innerHTML = cells.map(([v, l, cls]) => `<div><b class="${cls}">${v}</b><span>${l}</span></div>`).join("");
  })();

  /* ------------------------------------------------------------ Mosca */
  (function mosca() {
    const NOW = 2026;
    const x = $("#mx"), y = $("#my"), z = $("#mz"), svg = $("#mosca-chart");
    const yrs = (n) => `${n} year${n === 1 ? "" : "s"}`;
    function render() {
      const X = +x.value, Y = +y.value, Z = +z.value;
      $("#mx-out").textContent = yrs(X); $("#my-out").textContent = yrs(Y); $("#mz-out").textContent = `${yrs(Z)} (${NOW + Z})`;
      const late = X + Y > Z;
      $("#mosca-formula").innerHTML = `<b>x + y = ${X + Y}</b> ${late ? "&gt;" : "≤"} <b>z = ${Z}</b>`;
      const span = Math.min(60, Math.max(16, X + Y + 3, Z + 3));
      const VW = Math.max(300, Math.round(svg.clientWidth || 640));
      svg.setAttribute("viewBox", `0 0 ${VW} 150`);
      const L = 18, Rr = VW - 18, sx = (yr) => L + ((yr - NOW) / span) * (Rr - L);
      const parts = [];
      const step = span > 40 || VW < 460 ? 10 : 5;
      for (let yr = NOW - (NOW % step) + step; yr <= NOW + span; yr += step) {
        parts.push(`<line x1="${sx(yr)}" x2="${sx(yr)}" y1="20" y2="118" stroke="var(--line)" stroke-dasharray="2 4"/>`,
          `<text x="${sx(yr)}" y="138" text-anchor="middle" fill="var(--faint)" font-size="11" font-family="var(--mono)">${yr}</text>`);
      }
      parts.push(`<text x="${L}" y="138" fill="var(--dim)" font-size="11" font-family="var(--mono)">${NOW}</text>`);
      parts.push(`<line x1="${L}" x2="${Rr}" y1="118" y2="118" stroke="var(--faint)"/>`);
      // migration
      parts.push(`<rect x="${sx(NOW)}" y="30" width="${sx(NOW + Y) - sx(NOW)}" height="20" rx="4" fill="color-mix(in srgb, var(--info) 55%, transparent)"/>`,
        `<text x="${sx(NOW) + 6}" y="44" fill="var(--ink)" font-size="11" font-family="var(--mono)">${Y > 2 ? "migrating" : ""}</text>`);
      // secrecy window of the last data sent with classical crypto
      const s0 = NOW + Y, s1 = NOW + Y + X, q = NOW + Z;
      parts.push(`<rect x="${sx(s0)}" y="66" width="${sx(s1) - sx(s0)}" height="20" rx="4" fill="color-mix(in srgb, var(--gold) 70%, transparent)"/>`);
      if (late) {
        const a = Math.max(q, s0);
        parts.push(`<rect x="${sx(a)}" y="66" width="${sx(s1) - sx(a)}" height="20" rx="4" fill="var(--bad)"/>`);
      }
      parts.push(`<text x="${sx(s0) + 6}" y="80" fill="var(--gold-ink)" font-size="11" font-family="var(--mono)">${X > 3 ? "must stay secret" : ""}</text>`);
      // CRQC
      parts.push(`<line x1="${sx(q)}" x2="${sx(q)}" y1="10" y2="118" stroke="var(--bad)" stroke-width="2"/>`,
        `<text x="${Math.min(sx(q) + 6, Rr - 4)}" y="20" text-anchor="${sx(q) > Rr - 120 ? "end" : "start"}" fill="var(--bad)" font-size="11" font-family="var(--mono)">quantum computer · ${q}</text>`);
      svg.innerHTML = parts.join("");
      const v = $("#mosca-verdict");
      v.classList.toggle("ok", !late);
      $("p", v).innerHTML = late
        ? `Traffic you send until <b>${s0}</b> has to stay secret until <b>${s1}</b>, but it can be decrypted from <b>${q}</b>. That is <b>${yrs(s1 - Math.max(q, s0))}</b> of exposure for data recorded today.`
        : `On this schedule the last traffic sent with classical key exchange stops mattering in <b>${s1}</b>, before a quantum computer arrives in <b>${q}</b>. Margin: <b>${yrs(Z - X - Y)}</b>.`;
    }
    [x, y, z].forEach((el) => el.addEventListener("input", render));
    let lw = window.innerWidth;
    window.addEventListener("resize", () => { if (window.innerWidth !== lw) { lw = window.innerWidth; render(); } });
    render();
  })();

  /* ------------------------------------------------------------ demo services */
  (function demo() {
    const grid = $("#services");
    const btnB = $("#show-before"), btnA = $("#show-after");
    $("#demo-meta").textContent = [D.generated_at && `scanned ${D.generated_at.replace("T", " ").slice(0, 16)} UTC`, D.runtime].filter(Boolean).join("  ·  ");
    function card(s) {
      const ep = s.endpoint || {};
      const f = s.findings || {};
      const total = SEV.reduce((a, k) => a + (f[k] || 0), 0);
      const bar = total
        ? SEV.filter((k) => f[k]).map((k) => `<i style="flex-grow:${f[k]};background:${SEV_COLOR[k]}"></i>`).join("")
        : `<i style="flex-grow:1;background:var(--safe)"></i>`;
      const legend = total ? SEV.filter((k) => f[k]).map((k) => `<span style="--c:${SEV_COLOR[k]}">${f[k]} ${k}</span>`).join("") : `<span style="--c:var(--safe)">no findings</span>`;
      const state = { "quantum-safe": "var(--safe)", partial: "var(--warn)", vulnerable: "var(--bad)" }[s.status] || "var(--info)";
      return `<article class="panel svc" style="--state:${state}">
        <div class="svc-head"><h3>${esc(s.service)}</h3><span class="chip ${STATUS_CHIP[s.status] || "c-dim"}">${esc(s.status)}</span></div>
        <div class="svc-score"><b data-count="${s.score}">${s.score}</b><span>risk score</span></div>
        <dl class="kv">
          <dt>Endpoint</dt><dd>${esc(ep.target || "-")}</dd>
          <dt>Key exch.</dt><dd style="color:${PQC.has(ep.negotiated_group) ? "var(--safe)" : "var(--bad)"}">${esc(ep.negotiated_group || "-")}</dd>
          <dt>Cert key</dt><dd>${esc(ep.cert_key || (s.cert_keys || []).join(", ") || "-")}</dd>
          <dt>Protocols</dt><dd>${esc((ep.protocols || []).join(" ") || "-")}</dd>
          <dt>mTLS</dt><dd>${ep.mtls ? "required" : "not required"}</dd>
        </dl>
        <div><div class="sevbar" aria-hidden="true">${bar}</div><div class="sevlegend">${legend}</div></div>
      </article>`;
    }
    function show(which) {
      const v = D[which];
      if (!v) return;
      btnB.setAttribute("aria-pressed", String(which === "before"));
      btnA.setAttribute("aria-pressed", String(which === "after"));
      const prev = Object.fromEntries([...grid.querySelectorAll("[data-count]")].map((el, i) => [i, +el.textContent]));
      grid.innerHTML = v.services.map(card).join("");
      if (!reduced) {
        grid.querySelectorAll("[data-count]").forEach((el, i) => {
          const from = prev[i] ?? +el.dataset.count, to = +el.dataset.count, t0 = performance.now();
          if (from === to) return;
          const tick = (now) => {
            const k = Math.min(1, (now - t0) / 600), e = 1 - Math.pow(1 - k, 3);
            el.textContent = Math.round(from + (to - from) * e);
            if (k < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        });
      }
    }
    btnB.addEventListener("click", () => show("before"));
    btnA.addEventListener("click", () => show("after"));
    show("after");

    $("#zt").innerHTML = (D.zero_trust || []).map((z) => `<article class="panel">
        <div class="zt-head"><h3>${esc(z.check)}</h3><span class="chip c-safe">${esc(z.outcome)}</span></div>
        <p>${esc(z.detail)}</p>
        ${z.log ? `<pre class="log">${esc(z.log)}</pre>` : ""}
      </article>`).join("");
  })();

  /* ------------------------------------------------------------ benchmarks */
  (function bench() {
    const B = D.bench || {}, local = B.local || [], net = B.network || [];
    if (!local.length) return;
    const by = Object.fromEntries(local.map((r) => [r.scenario, r]));
    const c = by["classical-ecdsa"], h = by["hybrid-ecdsa"], m = by["hybrid-mldsa"];
    $("#iters").textContent = fmt(local[0].iterations);
    if (c && h && m) {
      const dms = h.wall_ms_median - c.wall_ms_median, db = h.bytes_total - c.bytes_total;
      $("#bench-lede").innerHTML = `Switching key exchange from X25519 to hybrid X25519MLKEM768 adds
        <b>${fmt(dms, 2)} ms</b> and <b>${fmt(db)} bytes</b> to a handshake. Post-quantum certificates are
        the expensive part: ML-DSA-65 brings a handshake to <b>${fmt(m.bytes_total / 1000, 1)} KB</b>. That is why
        QuantumShield moves key exchange first and signatures later. Measured with ${esc(String(B.runtime || "OpenSSL 3.5").split(";")[0])}.`;
      $("#takeaway").innerHTML = [
        [`+${fmt(dms, 2)} ms`, "per handshake for hybrid ML-KEM key exchange, same ECDSA certificate"],
        [`+${fmt(db / 1000, 1)} KB`, "on the wire for the ML-KEM-768 key shares (1,216 B out, 1,120 B back)"],
        [`${fmt(m.bytes_total / c.bytes_total, 1)}×`, "the bytes of a classical handshake once certificates move to ML-DSA-65 too"],
      ].map(([v, l]) => `<div class="panel"><b>${v}</b><span>${l}</span></div>`).join("");
    }

    let W = 560;
    const LBL = 18, BAR = 9, GAP = 4, ROW = LBL + BAR * 2 + GAP + 18, PADR = 70;
    function axis(max, unit, top, bottom) {
      const steps = [0.5, 1, 2, 2.5, 5, 10, 20, 25, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000];
      const step = steps.find((s) => max / s <= 5) || max / 5;
      const out = [];
      for (let v = 0; v <= max + 1e-9; v += step) {
        const x = (v / max) * (W - PADR);
        out.push(`<line class="grid" x1="${x}" x2="${x}" y1="${top}" y2="${bottom}"/>`,
          `<text x="${x}" y="${bottom + 14}" text-anchor="${v === 0 ? "start" : "middle"}">${fmt(v, step < 1 ? 1 : 0)}${v === 0 ? "" : ""}</text>`);
      }
      out.push(`<text x="${W - PADR}" y="${bottom + 28}" text-anchor="end">${unit}</text>`);
      return out.join("");
    }
    function niceMax(v) { const p = Math.pow(10, Math.floor(Math.log10(v))); return Math.ceil(v / p * 2) / 2 * p; }

    function drawCharts() {
    // time + cpu
    (function () {
      W = Math.max(300, Math.round($("#ch-time").clientWidth || 560));
      const rows = local.map((r) => ({ label: r.label, wall: r.wall_ms_median, cpu: r.client_cpu_ms + r.server_cpu_ms }));
      const max = niceMax(Math.max(...rows.map((r) => Math.max(r.wall, r.cpu))));
      const sx = (v) => (v / max) * (W - PADR);
      const H = rows.length * ROW;
      const body = rows.map((r, i) => {
        const y = i * ROW;
        return `<text class="lbl" x="0" y="${y + 13}">${esc(r.label)}</text>
          <rect x="0" y="${y + LBL}" width="${sx(r.wall)}" height="${BAR}" rx="2" fill="var(--gold)"/>
          <text class="val" x="${sx(r.wall) + 6}" y="${y + LBL + 8}">${fmt(r.wall, 2)} ms</text>
          <rect x="0" y="${y + LBL + BAR + GAP}" width="${sx(r.cpu)}" height="${BAR}" rx="2" fill="var(--info)"/>
          <text class="val" x="${sx(r.cpu) + 6}" y="${y + LBL + BAR * 2 + GAP - 1}">${fmt(r.cpu, 2)} ms</text>`;
      }).join("");
      const svg = $("#ch-time");
      svg.setAttribute("viewBox", `0 0 ${W} ${H + 34}`);
      svg.innerHTML = axis(max, "milliseconds", 0, H) + body;
    })();

    // bytes
    (function () {
      W = Math.max(300, Math.round($("#ch-bytes").clientWidth || 560));
      const rows = local.map((r) => ({ label: r.label, cs: r.bytes_client_to_server, sc: r.bytes_server_to_client, t: r.bytes_total }));
      const max = niceMax(Math.max(...rows.map((r) => r.t)));
      const sx = (v) => (v / max) * (W - PADR);
      const R2 = LBL + 16 + 14, H = rows.length * R2;
      const body = rows.map((r, i) => {
        const y = i * R2;
        return `<text class="lbl" x="0" y="${y + 13}">${esc(r.label)}</text>
          <rect x="0" y="${y + LBL}" width="${sx(r.cs)}" height="16" rx="2" fill="var(--gold)"/>
          <rect x="${sx(r.cs)}" y="${y + LBL}" width="${sx(r.sc)}" height="16" rx="2" fill="color-mix(in srgb, var(--gold) 45%, var(--bg-3))"/>
          <text class="val" x="${sx(r.t) + 6}" y="${y + LBL + 12}">${fmt(r.t / 1000, 1)} KB</text>`;
      }).join("");
      const svg = $("#ch-bytes");
      svg.setAttribute("viewBox", `0 0 ${W} ${H + 34}`);
      svg.innerHTML = axis(max, "bytes", 0, H) + body;
    })();

    // network
    (function () {
      if (!net.length) return;
      W = Math.max(300, Math.round($("#ch-net").clientWidth || 560));
      const max = niceMax(Math.max(...net.map((r) => r.connect_ms_p95)));
      const sx = (v) => (v / max) * (W - PADR);
      const R2 = LBL + 14 + 16, H = net.length * R2;
      const body = net.map((r, i) => {
        const y = i * R2;
        const pq = PQC.has(r.negotiated_group);
        return `<text class="lbl" x="0" y="${y + 13}">${esc(r.name)}${pq ? "" : ""}</text>
          <rect x="0" y="${y + LBL}" width="${sx(r.connect_ms_p95)}" height="14" rx="2" fill="color-mix(in srgb, var(--safe) 35%, var(--bg-3))"/>
          <rect x="0" y="${y + LBL}" width="${sx(r.connect_ms_median)}" height="14" rx="2" fill="var(--safe)"/>
          <text class="val" x="${sx(r.connect_ms_p95) + 6}" y="${y + LBL + 11}">${fmt(r.connect_ms_median, 2)} ms</text>`;
      }).join("");
      const svg = $("#ch-net");
      svg.setAttribute("viewBox", `0 0 ${W} ${H + 34}`);
      svg.innerHTML = axis(max, "milliseconds", 0, H) + body;
    })();

    }
    drawCharts();
    let lastW = window.innerWidth, rt = null;
    window.addEventListener("resize", () => {
      clearTimeout(rt);
      rt = setTimeout(() => { if (window.innerWidth !== lastW) { lastW = window.innerWidth; drawCharts(); } }, 150);
    });

    // byte budget (FIPS 203 / 204 sizes)
    (function () {
      const items = [
        ["X25519 public key", 32, "var(--info)"],
        ["ECDSA P-256 signature", 72, "var(--info)"],
        ["RSA-2048 signature", 256, "var(--info)"],
        ["ML-KEM-768 ciphertext", 1088, "var(--gold)"],
        ["ML-KEM-768 encapsulation key", 1184, "var(--gold)"],
        ["X25519MLKEM768 client share", 1216, "var(--safe)"],
        ["ML-DSA-65 public key", 1952, "var(--gold)"],
        ["ML-DSA-65 signature", 3309, "var(--gold)"],
      ];
      const w = (v) => (Math.log10(v / 10) / Math.log10(10000 / 10)) * 100;
      $("#budget").insertAdjacentHTML("beforeend", items.map(([k, v, col]) => `<div class="budget-row">
          <span class="k">${k}</span><span class="track"><span class="bar" style="display:block;width:${w(v).toFixed(1)}%;--c:${col}"></span></span><span class="v">${fmt(v)} B</span>
        </div>`).join("") + `<div class="legend"><span style="--c:var(--info)">classical</span><span style="--c:var(--gold)">post-quantum</span><span style="--c:var(--safe)">hybrid</span></div>`);
    })();
  })();

  /* ------------------------------------------------------------ analyzer */
  (function analyzer() {
    const tabs = $("#an-tabs"), name = $("#an-name"), text = $("#an-text"), gutter = $("#an-gutter"), out = $("#an-out");
    const samples = D.samples || [];
    let last = null, timer = null;

    tabs.innerHTML = samples.map((s, i) => `<button type="button" role="tab" aria-selected="${i === 0}" data-i="${i}" title="${esc(s.label)}">${esc(s.name)}</button>`).join("");
    tabs.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]");
      if (!b) return;
      tabs.querySelectorAll("button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
      load(samples[+b.dataset.i]);
    });
    function load(s) { name.value = s.name; text.value = s.text; text.scrollTop = 0; run(); }

    function lineOf(f) { const m = /:(\d+)$/.exec(f.asset || ""); return m ? +m[1] : (f.line || null); }
    function gutterUpdate(hits) {
      const n = text.value.split("\n").length;
      let s = "";
      for (let i = 1; i <= n; i++) s += hits.has(i) ? `<span class="hit">${i}</span>\n` : `${i}\n`;
      gutter.innerHTML = s;
      gutter.scrollTop = text.scrollTop;
    }
    text.addEventListener("scroll", () => { gutter.scrollTop = text.scrollTop; });

    function run() {
      clearTimeout(timer);
      if (!window.QSAnalyzer) { gutterUpdate(new Set()); out.innerHTML = `<p class="empty">The analyzer script did not load. Reload the page to try again.</p>`; return; }
      let r;
      try { r = window.QSAnalyzer.analyze(name.value.trim() || "config", text.value); }
      catch (err) { out.innerHTML = `<p class="empty">Could not analyze this file: ${esc(err.message)}</p>`; gutterUpdate(new Set()); return; }
      last = r;
      const F = (r.findings || []).slice().sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || (lineOf(a) || 0) - (lineOf(b) || 0));
      gutterUpdate(new Set(F.map(lineOf).filter(Boolean)));
      if (!r.kind) {
        out.innerHTML = `<p class="empty">This doesn't look like a format QuantumShield reads. Name the file like the real one (for example <code>nginx.conf</code>, <code>sshd_config</code>, <code>haproxy.cfg</code>, <code>server.pem</code> or <code>client.py</code>) so the right parser is used.</p>`;
        return;
      }
      const counts = {};
      F.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
      const algs = new Map();
      (r.items || []).forEach((it) => (it.algorithms || []).forEach((a) => { if (a && a.name && !algs.has(a.name)) algs.set(a.name, a); }));
      (r.certificates || []).forEach((c) => {
        [c.public_key_algorithm, c.signature_algorithm].forEach((n) => { if (n && !algs.has(n)) algs.set(n, { name: n, status: c.quantum_status || null }); });
      });
      const head = `<div class="an-sum"><span class="kind">${esc(r.kind)}${r.service ? ` · ${esc(r.service)}` : ""}</span>
          ${SEV.filter((k) => counts[k]).map((k) => `<span class="chip ${SEV_CHIP[k]}">${counts[k]} ${k}</span>`).join("") || `<span class="chip c-safe">no findings</span>`}</div>`;
      const algHtml = algs.size ? `<div><p class="label" style="margin-bottom:10px">Algorithms found</p><div class="algs">${[...algs.values()].map((a) =>
        `<span class="chip ${QSTATUS_CHIP[a.status] || "c-dim"}" title="${esc(a.status || "unclassified")}">${esc(a.name)}</span>`).join("")}</div></div>` : "";
      const list = F.length ? `<div class="findings">${F.map((f) => {
        const ln = lineOf(f);
        return `<article class="finding" style="--c:${SEV_COLOR[f.severity] || "var(--faint)"}">
          <div class="finding-top"><span class="chip ${SEV_CHIP[f.severity] || "c-dim"}">${esc(f.severity)}</span>
            <span class="rule">${esc(f.rule_id)}${ln ? ` · line ${ln}` : ""}</span>
            ${f.hndl ? `<span class="chip c-warn" title="Exposed to harvest-now-decrypt-later">HNDL</span>` : ""}</div>
          <h4>${esc(f.title)}</h4>
          ${f.evidence ? `<div class="ev">${esc(f.evidence)}</div>` : ""}
          ${f.recommendation ? `<p class="fix"><b>Fix</b> ${esc(f.recommendation)}</p>` : ""}
        </article>`;
      }).join("")}</div>` : `<p class="empty">No findings. Every algorithm in this file is post-quantum, hybrid, or strong enough against Grover's algorithm.</p>`;
      out.innerHTML = head + algHtml + list;
    }
    const schedule = () => { clearTimeout(timer); timer = setTimeout(run, 160); };
    text.addEventListener("input", schedule);
    name.addEventListener("input", schedule);

    const drop = $(".an-in");
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.style.borderColor = "var(--gold)"; });
    drop.addEventListener("dragleave", () => { drop.style.borderColor = ""; });
    drop.addEventListener("drop", (e) => {
      e.preventDefault(); drop.style.borderColor = "";
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) { out.innerHTML = `<p class="empty">${esc(f.name)} is larger than 2 MB, the same limit the command-line scanner uses.</p>`; return; }
      f.text().then((t) => { tabs.querySelectorAll("button").forEach((x) => x.setAttribute("aria-selected", "false")); name.value = f.name; text.value = t; run(); });
    });

    $("#an-cbom").addEventListener("click", () => {
      if (!last || !window.QSAnalyzer || !window.QSAnalyzer.cbom) return;
      const blob = new Blob([JSON.stringify(window.QSAnalyzer.cbom([last]), null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = (name.value.replace(/[^\w.-]+/g, "_") || "config") + ".cbom.json";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });

    if (samples.length) load(samples[0]);
  })();

  /* ------------------------------------------------------------ copy buttons */
  document.querySelectorAll(".code .copy").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pre = btn.parentElement.querySelector("pre");
      const txt = pre.textContent.split("\n").map((l) => l.replace(/^\$ /, "")).join("\n");
      const done = () => { btn.textContent = "Copied"; setTimeout(() => { btn.textContent = "Copy"; }, 1400); };
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(done, () => selectText(pre));
      else selectText(pre);
    });
  });
  function selectText(el) { const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }
})();
