"""Self-contained HTML dashboard (no external assets) for inventories and benchmarks."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .analyzer import service_summary
from .models import Inventory


def _inv_view(inv: Inventory) -> dict:
    return {
        "generated_at": inv.generated_at,
        "tls_library": inv.tls_library,
        "services": service_summary(inv),
        "endpoints": [{**e.__dict__, "pqc_groups": e.pqc_groups} for e in inv.endpoints],
        "certificates": [c.__dict__ for c in inv.certificates.values()],
        "configs": [{"path": c.path, "kind": c.kind, "service": c.service,
                     "items": len(c.items)} for c in inv.configs],
        "findings": [f.__dict__ for f in inv.findings],
    }


def render(before: Inventory | None, after: Inventory | None = None, bench: dict | None = None,
           plan: dict | None = None, title: str = "QuantumShield") -> str:
    data = {"before": _inv_view(before) if before else None,
            "after": _inv_view(after) if after else None,
            "bench": bench, "plan": plan}
    blob = json.dumps(data).replace("</", "<\\/")
    return TEMPLATE.replace("__TITLE__", html.escape(title)).replace("__DATA__", blob)


def write(path: Path, **kw) -> Path:
    path.write_text(render(**kw))
    return path


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f7f8fa;--panel:#fff;--text:#16181d;--muted:#5d6472;--line:#e3e6eb;
--safe:#1f8a4c;--warn:#b26a00;--bad:#c2362b;--info:#3d63c9;--bar1:#8a94a6;--bar2:#3d63c9;--bar3:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--panel:#1a1d24;--text:#e7e9ee;--muted:#9aa2b1;
--line:#2a2f3a;--safe:#4cc17f;--warn:#e0a03a;--bad:#f06a5f;--info:#7c9cf0;--bar1:#6b7385;--bar2:#7c9cf0;--bar3:#4cc17f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;min-width:0;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px}
.sub{color:var(--muted);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:24px}.tile span{color:var(--muted);font-size:12px}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:none}
.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid}
.s-quantum-safe,.s-hybrid,.s-quantum-resistant{color:var(--safe)}.s-partial,.s-medium,.s-quantum-weakened{color:var(--warn)}
.s-vulnerable,.s-critical,.s-high,.s-quantum-broken,.s-insecure{color:var(--bad)}.s-review,.s-low,.s-info{color:var(--info)}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:12px}
.chart{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.chart h3{font-size:13px;margin:0 0 8px}.bar{display:grid;grid-template-columns:150px 1fr 70px;gap:8px;align-items:center;margin:4px 0;font-size:12px}
.bar .t{height:12px;background:var(--line);border-radius:3px;overflow:hidden}.bar .f{height:100%}
.bar .v{text-align:right;font-variant-numeric:tabular-nums}
.ba{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}@media(max-width:700px){.ba{grid-template-columns:minmax(0,1fr)}.bar{grid-template-columns:100px 1fr 60px}}
code{font-size:12px}details{margin-top:8px}summary{cursor:pointer;color:var(--muted)}
</style></head><body><main>
<h1>__TITLE__</h1><div class="sub" id="meta"></div>
<div class="tiles" id="tiles"></div>
<section id="readiness"></section>
<section id="endpoints"></section>
<section id="bench"></section>
<section id="certs"></section>
<section id="findings"></section>
<section id="plan"></section>
</main>
<script>
const D=__DATA__;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pill=s=>`<span class="pill s-${esc(s)}">${esc(s)}</span>`;
const table=(head,rows,num=[])=>`<div class="wrap"><table><thead><tr>${head.map((h,i)=>`<th class="${num.includes(i)?'num':''}">${h}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map((c,i)=>`<td class="${num.includes(i)?'num':''}">${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const cur=D.after||D.before;
const SAFE=new Set(['X25519MLKEM768','SecP256r1MLKEM768','SecP384r1MLKEM1024','MLKEM768','MLKEM1024','MLKEM512']);
function tiles(v,label){if(!v)return'';const f={};v.findings.forEach(x=>f[x.severity]=(f[x.severity]||0)+1);
const safe=v.endpoints.filter(e=>SAFE.has(e.negotiated_group)).length;
return `<div class="tile"><b>${v.services.length}</b><span>${label} services</span></div>
<div class="tile"><b>${safe}/${v.endpoints.length}</b><span>${label} endpoints with PQC key exchange</span></div>
<div class="tile"><b class="s-critical">${(f.critical||0)+(f.high||0)}</b><span>${label} critical + high findings</span></div>
<div class="tile"><b>${v.certificates.length}</b><span>${label} certificates inventoried</span></div>`}
$('#meta').textContent=cur?`Scanned ${cur.generated_at} · ${cur.tls_library}`:'';
$('#tiles').innerHTML=tiles(D.before,D.after?'Before:':'')+(D.after?tiles(D.after,'After:'):'');
function readiness(v){return table(['Service','Status','Risk','Key exchange','Cert key','Findings'],v.services.map(s=>[esc(s.service),pill(s.status),s.score,esc(s.kex.join(', ')||'-'),esc(s.cert_keys.join(', ')||'-'),Object.entries(s.findings).map(([k,n])=>`${n} ${pill(k)}`).join(' ')]),[2])}
if(cur){$('#readiness').innerHTML='<h2>Migration readiness</h2>'+(D.after?`<div class="ba"><div><div class="sub">Before</div>${readiness(D.before)}</div><div><div class="sub">After</div>${readiness(D.after)}</div></div>`:readiness(cur))}
function eps(v){return table(['Service','Endpoint','Protocols','Negotiated group','PQC groups','Cipher','mTLS'],v.endpoints.map(e=>[esc(e.name),`<code>${esc(e.target)}</code>`,esc(Object.entries(e.protocols).filter(x=>x[1]).map(x=>x[0].replace('TLSv','')).join(', ')||e.negotiated_version||'-'),
e.negotiated_group?`${esc(e.negotiated_group)} ${pill(SAFE.has(e.negotiated_group)?'hybrid':'quantum-broken')}`:(e.reachable?'-':pill('unreachable')),esc(e.pqc_groups.join(', ')||'none'),esc(e.negotiated_cipher||'-'),e.peer_requires_client_cert?'required':'no']))}
if(cur){let h='<h2>Cryptographic inventory: TLS endpoints</h2>';if(D.after){h+='<div class="sub">Before</div>'+eps(D.before)+'<div class="sub" style="margin-top:10px">After</div>'+eps(D.after)}else h+=eps(cur);$('#endpoints').innerHTML=h}
function bars(title,rows,key,unit,fmt=x=>x){const max=Math.max(...rows.map(r=>r[key]||0))||1;
return `<div class="chart"><h3>${title}</h3>${rows.map((r,i)=>`<div class="bar"><span>${esc(r._label)}</span><div class="t"><div class="f" style="width:${(100*(r[key]||0)/max).toFixed(1)}%;background:var(${SAFE.has(r.negotiated_group||r.group)?'--bar2':'--bar1'})"></div></div><span class="v">${fmt(r[key]??0)}${unit}</span></div>`).join('')}</div>`}
if(D.bench){let h='<h2>Performance: classical vs. hybrid post-quantum</h2><div class="sub">Blue bars use post-quantum key exchange; grey bars are classical. '+esc(D.bench.runtime||'')+'</div>';
const L=(D.bench.local||[]).map(r=>({...r,_label:r.scenario,cpu:r.client_cpu_ms+r.server_cpu_ms}));
if(L.length){h+='<div class="charts" style="margin-top:10px">'+bars('Handshake wall time (ms, in-process)',L,'wall_ms_median',' ms',x=>x.toFixed(2))+bars('Handshake CPU, client + server (ms)',L,'cpu',' ms',x=>x.toFixed(2))+bars('Handshake bytes on the wire',L,'bytes_total',' B',x=>x.toLocaleString())+'</div>';
h+=table(['Scenario','Group','Certs','Wall ms','Client CPU ms','Server CPU ms','C→S bytes','S→C bytes','Total bytes'],L.map(r=>[esc(r.label),esc(r.negotiated_group||r.group),esc(r.cert_alg),r.wall_ms_median.toFixed(3),r.client_cpu_ms.toFixed(3),r.server_cpu_ms.toFixed(3),r.bytes_client_to_server.toLocaleString(),r.bytes_server_to_client.toLocaleString(),r.bytes_total.toLocaleString()]),[3,4,5,6,7,8])}
const N=(D.bench.network||[]).map(r=>({...r,_label:r.name}));
if(N.length){h+='<div class="charts" style="margin-top:12px">'+bars('Connection time, TCP + TLS (ms, p50)',N,'connect_ms_median',' ms',x=>x.toFixed(2))+bars('Client CPU per connection (ms)',N,'client_cpu_ms',' ms',x=>x.toFixed(2))+bars('Handshake bytes',N,'bytes_total',' B',x=>x.toLocaleString())+'</div>';
h+=table(['Path','Group','Connect ms p50','p95','Client CPU ms','Proxy CPU ms/conn','Bytes','Errors'],N.map(r=>[esc(r.name),esc(r.negotiated_group||'-'),r.connect_ms_median.toFixed(3),r.connect_ms_p95.toFixed(3),r.client_cpu_ms.toFixed(3),r.server_cpu_ms_per_conn==null?'-':r.server_cpu_ms_per_conn.toFixed(3),r.bytes_total.toLocaleString(),r.errors]),[2,3,4,5,6,7])}
$('#bench').innerHTML=h}
if(cur&&cur.certificates.length){$('#certs').innerHTML='<h2>Certificates</h2>'+table(['Subject','Key','Signature','Expires','Seen at'],[...(D.before?D.before.certificates:[]),...(D.after?D.after.certificates:[])].filter((c,i,a)=>a.findIndex(x=>x.fingerprint_sha256===c.fingerprint_sha256)===i).map(c=>[esc(c.subject),`${esc(c.public_key_detail||c.public_key_algorithm)} ${pill(/ML-DSA/.test(c.public_key_algorithm)?'quantum-resistant':'quantum-broken')}`,esc(c.signature_algorithm+(c.signature_hash?'/'+c.signature_hash:'')),esc(c.not_after.slice(0,10)),esc(c.sources.slice(0,2).join(', '))]))}
if(cur){const F=cur.findings.filter(f=>f.severity!=='info');$('#findings').innerHTML=`<h2>Findings ${D.after?'(after migration)':''}: ${F.length}</h2>`+table(['Severity','Rule','Service','Finding','Evidence','Recommendation'],F.map(f=>[pill(f.severity)+(f.hndl?' <span class="sub">HNDL</span>':''),`<code>${esc(f.rule_id)}</code>`,esc(f.service||'-'),esc(f.title),esc(f.evidence),esc(f.recommendation)]))+(D.after&&D.before?`<details><summary>Findings before migration (${D.before.findings.filter(f=>f.severity!=='info').length})</summary>`+table(['Severity','Rule','Service','Finding','Evidence'],D.before.findings.filter(f=>f.severity!=='info').map(f=>[pill(f.severity),`<code>${esc(f.rule_id)}</code>`,esc(f.service||'-'),esc(f.title),esc(f.evidence)]))+'</details>':'')}
if(D.plan){$('#plan').innerHTML='<h2>Migration plan</h2>'+table(['Service','Phase','Severity','Action'],D.plan.services.flatMap(s=>s.steps.map(st=>[esc(s.service),st.phase,pill(st.severity),esc(st.description)])),[1])}
</script></body></html>
"""
