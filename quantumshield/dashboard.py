"""Self-contained HTML dashboard for inventories, benchmarks and the migration plan.

The page has no external assets (the template lives next to this module as
dashboard.html), so it can be opened from disk or attached to a ticket. With
``web=True`` it also links the website's fonts and adds a link back to the site.
"""

from __future__ import annotations

import html
import json
from importlib import resources
from pathlib import Path

from .analyzer import service_summary
from .catalog import lookup
from .migrate import PHASES
from .models import Inventory


def _status(name: str | None) -> str | None:
    alg = lookup(name)
    return alg.status.value if alg else None


def _inv_view(inv: Inventory) -> dict:
    return {
        "generated_at": inv.generated_at,
        "tls_library": inv.tls_library,
        "services": service_summary(inv),
        "endpoints": [{**e.__dict__, "pqc_groups": e.pqc_groups,
                       "group_status": _status(e.negotiated_group)} for e in inv.endpoints],
        "certificates": [{**c.__dict__, "key_status": _status(c.public_key_algorithm),
                          "sig_status": _status(c.signature_algorithm)}
                         for c in inv.certificates.values()],
        "configs": [{"path": c.path, "kind": c.kind, "service": c.service,
                     "items": len(c.items)} for c in inv.configs],
        "findings": [f.__dict__ for f in inv.findings],
    }


def template() -> str:
    return resources.files(__package__).joinpath("dashboard.html").read_text(encoding="utf-8")


# Relative links, so the site works from any host or sub-path (web/ is its root).
WEB_HEAD = ('<link rel="icon" href="assets/favicon.svg" type="image/svg+xml">\n'
            '<link rel="stylesheet" href="assets/tokens.css">')
WEB_NAV = '<a class="back" href="./">QuantumShield site</a>'


def render(before: Inventory | None, after: Inventory | None = None, bench: dict | None = None,
           plan: dict | None = None, title: str = "QuantumShield", web: bool = False) -> str:
    data = {"before": _inv_view(before) if before else None,
            "after": _inv_view(after) if after else None,
            "bench": bench, "plan": plan, "phases": PHASES}
    # Escape "</" so inventory strings can never close the script element.
    blob = json.dumps(data).replace("</", "<\\/")
    return (template()
            .replace("__HEAD__", WEB_HEAD if web else "")
            .replace("__NAV__", WEB_NAV if web else "")
            .replace("__TITLE__", html.escape(title))
            .replace("__DATA__", blob))


def write(path: Path, **kw) -> Path:
    path.write_text(render(**kw), encoding="utf-8")
    return path
