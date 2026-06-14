"""MISP adapter — Findings -> a MISP Event, and push to a MISP instance.

Maps indicators to MISP attribute types/categories; unknown ones become comments.
Pure stdlib.
"""

from __future__ import annotations

from cognis_connect.findings import Finding
from cognis_connect.transport import post

# canonical indicator -> (MISP type, MISP category)
_ATTR = {
    "ipv4": ("ip-dst", "Network activity"), "ipv6": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"), "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"), "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"), "sha256": ("sha256", "Payload delivery"),
    "cve": ("vulnerability", "External analysis"), "btc": ("btc", "Financial fraud"),
}
_THREAT = {"info": 4, "low": 3, "medium": 2, "high": 1, "critical": 1}   # MISP: 1=high..4=undefined


def to_event(findings: list[Finding], info: str = "Cognis findings") -> dict:
    attrs, tags = [], set()
    worst = 4
    for f in findings:
        worst = min(worst, _THREAT.get(f.severity, 2))
        tags.add(f"source:{f.source}")
        tags.update(f.tags)
        matched = False
        for k, v in f.indicators.items():
            if k in _ATTR:
                t, cat = _ATTR[k]
                attrs.append({"type": t, "category": cat, "value": str(v),
                              "to_ids": f.severity in ("high", "critical"), "comment": f.title})
                matched = True
        if not matched:
            blob = ", ".join(f"{k}={v}" for k, v in f.indicators.items()) or f.description or f.title
            attrs.append({"type": "comment", "category": "Other", "value": blob, "comment": f.title})
    return {"Event": {"info": info, "threat_level_id": worst, "analysis": 1, "distribution": 0,
                      "Attribute": attrs, "Tag": [{"name": t} for t in sorted(tags)]}}


def push(findings, base_url: str, token: str, *, info: str = "Cognis findings", dry_run: bool = False):
    """POST an event to MISP (`base_url`/events/add). `token` is the MISP Auth key."""
    return post(base_url.rstrip("/") + "/events/add", to_event(findings, info),
                headers={"Authorization": token, "Accept": "application/json"}, dry_run=dry_run)
