"""Sigma adapter — emit a Sigma detection-rule skeleton from a Finding.

Sigma is the portable detection format SIEMs compile from. We can't infer full log
logic from a finding, so we emit a valid, ready-to-edit rule keyed on the finding's
indicators. Pure stdlib (hand-rolled YAML — no pyyaml dependency)."""

from __future__ import annotations

from cognis_connect.findings import Finding

_LEVEL = {"info": "informational", "low": "low", "medium": "medium",
          "high": "high", "critical": "critical"}
# indicator -> a plausible Sigma field name
_FIELD = {"ipv4": "DestinationIp", "ipv6": "DestinationIp", "domain": "QueryName",
          "url": "Url", "sha256": "Hashes", "md5": "Hashes", "email": "RecipientAddress"}


def to_rule(f: Finding) -> str:
    sel = {_FIELD.get(k, k): v for k, v in f.indicators.items()}
    lines = [
        f"title: {f.title}",
        f"id: {f.id}",
        "status: experimental",
        f"description: {f.description or f.title}",
        f"references:\n  - cognis:{f.source}",
        f"tags:\n" + "\n".join(f"  - {t}" for t in (f.tags or [f.type])),
        "logsource:",
        "  category: threat-intel",
        "detection:",
        "  selection:",
    ]
    if sel:
        for k, v in sel.items():
            lines.append(f"    {k}: {v}")
    else:
        lines.append(f"    keyword: '{f.title}'")
    lines += ["  condition: selection", f"level: {_LEVEL.get(f.severity, 'medium')}"]
    return "\n".join(lines) + "\n"


def to_rules(findings) -> str:
    return "\n---\n".join(to_rule(f) for f in findings)
