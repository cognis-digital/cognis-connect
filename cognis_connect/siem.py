"""SIEM adapters — ship Findings to Splunk (HEC), Elastic (bulk), or any webhook.

Build-functions are pure (testable); send-functions perform the HTTP POST (or preview
it with dry_run). Pure stdlib.
"""

from __future__ import annotations

import json

from cognis_connect.findings import Finding
from cognis_connect.transport import post


def splunk_events(findings: list[Finding], sourcetype: str = "cognis:finding") -> str:
    """Splunk HEC accepts concatenated {"event": …} JSON objects."""
    return "".join(json.dumps({"sourcetype": sourcetype, "source": f.source,
                               "event": f.to_dict()}) for f in findings)


def send_splunk(findings, hec_url: str, token: str, *, dry_run: bool = False):
    return post(hec_url.rstrip("/") + "/services/collector", splunk_events(findings),
                headers={"Authorization": f"Splunk {token}"}, dry_run=dry_run)


def elastic_bulk(findings: list[Finding], index: str = "cognis-findings") -> str:
    """Elastic _bulk NDJSON: an action line + a doc line per finding (trailing newline)."""
    lines = []
    for f in findings:
        lines.append(json.dumps({"index": {"_index": index, "_id": f.id}}))
        lines.append(json.dumps(f.to_dict()))
    return "\n".join(lines) + "\n"


def send_elastic(findings, base_url: str, *, index: str = "cognis-findings",
                 token: str | None = None, dry_run: bool = False):
    return post(base_url.rstrip("/") + "/_bulk", elastic_bulk(findings, index),
                content_type="application/x-ndjson", token=token, dry_run=dry_run)


def send_webhook(findings, url: str, *, token: str | None = None, dry_run: bool = False):
    return post(url, {"findings": [f.to_dict() for f in findings]}, token=token, dry_run=dry_run)
