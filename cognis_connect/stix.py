"""STIX 2.1 adapter — Findings -> a valid STIX bundle, and push to a TAXII 2.1 server.

Deterministic ids (uuid5 of the finding id), so the same finding always yields the same
STIX object — diff-friendly and testable. Maps known indicator types to STIX patterns;
domain-specific ones (imo/mmsi/lat/lon) ride along as labels + a note. Pure stdlib.
"""

from __future__ import annotations

import uuid

from cognis_connect.findings import Finding
from cognis_connect.transport import post

_NS = uuid.UUID("c0c0c0c0-0000-4000-8000-000000000002")
_DEFAULT_TIME = "2026-01-01T00:00:00.000Z"

# canonical indicator -> STIX pattern fragment
_PATTERN = {
    "ipv4": "ipv4-addr:value = '{}'", "ipv6": "ipv6-addr:value = '{}'",
    "domain": "domain-name:value = '{}'", "url": "url:value = '{}'",
    "email": "email-addr:value = '{}'", "mac": "mac-addr:value = '{}'",
    "md5": "file:hashes.MD5 = '{}'", "sha1": "file:hashes.'SHA-1' = '{}'",
    "sha256": "file:hashes.'SHA-256' = '{}'",
}
_SEV_LABEL = {"info": "benign", "low": "anomalous-activity", "medium": "anomalous-activity",
              "high": "malicious-activity", "critical": "malicious-activity"}


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, seed)}"


def _pattern(f: Finding) -> str:
    parts = [_PATTERN[k].format(v) for k, v in f.indicators.items() if k in _PATTERN]
    if parts:
        return "[" + " OR ".join(parts) + "]"
    # no STIX-native indicator -> a generic note pattern so the SDO stays valid
    extra = ", ".join(f"{k}={v}" for k, v in f.indicators.items()) or f.title
    return f"[x-cognis:value = '{extra}']"


def to_indicator(f: Finding, *, created: str = _DEFAULT_TIME) -> dict:
    return {
        "type": "indicator", "spec_version": "2.1", "id": _id("indicator", f.id),
        "created": created, "modified": f.timestamp or created,
        "name": f.title, "description": f.description,
        "indicator_types": [_SEV_LABEL.get(f.severity, "anomalous-activity")],
        "pattern": _pattern(f), "pattern_type": "stix", "valid_from": f.timestamp or created,
        "labels": sorted(set(f.tags) | {f"source:{f.source}", f"severity:{f.severity}", f"type:{f.type}"}),
    }


def to_bundle(findings: list[Finding], *, created: str = _DEFAULT_TIME) -> dict:
    objects = [to_indicator(f, created=created) for f in findings]
    seed = "|".join(o["id"] for o in objects)
    return {"type": "bundle", "id": _id("bundle", seed or "empty"), "objects": objects}


def push_taxii(findings, collection_url: str, *, token: str | None = None, dry_run: bool = False):
    """POST a bundle to a TAXII 2.1 collection (…/collections/<id>/objects/)."""
    return post(collection_url.rstrip("/") + "/objects/", to_bundle(findings),
                token=token, content_type="application/taxii+json;version=2.1", dry_run=dry_run)
