"""The interop contract: a canonical **Finding** every Cognis tool emits.

Every tool in the 300+ suite produces heterogeneous output — vessels, IOCs, CVEs,
geolocations, drone tracks. `Finding` is the one shape they all map to, so a single
set of adapters can route *any* tool's output to *any* platform (STIX, MISP, Sigma,
Splunk, Elastic, Slack, a webhook, or an edgemesh `/v1` model).

A tool either emits `Finding`s directly, or you `normalize()` its JSON. Pure stdlib.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
_NS = uuid.UUID("c0c0c0c0-0000-4000-8000-000000000001")   # stable namespace for deterministic ids

# canonical indicator keys -> how platforms recognize them
INDICATOR_KEYS = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
                  "mac", "cve", "imo", "mmsi", "btc", "eth", "lat", "lon", "username")


@dataclass
class Finding:
    title: str
    source: str                                  # the producing tool, e.g. "maritimeint"
    severity: str = "medium"
    type: str = "observation"                    # category, e.g. sanctions-hit, ioc, cve, geoloc
    description: str = ""
    indicators: dict = field(default_factory=dict)   # subset of INDICATOR_KEYS -> value
    tags: list = field(default_factory=list)
    timestamp: str = ""                          # ISO-8601; optional
    id: str = ""                                 # stable; derived if absent
    raw: dict = field(default_factory=dict)      # the original record, untouched

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "medium"
        self.indicators = {k: v for k, v in self.indicators.items() if v not in (None, "")}
        if not self.id:
            seed = f"{self.source}|{self.title}|{json.dumps(self.indicators, sort_keys=True)}"
            self.id = str(uuid.uuid5(_NS, seed))

    def to_dict(self) -> dict:
        return asdict(self)


# common aliases seen across tools -> canonical Finding field / indicator key
_FIELD_ALIASES = {"name": "title", "summary": "title", "msg": "title",
                  "tool": "source", "producer": "source",
                  "sev": "severity", "level": "severity", "risk": "severity",
                  "category": "type", "kind": "type", "desc": "description", "details": "description"}
_IND_ALIASES = {"ip": "ipv4", "ip_address": "ipv4", "hostname": "domain", "fqdn": "domain",
                "hash": "sha256", "sha-256": "sha256", "latitude": "lat", "longitude": "lon",
                "vessel_imo": "imo", "imo_number": "imo", "mmsi_number": "mmsi"}
_SEV_MAP = {"informational": "info", "warn": "medium", "warning": "medium", "error": "high",
            "crit": "critical", "0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def normalize(record: dict, source: str = "unknown") -> Finding:
    """Map an arbitrary tool record (dict) to a Finding, best-effort + lossless (`raw`)."""
    fields, inds = {"source": source}, {}
    for k, v in record.items():
        kl = str(k).strip().lower()
        if kl in _FIELD_ALIASES:
            fields[_FIELD_ALIASES[kl]] = v
        elif kl in ("title", "source", "severity", "type", "description", "timestamp", "id"):
            fields[kl] = v
        elif kl in INDICATOR_KEYS:
            inds[kl] = v
        elif kl in _IND_ALIASES:
            inds[_IND_ALIASES[kl]] = v
        elif kl in ("indicators", "iocs") and isinstance(v, dict):
            inds.update(v)
        elif kl in ("tags", "labels") and isinstance(v, list):
            fields["tags"] = v
    sev = str(fields.get("severity", "medium")).lower()
    fields["severity"] = _SEV_MAP.get(sev, sev)
    fields.setdefault("title", record.get("title") or "finding")
    return Finding(indicators=inds, raw=record, **{k: v for k, v in fields.items()
                                                   if k in Finding.__dataclass_fields__ and k != "indicators"})


def load(path_or_text: str, source: str = "unknown") -> list[Finding]:
    """Load a JSON list/object of records (path or raw text) into Findings."""
    text = path_or_text
    if "\n" not in path_or_text and path_or_text.strip()[:1] not in "[{":
        with open(path_or_text, encoding="utf-8") as fh:
            text = fh.read()
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or data.get("watchlist") or [data]
    out = []
    for rec in data:
        out.append(rec if isinstance(rec, Finding) else normalize(rec, source))
    return out


def dump(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
