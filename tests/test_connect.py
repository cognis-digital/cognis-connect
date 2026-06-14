"""cognis-connect: the Finding contract + every platform adapter (offline, dry-run)."""

from __future__ import annotations

import json

from cognis_connect import edgemesh, misp, notify, sigma, siem, stix
from cognis_connect.findings import Finding, load, normalize
from cognis_connect.cli import main


SAMPLE = [
    {"title": "NEPTUNE STAR on OFAC list", "severity": "critical", "type": "sanctions-hit",
     "source": "maritimeint", "imo": "9700001", "mmsi": "210111000", "tags": ["russia"]},
    {"name": "C2 beacon", "risk": "high", "ip": "203.0.113.5", "domain": "evil.example",
     "sha256": "a" * 64},
]


# --- the contract ------------------------------------------------------------
def test_normalize_aliases_and_severity():
    f = normalize(SAMPLE[1], source="iocextract")
    assert f.title == "C2 beacon" and f.severity == "high"
    assert f.indicators["ipv4"] == "203.0.113.5" and f.indicators["domain"] == "evil.example"
    assert f.source == "iocextract" and f.raw == SAMPLE[1]


def test_finding_id_is_deterministic():
    a = Finding(title="x", source="t", indicators={"ipv4": "1.1.1.1"})
    b = Finding(title="x", source="t", indicators={"ipv4": "1.1.1.1"})
    assert a.id == b.id and a.id != Finding(title="y", source="t").id


def test_load_handles_watchlist_wrapper():
    findings = load(json.dumps({"watchlist": SAMPLE}), source="maritimeint")
    assert len(findings) == 2


# --- STIX --------------------------------------------------------------------
def test_stix_bundle_valid_and_deterministic():
    fs = load(json.dumps(SAMPLE), source="x")
    b1 = stix.to_bundle(fs); b2 = stix.to_bundle(fs)
    assert b1["type"] == "bundle" and b1 == b2          # deterministic
    ind = [o for o in b1["objects"] if o["type"] == "indicator"]
    assert len(ind) == 2 and all(o["pattern_type"] == "stix" for o in ind)
    pats = " ".join(o["pattern"] for o in ind)
    assert "ipv4-addr:value = '203.0.113.5'" in pats and "SHA-256" in pats


# --- MISP --------------------------------------------------------------------
def test_misp_event_attributes_and_threat_level():
    ev = misp.to_event(load(json.dumps(SAMPLE), source="x"))["Event"]
    vals = [a["value"] for a in ev["Attribute"]]
    assert "203.0.113.5" in vals and ev["threat_level_id"] == 1   # critical present


# --- Sigma -------------------------------------------------------------------
def test_sigma_rule_has_required_keys():
    r = sigma.to_rule(normalize(SAMPLE[1], "iocextract"))
    assert "title:" in r and "detection:" in r and "level: high" in r


# --- SIEM --------------------------------------------------------------------
def test_elastic_bulk_is_ndjson_action_doc_pairs():
    nd = siem.elastic_bulk(load(json.dumps(SAMPLE), source="x"))
    lines = [ln for ln in nd.splitlines() if ln]
    assert len(lines) == 4 and json.loads(lines[0])["index"]["_index"] == "cognis-findings"


def test_splunk_events_wrap_each_finding():
    ev = siem.splunk_events(load(json.dumps(SAMPLE), source="x"))
    objs = [json.loads(x) for x in ev.replace("}{", "}\n{").splitlines()]
    assert all("event" in o for o in objs) and len(objs) == 2


def test_send_webhook_dry_run_previews_request():
    r = siem.send_webhook(load(json.dumps(SAMPLE), "x"), "https://hook.example", dry_run=True)
    assert r["dry_run"] and r["url"] == "https://hook.example" and "findings" in r["body"]


# --- notify ------------------------------------------------------------------
def test_slack_payload_blocks():
    p = notify.slack_payload(load(json.dumps(SAMPLE), "maritimeint"))
    assert p["blocks"][0]["type"] == "header"
    assert any("NEPTUNE" in b.get("text", {}).get("text", "") for b in p["blocks"])


# --- edgemesh ----------------------------------------------------------------
def test_edgemesh_discover_returns_none_when_nothing_up(monkeypatch):
    monkeypatch.setattr(edgemesh, "_PORTS", ())          # probe nothing
    for e in edgemesh._ENV:
        monkeypatch.delenv(e, raising=False)
    assert edgemesh.discover(timeout=0.01) is None


def test_edgemesh_env_endpoint(monkeypatch):
    monkeypatch.setenv("COGNIS_ENDPOINT", "http://localhost:9/v1")
    assert edgemesh.discover() == "http://localhost:9/v1"


# --- CLI ---------------------------------------------------------------------
def test_cli_emit_stix(capsys, tmp_path):
    p = tmp_path / "f.json"; p.write_text(json.dumps(SAMPLE), encoding="utf-8")
    assert main(["emit", "--to", "stix", str(p), "--source", "x"]) == 0
    assert json.loads(capsys.readouterr().out)["type"] == "bundle"


def test_cli_emit_slack_dry_run(capsys, tmp_path):
    p = tmp_path / "f.json"; p.write_text(json.dumps(SAMPLE), encoding="utf-8")
    rc = main(["emit", "--to", "slack", str(p), "--url", "https://hook", "--dry-run"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["dry_run"] is True
