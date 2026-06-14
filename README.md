<a name="top"></a>
# cognis-connect

**The integration SDK for the [Cognis suite](https://github.com/cognis-digital).** One
canonical **Finding** contract that every tool maps to — and adapters that route those
findings to **STIX/TAXII, MISP, Sigma, Splunk, Elastic, Slack, Discord, webhooks**, and
your **edgemesh `/v1` fleet**. Pure standard library, zero dependencies.

This is what makes the 300+ tools genuinely *compose*: each tool emits JSON, `Finding`
normalizes it, and one set of adapters delivers it anywhere your SOC already lives.

```mermaid
flowchart LR
  subgraph tools["any Cognis tool (--format json)"]
    MI[maritimeint]; IO[iocextract]; CV[cvecheck]; GE[geolens]; UL[uaslog]
  end
  tools --> F[["Finding<br/>(the contract)"]]
  F --> STIX[STIX 2.1 / TAXII]
  F --> MISP[MISP]
  F --> SIG[Sigma]
  F --> SIEM[Splunk · Elastic]
  F --> CHAT[Slack · Discord · webhook]
  F --> AI[edgemesh /v1<br/>summarize]
  classDef c fill:#6b46c1,color:#fff; class F c;
```

## Install

```bash
pip install "git+https://github.com/cognis-digital/cognis-connect.git"
```

## Use it — from the shell

Pipe any tool's JSON straight to a platform:

```bash
maritimeint locate fleet.csv --sanctions s.json --format json \
  | cognis-connect emit --to stix --source maritimeint > bundle.stix.json

iocextract scan log.txt --format json | cognis-connect emit --to misp --url $MISP --token $KEY
cvecheck . --format json             | cognis-connect emit --to sigma > rules.yml
cat findings.json | cognis-connect emit --to splunk --url $HEC --token $TOK --dry-run
cat findings.json | cognis-connect emit --to slack  --url $SLACK_WEBHOOK
cat findings.json | cognis-connect emit --to brief                     # analyst summary via your fleet
```

`--dry-run` previews the exact HTTP request (method/url/headers/body) without sending —
so you can wire pipelines safely and test offline.

## Use it — from Python

```python
from cognis_connect import load, stix, misp, sigma, siem, notify, edgemesh

findings = load("vessels.json", source="maritimeint")   # normalize any tool's JSON
stix.to_bundle(findings)                                  # -> STIX 2.1 dict
misp.to_event(findings)                                   # -> MISP event
print(sigma.to_rules(findings))                           # -> Sigma YAML
siem.send_splunk(findings, hec_url, token, dry_run=True)  # preview the HEC POST
notify.send_slack(findings, webhook_url)                  # post to Slack
edgemesh.summarize(findings)                              # one-paragraph brief via /v1
```

### The contract

Every tool either emits `Finding`s or you `normalize()` its records. Field/indicator
aliases are mapped automatically; the original record is preserved in `raw`:

```python
from cognis_connect import normalize
f = normalize({"name": "C2 beacon", "risk": "high", "ip": "203.0.113.5",
               "sha256": "…"}, source="iocextract")
# Finding(title='C2 beacon', severity='high', source='iocextract',
#         indicators={'ipv4': '203.0.113.5', 'sha256': '…'})
```

| canonical field | aliases accepted |
|---|---|
| `title` | name, summary, msg |
| `severity` | sev, level, risk, 0–4, warn/error/crit |
| indicators | ip→ipv4, hostname/fqdn→domain, hash→sha256, latitude/longitude, vessel_imo→imo, … |

## Platforms

| `--to` | Output / destination |
|---|---|
| `stix` / `taxii` | STIX 2.1 bundle (deterministic ids) / push to a TAXII 2.1 collection |
| `misp` | MISP Event (typed attributes, threat level) / push to a MISP instance |
| `sigma` | Sigma detection-rule skeletons (no pyyaml) |
| `splunk` / `elastic` | Splunk HEC events / Elastic `_bulk` NDJSON |
| `slack` / `discord` / `webhook` | chat notifications / generic JSON webhook |
| `brief` | one-paragraph analyst summary via the edgemesh `/v1` fleet |

## Interoperability

See **[INTEROP.md](INTEROP.md)** — cognis-connect is the backbone the suite's composition
patterns and reference stacks are built on. **300+ tools →**
[github.com/cognis-digital](https://github.com/cognis-digital).

## License

[COCL 1.0](LICENSE) — Cognis Open Collaboration License. © 2026 Cognis Digital LLC.

<div align="right"><a href="#top">↑ back to top</a></div>
