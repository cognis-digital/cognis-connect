"""cognis-connect — the integration SDK that makes the 300+ Cognis suite composable.

Every tool maps its output to one canonical `Finding`; these adapters then route any
findings to any platform:

    from cognis_connect import load, stix, misp, sigma, siem, notify, edgemesh
    findings = load("vessels.json", source="maritimeint")
    bundle   = stix.to_bundle(findings)                 # STIX 2.1
    event    = misp.to_event(findings)                  # MISP
    rules    = sigma.to_rules(findings)                 # Sigma
    siem.send_splunk(findings, url, token)              # Splunk HEC
    notify.send_slack(findings, webhook)                # Slack
    brief    = edgemesh.summarize(findings)             # your fleet, via /v1

Pure standard library. Network calls support `dry_run=True` for offline preview/testing.
"""

from cognis_connect import edgemesh, misp, notify, sigma, siem, stix, transport
from cognis_connect.findings import (Finding, INDICATOR_KEYS, SEVERITIES,
                                     dump, load, normalize)

__version__ = "0.1.0"

__all__ = ["Finding", "normalize", "load", "dump", "SEVERITIES", "INDICATOR_KEYS",
           "stix", "misp", "sigma", "siem", "notify", "edgemesh", "transport", "__version__"]
