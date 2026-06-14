"""cognis-connect CLI — route any tool's findings to any platform.

    <tool> ... --format json | cognis-connect emit --to stix --source maritimeint
    cognis-connect emit --to slack  --url $SLACK_WEBHOOK   < findings.json
    cognis-connect emit --to splunk --url $HEC --token $TOK --dry-run < findings.json
    cognis-connect emit --to brief  # one-paragraph analyst summary via your fleet (/v1)
"""

from __future__ import annotations

import argparse
import json
import sys

from cognis_connect import __version__, edgemesh, misp, notify, sigma, siem, stix
from cognis_connect.findings import load

TARGETS = ("stix", "taxii", "misp", "sigma", "splunk", "elastic", "slack", "discord",
           "webhook", "brief", "findings")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cognis-connect", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"cognis-connect {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit", help="convert/forward findings to a platform")
    e.add_argument("--to", required=True, choices=TARGETS)
    e.add_argument("input", nargs="?", default="-", help="findings JSON file (default: stdin)")
    e.add_argument("--source", default="unknown", help="producing tool name")
    e.add_argument("--url", default=None); e.add_argument("--token", default=None)
    e.add_argument("--index", default="cognis-findings"); e.add_argument("--header", default="Cognis findings")
    e.add_argument("--model", default="local")
    e.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    findings = load(text, source=args.source)

    def need_url():
        if not args.url:
            print(f"error: --to {args.to} needs --url", file=sys.stderr); raise SystemExit(2)

    try:
        if args.to == "stix":
            print(json.dumps(stix.to_bundle(findings), indent=2))
        elif args.to == "taxii":
            need_url(); print(json.dumps(stix.push_taxii(findings, args.url, token=args.token, dry_run=args.dry_run), indent=2))
        elif args.to == "misp":
            if args.url:
                print(json.dumps(misp.push(findings, args.url, args.token or "", dry_run=args.dry_run), indent=2))
            else:
                print(json.dumps(misp.to_event(findings, args.header), indent=2))
        elif args.to == "sigma":
            print(sigma.to_rules(findings))
        elif args.to == "splunk":
            need_url(); print(json.dumps(siem.send_splunk(findings, args.url, args.token or "", dry_run=args.dry_run), indent=2))
        elif args.to == "elastic":
            need_url(); print(json.dumps(siem.send_elastic(findings, args.url, index=args.index, token=args.token, dry_run=args.dry_run), indent=2))
        elif args.to == "slack":
            need_url(); print(json.dumps(notify.send_slack(findings, args.url, header=args.header, dry_run=args.dry_run), indent=2))
        elif args.to == "discord":
            need_url(); print(json.dumps(notify.send_discord(findings, args.url, header=args.header, dry_run=args.dry_run), indent=2))
        elif args.to == "webhook":
            need_url(); print(json.dumps(siem.send_webhook(findings, args.url, token=args.token, dry_run=args.dry_run), indent=2))
        elif args.to == "brief":
            print(edgemesh.summarize(findings, base=args.url, model=args.model))
        elif args.to == "findings":
            from cognis_connect.findings import dump
            print(dump(findings))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
