"""Chat notifications — Slack / Discord / generic webhook from Findings. Pure stdlib."""

from __future__ import annotations

from cognis_connect.findings import Finding
from cognis_connect.transport import post

_EMOJI = {"info": "white_circle", "low": "large_blue_circle", "medium": "large_yellow_circle",
          "high": "large_orange_circle", "critical": "red_circle"}


def _line(f: Finding) -> str:
    ind = " ".join(f"`{k}={v}`" for k, v in f.indicators.items())
    return f":{_EMOJI.get(f.severity, 'white_circle')}: *[{f.severity.upper()}]* {f.title} " \
           f"_({f.source})_ {ind}".rstrip()


def slack_payload(findings: list[Finding], header: str = "Cognis findings") -> dict:
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": header}}]
    for f in findings[:48]:                       # Slack block limit guard
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _line(f)}})
    if len(findings) > 48:
        blocks.append({"type": "context", "elements":
                       [{"type": "mrkdwn", "text": f"+{len(findings) - 48} more"}]})
    return {"blocks": blocks}


def discord_payload(findings: list[Finding], header: str = "Cognis findings") -> dict:
    body = "\n".join(_line(f).replace(":red_circle:", "🔴").replace(":large_orange_circle:", "🟠")
                     for f in findings[:40])
    return {"content": f"**{header}**\n{body}"[:1900]}


def send_slack(findings, webhook_url: str, *, header: str = "Cognis findings", dry_run: bool = False):
    return post(webhook_url, slack_payload(findings, header), dry_run=dry_run)


def send_discord(findings, webhook_url: str, *, header: str = "Cognis findings", dry_run: bool = False):
    return post(webhook_url, discord_payload(findings, header), dry_run=dry_run)
