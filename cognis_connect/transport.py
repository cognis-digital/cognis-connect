"""Tiny HTTP transport — one stdlib POST helper shared by every platform adapter.

`dry_run=True` returns the request it *would* send (method/url/headers/body) instead of
performing it, so adapters are fully testable offline and you can preview a push.
"""

from __future__ import annotations

import json
import urllib.request


def post(url: str, body, *, headers: dict | None = None, token: str | None = None,
         content_type: str = "application/json", dry_run: bool = False, timeout: float = 30.0):
    h = {"Content-Type": content_type}
    if token:
        h["Authorization"] = token if token.lower().startswith(("bearer ", "splunk ")) else f"Bearer {token}"
    if headers:
        h.update(headers)
    data = body if isinstance(body, (bytes, bytearray)) else \
        (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
    if dry_run:
        return {"dry_run": True, "method": "POST", "url": url, "headers": h,
                "body": data.decode("utf-8", "replace")}
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
