"""edgemesh / OpenAI-compatible `/v1` client — the shared AI backbone.

Any tool's add-ins call this to reach one `/v1` across the whole fleet (edgemesh, or
Ollama / vLLM / LM Studio). `discover()` finds a reachable gateway by env or by probing
the common local ports, so add-ins "just work" without per-tool config. Pure stdlib.
"""

from __future__ import annotations

import json
import os
import urllib.request

# common local OpenAI-compatible ports across the fleet/tools
_PORTS = (8080, 8000, 11434, 1234, 8774, 8772, 8773, 5000)
_ENV = ("COGNIS_ENDPOINT", "EDGEMESH_ENDPOINT", "OPENAI_BASE_URL", "OPENAI_API_BASE")


def discover(timeout: float = 0.6) -> str | None:
    """Return a reachable `/v1` base URL (env first, then probe localhost), else None."""
    for e in _ENV:
        if os.environ.get(e):
            return os.environ[e].rstrip("/")
    for port in _PORTS:
        base = f"http://localhost:{port}/v1"
        try:
            urllib.request.urlopen(base + "/models", timeout=timeout)
            return base
        except Exception:
            continue
    return None


def _req(url: str, payload: dict, timeout: float) -> dict:
    key = os.environ.get("OPENAI_API_KEY", "sk-local")
    req = urllib.request.Request(url, json.dumps(payload).encode(),
                                 {"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def chat(messages, *, base: str | None = None, model: str = "local", timeout: float = 60.0) -> str:
    base = (base or discover())
    if not base:
        raise RuntimeError("no /v1 backend reachable; set COGNIS_ENDPOINT or run an edgemesh gateway")
    data = _req(base.rstrip("/") + "/chat/completions",
                {"model": model, "messages": messages}, timeout)
    return data["choices"][0]["message"]["content"]


def summarize(findings, *, base: str | None = None, model: str = "local") -> str:
    """One-paragraph analyst brief over Findings, via the fleet."""
    facts = "; ".join(f"[{f.severity}] {f.title} ({f.source})" for f in findings) or "no findings"
    return chat([{"role": "system", "content": "You are a security analyst. One paragraph."},
                 {"role": "user", "content": f"Brief these findings: {facts}"}],
                base=base, model=model)
