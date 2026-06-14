# Changelog

## [0.1.0] — 2026-06-13

Initial release — the integration SDK that makes the 300+ Cognis suite genuinely
composable, turning the INTEROP composition patterns into working code.

### Added
- **`Finding`** — the canonical interop contract every tool maps to (`normalize()` from
  arbitrary tool JSON, deterministic ids, lossless `raw`, indicator aliasing,
  severity normalization). `load()` understands `findings` / `results` / `watchlist`
  wrappers.
- **Platform adapters** (pure stdlib; HTTP supports `dry_run` preview):
  - `stix` — STIX 2.1 bundle (deterministic ids, indicator→pattern) + TAXII 2.1 push
  - `misp` — MISP Event (attribute typing + threat level) + push
  - `sigma` — Sigma detection-rule skeleton (no pyyaml)
  - `siem` — Splunk HEC, Elastic `_bulk` NDJSON, generic webhook
  - `notify` — Slack Block Kit + Discord
  - `edgemesh` — OpenAI-compatible `/v1` client with port auto-discovery + `summarize()`
- **`cognis-connect emit --to {stix,taxii,misp,sigma,splunk,elastic,slack,discord,webhook,brief}`**
  — pipe any tool's `--format json` straight to any platform.
- Cross-OS CI (Linux/macOS/Windows × Py 3.10–3.13); 14 tests, zero dependencies.
