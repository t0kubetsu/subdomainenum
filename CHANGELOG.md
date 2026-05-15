# Changelog

All notable changes to **subdomainenum** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.14.1] — 2026-05-15

### Changed
- `__init__`: version fallback now catches `PackageNotFoundError` explicitly
  instead of bare `Exception`, consistent with all other platform modules.
- `reporter`: exposes a public `console` alias (`Console(record=True)`) and
  a `save_report(path)` function supporting `.txt`, `.svg`, and `.html`
  extensions (unknown extensions fall back to plain text); the old JSON-only
  `save_report(report, path)` signature has been replaced.
- CLI migrated to use `reporter.console` and `reporter.save_report()` —
  the private `_save_report()` helper in `cli.py` has been removed.

---

## [0.14.0] — 2026-04-27

### Added
- **Streaming DNS resolver** (`StreamingResolver`) — resolves FQDNs in the
  background as each tool wrapper parses them; avoids a full post-scan batch
  and speeds up large enumerations.
- **`--debug-log` flag** — collects per-tool raw output to an auto-named log
  file (`<domain>_YYYYMMDD_HHMMSS.log`); written to `/reports/` if mounted,
  otherwise to the current directory.
- **Docker Compose support** — multi-stage Dockerfile builds all Go tools
  (subfinder, findomain, assetfinder, gobuster, ffuf) in stage 1; installs
  the Python package in stage 2.
- **Phase fusion** (`all` mode) — passive and active-enum pools run
  concurrently under an outer executor, reducing total wall-clock time.
- **ffuf fanout** — multiple target URLs fuzzed in parallel (capped at 8
  workers); passive-phase resolved IPs reused for URL enrichment to avoid
  duplicate lookups.
- CodeTour walkthrough (`.tours/new-joiner-architecture.tour`) — end-to-end
  request lifecycle for new contributors.

### Changed
- Repository moved to the
  [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform) GitHub
  organisation; all internal URLs updated.
- Active-enum pool is always **gobuster** (1 worker); dnsrecon moved
  permanently to the passive phase (AXFR + DNSSEC zone walk target public
  authoritative nameservers).
- Per-FQDN `A` and `AAAA` queries fan out on a shared 256-worker pool so the
  slower query bounds per-FQDN latency.

### Removed
- amass removed from all enumeration phases.

---

## [0.1.0] — 2026-04-13

### Added
- Initial release of **subdomainenum**.
- Passive enumeration: subfinder, findomain, assetfinder, dnsrecon
  (`std,srv` with Bing/Yandex/crt.sh/SPF/AXFR/DNSSEC zone walk).
- Active enumeration: gobuster DNS (brute-force), ffuf vhost discovery.
- CLI: `subdomainenum check <domain>` with `--mode`, `--wordlist`, `--url`,
  `--json`, `--output` flags.
- `subdomainenum info` — shows installed tool availability and install hints.
- Report export to `.txt`, `.svg`, `.html`.
- Missing external tools auto-skipped via `constants.detect_tools()`.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.1...HEAD
[0.14.1]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.1.0...v0.14.0
[0.1.0]: https://github.com/NC3-TestingPlatform/subdomainenum/releases/tag/v0.1.0
