# subdomainenum — Project Instructions

## Tech Stack
| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | ≥ 3.11 |
| CLI framework | Typer | ≥ 0.12 |
| Terminal output | Rich | ≥ 13.7 |
| DNS resolver | dnspython | ≥ 2.6 |
| Testing | pytest + pytest-cov + pytest-mock | ≥ 8 / ≥ 5 / ≥ 3.12 |

## Build & Run
```bash
pip install -e ".[dev]"                         # install in editable mode with dev deps
subdomainenum check example.com                 # passive enumeration (default)
subdomainenum check example.com --mode active --wordlist /opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt
subdomainenum check example.com --mode all --url http://10.0.0.1 --json
subdomainenum info                              # show tool availability
python -m pytest                                # run tests with coverage
python -m pytest --tb=short -q                 # quick run
```

## Project Structure
```
subdomainenum/
  cli.py              → Typer entry point; calls assessor + reporter; I/O, validation
  assessor.py         → Public API: assess(...) → EnumReport (ThreadPoolExecutor orchestration)
  models.py           → Status, EnumMode enums; SubdomainResult, EnumReport, VhostResult dataclasses
  constants.py        → ACTIVE_TOOLS registry; detect_tools(); get_install_hint()
  dns_utils.py        → resolve_ips(), is_alive() via dnspython (never raises)
  reporter.py         → Rich terminal renderers; to_dict(); save_report()
  verdict.py          → VerdictSummary dataclass + make_verdict() (pure, no I/O)
  tools/
    tool_runner.py  → run_tool(): subprocess wrapper with timeout + streaming
    subfinder.py    → run_subfinder()
    amass.py        → run_amass()
    findomain.py    → run_findomain()
    assetfinder.py  → run_assetfinder()
    dnsrecon.py     → run_dnsrecon()
    gobuster_dns.py → run_gobuster_dns()
    ffuf.py         → run_ffuf() → list[VhostResult]
tests/
  conftest.py              → shared fixtures
  test_*.py                → pytest, AAA pattern, class-per-feature grouping
  tools/
    test_tool_runner.py
    test_wrappers.py
```

## Architecture

### Request lifecycle
1. `cli.py` validates domain and flags, builds `debug_cb` / `progress_cb`
2. `cli.py` calls `assess(domain, mode, ...)` from `assessor.py`
3. `assessor.py` fans out passive tools in a `ThreadPoolExecutor` (5 parallel workers)
4. The 3 non-ffuf active tools (amass, dnsrecon, gobuster) run in their own `ThreadPoolExecutor` (3 parallel workers) via `_run_active_enum`. In `ALL` mode, the passive pool and the active-enum pool run concurrently under an outer executor (phase fusion).
5. `ffuf` runs after the enumeration pools drain so it can target IPs resolved from passive FQDNs; multiple URLs are fuzzed in parallel (`_run_ffuf_fanout`, capped at 8 workers).
6. Discovered FQDNs are DNS-resolved in parallel (50 workers, `dns_utils.resolve_ips`). IPs resolved for ffuf URL enrichment are cached and reused to avoid duplicate lookups.
7. `EnumReport` is returned; `reporter.py` renders with Rich or serialises to JSON

### I/O boundaries (mock these in tests)
| Boundary | Module | What to patch |
|----------|--------|---------------|
| Subprocess tools | `tools/tool_runner.py` | `subprocess.Popen` |
| DNS resolution | `dns_utils.py` | `dns.resolver.Resolver.resolve` |

### EnumMode behaviour
- `passive` — subfinder, amass, findomain, assetfinder (assetfinder also queries crt.sh, certspotter, and other CT sources internally)
- `active` — dnsrecon, gobuster dns (require `--wordlist`); ffuf only when `--url` provided
- `all` — both passive and active

## Testing Conventions
- Mock at the I/O boundary listed in the table above — never mock `assess()` itself
- Use `monkeypatch` (pytest-mock) or `unittest.mock.patch`
- Test class naming: `TestRunTool`, `TestQueryCrtSh`, `TestAssess`, etc. (class-per-feature)
- AAA pattern: Arrange → Act → Assert in every test method
- Coverage target: ≥ 80% (configured in `pyproject.toml`)
- Current test count: **341 tests**

## Adding a New Passive Source
1. Add a `query_<name>(domain) → ToolResult` function directly in `assessor.py` or a new helper module
2. Import and add it to the passive sources list in `assessor.py`
3. Wire `debug_cb` if the source is streaming
4. Write tests in `tests/test_assessor.py` or a dedicated file

## Adding a New Active Tool
1. Create `subdomainenum/tools/<name>.py` using `run_tool()` from `tool_runner.py`
2. Add an entry to `ACTIVE_TOOLS` in `constants.py` (binary name + install hint)
3. Import and add it to the active sources in `assessor.py`
4. Write tests in `tests/tools/test_wrappers.py` (or a new file)

## Debug Log
`--debug-log` (boolean flag, no argument) collects each tool's raw output to an
auto-named log file: `<domain>_YYYYMMDD_HHMMSS.log`.  When `/reports/` is a
mounted directory (Docker), the file is written there so it survives
`docker compose run --rm`; otherwise it lands in the current directory.
`DebugLogger` in `debug_logger.py` is the thread-safe collector; it receives
`debug_cb`, `cmd_cb`, and `finish_cb` callbacks from `assess()` and writes one
section per source (command, all output lines, status, optional error).
No debug output is sent to stderr. After the scan a brief `Debug log → <path>`
confirmation is printed to stderr.

## JSON / Output flags
- `--json` → `to_dict(report)` printed as JSON to stdout (machine-readable)
- `--output <path>` → saves rendered report; extension determines format:
  - `.txt` plain text, `.svg` SVG image, `.html` self-contained HTML (via Rich record)
- Both flags can be combined

## Docker
```bash
sudo docker compose up -d --build   # builds all Go tools in stage 1; installs package in stage 2
# Reports volume is mounted at ./reports → /reports inside container
```
Environment variables for wordlist paths: `DEFAULT_DNS_WORDLIST`, `DEFAULT_VHOST_WORDLIST`

## Conventions
- `from __future__ import annotations` at the top of every module
- Snake_case for all files, functions, and variables
- Sphinx-style docstrings: `:param name:`, `:returns:`, `:rtype:` (no `:type:` — type annotations on signatures are sufficient)
- Conventional commits: `fix:`, `feat:`, `fix(scope):`, `refactor:`, `test:`, `docs:`
- All external calls (subprocess, HTTP, TLS, DNS) are wrapped to never raise — errors captured in `ToolResult.error`
- No CI config currently present

## Before Every Commit

Run these checks and update these files as needed — do not skip any step:

```bash
# 1. Verify tests pass and coverage is ≥ 80%
pytest

# 2. Check for lint issues
ruff check subdomainenum/
```

If the test count changed, update **both** occurrences in `README.md`:
- Badge line (near top): `![Tests](https://img.shields.io/badge/tests-NNN%20passing-brightgreen)`
- Running Tests section: "The test suite has **NNN tests**…" sentence

Also update the count in **this file** (`CLAUDE.md`) under "Testing Conventions".

## Code Tours

The `.tours/` directory contains CodeTour walkthroughs (VS Code / JetBrains extension). Tours are checked into the repo and should stay accurate.

**When to update a tour:**
- Adding or removing a passive or active source
- Changing the public `assess()` signature or its phase structure
- Reorganising the `tools/` directory
- Changing the request lifecycle (passive → active → DNS order)
- Adding a major new subsystem (new output format, new debug mechanism, etc.)

**When you do NOT need to update a tour:**
- Bug fixes or internal refactors that don't move key anchors
- Line-number drift of a few lines (tours reference landmarks, not exact lines)
- New tests or documentation that don't affect the runtime call graph

Current tours:
- `.tours/new-joiner-architecture.tour` — end-to-end request lifecycle for new contributors

## Version Bumping

When committing a set of changes, bump the version using semver:
- **patch** (`0.1.x`) — bug fixes, refactor, docs, lint
- **minor** (`0.x.0`) — new sources, new CLI options, new features
- **major** (`x.0.0`) — breaking API changes

Two files must always be updated together:
- `pyproject.toml` → `version = "x.y.z"`
- `subdomainenum/__init__.py` → fallback `__version__ = "x.y.z"` (the `except` branch)
