# subdomainenum — Project Instructions

## Tech Stack
| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | ≥ 3.11 |
| CLI framework | Typer | ≥ 0.12 |
| Terminal output | Rich | ≥ 13.7 |
| HTTP client | requests | ≥ 2.31 |
| DNS resolver | dnspython | ≥ 2.6 |
| TLS parsing | cryptography | ≥ 42 |
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
  checks/
    passive/
      crt_sh.py       → query_crt_sh(): Certificate Transparency via crt.sh API
      san.py          → query_san(): TLS Subject Alt Names from live certificate
    active/
      tool_runner.py  → run_tool(): subprocess wrapper with timeout + streaming
      subfinder.py    → run_subfinder()
      amass.py        → run_amass()
      findomain.py    → run_findomain()
      assetfinder.py  → run_assetfinder()
      dnsrecon.py     → run_dnsrecon()
      gobuster_dns.py → run_gobuster_dns()
      wfuzz.py        → run_wfuzz() → list[VhostResult]
tests/
  conftest.py              → shared fixtures
  test_*.py                → pytest, AAA pattern, class-per-feature grouping
  checks/passive/
    test_crt_sh.py
    test_san.py
  checks/active/
    test_tool_runner.py
    test_wrappers.py
```

## Architecture

### Request lifecycle
1. `cli.py` validates domain and flags, builds `debug_cb` / `progress_cb`
2. `cli.py` calls `assess(domain, mode, ...)` from `assessor.py`
3. `assessor.py` fans out passive sources in a `ThreadPoolExecutor` (all run concurrently)
4. Active sources run sequentially after passive (require wordlist)
5. Discovered FQDNs are DNS-resolved in parallel (50 workers, `dns_utils.resolve_ips`)
6. `EnumReport` is returned; `reporter.py` renders with Rich or serialises to JSON

### I/O boundaries (mock these in tests)
| Boundary | Module | What to patch |
|----------|--------|---------------|
| HTTP (crt.sh) | `checks/passive/crt_sh.py` | `requests.get` |
| TLS socket | `checks/passive/san.py` | `ssl.create_default_context` / `socket.create_connection` |
| Subprocess tools | `checks/active/tool_runner.py` | `subprocess.Popen` |
| DNS resolution | `dns_utils.py` | `dns.resolver.Resolver.resolve` |

### EnumMode behaviour
- `passive` — crt.sh, SAN, subfinder, amass (passive), findomain, assetfinder
- `active` — dnsrecon, gobuster dns (require `--wordlist`); wfuzz only when `--url` provided
- `all` — both passive and active

## Testing Conventions
- Mock at the I/O boundary listed in the table above — never mock `assess()` itself
- Use `monkeypatch` (pytest-mock) or `unittest.mock.patch`
- Test class naming: `TestRunTool`, `TestQueryCrtSh`, `TestAssess`, etc. (class-per-feature)
- AAA pattern: Arrange → Act → Assert in every test method
- Coverage target: ≥ 80% (configured in `pyproject.toml`)
- Current test count: **160 tests**

## Adding a New Passive Source
1. Create `subdomainenum/checks/passive/<name>.py` with a `query_<name>(domain) → SourceResult` function
2. Import and add it to the passive sources list in `assessor.py`
3. Wire `debug_cb` if the source is streaming
4. Write tests in `tests/checks/passive/test_<name>.py`

## Adding a New Active Tool
1. Create `subdomainenum/checks/active/<name>.py` using `run_tool()` from `tool_runner.py`
2. Add an entry to `ACTIVE_TOOLS` in `constants.py` (binary name + install hint)
3. Import and add it to the active sources in `assessor.py`
4. Write tests in `tests/checks/active/test_wrappers.py` (or a new file)

## Debug Mode
`--debug` streams each tool's raw output to stderr in real time using a `rich.live.Live`
display. Each source gets its own coloured `Panel`; panels are stacked vertically and
refresh up to 10×/s. Each panel keeps at most `_MAX_DEBUG_LINES` (20) lines via a
`collections.deque`. The `_DebugDisplay` class in `cli.py` owns this logic and is
thread-safe (passive sources run concurrently via `ThreadPoolExecutor`).
The colour map lives in `_DEBUG_COLOURS` in `cli.py`. Add new sources there when adding checks.

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
- All external calls (subprocess, HTTP, TLS, DNS) are wrapped to never raise — errors captured in `SourceResult.error`
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

## Version Bumping

When committing a set of changes, bump the version using semver:
- **patch** (`0.1.x`) — bug fixes, refactor, docs, lint
- **minor** (`0.x.0`) — new sources, new CLI options, new features
- **major** (`x.0.0`) — breaking API changes

Two files must always be updated together:
- `pyproject.toml` → `version = "x.y.z"`
- `subdomainenum/__init__.py` → fallback `__version__ = "x.y.z"` (the `except` branch)
