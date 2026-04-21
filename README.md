# subdomainenum

> Passive and active subdomain enumeration for any target domain — from the
> command line or as a Python library.

**subdomainenum** discovers subdomains through passive tools (subfinder, amass,
findomain, assetfinder — which also queries crt.sh and other CT logs internally),
optionally brute-forces DNS with dnsrecon and gobuster, fuzzes virtual hosts via
wfuzz, resolves each result, and prints a colour-coded summary.

```
$ subdomainenum check example.com
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-382%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)
![License](https://img.shields.io/badge/license-GPLv3-lightgrey)

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [External Tools](#external-tools)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [Docker](#docker)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Contributing](#contributing)

---

## Features

| Source / Mode      | Type    | What it does                                                                         |
| ------------------ | ------- | ------------------------------------------------------------------------------------ |
| **subfinder**      | Passive | Runs `subfinder -d domain -silent -all` (queries all sources)                        |
| **amass**          | Passive | Runs `amass enum -d domain`; parses v4 graph-format output to extract FQDNs         |
| **findomain**      | Passive | Runs `findomain --target domain --quiet`                                             |
| **assetfinder**    | Passive | Runs `assetfinder --subs-only domain`                                                |
| **dnsrecon**       | Passive + Active | Passive: `std,srv` with Bing/Yandex/crt.sh (`-b -y -k`), SPF reverse + deep whois (`-s -w`); adds `snoop` (NS cache-snoop) when `--wordlist` is supplied; adds `--shodan --shodan-active` when `SHODAN_API_KEY` is in the environment. Active: `std,srv` with AXFR and DNSSEC zone walk (`-a -z`); brute-force is delegated to `gobuster dns` so dnsrecon no longer emits `brt`. |
| **gobuster dns**   | Active  | Brute-forces DNS with a wordlist (`gobuster dns --domain domain -w wordlist`)        |
| **ffuf**           | Active  | Fuzzes virtual hosts via the `Host` header against a target URL                      |
| **DNS resolution** | —       | All discovered FQDNs are resolved (A + AAAA in parallel per FQDN) — `A`/`AAAA` queries fan out on a shared 256-worker pool, final batch resolves in up to 100 parallel workers. A `StreamingResolver` overlaps DNS with enumeration: each tool pushes FQDNs into the resolver as soon as it parses them, so by the time enumeration finishes most lookups are already complete. |

Passive and active sources can be run independently or combined (`--mode all`).
In `--mode all`, the passive pool (5 workers) and the non-ffuf active pool
(2 workers: amass, gobuster) run concurrently — dnsrecon already runs in the
passive pool, so re-running it actively would duplicate work. In `--mode
active` (no passive) the active pool grows to 3 workers (amass, gobuster,
dnsrecon) so AXFR and DNSSEC zone walk are still executed. `ffuf` then fans
out one worker per resolved target IP (capped at 8). IPs looked up while
building `ffuf` URLs are cached so no FQDN is DNS-resolved twice.

---

## Requirements

- Python ≥ 3.11
- [`dnspython`](https://www.dnspython.org/) ≥ 2.6
- [`rich`](https://github.com/Textualize/rich) ≥ 13.7
- [`typer`](https://typer.tiangolo.com/) ≥ 0.12
- [`psycopg2-binary`](https://pypi.org/project/psycopg2-binary/) ≥ 2.9
- [`cryptography`](https://cryptography.io/) ≥ 42

External tools are optional — absent tools are silently skipped. Run
`subdomainenum info` to see which are available.

---

## Installation

**From source (recommended):**

```bash
git clone https://github.com/t0kubetsu/subdomainenum.git
cd subdomainenum
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"   # installs the CLI + all dev/test dependencies
```

The `subdomainenum` command is then available in your shell.

---

## External Tools

Run `subdomainenum info` to check which tools are detected on your `$PATH`:

| Tool        | Install                                                                    |
| ----------- | -------------------------------------------------------------------------- |
| subfinder   | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass       | `go install github.com/owasp-amass/amass/v4/...@latest`                    |
| findomain   | Download from https://github.com/Findomain/Findomain/releases              |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest`                       |
| dnsrecon    | `pip install git+https://github.com/darkoperator/dnsrecon.git@master` (installed from source in the Docker image) |
| gobuster    | `go install github.com/OJ/gobuster/v3@latest`                              |
| ffuf        | `go install github.com/ffuf/ffuf/v2@latest`                                |

---

## CLI Usage

### Passive enumeration (default)

```bash
# Queries subfinder, amass, findomain, assetfinder, dnsrecon passive (crt.sh via -k)
subdomainenum check example.com
```

### Active enumeration (DNS brute-force + optional vhost fuzzing)

```bash
# Brute-force DNS with a wordlist
subdomainenum check example.com \
  --mode active \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Brute-force + vhost fuzzing
subdomainenum check example.com \
  --mode active \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --url http://10.0.0.1
```

### All sources combined

```bash
subdomainenum check example.com \
  --mode all \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --url http://10.0.0.1
```

### JSON output

```bash
# Machine-readable output (stdout)
subdomainenum check example.com --json

# Save to file
subdomainenum check example.com --json --output report.json
```

### Debug log

```bash
# Save each tool's raw output to an auto-named log file
subdomainenum check example.com --debug-log

# Also works with --json
subdomainenum check example.com --json --debug-log
```

When `--debug-log` is specified, every line emitted by each tool is written to
a file named `<domain>_YYYYMMDD_HHMMSS.log`. The file is placed in `/reports/`
when that volume is mounted (Docker), otherwise in the current directory. No
debug output is sent to stderr — a brief `Debug log → <path>` confirmation
appears at the end.

### DNS timeout

```bash
# Adjust per-query DNS resolution timeout (default 5.0 s)
subdomainenum check example.com --timeout 10
```

### Tool availability

```bash
subdomainenum info
```

### Version

```bash
subdomainenum --version
```

---

## Python API

### Full assessment

```python
from subdomainenum.assessor import assess
from subdomainenum.models import EnumMode
from subdomainenum.reporter import print_report

report = assess(
    "example.com",
    mode=EnumMode.PASSIVE,          # passive | active | all
    wordlist=None,                  # required for active/all
    url=None,                       # optional: target URL for wfuzz
    timeout=5.0,                    # DNS resolution timeout per query
    progress_cb=print,              # optional: called with status strings
)

print_report(report)
```

### Working with results

```python
from subdomainenum.assessor import assess

report = assess("example.com")

print(report.domain)       # "example.com"
print(report.mode.value)   # "passive"

# Subdomains
for sub in report.subdomains:
    print(sub.fqdn, sub.status.value, sub.ip_addresses, sub.tools)

# Virtual hosts (wfuzz, only in active/all mode with --url)
for vhost in report.vhosts:
    print(vhost.vhost, vhost.status_code, vhost.content_length)

# Per-tool results
for tool in report.tools:
    print(tool.name, len(tool.subdomains), tool.available, tool.error)
```

`Status` values: `ALIVE`, `DEAD`, `TIMEOUT`, `ERROR`, `FOUND`, `NOT_FOUND`, `SKIPPED`.

### JSON serialization

```python
import json
from subdomainenum.assessor import assess
from subdomainenum.reporter import to_dict

report = assess("example.com")
print(json.dumps(to_dict(report), indent=2))
```

Top-level schema:

| Key | Type | Notes |
|---|---|---|
| `domain` | string | Target base domain |
| `mode` | string | `"passive"`, `"active"`, or `"all"` |
| `subdomains[]` | array | `{fqdn, status, alive, ip_addresses, tools}` |
| `vhosts[]` | array | `{vhost, status_code, content_length}` |
| `tools[]` | array | `{name, count, available, error, timed_out, mode}` |

Each `tools[]` entry reflects the lifecycle of one tool run: `available=false` means the binary or API was missing; `timed_out=true` means the tool was killed by the wall-clock or idle-timeout watchdog (distinct from `error`); `error` is a string when the tool raised or reported an error, otherwise `null`.

---

## Docker

A Docker image with all tools pre-installed and SecLists (DNS + Web-Content
directories) bundled is available via the included `Dockerfile`.

```bash
# Build the image
docker compose build

# Passive check
docker compose run subdomainenum check example.com

# Active check with bundled SecLists wordlist
docker compose run subdomainenum check example.com \
  --mode active \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# All modes + vhost fuzzing, save report to host ./reports/
docker compose run subdomainenum check example.com \
  --mode all \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --url http://10.0.0.1 \
  --json \
  --output /reports/example.json

# Check available tools inside the container
docker compose run subdomainenum info
```

---

## Project Structure

```
subdomainenum/
├── subdomainenum/
│   ├── __init__.py              Package version
│   ├── models.py                Dataclasses: SubdomainResult, VhostResult,
│   │                              ToolResult, EnumReport + Status/EnumMode enums
│   ├── dns_utils.py             resolve_ips(), is_alive() — dnspython wrappers
│   │                              (A+AAAA queried in parallel on a shared pool)
│   ├── streaming.py             StreamingResolver — background DNS queue that
│   │                              overlaps resolution with enumeration
│   ├── constants.py             ACTIVE_TOOLS registry, detect_tools(), get_install_hint()
│   ├── assessor.py              assess() — orchestrates passive + active sources
│   ├── reporter.py              Rich terminal output + to_dict() + save_report()
│   ├── verdict.py               build_verdict() — factual count summary
│   ├── cli.py                   Typer CLI: check, info sub-commands
│   └── tools/
│       ├── tool_runner.py   subprocess wrapper used by all active tools
│       ├── subfinder.py     subfinder wrapper
│       ├── amass.py         amass enum wrapper (passive is amass's default;
│       │                      active no longer uses -brute -w — see gobuster)
│       ├── findomain.py     findomain wrapper
│       ├── assetfinder.py   assetfinder wrapper
│       ├── dnsrecon.py      dnsrecon passive (std,srv,snoop) and active
│       │                      (std,srv + AXFR + DNSSEC zone walk) wrapper
│       ├── gobuster_dns.py  gobuster dns wrapper (sole DNS brute-forcer)
│       └── ffuf.py          ffuf vhost fuzzing wrapper
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_verdict.py
│   ├── test_constants.py
│   ├── test_dns_utils.py
│   ├── test_assessor.py
│   ├── test_reporter.py
│   ├── test_cli.py
│   └── tools/
│       ├── test_tool_runner.py
│       └── test_wrappers.py
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## Running Tests

```bash
source .venv/bin/activate

# Run all tests with coverage (configured automatically via pyproject.toml)
pytest

# Quick run (short tracebacks)
pytest --tb=short -q

# Run a single module
pytest tests/test_assessor.py -v

# Run a single test class
pytest tests/test_cli.py::TestCheckCommand -v
```

The test suite has **382 tests** and achieves **99% coverage** across all modules.

All DNS I/O (`dns.resolver.Resolver.resolve`), TLS
sockets, and subprocess calls are mocked at the boundary — no test touches a real
server or the internet.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Add or update tests — the project targets 80%+ unit test coverage.
3. Run `pytest` and confirm all tests pass before opening a pull request.
4. Follow the existing docstring format (reStructuredText / docutils field lists).
5. Use [conventional commits](https://www.conventionalcommits.org/):
   `fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `chore:`

---

## License

GPLv3 — see [LICENSE](LICENSE) for details.
