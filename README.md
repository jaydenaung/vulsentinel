# VulSentinel

AI-powered CVE triage agent for cloud-native and telco/5G environments. VulSentinel fetches the latest CVEs from the NVD, autonomously enriches each one with real-world exploitation intelligence, and surfaces a prioritised patch advisory — via a web dashboard or CLI report.

> Part of the Sentinel agent family alongside **KubeSentinel** (K8s misconfiguration + container image CVEs).

## How it works

VulSentinel runs a **multi-turn agentic loop**: Claude receives a CVE, decides which tools to call, executes them, and reasons over the combined evidence before issuing a recommendation. A CVE that looks like `MONITOR` based on CVSS alone will be escalated to `PATCH NOW` if it appears in the CISA KEV catalog or has a high exploitation probability.

```
NVD API ──► fetcher.py ──► scorer.py (agentic loop) ──► reporter.py / web dashboard
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
             CISA KEV catalog          EPSS API
          (known exploited CVEs)  (exploitation probability)
```

**Tool use rules Claude follows:**
1. Always call `check_cisa_kev` for CVSS ≥ 7.0 — a KEV hit immediately escalates to `PATCH NOW`
2. Call `check_epss` when CVSS ≥ 6.0 and KEV status alone is ambiguous
3. Skip tools for low-CVSS CVEs where additional data would not change `LOW PRIORITY`

## Features

- **Web dashboard** — multi-user visibility into CVEs by asset, severity, and triage status
- **Asset inventory** — define the products/systems you track via UI or `config.yaml`
- **Scheduled scans** — configurable background scanning (default: every 24h)
- **CVE triage workflow** — mark CVEs as open / accepted / in remediation / mitigated
- Fetches CVEs from [NVD API v2](https://services.nvd.nist.gov/rest/json/cves/2.0) — no API key required
- **Agentic tool-use loop** — Claude autonomously calls tools to enrich analysis before scoring
- **CISA KEV cross-reference** — confirmed exploitation in the wild overrides CVSS-based scoring
- **EPSS scores** — exploitation probability from [FIRST.org](https://www.first.org/epss/) as a second signal
- Environment-specific exposure scoring (not just raw CVSS)
- Findings grouped by action: **PATCH NOW**, **MONITOR**, **LOW PRIORITY**

## Prerequisites

- Python 3.11+
- `ANTHROPIC_API_KEY` or `CLAUDEAPI` environment variable set

## Setup

```bash
git clone https://github.com/jaydenaung/cve-triage-ai-agent.git
cd cve-triage-ai-agent

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

### Web Dashboard (primary)

```bash
python agent.py --serve              # http://0.0.0.0:8000
python agent.py --serve --port 8001  # custom port
python agent.py --serve --host 127.0.0.1 --port 8001
```

On first visit, the setup wizard creates your admin account and optionally imports assets from `config.yaml`.

### CLI (one-off scan)

```bash
# Scan last 7 days (default), full agentic scoring
python agent.py

# Scan last 14 days
python agent.py --days 14

# Dry run — fetch only, no Claude or external tool calls
python agent.py --dry-run

# Custom config file
python agent.py --config /path/to/config.yaml
```

CLI reports are written to `reports/YYYY-MM-DD.md`.

## Configuration (`config.yaml`)

```yaml
products:
  - kubernetes
  - nginx
  - containerd
  - linux kernel
  - openssl
  - istio

settings:
  default_days: 7
  nvd_rate_limit_delay: 6.5   # seconds between NVD requests
  max_cves_per_product: 50
  reports_dir: reports

scoring:
  environment_context: |
    <Describe your environment here — Claude uses this to assess exposure>
```

Assets and environment context can also be managed via the web UI (Settings page).

## Architecture

```
agent.py          Entry point — CLI scan or web server (--serve)
fetcher.py        NVD API v2 client — keyword search + rate limiting
scorer.py         Agentic scoring loop — Claude + CISA KEV + EPSS tool use
reporter.py       Markdown report builder (CLI mode)
config.yaml       Product watchlist + environment context
web/
  app.py          FastAPI application factory
  db.py           SQLite schema + query helpers
  auth.py         Session auth (bcrypt + signed cookies)
  scanner.py      Scan orchestrator — wraps fetcher + scorer, persists to DB
  scheduler.py    APScheduler background periodic scans
  routes/         Page and API route handlers
  templates/      Jinja2 HTML templates
  static/         CSS
```

### Agentic scoring loop (`scorer.py`)

```
user prompt (CVE details)
        │
        ▼
   Claude (tool_use) ──► execute tool ──► tool_result
        │                                      │
        └──────────────────────────────────────┘
                    (repeat until end_turn)
        │
        ▼
   final JSON recommendation
```

| Tool | Source | Signal |
|------|--------|--------|
| `check_cisa_kev` | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed real-world exploitation |
| `check_epss` | [FIRST.org EPSS API](https://www.first.org/epss/) | Probability of exploitation within 30 days |

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| 0 | Success (even if no CVEs found) |
| 1 | Fetch failure or missing API key |
