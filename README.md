# CVE Triage Agent

An AI security agent for cloud-native and telco/5G environments. It fetches the latest CVEs from the NVD API, autonomously enriches each one using real-world exploitation intelligence, and produces a prioritised Markdown patch advisory report.

## How it works

Unlike a simple scoring script, the agent runs a **multi-turn agentic loop**: Claude receives a CVE, decides which tools to call, executes them, and reasons over the combined evidence before issuing a recommendation. A CVE that looks like `MONITOR` based on CVSS alone will be escalated to `PATCH NOW` if it appears in the CISA KEV catalog or has a high exploitation probability.

```
NVD API ──► fetcher.py ──► scorer.py (agentic loop) ──► reporter.py ──► report
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

- Fetches CVEs from [NVD API v2](https://services.nvd.nist.gov/rest/json/cves/2.0) — no API key required
- **Agentic tool-use loop** — Claude autonomously calls tools to enrich analysis before scoring
- **CISA KEV cross-reference** — confirmed exploitation in the wild overrides CVSS-based scoring
- **EPSS scores** — exploitation probability from [FIRST.org](https://www.first.org/epss/) as a second signal
- Environment-specific exposure scoring (not just raw CVSS)
- Telco/CNF relevance assessment for 5G/cloud-native stacks
- Findings grouped by action: **PATCH NOW**, **MONITOR**, **LOW PRIORITY**
- Respects NVD rate limits (5 req/30s without API key)
- `--dry-run` mode for testing the fetch pipeline without calling Claude

## Prerequisites

- Python 3.11+
- `ANTHROPIC_API_KEY` environment variable set

## Setup

```bash
cd cve-triage-agent

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

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

Reports are written to `reports/YYYY-MM-DD.md`.

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

Customise `products` and `environment_context` to match your stack.

## Report Format

Each report (`reports/YYYY-MM-DD.md`) contains:

1. **Header** — date, products scanned, total CVEs found
2. **Summary table** — counts per action category
3. **Findings** — grouped by PATCH NOW → MONITOR → LOW PRIORITY, sorted by CVSS descending

Each finding includes:

| Field | Description |
|-------|-------------|
| CVE ID | Linked to NVD |
| Product | Matched product keyword |
| Published | NVD publish date |
| CVSS Score | Base score (v3.1/v3.0/v2) |
| Exposure Score | Claude's 1–10 score for your environment |
| Telco/CNF Relevance | HIGH / MEDIUM / LOW |
| Recommended Action | PATCH NOW / MONITOR / LOW PRIORITY |
| Reason | Claude's rationale — cites KEV/EPSS findings when they drove the decision |

## Architecture

```
agent.py          Orchestrates the full pipeline
fetcher.py        NVD API v2 client — keyword search + rate limiting
scorer.py         Agentic scoring loop — Claude + CISA KEV + EPSS tool use
reporter.py       Markdown report builder
config.yaml       Product watchlist + environment context
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

Tools available to Claude:

| Tool | Source | Signal |
|------|--------|--------|
| `check_cisa_kev` | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed real-world exploitation |
| `check_epss` | [FIRST.org EPSS API](https://www.first.org/epss/) | Probability of exploitation within 30 days |

The KEV catalog is fetched once and cached in-process for one hour to avoid redundant network calls across CVEs in the same run.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (even if no CVEs found) |
| 1 | Fetch failure or missing API key |
