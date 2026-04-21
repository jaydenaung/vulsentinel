# CVE Triage Agent

An AI-powered CVE triage pipeline for cloud-native and telco/5G security environments. It fetches the latest CVEs from the NVD API, scores each one for your specific environment using Claude AI, and produces a prioritised Markdown patch advisory report.

## Features

- Fetches CVEs from [NVD API v2](https://services.nvd.nist.gov/rest/json/cves/2.0) — no API key required
- Scores each CVE with Claude AI for environment-specific exposure (not just raw CVSS)
- Factors in telco/CNF relevance and patch availability
- Groups findings by recommended action: **PATCH NOW**, **MONITOR**, **LOW PRIORITY**
- Respects NVD rate limits (5 req/30s without key)
- `--dry-run` mode for testing the fetch pipeline without calling Claude

## Prerequisites

- Python 3.11+
- `ANTHROPIC_API_KEY` environment variable set

## Setup

```bash
# Clone / enter the project directory
cd cve-triage-agent

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Scan last 7 days (default), full AI scoring
python agent.py

# Scan last 14 days
python agent.py --days 14

# Dry run — fetch only, no Claude calls
python agent.py --dry-run

# Dry run with custom window
python agent.py --dry-run --days 3

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
    <Describe your environment here — this is what Claude uses to score exposure>
```

Customise `products` and `environment_context` to match your stack.

## Report Format

Each report (`reports/YYYY-MM-DD.md`) contains:

1. **Header** — date, products scanned, total CVEs found
2. **Summary table** — counts per action category
3. **Findings** — grouped by PATCH NOW → MONITOR → LOW PRIORITY, sorted by CVSS descending

Each finding shows:

| Field | Description |
|-------|-------------|
| CVE ID | Linked to NVD |
| Product | Matched product keyword |
| Published | NVD publish date |
| CVSS Score | Base score (v3.1/v3.0/v2) |
| Exposure Score | Claude's 1–10 score for your environment |
| Telco/CNF Relevance | HIGH / MEDIUM / LOW |
| Recommended Action | PATCH NOW / MONITOR / LOW PRIORITY |
| Reason | One-line Claude rationale |

## Architecture

```
agent.py          Orchestrates the full pipeline
fetcher.py        NVD API v2 client — keyword search + rate limiting
scorer.py         Claude AI scoring — contextual risk analysis
reporter.py       Markdown report builder
config.yaml       Product watchlist + environment context
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (even if no CVEs found) |
| 1 | Fetch failure or missing API key |
