---
name: project-web-interface
description: CVE Triage Agent web dashboard — architecture decisions and current state
metadata:
  type: project
---

Web interface added in May 2026. FastAPI + Jinja2 + SQLite, runs locally on internal network.

**Why:** User wanted dashboard visibility into CVEs by asset/product, multi-user accounts, and persistent storage instead of one-off markdown reports.

**How to apply:** The web server is now the primary interface. CLI still works for one-off scans.

Key decisions:
- FastAPI + Jinja2 (no JS build step, Starlette 1.0.0 — TemplateResponse takes `request` as first arg, not in context dict)
- SQLite with WAL mode (single file, no separate DB service needed for internal use)
- `bcrypt` directly (passlib has compatibility issues with bcrypt>=5.0.0)
- Session auth via itsdangerous signed cookies (7-day TTL)
- APScheduler background thread for periodic scans
- First-run wizard at /setup (redirects there until first admin account created)

**Start server:** `python agent.py --serve` (default port 8000)
**CLI scan still works:** `python agent.py --days 7`

**Roles:** admin (full access), viewer (read-only). Admins can: add/remove assets, add/remove users, trigger scans, update CVE status/notes.

**CVE status lifecycle:** open → accepted | in_remediation | mitigated (set per CVE, preserved across re-scans).

**Settings stored in DB:** scan_interval_hours, scan_days_lookback, max_cves_per_asset, nvd_rate_limit_delay, env_context (the Claude AI prompt context).
