# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""VulSentinel by Jayden Aung — main entry point.

Usage:
    python agent.py                  # check last 7 days (live AI scoring)
    python agent.py --days 14        # check last 14 days
    python agent.py --dry-run        # fetch + rules only, skip Claude
    python agent.py --serve          # start the web dashboard server
    python agent.py --daily          # collect today's critical CVEs (no AI)
    python agent.py --serve --port 9000 --host 127.0.0.1
    python agent.py --reset-password admin   # prompts for a new password (hidden input)
"""

import argparse
import getpass
import sys
from datetime import date

import yaml

from fetcher import fetch_cves, format_cve_summary
from reporter import generate_report, write_report
from scorer import build_client
from settings import ConfigError, load_dotenv
from triage import triage


def load_config(path: str = "config.yaml") -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VulSentinel — AI-powered CVE triage for cloud-native / telco environments."
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the web dashboard server instead of running a one-off check.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the web server to (default: 127.0.0.1; use 0.0.0.0 to expose on the network).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the web server to (default: 8000).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Look-back window in days (default: from config.yaml, usually 7).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch CVEs but skip Claude AI scoring.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml).",
    )
    parser.add_argument(
        "--news-sweep",
        action="store_true",
        help="Fetch enabled research/news feeds and store new articles, then exit.",
    )
    parser.add_argument(
        "--daily",
        action="store_true",
        help="Collect today's critical CVEs (CVSS 9+, new KEV, EPSS crossers) into the web DB, then exit.",
    )
    parser.add_argument(
        "--reset-password",
        metavar="USERNAME",
        help="Set a new password for a web user (prompts, input hidden).",
    )
    return parser.parse_args()


def news_sweep() -> int:
    """Run one news sweep and print a per-feed summary. Exit 1 if every feed failed."""
    import logging

    from web.db import init_db
    from web.news_sweep import run_news_sweep

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    init_db()
    results = run_news_sweep()
    for r in results:
        status = f"{r['parsed']} parsed, {r['new']} new" if r["ok"] else f"FAILED ({r['error']})"
        print(f"  {r['feed']}: {status}")
    return 0 if any(r["ok"] for r in results) or not results else 1


def daily(days: int | None) -> int:
    """Run one daily critical collection and print the counts. No AI."""
    import logging

    from web.daily import run_daily
    from web.db import get_db, init_db

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    init_db()
    run_id = run_daily(triggered_by="cli", days=days)
    if run_id is None:
        print("A daily run is already in progress.", file=sys.stderr)
        return 1
    with get_db() as conn:
        run = dict(conn.execute("SELECT * FROM daily_runs WHERE id = ?", (run_id,)).fetchone())
    print(f"Daily run {run_id}: {run['status']}")
    for key in ("nvd_fetched", "critical_new", "critical_updated", "kev_new", "epss_crossers", "watchlist_hits"):
        print(f"  {key:17} {run[key]}")
    return 0 if run["status"] == "completed" else 1


def reset_password(username: str, prompt=getpass.getpass) -> int:
    """Reset a web user's password from the terminal. Never echoes or logs the password."""
    from web.auth import hash_password, password_problem
    from web.db import get_db, init_db

    init_db()
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if not exists:
        print(f"ERROR: no user named {username!r}", file=sys.stderr)
        return 1

    password = prompt(f"New password for {username}: ")
    if password != prompt("Repeat new password: "):
        print("ERROR: passwords do not match", file=sys.stderr)
        return 1
    problem = password_problem(password)
    if problem:
        print(f"ERROR: {problem}", file=sys.stderr)
        return 1

    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE username = ?",
            (hash_password(password), username),
        )
    print(f"Password updated for {username}. Their existing sessions are signed out.")
    return 0


def main() -> int:
    args = parse_args()
    load_dotenv()

    if args.reset_password:
        return reset_password(args.reset_password.strip())

    if args.news_sweep:
        return news_sweep()

    if args.daily:
        return daily(args.days)

    # ── Web server mode ──────────────────────────────────────────────────────
    if args.serve:
        import logging

        import uvicorn

        from web.app import create_app
        logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
        try:
            app = create_app()
        except ConfigError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(f"VulSentinel: starting web server on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True)
        return 0

    # ── Load config ──────────────────────────────────────────────────────────
    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        return 1

    products: list[str] = cfg.get("products", [])
    settings: dict = cfg.get("settings", {})
    scoring_cfg: dict = cfg.get("scoring", {})

    days: int = args.days or settings.get("default_days", 7)
    rate_delay: float = settings.get("nvd_rate_limit_delay", 6.5)
    max_per_product: int = settings.get("max_cves_per_product", 50)
    reports_dir: str = settings.get("reports_dir", "reports")
    env_context: str = scoring_cfg.get("environment_context", "")

    print(f"VulSentinel — checking last {days} day(s)")
    print(f"Products: {', '.join(products)}")
    if args.dry_run:
        print("Mode: DRY RUN (no AI scoring)")
    print()

    # ── Initialise Claude client (unless dry-run) ────────────────────────────
    client = None
    if not args.dry_run:
        try:
            client = build_client()
        except OSError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    # ── Fetch CVEs ───────────────────────────────────────────────────────────
    all_summaries: list[dict] = []
    for product in products:
        print(f"Fetching CVEs for: {product} ...", end=" ", flush=True)
        try:
            raw_cves = fetch_cves(
                product,
                days=days,
                rate_limit_delay=rate_delay,
                max_results=max_per_product,
            )
        except Exception as exc:
            print(f"FAILED — {exc}", file=sys.stderr)
            return 1

        summaries = [format_cve_summary(c, product) for c in raw_cves]
        print(f"{len(summaries)} CVE(s) found")
        all_summaries.extend(summaries)

    print(f"\nTotal CVEs fetched: {len(all_summaries)}")

    # ── Triage: rules first, Claude only for the gray zone ────────────────────
    if args.dry_run:
        print("\nTriage (rules only, AI skipped)...")
    else:
        print("\nTriage: rules first, Claude only for CVEs rules cannot decide...")
    decisions, _evidence, stats = triage(all_summaries, env_context, client)
    findings: list[dict] = []
    for s in all_summaries:
        d = decisions.get(s["cve_id"])
        findings.append({**s, **d.model_dump(exclude={"cve_id", "input_hash"})} if d else s)
    print(f"  Decided by rules: {stats.rule_decided}")
    print(f"  Decided by AI:    {stats.ai_decided} (fallback {stats.fallback})")
    cost = "unknown model price" if stats.cost_usd is None else f"~${stats.cost_usd:.4f}"
    print(f"  AI usage:         {stats.usage.calls} call(s), {stats.usage.input_tokens} in / "
          f"{stats.usage.output_tokens} out tokens, {cost}")

    # ── Generate report ──────────────────────────────────────────────────────
    print("\nGenerating report...")
    today = date.today()
    report_md = generate_report(
        findings=findings,
        products=products,
        days=days,
        run_date=today,
        dry_run=args.dry_run,
    )

    report_path = write_report(report_md, reports_dir=reports_dir, run_date=today)
    print(f"Report written to: {report_path}")

    # Print summary counts
    from collections import Counter
    counts = Counter(f.get("recommended_action", "MONITOR") for f in findings)
    print(f"\n{'='*50}")
    print(f"  PATCH NOW:    {counts.get('PATCH NOW', 0)}")
    print(f"  MONITOR:      {counts.get('MONITOR', 0)}")
    print(f"  LOW PRIORITY: {counts.get('LOW PRIORITY', 0)}")
    print(f"{'='*50}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
