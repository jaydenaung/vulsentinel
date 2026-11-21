# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Jayden Aung
"""VulSentinel by Jayden Aung — main entry point.

Usage:
    python agent.py                  # check last 7 days (live AI scoring)
    python agent.py --days 14        # check last 14 days
    python agent.py --dry-run        # fetch CVEs only, skip Claude scoring
    python agent.py --serve          # start the web dashboard server
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
from scorer import build_client, score_cve
from settings import ConfigError, load_dotenv


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
        "--reset-password",
        metavar="USERNAME",
        help="Set a new password for a web user (prompts, input hidden).",
    )
    return parser.parse_args()


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
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_password(password), username))
    print(f"Password updated for {username}.")
    return 0


def main() -> int:
    args = parse_args()
    load_dotenv()

    if args.reset_password:
        return reset_password(args.reset_password.strip())

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

    # ── Score CVEs with Claude ───────────────────────────────────────────────
    findings: list[dict] = []
    if args.dry_run or not all_summaries:
        for s in all_summaries:
            s.update({
                "exposure_score": None,
                "telco_cnf_relevance": "N/A",
                "recommended_action": "MONITOR",
                "reason": "(dry run — scoring skipped)",
            })
        findings = all_summaries
    else:
        if client is None:  # unreachable: client is built whenever not dry_run
            print("ERROR: Claude client not initialised", file=sys.stderr)
            return 1
        print("\nScoring CVEs with Claude AI...")
        for i, summary in enumerate(all_summaries, 1):
            cve_id = summary["cve_id"]
            print(f"  [{i}/{len(all_summaries)}] {cve_id} ({summary['product']}) ...", end=" ", flush=True)
            score = score_cve(client, summary, env_context)
            merged = {**summary, **score}
            findings.append(merged)
            print(merged["recommended_action"])

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
