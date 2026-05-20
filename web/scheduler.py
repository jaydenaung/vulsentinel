# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""APScheduler background job — periodic CVE scans."""

import logging
import threading

from apscheduler.schedulers.background import BackgroundScheduler

from web.db import get_setting
from web.scanner import run_scan

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_JOB_ID = "periodic_scan"


def _scan_job() -> None:
    log.info("Scheduler: starting periodic CVE scan")
    run_scan(triggered_by="scheduler")
    log.info("Scheduler: periodic scan complete")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    hours = _get_interval_hours()
    _scheduler.add_job(
        _scan_job,
        trigger="interval",
        hours=hours,
        id=_JOB_ID,
        replace_existing=True,
    )
    _scheduler.start()
    log.info(f"Scheduler started — scan every {hours}h")


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def reschedule(hours: int) -> None:
    if _scheduler and _scheduler.running:
        _scheduler.reschedule_job(_JOB_ID, trigger="interval", hours=hours)
        log.info(f"Scheduler rescheduled — scan every {hours}h")


def _get_interval_hours() -> int:
    try:
        return max(1, int(get_setting("scan_interval_hours", "24")))
    except ValueError:
        return 24
