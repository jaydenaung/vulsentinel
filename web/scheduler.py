# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""APScheduler background job — periodic CVE checks."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from web.daily import run_daily
from web.db import get_setting
from web.scanner import run_check

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_JOB_ID = "periodic_check"
_DAILY_JOB_ID = "daily_critical"


def _check_job() -> None:
    log.info("Scheduler: starting periodic CVE check")
    run_check(triggered_by="scheduler")
    log.info("Scheduler: periodic check complete")


def _daily_job() -> None:
    log.info("Scheduler: starting daily critical collection")
    run_daily(triggered_by="scheduler")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    hours = _get_interval_hours()
    _scheduler.add_job(
        _check_job,
        trigger="interval",
        hours=hours,
        id=_JOB_ID,
        replace_existing=True,
    )
    daily_hour = _get_daily_hour()
    _scheduler.add_job(
        _daily_job,
        trigger="cron",
        hour=daily_hour,
        minute=0,
        timezone="UTC",
        id=_DAILY_JOB_ID,
        replace_existing=True,
    )
    _scheduler.start()
    log.info(f"Scheduler started — check every {hours}h, daily criticals at {daily_hour:02d}:00 UTC")


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def reschedule(hours: int) -> None:
    if _scheduler and _scheduler.running:
        _scheduler.reschedule_job(_JOB_ID, trigger="interval", hours=hours)
        log.info(f"Scheduler rescheduled — check every {hours}h")


def _get_interval_hours() -> int:
    try:
        return max(1, int(get_setting("check_interval_hours", "24")))
    except ValueError:
        return 24


def _get_daily_hour() -> int:
    try:
        hour = int(get_setting("daily_run_hour_utc", "6"))
    except ValueError:
        return 6
    return hour if 0 <= hour <= 23 else 6
