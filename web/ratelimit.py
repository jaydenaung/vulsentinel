# Copyright 2026 Jayden Aung
# Licensed under the Apache License, Version 2.0
"""Login throttling. In memory, single process (one uvicorn worker), stdlib only.

Two counters over a sliding window:
  (username, ip)  small limit: stops guessing one account from one place.
  ip              larger limit: stops spraying many usernames from one place.
Keyed by the pair, not the username alone, so an attacker cannot lock the real
admin out from somewhere else. State resets on restart, which is acceptable here.
"""

import threading
import time
from collections import deque

from settings import get_settings

_lock = threading.Lock()
_failures: dict[str, deque[float]] = {}
MAX_KEYS = 10_000  # bound memory if someone sprays random usernames


def _keys(username: str, ip: str) -> tuple[str, str]:
    return f"user:{username.lower()}|{ip}", f"ip:{ip}"


def _recent(key: str, now: float, window: float) -> deque[float]:
    q = _failures.setdefault(key, deque())
    while q and now - q[0] > window:
        q.popleft()
    return q


def is_blocked(username: str, ip: str) -> bool:
    cfg = get_settings()
    now = time.monotonic()
    pair, by_ip = _keys(username, ip)
    with _lock:
        return (len(_recent(pair, now, cfg.login_window_seconds)) >= cfg.login_max_failures_per_user_ip
                or len(_recent(by_ip, now, cfg.login_window_seconds)) >= cfg.login_max_failures_per_ip)


def record_failure(username: str, ip: str) -> None:
    now = time.monotonic()
    with _lock:
        if len(_failures) > MAX_KEYS:
            window = get_settings().login_window_seconds
            for key in [k for k, q in _failures.items() if not q or now - q[-1] > window]:
                del _failures[key]
        for key in _keys(username, ip):
            _failures.setdefault(key, deque()).append(now)


def record_success(username: str, ip: str) -> None:
    with _lock:
        _failures.pop(_keys(username, ip)[0], None)


def reset() -> None:
    """For tests."""
    with _lock:
        _failures.clear()
