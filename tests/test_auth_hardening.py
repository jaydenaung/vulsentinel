"""Login throttling and session revocation."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import web.db as db_mod
from tests.test_web_security import ADMIN, add_viewer, login, setup_admin, token
from web import ratelimit
from web.app import create_app
from web.auth import SESSION_COOKIE, _serializer


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "auth.db"))
    db_mod.init_db()
    return TestClient(create_app(start_background=False), follow_redirects=False)


def bad_login(client: TestClient, username: str = "admin") -> int:
    return client.post("/login", data={"username": username, "password": "wrong-password",
                                       "csrf_token": token(client, "/login")}).status_code


def test_repeated_failures_lock_out_even_the_right_password(client: TestClient) -> None:
    setup_admin(client)
    assert [bad_login(client) for _ in range(5)] == [401] * 5
    resp = client.post("/login", data={"username": "admin", "password": ADMIN["password"],
                                       "csrf_token": token(client, "/login")})
    assert resp.status_code == 429 and "Too many failed attempts" in resp.text


def test_success_clears_the_counter(client: TestClient) -> None:
    setup_admin(client)
    for _ in range(4):
        bad_login(client)
    login(client)
    assert [bad_login(client) for _ in range(4)] == [401] * 4  # counter started again


def test_spraying_usernames_from_one_ip_is_throttled(client: TestClient) -> None:
    setup_admin(client)
    codes = [bad_login(client, f"user{i}") for i in range(21)]
    assert codes[:20] == [401] * 20 and codes[20] == 429


def test_lockout_is_per_ip_so_admin_elsewhere_is_unaffected() -> None:
    for _ in range(5):
        ratelimit.record_failure("admin", "203.0.113.9")
    assert ratelimit.is_blocked("admin", "203.0.113.9")
    assert not ratelimit.is_blocked("admin", "198.51.100.1")


def _stolen_cookie(client: TestClient) -> str:
    cookie = client.cookies.get(SESSION_COOKIE)
    assert cookie
    return cookie


def _get_with(cookie: str, client: TestClient, path: str = "/critical") -> int:
    other = TestClient(client.app, follow_redirects=False)
    other.cookies.set(SESSION_COOKIE, cookie)
    return other.get(path).status_code


def test_admin_password_reset_revokes_existing_sessions(client: TestClient) -> None:
    setup_admin(client)
    add_viewer(client)
    viewer = TestClient(client.app, follow_redirects=False)
    login(viewer, "viewer", "viewer-pass-1")
    stolen = _stolen_cookie(viewer)
    assert _get_with(stolen, client) == 200

    login(client)
    with db_mod.get_db() as conn:
        viewer_id = conn.execute("SELECT id FROM users WHERE username = 'viewer'").fetchone()[0]
    resp = client.post(f"/users/{viewer_id}/reset-password",
                       data={"new_password": "new-viewer-pass-2", "csrf_token": token(client, "/users")})
    assert resp.status_code == 303
    assert _get_with(stolen, client) == 303  # old cookie now redirects to login


def test_logout_revokes_a_copied_cookie(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    stolen = _stolen_cookie(client)
    client.post("/logout", data={"csrf_token": token(client, "/critical")})
    assert _get_with(stolen, client) == 303


def test_old_style_cookie_without_version_is_rejected(client: TestClient) -> None:
    setup_admin(client)
    legacy = _serializer().dumps(1)  # pre-fix format: bare user id
    assert _get_with(legacy, client) == 303


def test_cli_reset_revokes_sessions(client: TestClient) -> None:
    import agent
    setup_admin(client)
    login(client)
    stolen = _stolen_cookie(client)
    answers = iter(["brand-new-pass-9", "brand-new-pass-9"])
    assert agent.reset_password("admin", prompt=lambda _msg: next(answers)) == 0
    assert _get_with(stolen, client) == 303
