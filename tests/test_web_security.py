"""Web security tests: CSRF, headers, authz, input validation, flash allowlist, cookies."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import settings as settings_mod
import web.auth as auth_mod
import web.db as db_mod
from web.app import create_app

TOKEN_RE = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')
ADMIN = {"username": "admin", "email": "admin@example.com", "password": "correct-horse-1"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "web.db"))
    db_mod.init_db()
    return TestClient(create_app(start_background=False), follow_redirects=False)


def token(client: TestClient, path: str) -> str:
    match = TOKEN_RE.search(client.get(path).text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def setup_admin(client: TestClient) -> None:
    resp = client.post("/setup", data={**ADMIN, "csrf_token": token(client, "/setup")})
    assert resp.status_code == 303


def login(client: TestClient, username: str = ADMIN["username"], password: str = ADMIN["password"]) -> None:
    resp = client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": token(client, "/login")})
    assert resp.status_code == 303, resp.text


def add_viewer(client: TestClient) -> None:
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'viewer')",
                     ("viewer", "v@example.com", auth_mod.hash_password("viewer-pass-1")))


# ── Config ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("secret", [None, "too-short"])
def test_app_refuses_to_start_without_strong_secret(monkeypatch: pytest.MonkeyPatch, secret: str | None) -> None:
    if secret is None:
        monkeypatch.delenv("CVE_SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("CVE_SECRET_KEY", secret)
    settings_mod.get_settings.cache_clear()
    try:
        with pytest.raises(settings_mod.ConfigError):
            create_app(start_background=False)
    finally:
        monkeypatch.undo()
        settings_mod.get_settings.cache_clear()


def test_dotenv_loader_does_not_override_existing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('# comment\nVS_TEST_A="from-file"\nexport VS_TEST_B=b\nVS_TEST_C=file\n')
    monkeypatch.setenv("VS_TEST_C", "already-set")
    monkeypatch.delenv("VS_TEST_A", raising=False)
    monkeypatch.delenv("VS_TEST_B", raising=False)
    settings_mod.load_dotenv(env_file)
    import os
    got = (os.environ["VS_TEST_A"], os.environ["VS_TEST_B"], os.environ["VS_TEST_C"])
    assert got == ("from-file", "b", "already-set")


# ── CSRF ──────────────────────────────────────────────────────────────────────

def test_post_without_csrf_token_is_rejected(client: TestClient) -> None:
    setup_admin(client)
    resp = client.post("/login", data={"username": "admin", "password": ADMIN["password"]})
    assert resp.status_code == 403


def test_csrf_token_bound_to_browser_seed(client: TestClient) -> None:
    setup_admin(client)
    stolen = token(client, "/login")
    attacker = TestClient(client.app, follow_redirects=False)
    attacker.get("/login")  # attacker has their own seed cookie
    resp = attacker.post("/login", data={"username": "admin", "password": ADMIN["password"], "csrf_token": stolen})
    assert resp.status_code == 403


def test_logout_requires_post(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    assert client.get("/logout").status_code == 405
    resp = client.post("/logout", data={"csrf_token": token(client, "/dashboard")})
    assert resp.status_code == 303
    assert client.get("/dashboard").headers["location"] == "/login"


# ── Headers and cookies ───────────────────────────────────────────────────────

def test_security_headers_present(client: TestClient) -> None:
    setup_admin(client)
    headers = client.get("/login").headers
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "script-src 'self' https://cdn.jsdelivr.net" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"


def test_cookies_httponly_and_secure_auto_on_http(client: TestClient) -> None:
    setup_admin(client)
    tok = token(client, "/login")
    resp = client.post("/login", data={"username": "admin", "password": ADMIN["password"], "csrf_token": tok})
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert "secure" not in cookie  # plain http in auto mode


def test_secure_flag_forced_on(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CVE_COOKIE_SECURE", "true")
    settings_mod.get_settings.cache_clear()
    try:
        # Only inspect Set-Cookie: a compliant client will not send a Secure cookie back over http.
        resp = client.get("/setup")
        assert "; secure" in resp.headers.get("set-cookie", "").lower()
    finally:
        monkeypatch.undo()
        settings_mod.get_settings.cache_clear()


# ── AuthZ ─────────────────────────────────────────────────────────────────────

def test_viewer_cannot_add_product_or_users(client: TestClient) -> None:
    setup_admin(client)
    add_viewer(client)
    login(client, "viewer", "viewer-pass-1")
    tok = token(client, "/products")
    client.post("/products/add", data={"name": "Evil", "keyword": "evil", "csrf_token": tok})
    client.post("/users/add", data={"username": "x1x", "email": "x@example.com", "password": "password123",
                                    "role": "admin", "csrf_token": tok})
    with db_mod.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    assert client.get("/settings").headers["location"] == "/dashboard"


def test_login_failure_is_generic(client: TestClient) -> None:
    setup_admin(client)
    tok = token(client, "/login")
    unknown = client.post("/login", data={"username": "nobody", "password": "x", "csrf_token": tok})
    wrong = client.post("/login", data={"username": "admin", "password": "wrong-password", "csrf_token": tok})
    assert unknown.status_code == wrong.status_code == 401
    assert "Invalid username or password." in unknown.text and "Invalid username or password." in wrong.text


# ── Input validation and output ───────────────────────────────────────────────

def test_bad_query_params_do_not_500(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    resp = client.get("/cves", params={"page": "abc", "product_id": "x", "action": "DROP", "status": "'; --"})
    assert resp.status_code == 200


def test_invalid_settings_rejected(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    tok = token(client, "/settings")
    resp = client.post("/settings", data={"check_interval_hours": "0", "check_days_lookback": "500",
                                          "max_cves_per_product": "50", "nvd_rate_limit_delay": "6.5",
                                          "csrf_token": tok})
    assert resp.headers["location"] == "/settings?error=Invalid+settings+value"
    assert db_mod.get_setting("check_days_lookback") == "7"


def test_flash_messages_are_allowlisted(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    phish = client.get("/dashboard", params={"msg": "Session expired, call +1-555-0100"}).text
    assert "call +1-555-0100" not in phish
    assert "Settings saved" in client.get("/dashboard", params={"msg": "Settings saved"}).text


def test_product_name_not_injected_into_script(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    evil = "x');alert(1);('"
    client.post("/products/add", data={"name": evil, "keyword": "evil", "csrf_token": token(client, "/products")})
    html = client.get("/products").text
    assert "onsubmit" not in html
    assert "alert(1)" not in html or "&#39;" in html


def test_add_product_db_error_is_generic(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    setup_admin(client)
    login(client)
    tok = token(client, "/products")
    with db_mod.get_db() as conn:
        conn.execute("DROP TABLE cves")
        conn.execute("DROP TABLE products")
    resp = client.post("/products/add", data={"name": "Nginx", "keyword": "nginx", "csrf_token": tok})
    assert resp.headers["location"] == "/products?error=Could+not+add+product"


def test_news_widget_escapes_feed_text_and_isolates_links(client: TestClient) -> None:
    setup_admin(client)
    login(client)
    with db_mod.get_db() as conn:
        feed_id = conn.execute("SELECT id FROM feeds").fetchone()[0]
        conn.execute(
            "INSERT INTO articles (feed_id, guid, url, title, summary, cve_ids) VALUES (?, 'g1', ?, ?, ?, ?)",
            (feed_id, "https://research.example.com/p", "<script>alert(1)</script> PHP2Shell",
             "<img src=x onerror=alert(2)>", '["CVE-2026-109618"]'),
        )
    html = client.get("/dashboard").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert 'href="https://research.example.com/p" target="_blank" rel="noopener noreferrer"' in html
    assert "CVE-2026-109618" in html
