"""CLI tests: --reset-password."""

from pathlib import Path

import pytest

import agent
import web.auth as auth_mod
import web.db as db_mod


@pytest.fixture()
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "cli.db"))
    db_mod.init_db()
    with db_mod.get_db() as conn:
        conn.execute("INSERT INTO users (username, email, password_hash, role) VALUES ('admin', 'a@x.io', ?, 'admin')",
                     (auth_mod.hash_password("old-password-1"),))


def stored_hash() -> str:
    with db_mod.get_db() as conn:
        return conn.execute("SELECT password_hash FROM users WHERE username = 'admin'").fetchone()[0]


def prompts(*answers: str):
    it = iter(answers)
    return lambda _msg: next(it)


def test_reset_password_updates_hash(db, capsys: pytest.CaptureFixture[str]) -> None:
    assert agent.reset_password("admin", prompt=prompts("new-password-1", "new-password-1")) == 0
    assert auth_mod.verify_password("new-password-1", stored_hash())
    assert "new-password-1" not in capsys.readouterr().out


@pytest.mark.parametrize("answers", [("new-password-1", "different-1"), ("short", "short")])
def test_reset_password_rejects_mismatch_and_weak(db, answers: tuple[str, str]) -> None:
    before = stored_hash()
    assert agent.reset_password("admin", prompt=prompts(*answers)) == 1
    assert stored_hash() == before


def test_reset_password_unknown_user(db) -> None:
    assert agent.reset_password("ghost", prompt=prompts("x", "x")) == 1
