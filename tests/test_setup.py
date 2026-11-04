"""`bbv setup`: config status + interactive fixes. Secrets go only to .env,
masked in status, never printed in full."""
import os
import stat

import pytest

import bbv.cli as cli
from bbv import setup as st
from bbv.config import Settings


def test_mask_never_reveals_full_secret():
    assert st.mask("sk-ant-SECRET1234") == "set (****1234)"
    assert st.mask("") == "not set"
    assert st.mask("ab") == "set"               # too short to show last 4
    assert "SECRET" not in st.mask("sk-ant-SECRET1234")


def test_set_env_var_creates_updates_and_preserves(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# header\nBBV_DB_PATH=data/x.db\nOTHER=keep\n")

    st.set_env_var("BBV_ANTHROPIC_API_KEY", "sk-123", str(env))
    st.set_env_var("BBV_DB_PATH", "data/y.db", str(env))      # update existing

    text = env.read_text()
    assert "BBV_ANTHROPIC_API_KEY=sk-123" in text
    assert "BBV_DB_PATH=data/y.db" in text and "data/x.db" not in text
    assert "# header" in text and "OTHER=keep" in text       # preserved
    # mode 0600 on POSIX
    if os.name == "posix":
        assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_status_masks_key_and_shows_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "_chromium_status", lambda: (True, "installed"))
    s = Settings(_env_file=None, llm_provider="anthropic",
                 anthropic_api_key="sk-ant-TOPSECRET9999")
    items = st.gather_status(s, env_path=str(tmp_path / ".env"))
    by_label = {i.label.strip(): i for i in items}

    assert by_label["LLM provider"].value == "anthropic (BBV_ANTHROPIC_API_KEY set)"
    assert by_label["LLM provider"].ok is True
    # The full secret never appears anywhere in the rendered status.
    assert "TOPSECRET9999" not in st.render_status(items)
    assert by_label["Anthropic API key"].value == "set (****9999)"


def test_status_flags_self_hosted_missing_base_url(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "_chromium_status", lambda: (True, "installed"))
    s = Settings(_env_file=None, llm_provider="self_hosted")
    by_label = {i.label.strip(): i for i in st.gather_status(s, str(tmp_path / ".env"))}
    assert by_label["LLM provider"].ok is False
    assert "BBV_OPENAI_BASE_URL not set" in by_label["LLM provider"].value


def test_check_cli_is_noninteractive_and_exits_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(st, "_chromium_status", lambda: (True, "installed"))
    s = Settings(_env_file=None)
    s.db_path = str(tmp_path / "bbv.db")
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    rc = cli.main(["setup", "--check"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Configuration status" in out and "LLM provider" in out


def test_interactive_choose_openai_provider_writes_env(tmp_path, monkeypatch):
    env = str(tmp_path / ".env")
    monkeypatch.setattr(st, "_chromium_status", lambda: (True, "installed"))

    # Script the menu: choose provider -> option 2 (openai) -> key -> quit.
    inputs = iter(["1", "2", "0"])          # action 1, provider 2 (openai), then quit
    secrets = iter(["sk-openai-ABCD"])      # the hidden API key

    def fake_loader():
        return Settings(_env_file=env)

    st.run_setup(env_path=env, loader=fake_loader,
                 inp=lambda prompt: next(inputs),
                 secret=lambda prompt: next(secrets),
                 out=lambda *_: None)

    text = (tmp_path / ".env").read_text()
    assert "BBV_LLM_PROVIDER=openai" in text
    assert "BBV_OPENAI_API_KEY=sk-openai-ABCD" in text


def test_self_test_never_touches_dev_db(tmp_path, monkeypatch):
    """Open the real dev DB before and after run_self_test and assert its row
    count is identical: the self-test must use a temporary DB only."""
    from bbv import models as m
    from bbv.db import connect, init_db
    from bbv.repository import Repository

    dev_db = tmp_path / "data" / "bbv.db"
    dev_db.parent.mkdir(parents=True)
    repo = Repository(connect(str(dev_db)))
    init_db(repo.conn)
    repo.create_finding(m.Finding(program="real", vuln_class="idor",
                                  target_url="http://127.0.0.1/a", request={}))
    repo.create_finding(m.Finding(program="real", vuln_class="idor",
                                  target_url="http://127.0.0.1/b", request={}))
    before = len(repo.list_findings())
    repo.conn.close()

    def loader():
        s = Settings(_env_file=None)
        s.db_path = str(dev_db)   # point at the "real" db; self-test must override it
        return s

    ok = st.run_self_test(loader=loader, out=lambda *_: None)
    assert isinstance(ok, bool)

    after = len(Repository(connect(str(dev_db))).list_findings())
    assert after == before == 2   # dev db untouched


def test_self_test_check_cli_exit_code(tmp_path, monkeypatch):
    s = Settings(_env_file=None)
    s.db_path = str(tmp_path / "data" / "bbv.db")
    monkeypatch.setattr(cli, "load_settings", lambda: s)
    rc = cli.main(["setup", "--self-test"])
    assert rc in (0, 1)   # 0 all pass, 1 if a check failed (e.g. no Chromium)


def test_write_scope_template_does_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p1 = st.write_scope_template("demo")
    assert p1 is not None and p1.exists()
    p2 = st.write_scope_template("demo")       # second call must not clobber
    assert p2 is None
