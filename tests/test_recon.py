import subprocess
import types

import pytest

from bbv import models as m
from bbv.config import Settings
from bbv.db import connect, init_db
from bbv.recon import ReconRunner
from bbv.repository import Repository
from bbv.scope import Scope


def _repo(tmp_path):
    conn = connect(str(tmp_path / "recon.db"))
    init_db(conn)
    return Repository(conn)


def _scope():
    return Scope.from_dict({
        "in_domains": ["example.com", "*.example.com"],
        "in_cidrs": ["127.0.0.1/32"],
        "out_domains": ["admin.example.com"],
    })


def test_recon_seeds_assets_without_tools(tmp_path):
    """With no external tools on PATH, recon must not crash and must persist the
    declared in-scope seeds."""
    repo = _repo(tmp_path)
    s = Settings(_env_file=None, subfinder_bin="definitely-not-a-tool-xyz",
                 httpx_bin="definitely-not-a-tool-xyz", katana_bin="definitely-not-a-tool-xyz")
    summary = ReconRunner(repo, _scope(), s, "demo").run()

    assert summary.tools_available == {"subfinder": False, "httpx": False, "katana": False}
    hosts = repo.list_assets("demo", kind=m.KIND_HOST)
    values = {h.value for h in hosts}
    assert "example.com" in values and "127.0.0.1" in values
    assert all(h.in_scope for h in hosts)


def test_subfinder_output_scope_checked(tmp_path, monkeypatch):
    """A discovered out-of-scope subdomain is recorded as out-of-scope (not
    dropped), and out-of-scope hosts are never fed to the active probers."""
    import bbv.recon as recon

    repo = _repo(tmp_path)
    s = Settings(_env_file=None)

    monkeypatch.setattr(recon.shutil, "which",
                        lambda name: "/usr/bin/subfinder" if "subfinder" in name else None)

    def fake_run(cmd, timeout, stdin_data=None):
        # subfinder returns one in-scope and one out-of-scope subdomain.
        out = "api.example.com\nevil.com\nadmin.example.com\n"
        return types.SimpleNamespace(stdout=out, stderr="", returncode=0)

    monkeypatch.setattr(recon, "_run", fake_run)

    runner = ReconRunner(repo, _scope(), s, "demo")
    summary = runner.run()

    subs = {a.value: a.in_scope for a in repo.list_assets("demo", kind=m.KIND_SUBDOMAIN)}
    assert subs["api.example.com"] is True
    assert subs["evil.com"] is False          # recorded, flagged out-of-scope
    assert subs["admin.example.com"] is False  # explicit exclusion wins
    assert summary.counts.get("subdomains_out_of_scope", 0) == 2


def test_httpx_name_collision_guarded(tmp_path, monkeypatch):
    """A non-ProjectDiscovery 'httpx' on PATH (e.g. the Python httpx CLI) must
    not be invoked as the recon tool."""
    import bbv.recon as recon
    repo = _repo(tmp_path)
    s = Settings(_env_file=None)

    monkeypatch.setattr(recon.shutil, "which",
                        lambda name: "/usr/bin/httpx" if name == "httpx" else None)

    def fake_run(cmd, timeout, stdin_data=None):
        # Simulate the Python httpx CLI: no 'projectdiscovery' in version output.
        return types.SimpleNamespace(stdout="0.28.1", stderr="", returncode=0)

    monkeypatch.setattr(recon, "_run", fake_run)
    summary = ReconRunner(repo, _scope(), s, "demo").run()
    assert summary.tools_available["httpx"] is False
    assert any("not ProjectDiscovery" in n for n in summary.notes)
