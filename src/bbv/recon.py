"""Passive recon: wrap EXISTING external tools (subfinder, httpx, katana) via
subprocess — never reimplement them. Every discovered asset is scope-checked
before it is persisted; out-of-scope assets are recorded as such, and ONLY
in-scope hosts are ever handed to the active probers (httpx/katana), so we never
silently probe out of scope.

The wrapped tools run their own HTTP stacks, so we cannot route them through
ScopedHttpClient. We uphold the scope guarantee two ways instead: (1) we feed
them only pre-scope-checked in-scope targets, and (2) we scope-check all of
their output before persisting. We also pass each tool its native rate-limit
flag from config so recon traffic stays conservative.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from . import models as m
from .config import Settings
from .repository import Repository
from .scope import Scope

log = logging.getLogger("bbv.recon")


@dataclass
class ReconSummary:
    program: str
    tools_available: dict[str, bool] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def bump(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n


def _run(cmd: list[str], timeout: int, stdin_data: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, input=stdin_data, capture_output=True, text=True,
        timeout=timeout, check=False,
    )


def _is_projectdiscovery_httpx(bin_path: str, timeout: int) -> bool:
    """Guard against the name collision with the Python httpx library's CLI:
    only treat `httpx` as the recon tool if its -version mentions projectdiscovery."""
    try:
        res = _run([bin_path, "-version"], timeout=min(timeout, 10))
    except (OSError, subprocess.SubprocessError):
        return False
    blob = (res.stdout + res.stderr).lower()
    return "projectdiscovery" in blob or "httpx version" in blob


class ReconRunner:
    def __init__(self, repo: Repository, scope: Scope, settings: Settings, program: str):
        self.repo = repo
        self.scope = scope
        self.settings = settings
        self.program = program
        self.rate = max(1, int(settings.rate_global))

    # ---- entry point ----
    def run(self) -> ReconSummary:
        summary = ReconSummary(program=self.program)

        seeds = self._seed_hosts(summary)
        subs = self._run_subfinder(seeds, summary)

        # Active probing targets: in-scope seeds + in-scope discovered subdomains.
        in_scope_hosts = [s for s in seeds]
        in_scope_hosts += [v for (v, ok) in subs if ok]

        in_scope_hosts = list(dict.fromkeys(in_scope_hosts))  # dedupe, keep order
        live = self._run_httpx(in_scope_hosts, summary)
        self._run_katana(live, summary)
        return summary

    # ---- seeds ----
    def _seed_hosts(self, summary: ReconSummary) -> list[str]:
        """Persist the program's declared in-scope apexes / IPs as host assets so
        recon always populates something deterministic, even with no tools."""
        hosts: list[str] = []
        for d in self.scope.in_domains:
            host = d[2:] if d.startswith("*.") else d
            self.repo.upsert_asset(m.Asset(
                self.program, m.KIND_HOST, host, in_scope=True, source="seed",
            ))
            hosts.append(host)
            summary.bump("seed_hosts")
        for cidr in self.scope.in_cidrs:
            # Single-IP CIDRs make a usable seed host.
            ip = cidr.split("/")[0]
            if cidr.endswith("/32") or "/" not in cidr:
                self.repo.upsert_asset(m.Asset(
                    self.program, m.KIND_HOST, ip, in_scope=True, source="seed",
                ))
                hosts.append(ip)
                summary.bump("seed_hosts")
        return list(dict.fromkeys(hosts))  # dedupe apex/IP seeds

    # ---- subfinder ----
    def _run_subfinder(self, seeds: list[str], summary: ReconSummary) -> list[tuple[str, bool]]:
        bin_path = shutil.which(self.settings.subfinder_bin)
        summary.tools_available["subfinder"] = bool(bin_path)
        if not bin_path:
            summary.notes.append("subfinder not found on PATH; skipping subdomain enum")
            return []

        discovered: list[tuple[str, bool]] = []
        # subfinder takes domains, not IPs.
        domains = [s for s in seeds if not _looks_like_ip(s)]
        for domain in domains:
            try:
                res = _run([bin_path, "-d", domain, "-silent"], self.settings.recon_timeout)
            except subprocess.SubprocessError as e:
                summary.notes.append(f"subfinder failed for {domain}: {e}")
                continue
            for line in filter(None, (l.strip() for l in res.stdout.splitlines())):
                in_scope = self.scope.is_allowed(f"https://{line}")
                self.repo.upsert_asset(m.Asset(
                    self.program, m.KIND_SUBDOMAIN, line, in_scope=in_scope,
                    source="subfinder",
                ))
                discovered.append((line, in_scope))
                summary.bump("subdomains")
                if not in_scope:
                    summary.bump("subdomains_out_of_scope")
        return discovered

    # ---- httpx (ProjectDiscovery) ----
    def _run_httpx(self, hosts: list[str], summary: ReconSummary) -> list[str]:
        bin_path = shutil.which(self.settings.httpx_bin)
        is_pd = bool(bin_path) and _is_projectdiscovery_httpx(bin_path, self.settings.recon_timeout)
        summary.tools_available["httpx"] = is_pd
        if not is_pd:
            if bin_path:
                summary.notes.append(
                    f"'{self.settings.httpx_bin}' on PATH is not ProjectDiscovery httpx "
                    "(likely the Python httpx CLI); skipping liveness/fingerprint")
            else:
                summary.notes.append("httpx not found on PATH; skipping liveness/fingerprint")
            return []
        if not hosts:
            return []

        stdin = "\n".join(dict.fromkeys(hosts))  # dedupe, keep order
        cmd = [bin_path, "-silent", "-json", "-status-code", "-title",
               "-tech-detect", "-rate-limit", str(self.rate)]
        try:
            res = _run(cmd, self.settings.recon_timeout, stdin_data=stdin)
        except subprocess.SubprocessError as e:
            summary.notes.append(f"httpx failed: {e}")
            return []

        live: list[str] = []
        for line in filter(None, (l.strip() for l in res.stdout.splitlines())):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input") or ""
            if not url:
                continue
            in_scope = self.scope.is_allowed(url)
            self.repo.upsert_asset(m.Asset(
                self.program, m.KIND_HOST, url, in_scope=in_scope, source="httpx",
                metadata={
                    "status_code": obj.get("status_code"),
                    "title": obj.get("title"),
                    "tech": obj.get("tech") or obj.get("technologies"),
                },
            ))
            summary.bump("live_hosts")
            if in_scope:
                live.append(url)
        return live

    # ---- katana ----
    def _run_katana(self, live_hosts: list[str], summary: ReconSummary) -> None:
        bin_path = shutil.which(self.settings.katana_bin)
        summary.tools_available["katana"] = bool(bin_path)
        if not bin_path:
            summary.notes.append("katana not found on PATH; skipping crawl")
            return
        for host in live_hosts:
            cmd = [bin_path, "-u", host, "-silent", "-jsonl",
                   "-depth", str(self.settings.katana_max_depth),
                   "-rate-limit", str(self.rate)]
            try:
                res = _run(cmd, self.settings.recon_timeout)
            except subprocess.SubprocessError as e:
                summary.notes.append(f"katana failed for {host}: {e}")
                continue
            for line in filter(None, (l.strip() for l in res.stdout.splitlines())):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                endpoint = (obj.get("request", {}) or {}).get("endpoint") or obj.get("endpoint") or ""
                if not endpoint:
                    continue
                in_scope = self.scope.is_allowed(endpoint)
                kind = m.KIND_JS if endpoint.split("?")[0].endswith(".js") else m.KIND_ENDPOINT
                self.repo.upsert_asset(m.Asset(
                    self.program, kind, endpoint, in_scope=in_scope, source="katana",
                ))
                summary.bump("js" if kind == m.KIND_JS else "endpoints")
                if not in_scope:
                    summary.bump("crawl_out_of_scope")


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
