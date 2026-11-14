"""The 12 checks. Each gives PASS / WARN / FAIL / SKIP with a one-line reason and, when not PASS, a fix."""

from __future__ import annotations

import fnmatch
import json
import re
import string
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from importlib import resources

from .parse import CollectError, Facts, natural_key, systemd_time, uu_runs

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
RANK = {SKIP: 0, PASS: 0, WARN: 1, FAIL: 2}
DAY = 86400
LATE_DAYS = 2  # a daily job not seen for longer has missed a run: WARN
FAIL_DAYS = 7  # a job missing, a reboot or a newer kernel pending for longer: FAIL
EOL_WARN_DAYS = 180
ERROR_WINDOW_DAYS = 14

TITLES = {
    "installed": "Auto-update tool installed",
    "schedule": "Scheduled to run and install",
    "origins": "Security updates allowed",
    "last-run": "Last successful run",
    "errors": "Package manager errors",
    "held": "Held or excluded packages",
    "pending": "Security updates waiting",
    "reboot": "Reboot required",
    "services": "Services needing restart",
    "kernel": "Running kernel",
    "livepatch": "Live kernel patching",
    "eol": "OS end of life",
}
NEEDS_TOOL = ("schedule", "origins", "last-run")  # skipped when the tool is not installed


@dataclass
class Result:
    id: str
    status: str
    reason: str
    fix: str = ""
    limited: str = ""  # what could not be read without root

    @property
    def title(self) -> str:
        return TITLES[self.id]


@dataclass
class HostReport:
    host: str
    os: str = ""
    manager: str = ""
    root: bool = False
    checks: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    error: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        return ("OK", "WARN", "FAIL")[max((RANK[c.status] for c in self.checks), default=0)]


def utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def span(seconds: float) -> str:
    seconds = max(seconds, 0)
    if seconds < 2 * 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 2 * DAY:
        return f"{int(seconds // 3600)} h"
    return f"{int(seconds // DAY)} days"


def ago(f: Facts, ts: int) -> str:
    return f"{span(f.now - ts)} ago ({utc(ts)})"


def by_age(seconds: float) -> str:
    return PASS if seconds <= LATE_DAYS * DAY else WARN if seconds <= FAIL_DAYS * DAY else FAIL


def some(items: list, n: int = 6) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def worst(*statuses: str) -> str:
    return max(statuses, key=lambda s: RANK[s])


def unit_state(u: dict) -> str:
    if u.get("LoadState") in (None, "not-found"):
        return "missing"
    if u.get("LoadState") == "masked":
        return "masked"
    return f"{u.get('UnitFileState') or '?'}/{u.get('ActiveState') or '?'}"


def unit_on(u: dict) -> bool:
    return u.get("LoadState") == "loaded" and u.get("UnitFileState") in ("enabled", "static") and u.get("ActiveState") == "active"


def journal_errors(f: Facts) -> list[str]:
    return [line for line in f.lines("journal") if not line.startswith("readable=")]


# ---------------------------------------------------------------- apt: Debian, Ubuntu


def apt_installed(f: Facts, m: dict) -> Result:
    uu = f.kv("apt").get("uu", "")
    if uu.startswith("ii"):
        return Result("installed", PASS, f"unattended-upgrades {uu[3:].strip()} is installed")
    return Result("installed", FAIL, "unattended-upgrades is not installed, so nothing installs updates automatically",
                  "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")


def periodic_days(value: str) -> float | None:
    """An APT::Periodic interval ('1', '7', '12h', 'always') in days; None when off."""
    if value == "always":
        return 0.0
    m = re.fullmatch(r"(\d+)([smhd]?)", value.strip())
    if not m or int(m.group(1)) == 0:
        return None
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": DAY, "": DAY}[m.group(2)] / DAY


def apt_schedule(f: Facts, m: dict) -> Result:
    conf = f.apt_config()
    bad, slow, fixes = [], [], []
    if conf.get("APT::Periodic::Enable", ["1"])[0] == "0":
        bad.append('APT::Periodic::Enable is "0"')
    for key, effect in (("Update-Package-Lists", "package lists are never refreshed"),
                        ("Unattended-Upgrade", "unattended-upgrade never runs")):
        raw = conf.get("APT::Periodic::" + key, ["0"])[0]
        days = periodic_days(raw)
        if days is None:
            bad.append(f'APT::Periodic::{key} is "{raw}": {effect}')
        elif days > 1:
            slow.append(f"APT::Periodic::{key} runs every {days:g} days")
    if bad:
        fixes.append("sudo dpkg-reconfigure -plow unattended-upgrades (writes both APT::Periodic values as \"1\" "
                     "to /etc/apt/apt.conf.d/20auto-upgrades)")
    units, limited, nxt = f.units(), "", None
    if units is None:
        limited = "systemd is not running, so the apt-daily timers were not checked"
    else:
        off = [t for t in ("apt-daily.timer", "apt-daily-upgrade.timer") if not unit_on(units.get(t, {}))]
        bad += [f"{t} is {unit_state(units.get(t, {}))}" for t in off]
        if off:
            fixes.append(f"sudo systemctl unmask {' '.join(off)}; sudo systemctl enable --now {' '.join(off)}")
        nxt = systemd_time(units.get("apt-daily-upgrade.timer", {}).get("NextElapseUSecRealtime"))
    if bad:
        return Result("schedule", FAIL, "; ".join(bad), "; ".join(fixes), limited)
    if slow:
        return Result("schedule", WARN, "; ".join(slow) + ", so updates can wait that long",
                      'set the APT::Periodic values to "1" (daily) in /etc/apt/apt.conf.d/20auto-upgrades', limited)
    reason = "apt-daily timers on; lists refreshed and upgrades run daily"
    if nxt:
        reason += f"; next upgrade run in {span(nxt - f.now)}"
    return Result("schedule", PASS, reason, limited=limited)


def legacy_origin(entry: str) -> str:
    """Allowed-Origins 'origin:archive' -> 'o=origin,a=archive', as unattended-upgrades converts it."""
    parts = re.split(r"(?<!\\):", entry, maxsplit=1) if re.search(r"(?<!\\):", entry) else entry.split(None, 1)
    if len(parts) != 2:
        return ""
    origin, archive = (p.replace("\\:", ":").replace(",", "\\,") for p in parts)
    return f"o={origin},a={archive}"


def origin_matches(pattern: str, archive: dict) -> bool:
    """unattended-upgrades' match_whitelist_string(): every key=value token must fnmatch the archive."""
    keys = {"o": "o", "origin": "o", "l": "l", "label": "l", "a": "a", "suite": "a", "archive": "a",
            "c": "c", "component": "c", "n": "n", "codename": "n", "site": None}
    for token in pattern.replace("\\,", "%2C").split(","):
        what, _, value = (s.strip().replace("%2C", ",") for s in token.partition("="))
        if what not in keys:
            return False
        if keys[what] and not fnmatch.fnmatchcase(archive.get(keys[what], ""), value):
            return False
    return True


def allowed_origins(f: Facts) -> list[str]:
    """Allowed-Origins and Origins-Pattern, with ${distro_id} etc. substituted from os-release."""
    conf = f.apt_config()
    distro_id = f.os.get("ID", "")[:1].upper() + f.os.get("ID", "")[1:]
    if f.os.get("NAME", "").lower() == distro_id.lower():
        distro_id = f.os["NAME"]
    subst = {"distro_id": distro_id, "distro_codename": f.os.get("VERSION_CODENAME", ""),
             "distro_release": f.os.get("VERSION_ID", "")}
    raw = [legacy_origin(v) for v in conf.get("Unattended-Upgrade::Allowed-Origins::", [])]
    raw += conf.get("Unattended-Upgrade::Origins-Pattern::", [])
    return [string.Template(p).safe_substitute(subst) for p in raw if p.strip()]


def esm_archives(f: Facts) -> list[dict]:
    return [a for a in f.archives() if a.get("o", "").startswith("UbuntuESM")]


def apt_origins(f: Facts, m: dict) -> Result:
    patterns = allowed_origins(f)
    file = "/etc/apt/apt.conf.d/50unattended-upgrades"
    if not patterns:
        return Result("origins", FAIL, "Allowed-Origins and Origins-Pattern are empty: unattended-upgrades runs but installs nothing",
                      f'add "${{distro_id}}:${{distro_codename}}-security"; to Unattended-Upgrade::Allowed-Origins in {file}')
    archives = f.archives()
    security = [a for a in archives if "security" in (a.get("a", "") + a.get("l", "")).lower()]
    if not archives:
        if any("security" in p.lower() for p in patterns):
            return Result("origins", PASS, "an allowed origin names the security pocket",
                          limited="apt has no package lists yet, so origins were matched by name only")
        return Result("origins", FAIL, "no allowed origin names a security pocket", f"allow the -security pocket in {file}")
    if not security:
        return Result("origins", FAIL, "apt has no security archive configured (no *-security suite in its sources), "
                      "so security updates never arrive", "add the security suite to /etc/apt/sources.list(.d), then apt update")
    matched = [a for a in security if any(origin_matches(p, a) for p in patterns)]
    names = sorted({f"{a.get('o')}/{a.get('a')}" for a in security})
    if not matched:
        return Result("origins", FAIL, f"the allowed origins match none of the security archives ({some(names)}), "
                      "so security updates are never installed (an old codename-based pattern?)",
                      f'allow the security archive in {file}, e.g. "origin=Debian,codename=${{distro_codename}}-security,'
                      'label=Debian-Security" or "${distro_id}:${distro_codename}-security"')
    missed = sorted({f"{a.get('o')}/{a.get('a')}" for a in esm_archives(f) if a not in matched})
    if missed:
        return Result("origins", WARN, f"Ubuntu Pro ESM is enabled but not allowed, so its fixes are not installed: {some(missed)}",
                      f'add "${{distro_id}}ESM:${{distro_codename}}-infra-security" and '
                      f'"${{distro_id}}ESMApps:${{distro_codename}}-apps-security" to Allowed-Origins in {file}')
    return Result("origins", PASS, "security updates are allowed from " + some(sorted({f"{a.get('o')}/{a.get('a')}" for a in matched})))


def lists_refreshed(f: Facts) -> int | None:
    return max(f.number("apt", "update-stamp") or 0, f.number("apt", "update-success-stamp") or 0) or None


def apt_last_run(f: Facts, m: dict) -> Result:
    log = f.lines("uu-log")
    readable = bool(log) and log[0] == "log=yes"
    runs = uu_runs(log[1:], f.meta.get("utc_offset", ""))
    last_ok = max([f.number("apt", "upgrade-stamp") or 0] + [r.start for r in runs if r.outcome == "ok"]) or None
    m["last_success"] = last_ok
    limited = "" if readable or (log and log[0] == "log=missing") else \
        "the unattended-upgrades log needs root or the adm group; used the stamp files only"
    fix = "sudo unattended-upgrade --dry-run --debug; see /var/log/unattended-upgrades/unattended-upgrades.log"
    if runs and runs[-1].outcome == "error":
        return Result("last-run", FAIL, f"the last run, {ago(f, runs[-1].start)}, failed: {runs[-1].errors[0]}", fix, limited)
    if last_ok is None:
        ran = f.number("apt", "unattended-upgrades-stamp")
        if limited and ran:
            return Result("last-run", worst(by_age(f.now - ran), WARN), f"no success stamp from apt; unattended-upgrades "
                          f"last ran {ago(f, ran)}, result unknown without the log", fix, limited)
        if limited:
            return Result("last-run", WARN, "apt recorded no successful unattended-upgrades run", fix, limited)
        return Result("last-run", FAIL, "no successful unattended-upgrades run on record", fix, limited)
    status, reason = by_age(f.now - last_ok), f"last successful run {ago(f, last_ok)}"
    lists = lists_refreshed(f)
    if lists is None:
        reason += "; no record of a successful package list refresh"
        status = worst(status, WARN)
    elif f.now - lists > LATE_DAYS * DAY:
        reason += f"; package lists last refreshed {ago(f, lists)}, so newer updates are not seen"
        status = worst(status, by_age(f.now - lists))
    if runs and runs[-1].outcome == "incomplete" and runs[-1].start > last_ok:
        reason += f"; a run started {ago(f, runs[-1].start)} has no result yet (running or killed)"
    return Result("last-run", status, reason, "" if status == PASS else fix, limited)


def apt_errors(f: Facts, m: dict) -> Result:
    a = f.kv("apt")
    if a.get("dpkg_interrupted"):
        return Result("errors", FAIL, "dpkg was interrupted: apt and unattended-upgrades install nothing until it is fixed",
                      "sudo dpkg --configure -a")
    audit = f.values("apt", "audit")
    if audit:
        pkgs = [line.split()[0] for line in audit if line.startswith(" ") and line.split()]
        return Result("errors", FAIL, "dpkg reports broken or half-installed packages" + (f": {some(pkgs)}" if pkgs else ""),
                      "sudo dpkg --configure -a && sudo apt-get -f install")
    since = f.now - ERROR_WINDOW_DAYS * DAY
    log = f.lines("uu-log")
    errors = [e for r in uu_runs(log[1:], f.meta.get("utc_offset", "")) if r.start >= since for e in r.errors]
    errors += journal_errors(f)
    limited = "" if (log and log[0] != "log=no-permission") or f.meta.get("journal") == "yes" else \
        "the log and journal need root or the adm group"
    if errors:
        lock = sum("lock" in e.lower() for e in errors)
        fix = ("another apt or dpkg process held the lock: look for stuck apt processes or overlapping jobs"
               if lock else "read /var/log/unattended-upgrades/unattended-upgrades.log and journalctl -u apt-daily-upgrade")
        return Result("errors", WARN, f"{len(errors)} error line(s) in the last {ERROR_WINDOW_DAYS} days"
                      + (f", {lock} about the dpkg lock" if lock else "") + f", e.g. {errors[-1][:160]}", fix, limited)
    return Result("errors", PASS, f"dpkg state is clean; no errors in the last {ERROR_WINDOW_DAYS} days", limited=limited)


def apt_held(f: Facts, m: dict) -> Result:
    holds = f.values("apt", "hold")
    blacklist = f.apt_config().get("Unattended-Upgrade::Package-Blacklist::", [])
    if not holds and not blacklist:
        return Result("held", PASS, "no held or excluded packages")
    parts = ([f"held: {some(holds)}"] if holds else []) + ([f"excluded by Package-Blacklist: {some(blacklist)}"] if blacklist else [])
    return Result("held", WARN, "; ".join(parts) + " (these never get automatic updates)",
                  "sudo apt-mark unhold <package> once the hold is no longer needed; review Unattended-Upgrade::Package-Blacklist")


def apt_pending(f: Facts, m: dict) -> Result:
    up = f.kv("apt-upgradable")
    if not up.get("security", "").isdigit():
        return Result("pending", SKIP, "could not list upgradable packages")
    n = int(up["security"])
    m["pending_security"] = n
    names = [line for line in f.lines("apt-upgradable") if "=" not in line]
    lists, last_ok = lists_refreshed(f), m.get("last_success")
    note = f"; package lists refreshed {ago(f, lists)}" if lists else ""
    if n == 0 and lists and f.now - lists > LATE_DAYS * DAY:
        return Result("pending", WARN, f"no security updates listed, but the package lists are {span(f.now - lists)} old, "
                      "so newer ones are not counted", "see the last-run check for why the lists are not refreshed")
    if n == 0:
        return Result("pending", PASS, "no security updates waiting" + note)
    reason = f"{n} security update(s) waiting: {some(names)}" + note
    fix = "sudo unattended-upgrade --dry-run --debug shows why packages are skipped (held, blacklisted, conffile prompt)"
    if lists and last_ok and last_ok > lists + 3600:
        return Result("pending", FAIL, reason + "; they were already available at the last successful run and were not installed", fix)
    return Result("pending", WARN, reason, fix)


def apt_reboot(f: Facts, m: dict) -> Result:
    since = f.number("apt", "reboot_required")
    m["reboot_required"] = 0 if since is None else 1
    if since is None:
        return Result("reboot", PASS, "no reboot required")
    pkgs = f.values("apt", "reboot_pkg")
    return Result("reboot", WARN if f.now - since < FAIL_DAYS * DAY else FAIL,
                  f"reboot required for {span(f.now - since)} (since {utc(since)})" + (f", for {some(pkgs)}" if pkgs else ""),
                  'reboot in a maintenance window, or set Unattended-Upgrade::Automatic-Reboot "true" '
                  'and Automatic-Reboot-Time "04:00"')


# ---------------------------------------------------------------- dnf: AlmaLinux, Rocky Linux


def dnf_installed(f: Facts, m: dict) -> Result:
    version = f.kv("dnf").get("automatic")
    if version:
        return Result("installed", PASS, f"dnf-automatic {version} is installed")
    return Result("installed", FAIL, "dnf-automatic is not installed, so nothing installs updates automatically",
                  "sudo dnf install dnf-automatic, set apply_updates = yes in /etc/dnf/automatic.conf, "
                  "then sudo systemctl enable --now dnf-automatic.timer")


def dnf_timer(f: Facts) -> str | None:
    """The dnf-automatic timer that installs updates, if any is on."""
    units = f.units() or {}
    if unit_on(units.get("dnf-automatic-install.timer", {})):
        return "dnf-automatic-install.timer"
    if unit_on(units.get("dnf-automatic.timer", {})) and f.kv("dnf").get("conf_apply_updates", "no").lower() in ("yes", "true", "1"):
        return "dnf-automatic.timer"
    return None


def dnf_schedule(f: Facts, m: dict) -> Result:
    units = f.units()
    if units is None:
        return Result("schedule", SKIP, "systemd is not running, so the dnf-automatic timers were not checked")
    timer = dnf_timer(f)
    if timer:
        nxt = systemd_time(units[timer].get("NextElapseUSecRealtime"))
        return Result("schedule", PASS, f"{timer} is on and installs updates" + (f"; next run in {span(nxt - f.now)}" if nxt else ""))
    on = [t for t in ("dnf-automatic.timer", "dnf-automatic-download.timer", "dnf-automatic-notifyonly.timer")
          if unit_on(units.get(t, {}))]
    fix = "set apply_updates = yes in /etc/dnf/automatic.conf, or sudo systemctl enable --now dnf-automatic-install.timer"
    if "dnf-automatic.timer" in on:
        return Result("schedule", FAIL, "dnf-automatic.timer runs but apply_updates is not yes: updates are only "
                      "downloaded or announced, never installed", fix)
    if on:
        return Result("schedule", FAIL, f"only {some(on)} is on: it never installs updates", fix)
    return Result("schedule", FAIL, "no dnf-automatic timer is enabled and active "
                  f"(dnf-automatic.timer is {unit_state(units.get('dnf-automatic.timer', {}))})", fix)


def dnf_origins(f: Facts, m: dict) -> Result:
    kind = f.kv("dnf").get("conf_upgrade_type", "default")
    if kind == "security":
        return Result("origins", PASS, "upgrade_type = security: installs updates that have a security advisory")
    if kind == "default":
        return Result("origins", PASS, "upgrade_type = default: installs all updates, security included")
    return Result("origins", WARN, f"upgrade_type = {kind} is not a value dnf-automatic knows",
                  "set upgrade_type = security (or default) in /etc/dnf/automatic.conf")


def dnf_last_run(f: Facts, m: dict) -> Result:
    units = f.units() or {}
    service = (dnf_timer(f) or "dnf-automatic.timer").replace(".timer", ".service")
    svc, timer = units.get(service, {}), units.get(service.replace(".service", ".timer"), {})
    ended, triggered = systemd_time(svc.get("ExecMainExitTimestamp")), systemd_time(timer.get("LastTriggerUSec"))
    installed = f.number("dnf", "last_install")
    fix = f"sudo journalctl -u {service} -n 50"
    if ended and svc.get("Result", "success") != "success":
        m["last_success"] = None
        return Result("last-run", FAIL, f"{service} failed {ago(f, ended)} with result {svc.get('Result')}, "
                      f"exit status {svc.get('ExecMainStatus', '?')}", fix)
    last = ended or triggered
    m["last_success"] = last
    if not last:
        return Result("last-run", FAIL, f"{service} has never run (no timer trigger on record)", fix)
    reason = f"{service} last ran {ago(f, last)}" + ("" if ended else " (its result is not kept across reboots)")
    if installed:
        reason += f"; packages last installed {ago(f, installed)}"
    status = by_age(f.now - last)
    return Result("last-run", status, reason, "" if status == PASS else fix)


def dnf_errors(f: Facts, m: dict) -> Result:
    errors = journal_errors(f)
    limited = "" if f.meta.get("journal") == "yes" else "the journal needs root or the adm/systemd-journal group"
    if errors:
        return Result("errors", WARN, f"{len(errors)} error line(s) from dnf-automatic in the last {ERROR_WINDOW_DAYS} days, "
                      f"e.g. {errors[-1][:160]}", "sudo journalctl -u dnf-automatic.service -u dnf-automatic-install.service", limited)
    return Result("errors", PASS, f"no dnf-automatic errors in the last {ERROR_WINDOW_DAYS} days", limited=limited)


def dnf_held(f: Facts, m: dict) -> Result:
    locks, excludes = f.values("dnf", "lock"), f.values("dnf", "exclude")
    if not locks and not excludes:
        return Result("held", PASS, "no versionlocks or excludes")
    parts = ([f"versionlocked: {some(locks)}"] if locks else []) + ([f"excluded in dnf.conf: {some(excludes)}"] if excludes else [])
    return Result("held", WARN, "; ".join(parts) + " (these never get automatic updates)",
                  "sudo dnf versionlock delete <package> once the lock is no longer needed; review exclude= in /etc/dnf/dnf.conf")


def dnf_pending(f: Facts, m: dict) -> Result:
    lines = f.lines("dnf-security")
    if not lines or lines[0] != "exit=0":
        return Result("pending", SKIP, "dnf could not read its metadata cache", limited="" if f.root else
                      "dnf's cache is readable by root only; run with --sudo")
    rows = [line.split() for line in lines[1:] if re.match(r"^\S+\s+\S*Sec\.\s+\S+$", line)]
    pkgs = sorted({r[-1] for r in rows})
    m["pending_security"] = len(pkgs)
    if not pkgs:
        return Result("pending", PASS, "no security updates waiting (from the local dnf cache)")
    return Result("pending", WARN, f"{len(pkgs)} package update(s) from {len({r[0] for r in rows})} security advisories "
                  f"waiting: {some(pkgs, 4)}", "sudo dnf upgrade --security")


def dnf_reboot(f: Facts, m: dict) -> Result:
    out = " ".join(f.values("dnf", "reboot_out"))
    fix = "reboot in a maintenance window, or set reboot = when-needed in /etc/dnf/automatic.conf (dnf 4.14+)"
    if "Reboot is required" in out:
        m["reboot_required"] = 1
        since = f.number("dnf", "reboot_since")
        if not since:
            return Result("reboot", WARN, "reboot required (since: unknown)", fix)
        return Result("reboot", WARN if f.now - since < FAIL_DAYS * DAY else FAIL,
                      f"reboot required for {span(f.now - since)} (since {utc(since)})", fix)
    if "should not be necessary" in out:
        m["reboot_required"] = 0
        return Result("reboot", PASS, "no reboot required")
    return Result("reboot", SKIP, "dnf needs-restarting is not available", "sudo dnf install dnf-utils")


# ---------------------------------------------------------------- both


def services(f: Facts, m: dict) -> Result:
    lines = f.lines("services")
    tool = f.kv("services").get("tool")
    limited = "" if f.root else "without root only your own processes are checked"
    if tool == "needrestart":
        names = [line.split(":", 1)[1].strip() for line in lines if line.startswith("NEEDRESTART-SVC:")]
    elif tool == "needs-restarting" and not any("rror" in line or "No such command" in line for line in lines):
        names = [line.strip() for line in lines[1:] if line.strip().endswith(".service")]
    else:
        hint = "sudo apt install needrestart" if f.has("apt") else "sudo dnf install dnf-utils"
        return Result("services", SKIP, "no restart checker (needrestart / needs-restarting) available", hint)
    if not names and limited:
        return Result("services", SKIP, "no restart needed among the processes visible without root", limited=limited)
    if not names:
        return Result("services", PASS, "no services need a restart")
    return Result("services", WARN, f"{len(names)} service(s) still run replaced library code: {some(names)}",
                  f"sudo systemctl restart {' '.join(names[:5])}", limited)


def livepatch_state(f: Facts) -> tuple[str, str]:
    """('on' | 'off' | 'none' | 'unknown', detail)."""
    lines = f.lines("livepatch")
    loaded = [line.split()[0][len("module="):] for line in lines if line.startswith("module=") and line.endswith(" 1")]
    if loaded:
        return "on", f"live patches loaded: {some(loaded)}"
    clients = [line for line in lines if line.startswith("client=")]
    if not clients:
        return "none", ""
    text = " ".join(line[2:] for line in lines if line.startswith("| ")).lower()
    if "client=canonical-livepatch" in " ".join(clients):
        if "not enabled" in text or "disabled" in text:
            return "off", "Canonical Livepatch is installed but not enabled"
        if "not covered" in text or "unsupported" in text or "not supported" in text:
            return "off", "Canonical Livepatch is enabled but this kernel is not covered"
        if "exit=0" in clients[0]:
            return "on", "Canonical Livepatch is enabled"
        return "unknown", "canonical-livepatch status could not be read"
    return "unknown", "kpatch is installed but no live patch is loaded (normal if none was released for this kernel)"


def kernel(f: Facts, m: dict) -> Result:
    if f.container:
        return Result("kernel", SKIP, f"{f.meta.get('container')} container: the kernel belongs to the host")
    running = f.kv("kernel").get("running", "")
    images = []
    for value in f.values("kernel", "image"):
        ts, _, release = value.partition(" ")
        if ts.isdigit() and release:
            images.append((int(ts), release))
    if not images:
        return Result("kernel", SKIP, f"running {running}; no kernel images in /boot to compare (kernel managed outside the OS?)")
    installed, newest = max(images, key=lambda i: natural_key(i[1]))
    if natural_key(running) >= natural_key(newest):
        m["kernel_outdated"] = 0
        return Result("kernel", PASS, f"running the newest installed kernel, {running}")
    m["kernel_outdated"] = 1
    age = f.now - installed
    status, reason = WARN if age < FAIL_DAYS * DAY else FAIL, \
        f"running {running}, but {newest} was installed {span(age)} ago: its fixes are not active until a reboot"
    if livepatch_state(f)[0] == "on" and status == FAIL:
        status, reason = WARN, reason + " (Livepatch covers high and critical kernel fixes meanwhile)"
    return Result("kernel", status, reason, "reboot into the new kernel in a maintenance window")


def livepatch(f: Facts, m: dict) -> Result:
    if f.container:
        return Result("livepatch", SKIP, "container: live patching belongs to the host")
    state, detail = livepatch_state(f)
    if state == "on":
        return Result("livepatch", PASS, detail)
    if state == "off":
        fix = "sudo pro enable livepatch (needs Ubuntu Pro)" if "Canonical" in detail else ""
        return Result("livepatch", WARN, detail, fix)
    if state == "unknown":
        return Result("livepatch", SKIP, detail, limited="" if f.root else "live patch clients need root to report status")
    return Result("livepatch", SKIP, "no live patching in use (optional: kernel fixes then need a reboot)")


def load_eol() -> dict:
    return json.loads(resources.files(__package__).joinpath("eol.json").read_text(encoding="utf-8"))


def eol(f: Facts, m: dict) -> Result:
    data, distro, version = load_eol(), f.os.get("ID", ""), f.os.get("VERSION_ID", "")
    release = version if distro == "ubuntu" else version.split(".")[0]
    rec = data.get(distro, {}).get(release)
    if not rec:
        return Result("eol", SKIP, f"no bundled end-of-life data for {distro} {version or '(no VERSION_ID)'}",
                      "see https://endoflife.date")
    end, today = date.fromisoformat(rec["eol"]), datetime.fromtimestamp(f.now, timezone.utc).date()
    m["eol"] = int(datetime(end.year, end.month, end.day, tzinfo=timezone.utc).timestamp())
    extended = date.fromisoformat(rec["extended"]) if rec.get("extended") else None
    paid = "Ubuntu Pro ESM" if distro == "ubuntu" else "Freexian ELTS (paid)"
    name, left = f.os.get("PRETTY_NAME", f"{distro} {version}"), (end - today).days
    source = f"endoflife.date, {data['retrieved']}"
    if left < 0:
        if distro == "ubuntu" and extended and today <= extended and esm_archives(f):
            return Result("eol", WARN, f"standard support ended {end}; Ubuntu Pro ESM is enabled and covers it until {extended} ({source})",
                          "plan the upgrade to a newer LTS release")
        return Result("eol", FAIL, f"{name} reached end of life on {end}: no more security updates"
                      + (f" ({paid} until {extended})" if extended and today <= extended else "") + f" ({source})",
                      "upgrade to a supported release")
    if left <= EOL_WARN_DAYS:
        return Result("eol", WARN, f"{name} reaches end of life in {left} days, on {end} ({source})", "plan the upgrade now")
    return Result("eol", PASS, f"security support until {end} ({source})")


APT = [apt_installed, apt_schedule, apt_origins, apt_last_run, apt_errors, apt_held, apt_pending, apt_reboot, services, kernel, livepatch, eol]
DNF = [dnf_installed, dnf_schedule, dnf_origins, dnf_last_run, dnf_errors, dnf_held, dnf_pending, dnf_reboot, services, kernel, livepatch, eol]


def evaluate(text: str, host: str) -> HostReport:
    """Run all 12 checks on one host's collector output."""
    rep = HostReport(host)
    try:
        f = Facts(text)
    except CollectError as exc:
        rep.error = str(exc)
        return rep
    rep.os, rep.root = f.os.get("PRETTY_NAME", "unknown OS"), f.root
    rep.metrics["collected"] = f.now
    if f.has("apt"):
        rep.manager, checks = "apt", APT
    elif f.has("dnf"):
        rep.manager, checks = "dnf", DNF
    else:
        rep.error = f"{rep.os}: neither apt nor dnf found (supported: Debian, Ubuntu, AlmaLinux, Rocky Linux)"
        return rep
    tool = "unattended-upgrades" if rep.manager == "apt" else "dnf-automatic"
    try:
        for check in checks:
            result = check(f, rep.metrics)
            if result.id in NEEDS_TOOL and rep.checks[0].status == FAIL:
                result = Result(result.id, SKIP, f"{tool} is not installed")
            rep.checks.append(result)
    except (ValueError, KeyError, IndexError, TypeError) as exc:  # one odd host must not stop a fleet run
        rep.checks, rep.error = [], f"unexpected collector output ({type(exc).__name__}: {exc}); please report it"
    return rep
