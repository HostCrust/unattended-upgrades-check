"""Outputs: terminal table, one self-contained HTML file, JSON and a Prometheus textfile."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone

from . import __version__
from .checks import TITLES, HostReport

REPO = "https://github.com/HostCrust/unattended-upgrades-check"
HOST_CODE = {"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}
CHECK_CODE = {"PASS": 0, "WARN": 1, "FAIL": 2, "SKIP": -1}
GAUGES = [
    ("uuc_pending_security_updates", "pending_security", "Security updates waiting to be installed."),
    ("uuc_reboot_required", "reboot_required", "1 if the host says it needs a reboot."),
    ("uuc_kernel_outdated", "kernel_outdated", "1 if a newer kernel is installed than the one running."),
    ("uuc_last_success_timestamp_seconds", "last_success", "Last successful unattended-upgrades or dnf-automatic run."),
    ("uuc_os_eol_timestamp_seconds", "eol", "End of security support for the OS release (bundled endoflife.date data)."),
    ("uuc_collected_timestamp_seconds", "collected", "When the host was checked, by the host's clock."),
]
COLOR = {"PASS": "32", "OK": "32", "WARN": "33", "FAIL": "31", "ERROR": "35", "SKIP": "2"}


def exit_code(reports: list[HostReport]) -> int:
    """0 all OK, 1 any WARN, 2 any FAIL, 3 a host could not be checked (a FAIL still wins)."""
    statuses = {r.status for r in reports}
    for status, code in (("FAIL", 2), ("ERROR", 3), ("WARN", 1)):
        if status in statuses:
            return code
    return 0


def summary(reports: list[HostReport]) -> str:
    counts = [f"{sum(r.status == s for r in reports)} {s}" for s in ("OK", "WARN", "FAIL", "ERROR")]
    return f"{len(reports)} host(s): " + ", ".join(c for c in counts if not c.startswith("0 "))


def limited_note(r: HostReport) -> str:
    n = sum(bool(c.limited) for c in r.checks)
    return f"not run as root: {n} check(s) limited; use --sudo for full results" if n and not r.root else ""


def terminal(reports: list[HostReport], color: bool) -> str:
    def paint(s: str, width: int = 4) -> str:
        return f"\033[{COLOR[s]}m{s:<{width}}\033[0m" if color else f"{s:<{width}}"

    out = []
    for r in reports:
        out.append(f"{paint(r.status, 5)} {r.host}" + (f"  ({r.os})" if r.os else ""))
        if r.error:
            out += [f"      {r.error}", ""]
            continue
        for c in r.checks:
            out.append(f"  {paint(c.status)}  {c.title:<29} {c.reason}")
            if c.fix and c.status in ("WARN", "FAIL"):
                out.append(f"{'':37} fix: {c.fix}")
            if c.limited:
                out.append(f"{'':37} limited: {c.limited}")
        if limited_note(r):
            out.append(f"  ({limited_note(r)})")
        out.append("")
    out.append(summary(reports))
    return "\n".join(out) + "\n"


def to_dict(reports: list[HostReport], generated: str) -> dict:
    return {
        "tool": "unattended-upgrades-check", "version": __version__, "generated": generated,
        "exit_code": exit_code(reports),
        "hosts": [{"host": r.host, "status": r.status, "os": r.os, "manager": r.manager, "root": r.root,
                   "error": r.error or None, "metrics": r.metrics,
                   "checks": [{"id": c.id, "title": c.title, "status": c.status, "reason": c.reason,
                               "fix": c.fix or None, "limited": c.limited or None} for c in r.checks]}
                  for r in reports],
    }


def write_atomic(path: str, text: str) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def prometheus(reports: list[HostReport]) -> str:
    """node_exporter textfile-collector format."""
    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    metrics = [
        ("uuc_host_status", "Overall result per host: 0 ok, 1 warn, 2 fail, 3 error.",
         [(r, {}, HOST_CODE[r.status]) for r in reports]),
        ("uuc_check_status", "Result per check: 0 pass, 1 warn, 2 fail, -1 skipped.",
         [(r, {"check": c.id}, CHECK_CODE[c.status]) for r in reports for c in r.checks]),
    ] + [(name, help_text, [(r, {}, r.metrics.get(key)) for r in reports]) for name, key, help_text in GAUGES]
    out = []
    for name, help_text, samples in metrics:
        samples = [s for s in samples if s[2] is not None]
        if not samples:
            continue
        out += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
        for r, labels, value in samples:
            label = ",".join(f'{k}="{esc(v)}"' for k, v in {"host": r.host, **labels}.items())
            out.append(f"{name}{{{label}}} {value}")
    return "\n".join(out) + "\n"


_CSS = """
:root{--bg:#fff;--fg:#1c2330;--muted:#5b6474;--line:#dde2ea;--soft:#f5f7fa;
--pass:#067647;--pass-bg:#ecfdf3;--warn:#a15c00;--warn-bg:#fff8e6;--fail:#b42318;--fail-bg:#fef3f2;--skip:#667085;--skip-bg:#f2f4f7}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2a313d;--soft:#181e27;
--pass:#47cd89;--pass-bg:#0e2a1d;--warn:#f5b546;--warn-bg:#2d2310;--fail:#f97066;--fail-bg:#33161a;--skip:#98a2b3;--skip-bg:#1f2530}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 40px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px}
.muted{color:var(--muted);font-size:13px}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--muted);background:var(--soft);font-weight:600}
.m th,.m td{white-space:nowrap}
.b{display:inline-block;min-width:44px;text-align:center;padding:1px 6px;border-radius:6px;font-weight:700;font-size:12px}
.PASS,.OK{color:var(--pass);background:var(--pass-bg)}.WARN{color:var(--warn);background:var(--warn-bg)}
.FAIL,.ERROR{color:var(--fail);background:var(--fail-bg)}.SKIP{color:var(--skip);background:var(--skip-bg)}
details{border:1px solid var(--line);border-radius:8px;margin:10px 0}
summary{cursor:pointer;padding:10px 12px;font-weight:600;overflow-wrap:anywhere}
details table{margin:0 0 4px}details td:last-child{overflow-wrap:anywhere}
.fix{color:var(--muted);font-size:12.5px}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
footer{margin-top:32px;padding-top:12px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
a{color:inherit}
@media print{details{break-inside:avoid}summary{list-style:none}}
"""


def render_html(reports: list[HostReport], generated: str) -> str:
    e = html.escape
    ids = list(TITLES)
    head = "".join(f'<th title="{e(TITLES[i])}">{e(i)}</th>' for i in ids)
    rows = []
    for r in reports:
        cells = {c.id: c for c in r.checks}
        tds = "".join(f'<td><span class="b {cells[i].status}" title="{e(cells[i].reason)}">{cells[i].status}</span></td>'
                      if i in cells else "<td></td>" for i in ids)
        rows.append(f'<tr><td><a href="#h{len(rows)}">{e(r.host)}</a></td>'
                    f'<td><span class="b {r.status}">{r.status}</span></td>{tds}</tr>')
    details = []
    for n, r in enumerate(reports):
        body = f"<p>{e(r.error)}</p>" if r.error else "<div class=wrap><table><tr><th>Result</th><th>Check</th><th>Why</th></tr>" + "".join(
            f'<tr><td><span class="b {c.status}">{c.status}</span></td><td>{e(c.title)}</td><td>{e(c.reason)}'
            + (f'<div class=fix>Fix: <code>{e(c.fix)}</code></div>' if c.fix and c.status in ("WARN", "FAIL") else "")
            + (f'<div class=fix>Limited: {e(c.limited)}</div>' if c.limited else "") + "</td></tr>"
            for c in r.checks) + "</table></div>"
        note = f'<p class="muted">{e(limited_note(r))}</p>' if limited_note(r) else ""
        details.append(f'<details id="h{n}"{" open" if r.status != "OK" else ""}><summary>'
                       f'<span class="b {r.status}">{r.status}</span> {e(r.host)} '
                       f'<span class="muted">{e(r.os)} {e(r.manager)}</span></summary>{body}{note}</details>')
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Auto-patching check</title><style>{_CSS}</style></head><body><main>
<h1>Is auto-patching actually working?</h1>
<p class="muted">unattended-upgrades-check {e(__version__)} &middot; generated {e(generated)} &middot; {e(summary(reports))}</p>
<div class="wrap"><table class="m"><tr><th>Host</th><th>Overall</th>{head}</tr>{"".join(rows)}</table></div>
<h2>Details</h2>{"".join(details)}
<footer>Read-only checks over SSH by <a href="{REPO}">unattended-upgrades-check</a> (Apache-2.0).
OS end-of-life dates: endoflife.date. CVE-level proof per server:
<a href="https://github.com/HostCrust/patch-proof">HostCrust Patch Proof</a>.</footer>
</main></body></html>
"""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_outputs(reports: list[HostReport], html_path: str | None, json_path: str | None, prom_path: str | None) -> None:
    generated = now_utc()
    if html_path:
        write_atomic(html_path, render_html(reports, generated))
    if json_path:
        text = json.dumps(to_dict(reports, generated), indent=2) + "\n"
        if json_path == "-":
            print(text, end="")
        else:
            write_atomic(json_path, text)
    if prom_path:
        write_atomic(prom_path, prometheus(reports))
