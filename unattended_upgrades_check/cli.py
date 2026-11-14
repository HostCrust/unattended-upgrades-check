"""The ``uuc`` / ``unattended-upgrades-check`` command line."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from importlib import resources
from pathlib import Path

from . import __version__
from .checks import HostReport, evaluate
from .report import exit_code, terminal, write_outputs

ERROR_EXIT = 3


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors exit 3 ("unknown"), not 2 ("fail")
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(ERROR_EXIT)


def script() -> bytes:
    return resources.files(__package__).joinpath("collect.sh").read_bytes()


def ssh_config_hosts(path: str) -> list[str]:
    """Host aliases from an OpenSSH client config; patterns (*, ?, !) are skipped, Include is not followed."""
    hosts: list[str] = []
    for line in Path(path).expanduser().read_text(encoding="utf-8").splitlines():
        words = line.strip().replace("=", " ", 1).split()
        if len(words) > 1 and words[0].lower() == "host":
            hosts += [h for h in words[1:] if not re.search(r"[*?!]", h) and h not in hosts]
    return hosts


def hosts_file(path: str) -> list[str]:
    """One host per line; '#' starts a comment."""
    return [line.split("#", 1)[0].split()[0] for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.split("#", 1)[0].strip()]


def valid_host(host: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.@%:\[\]-]+", host)) and not host.startswith("-")


def collect(host: str, args: argparse.Namespace) -> HostReport:
    """Run collect.sh on one host over ssh (read-only) and evaluate it."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(args.timeout, 15)}"]
    for opt in args.ssh_option:
        cmd += ["-o", opt]
    cmd += [host, "sudo -n sh -s" if args.sudo else "sh -s"]
    try:
        proc = subprocess.run(cmd, input=script(), capture_output=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return HostReport(host, error=f"timed out after {args.timeout} s")
    except OSError as exc:
        return HostReport(host, error=f"could not run ssh: {exc}")
    out = proc.stdout.decode("utf-8", "replace")
    if "# uuc-collector" not in out:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        why = err[-1] if err else f"exit status {proc.returncode}"
        return HostReport(host, error=("ssh failed: " if proc.returncode == 255 else "the collector did not run: ") + why)
    return evaluate(out, host)


def cmd_check(args: argparse.Namespace) -> list[HostReport]:
    hosts = list(args.hosts)
    for path in args.hosts_file:
        hosts += hosts_file(path)
    if args.ssh_config:
        hosts += ssh_config_hosts("~/.ssh/config")
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        raise SystemExit("uuc: no hosts given (name them, or use --hosts-file / --ssh-config)")
    bad = [h for h in hosts if not valid_host(h)]
    if bad:
        raise SystemExit(f"uuc: not a valid host name: {bad[0]!r}")
    if len(hosts) > 1 and sys.stderr.isatty():
        print(f"Checking {len(hosts)} hosts, {min(args.parallel, len(hosts))} at a time ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        return list(pool.map(lambda h: collect(h, args), hosts))


def cmd_parse(args: argparse.Namespace) -> list[HostReport]:
    reports = []
    for path in args.files:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8", errors="replace")
        reports.append(evaluate(text, "stdin" if path == "-" else Path(path).stem))
    return reports


def build_parser() -> argparse.ArgumentParser:
    p = Parser(prog="uuc", description="Is unattended-upgrades (or dnf-automatic) actually patching your servers? "
               "Twelve read-only checks per server, over SSH, with nothing installed.")
    p.add_argument("--version", action="version", version=f"unattended-upgrades-check {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=Parser)
    outputs = argparse.ArgumentParser(add_help=False)
    outputs.add_argument("--html", metavar="FILE", help="write one self-contained HTML report")
    outputs.add_argument("--json", metavar="FILE", help="write the results as JSON ('-' for stdout, instead of the table)")
    outputs.add_argument("--prometheus", metavar="FILE", help="write a node_exporter textfile (.prom)")
    outputs.add_argument("--no-color", action="store_true", help="no colours in the terminal table (also: NO_COLOR=1)")

    c = sub.add_parser("check", parents=[outputs], help="check hosts over SSH (read-only)")
    c.add_argument("hosts", nargs="*", help="ssh destinations: host, user@host or an alias from ~/.ssh/config")
    c.add_argument("-f", "--hosts-file", action="append", default=[], metavar="FILE", help="file with one host per line")
    c.add_argument("--ssh-config", action="store_true", help="check every Host alias in ~/.ssh/config (patterns skipped)")
    c.add_argument("--sudo", action="store_true", help="run the collector with 'sudo -n' so no check is limited")
    c.add_argument("-o", "--ssh-option", action="append", default=[], metavar="OPT", help="extra ssh -o option, e.g. Port=2222")
    c.add_argument("-j", "--parallel", type=int, default=10, metavar="N", help="hosts checked at once (default 10)")
    c.add_argument("--timeout", type=int, default=120, metavar="SEC", help="per-host time limit (default 120)")
    c.set_defaults(func=cmd_check)

    pa = sub.add_parser("parse", parents=[outputs], help="check saved collector output (from: ssh host 'sh -s' < collect.sh)")
    pa.add_argument("files", nargs="+", help="collector output files ('-' for stdin); the file name is the host label")
    pa.set_defaults(func=cmd_parse)

    s = sub.add_parser("script", help="print collect.sh, to read it or to run it yourself")
    s.set_defaults(func=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.func is None:
        sys.stdout.write(script().decode("utf-8"))
        return 0
    try:
        reports = args.func(args)
        write_outputs(reports, args.html, args.json, args.prometheus)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return ERROR_EXIT
    except OSError as exc:
        print(f"uuc: {exc}", file=sys.stderr)
        return ERROR_EXIT
    if args.json != "-":
        color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
        sys.stdout.write(terminal(reports, color))
    return exit_code(reports)


if __name__ == "__main__":
    sys.exit(main())
