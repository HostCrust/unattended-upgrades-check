"""The command line, the outputs and the collector script. Offline: SSH is replaced by a fake ssh on PATH."""

import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from unattended_upgrades_check.checks import HostReport, Result, evaluate
from unattended_upgrades_check.cli import hosts_file, main, script, ssh_config_hosts, valid_host
from unattended_upgrades_check.report import prometheus, render_html

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

FAKE_SSH = """#!/bin/sh
# Fake ssh for tests: logs its arguments, keeps stdin, prints a fixture for host "good".
echo "$@" >> "$UUC_TEST_DIR/args"
eval host=\\${$(($# - 1))}
cat > "$UUC_TEST_DIR/stdin-$host"
case $host in
    good) cat "$UUC_TEST_FIXTURE" ;;
    slow) sleep 5 ;;
    *) echo "Permission denied (publickey)." >&2; exit 255 ;;
esac
"""


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class ParseCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_exit_codes(self):
        healthy, broken = FIXTURES / "ubuntu-24.04-healthy.txt", FIXTURES / "ubuntu-22.04-broken.txt"
        warn = self.dir / "warn.txt"
        warn.write_text(healthy.read_text().replace("## apt-config", "hold=nginx\n## apt-config"))
        bad = self.dir / "bad.txt"
        bad.write_text("not collector output")
        self.assertEqual(run("parse", str(healthy))[0], 0)
        self.assertEqual(run("parse", str(warn))[0], 1)
        self.assertEqual(run("parse", str(broken))[0], 2)
        self.assertEqual(run("parse", str(bad))[0], 3)
        self.assertEqual(run("parse", str(healthy), str(bad))[0], 3)
        self.assertEqual(run("parse", str(broken), str(bad))[0], 2)  # a FAIL outranks a host that errored

    def test_terminal_table(self):
        code, out, _ = run("parse", "--no-color", str(FIXTURES / "ubuntu-22.04-broken.txt"))
        self.assertIn("FAIL  ubuntu-22.04-broken  (Ubuntu 22.04.5 LTS)", out)
        self.assertIn("fix: sudo systemctl unmask apt-daily-upgrade.timer", out)
        self.assertTrue(out.rstrip().endswith("1 host(s): 1 FAIL"))
        self.assertNotIn("\033[", out)

    def test_json_to_stdout_replaces_the_table(self):
        code, out, _ = run("parse", "--json", "-", str(FIXTURES / "rocky-9-broken.txt"))
        data = json.loads(out)
        self.assertEqual((data["exit_code"], code), (2, 2))
        host = data["hosts"][0]
        self.assertEqual((host["host"], host["status"], host["manager"]), ("rocky-9-broken", "FAIL", "dnf"))
        self.assertEqual(len(host["checks"]), 12)
        self.assertEqual(host["metrics"]["pending_security"], 3)

    def test_html_is_self_contained_and_escaped(self):
        path = self.dir / "report.html"
        run("parse", "--html", str(path), *[str(p) for p in sorted(FIXTURES.glob("*.txt"))])
        page = path.read_text()
        self.assertIn("ubuntu-22.04-broken", page)
        for external in ("<script", "src=", "<link", "@import", "url("):
            self.assertNotIn(external, page)
        rep = HostReport('<img src=x onerror="alert(1)">', checks=[Result("installed", "FAIL", "<b>x</b>", "a & b")])
        page = render_html([rep], "now")
        self.assertNotIn("<img", page)
        self.assertNotIn("<b>x", page)
        self.assertIn("&lt;img src=x", page)

    def test_prometheus_textfile(self):
        path = self.dir / "uuc.prom"
        run("parse", "--prometheus", str(path), str(FIXTURES / "ubuntu-22.04-broken.txt"))
        text = path.read_text()
        self.assertIn('uuc_host_status{host="ubuntu-22.04-broken"} 2', text)
        self.assertIn('uuc_check_status{host="ubuntu-22.04-broken",check="reboot"} 2', text)
        self.assertIn('uuc_pending_security_updates{host="ubuntu-22.04-broken"} 5', text)
        for line in text.splitlines():
            self.assertRegex(line, r'^(# (HELP|TYPE) uuc_\w+ .+|uuc_\w+\{host="[^"]*"(,check="[\w-]+")?\} -?\d+)$')
        self.assertFalse(Path(f"{path}.tmp").exists())
        quoted = prometheus([HostReport('a"b\\c', error="x")])
        self.assertIn('uuc_host_status{host="a\\"b\\\\c"} 3', quoted)


class HostListTests(unittest.TestCase):
    def test_hosts_file_and_ssh_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            hosts.write_text("# fleet\nweb-01\n\n  web-02   # comment\nadmin@db-01\n")
            self.assertEqual(hosts_file(str(hosts)), ["web-01", "web-02", "admin@db-01"])
            config = Path(tmp) / "config"
            config.write_text("Host *\n  User x\nHost web-01 web-02\nhost=db-01\nMatch host x\nHost web-01 bastion-? !no\n")
            self.assertEqual(ssh_config_hosts(str(config)), ["web-01", "web-02", "db-01"])

    def test_host_names_cannot_inject_ssh_options(self):
        for good in ("web-01", "admin@db-01.example.com", "[2001:db8::1]", "10.0.0.5"):
            self.assertTrue(valid_host(good), good)
        for bad in ("-oProxyCommand=sh", "a b", "x;rm", "$(id)", ""):
            self.assertFalse(valid_host(bad), bad)


class CheckCommandTests(unittest.TestCase):
    """`uuc check` end to end, with a fake ssh that returns a fixture."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        fake = self.dir / "ssh"
        fake.write_text(FAKE_SSH)
        fake.chmod(0o755)
        self.env = {"PATH": f"{self.dir}{os.pathsep}{os.environ['PATH']}", "UUC_TEST_DIR": str(self.dir),
                    "UUC_TEST_FIXTURE": str(FIXTURES / "debian-12-healthy.txt")}
        self.saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_good_and_unreachable_hosts(self):
        code, out, _ = run("check", "--no-color", "good", "denied")
        self.assertEqual(code, 3)
        self.assertIn("OK    good", out)
        self.assertIn("ERROR denied", out)
        self.assertIn("ssh failed: Permission denied (publickey).", out)
        self.assertEqual((self.dir / "stdin-good").read_bytes(), script())  # the collector is piped over ssh
        args = (self.dir / "args").read_text()
        self.assertIn("-o BatchMode=yes", args)
        self.assertIn("good sh -s", args)

    def test_sudo_ssh_options_and_timeout(self):
        code, out, _ = run("check", "--sudo", "-o", "Port=2222", "--timeout", "1", "good", "slow")
        self.assertEqual(code, 3)
        self.assertIn("timed out after 1 s", out)
        self.assertIn("-o Port=2222 good sudo -n sh -s", (self.dir / "args").read_text())

    def test_usage_errors_exit_3(self):
        self.assertEqual(run("check")[0], 3)
        self.assertEqual(run("check", "-oProxyCommand=x")[0], 3)
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
            main(["frobnicate"])
        self.assertEqual(ctx.exception.code, 3)


class CollectorScriptTests(unittest.TestCase):
    def test_packaged_copy_is_identical(self):
        self.assertEqual((ROOT / "collect.sh").read_bytes(), script())
        self.assertEqual(run("script")[0], 0)

    def test_posix_syntax_and_size(self):
        subprocess.run(["sh", "-n", str(ROOT / "collect.sh")], check=True)
        self.assertLessEqual(len(script().splitlines()), 200)

    def test_never_changes_the_server(self):
        text = "\n".join(line for line in script().decode().splitlines() if not line.lstrip().startswith("#"))
        text = re.sub(r"'[^']*'", "''", text)  # drop quoted awk/sed programs and format strings
        forbidden = re.compile(
            r"\bapt(-get)?\s+(update|upgrade|install|remove|purge|full-upgrade|dist-upgrade)\b"
            r"|\bapt-mark\s+(?!showhold)|(?<!has )\bdnf\s+(?!-C\b)|\bmakecache\b"
            r"|\bsystemctl\s+(?!show\b)"
            r"|(^|[;&|(]|\bthen|\bdo|\belse)\s*(rm|mv|cp|touch|tee|reboot|shutdown|kill|sudo|chmod|chown)\b"
            r"|(?<![0-9])>(?!/dev/null|&)")
        for line in text.splitlines():
            self.assertIsNone(forbidden.search(line), line)
        self.assertIn("needrestart -b -r l", script().decode())  # list only, never restart

if __name__ == "__main__":
    unittest.main()
