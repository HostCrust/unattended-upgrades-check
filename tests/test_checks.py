"""The 12 checks against synthetic collector output in tests/fixtures/. Offline: no servers needed."""

import unittest
from pathlib import Path

from unattended_upgrades_check.checks import (
    TITLES,
    evaluate,
    legacy_origin,
    origin_matches,
    periodic_days,
)
from unattended_upgrades_check.parse import natural_key, systemd_time, uu_runs

FIXTURES = Path(__file__).parent / "fixtures"

# Columns: installed schedule origins last-run errors held pending reboot services kernel livepatch eol
EXPECTED = {
    "ubuntu-24.04-healthy": ("OK", "PASS PASS PASS PASS PASS PASS PASS PASS PASS PASS PASS PASS"),
    "ubuntu-24.04-nonroot": ("OK", "PASS PASS PASS PASS PASS PASS PASS PASS SKIP PASS SKIP PASS"),
    "ubuntu-22.04-broken": ("FAIL", "PASS FAIL FAIL FAIL WARN WARN WARN FAIL WARN FAIL WARN PASS"),
    "ubuntu-20.04-esm": ("FAIL", "PASS PASS WARN PASS PASS WARN FAIL PASS PASS PASS SKIP WARN"),
    "debian-12-healthy": ("OK", "PASS PASS PASS PASS PASS PASS PASS PASS SKIP PASS SKIP PASS"),
    "debian-11-broken": ("FAIL", "PASS FAIL FAIL FAIL FAIL PASS WARN PASS SKIP PASS SKIP FAIL"),
    "almalinux-9-healthy": ("OK", "PASS PASS PASS PASS PASS PASS PASS PASS PASS PASS SKIP PASS"),
    "rocky-9-broken": ("FAIL", "PASS FAIL PASS FAIL WARN WARN WARN FAIL WARN FAIL SKIP PASS"),
    "almalinux-8-container-nonroot": ("FAIL", "FAIL SKIP SKIP SKIP PASS PASS SKIP SKIP SKIP SKIP SKIP PASS"),
}

# (check, words the reason must contain): the "why" a user sees for each broken case.
REASONS = {
    "ubuntu-22.04-broken": [
        ("schedule", "apt-daily-upgrade.timer is disabled/inactive"),
        ("origins", "Allowed-Origins and Origins-Pattern are empty"),
        ("last-run", "failed: Lock could not be acquired"),
        ("errors", "2 about the dpkg lock"),
        ("held", "held: nginx-core"),
        ("pending", "5 security update(s) waiting: libssl3, openssl, curl"),
        ("reboot", "reboot required for 12 days (since 2026-11-02 08:00 UTC), for linux-base"),
        ("services", "cron.service, ssh.service"),
        ("kernel", "running 5.15.0-122-generic, but 5.15.0-126-generic was installed 12 days ago"),
        ("livepatch", "installed but not enabled"),
    ],
    "ubuntu-20.04-esm": [
        ("origins", "UbuntuESM/focal-infra-security, UbuntuESMApps/focal-apps-security"),
        ("held", "excluded by Package-Blacklist: linux-"),
        ("pending", "already available at the last successful run and were not installed"),
        ("eol", "Ubuntu Pro ESM is enabled and covers it until 2030-04-23"),
        ("last-run", "2026-11-14 06:20 UTC"),  # log written at UTC-5, converted
    ],
    "debian-11-broken": [
        ("schedule", 'APT::Periodic::Unattended-Upgrade is "0"'),
        ("origins", "match none of the security archives (Debian/oldoldstable-security)"),
        ("last-run", "conffile prompt"),
        ("errors", "dpkg was interrupted"),
        ("pending", "25 days old"),
        ("eol", "reached end of life on 2026-08-31"),
    ],
    "rocky-9-broken": [
        ("schedule", "apply_updates is not yes"),
        ("last-run", "dnf-automatic.service failed 26 h ago (2026-11-13 06:21 UTC) with result exit-code"),
        ("errors", "2 error line(s)"),
        ("held", "versionlocked: kernel-0:5.14.0-503.11.1.el9_5.*; excluded in dnf.conf: docker-ce*"),
        ("pending", "3 package update(s) from 2 security advisories"),
        ("reboot", "reboot required for 12 days"),
        ("services", "chronyd.service, sshd.service"),
        ("kernel", "but 5.14.0-570.17.1.el9_6.x86_64 was installed 12 days ago"),
    ],
    "almalinux-8-container-nonroot": [
        ("installed", "dnf-automatic is not installed"),
        ("kernel", "lxc container"),
    ],
}


def fixture(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text(encoding="utf-8")


class FixtureTests(unittest.TestCase):
    def test_every_fixture_gives_the_expected_status_per_check(self):
        for name, (overall, statuses) in EXPECTED.items():
            with self.subTest(name):
                rep = evaluate(fixture(name), name)
                self.assertEqual(rep.error, "")
                self.assertEqual([c.id for c in rep.checks], list(TITLES))
                self.assertEqual(" ".join(c.status for c in rep.checks), statuses)
                self.assertEqual(rep.status, overall)

    def test_reasons_name_the_cause(self):
        for name, wanted in REASONS.items():
            checks = {c.id: c for c in evaluate(fixture(name), name).checks}
            for check, words in wanted:
                with self.subTest(name=name, check=check):
                    self.assertIn(words, checks[check].reason)

    def test_every_warn_and_fail_has_a_fix(self):
        for name in EXPECTED:
            for c in evaluate(fixture(name), name).checks:
                if c.status in ("WARN", "FAIL"):
                    with self.subTest(name=name, check=c.id):
                        self.assertTrue(c.fix)

    def test_limited_checks_are_reported_without_root(self):
        rep = evaluate(fixture("ubuntu-24.04-nonroot"), "h")
        self.assertFalse(rep.root)
        self.assertEqual(sorted(c.id for c in rep.checks if c.limited), ["errors", "last-run", "services"])
        self.assertFalse(any(c.limited for c in evaluate(fixture("ubuntu-24.04-healthy"), "h").checks))

    def test_metrics(self):
        m = evaluate(fixture("ubuntu-22.04-broken"), "h").metrics
        self.assertEqual((m["pending_security"], m["reboot_required"], m["kernel_outdated"]), (5, 1, 1))
        self.assertEqual(m["last_success"], 1793527201)  # the last good run in the log; the later one failed
        self.assertEqual(m["eol"], 1811808000)  # 2027-06-01


class VariantTests(unittest.TestCase):
    """Small edits to a healthy fixture, one condition at a time."""

    def run_variant(self, old: str, new: str, base: str = "ubuntu-24.04-healthy"):
        text = fixture(base)
        self.assertIn(old, text)
        return {c.id: c for c in evaluate(text.replace(old, new), "h").checks}

    def test_eol_warns_within_180_days(self):
        c = self.run_variant('VERSION_ID="24.04"', 'VERSION_ID="22.04"')["eol"]
        self.assertEqual(c.status, "PASS")  # 199 days left on 2026-11-14
        text = fixture("ubuntu-24.04-healthy").replace('VERSION_ID="24.04"', 'VERSION_ID="22.04"')
        c = {c.id: c for c in evaluate(text.replace("now=1794646800", "now=1796428800"), "h").checks}["eol"]
        self.assertEqual(c.status, "WARN")  # on 2026-12-05
        self.assertIn("reaches end of life in 178 days, on 2027-06-01", c.reason)

    def test_eol_without_esm_fails_and_unknown_release_skips(self):
        c = self.run_variant('VERSION_ID="24.04"', 'VERSION_ID="20.04"')["eol"]
        self.assertEqual(c.status, "FAIL")
        self.assertIn("Ubuntu Pro ESM until 2030-04-23", c.reason)
        self.assertEqual(self.run_variant('VERSION_ID="24.04"', 'VERSION_ID="99.04"')["eol"].status, "SKIP")

    def test_livepatch_turns_an_old_kernel_fail_into_warn(self):
        text = fixture("ubuntu-22.04-broken").replace("## livepatch\n", "## livepatch\nmodule=lkp_Ubuntu_5_15_0_122 1\n")
        kernel = {c.id: c for c in evaluate(text, "h").checks}["kernel"]
        self.assertEqual(kernel.status, "WARN")
        self.assertIn("Livepatch covers", kernel.reason)

    def test_systemd_manager_is_reexecuted_not_restarted(self):
        text = fixture("ubuntu-22.04-broken").replace("NEEDRESTART-SVC: cron.service\n",
                                                      "NEEDRESTART-SVC: cron.service\nNEEDRESTART-SVC: systemd-manager\n")
        c = {c.id: c for c in evaluate(text, "h").checks}["services"]
        self.assertEqual(c.status, "WARN")
        self.assertIn("sudo systemctl daemon-reexec", c.fix)
        self.assertNotIn("restart systemd-manager", c.fix)
        self.assertIn("sudo systemctl restart cron.service ssh.service", c.fix)

    def test_no_systemd_limits_the_schedule_check(self):
        text = fixture("ubuntu-24.04-healthy")
        text = text[:text.index("## systemd")] + text[text.index("## apt\n"):]
        c = {c.id: c for c in evaluate(text, "h").checks}["schedule"]
        self.assertEqual(c.status, "PASS")
        self.assertIn("systemd is not running", c.limited)

    def test_weekly_schedule_warns_and_masked_timer_fails(self):
        c = self.run_variant('Unattended-Upgrade "1"', 'Unattended-Upgrade "7"')["schedule"]
        self.assertEqual((c.status, "every 7 days" in c.reason), ("WARN", True))
        c = self.run_variant("Id=apt-daily.timer\nLoadState=loaded", "Id=apt-daily.timer\nLoadState=masked")["schedule"]
        self.assertEqual(c.status, "FAIL")
        self.assertIn("apt-daily.timer is masked", c.reason)

    def test_stale_last_run_and_lists(self):
        c = self.run_variant("upgrade-stamp=1794637200", "upgrade-stamp=1794200000")["last-run"]  # 5 days
        self.assertEqual(c.status, "PASS")  # the log shows a successful run today
        text = fixture("ubuntu-24.04-nonroot").replace("upgrade-stamp=1794637200", "upgrade-stamp=1794200000")
        c = {c.id: c for c in evaluate(text, "h").checks}["last-run"]
        self.assertEqual(c.status, "WARN")
        # Without root and without apt's success stamp, unattended-upgrades' own stamp still dates the last run.
        text = fixture("ubuntu-24.04-nonroot").replace("upgrade-stamp=1794637200", "unattended-upgrades-stamp=1714111695")
        c = {c.id: c for c in evaluate(text, "h").checks}["last-run"]
        self.assertEqual(c.status, "FAIL")
        self.assertIn("last ran 932 days ago (2024-04-26 06:08 UTC), result unknown without the log", c.reason)
        c = self.run_variant("update-stamp=1794634800\nupdate-success-stamp=1794634800",
                             "update-stamp=1793000000\nupdate-success-stamp=1793000000")["last-run"]
        self.assertEqual(c.status, "FAIL")
        self.assertIn("package lists last refreshed 19 days ago", c.reason)

    def test_not_installed_skips_dependent_checks(self):
        checks = self.run_variant("uu=ii 2.9.1+nmu4ubuntu1", "uu=")
        self.assertEqual(checks["installed"].status, "FAIL")
        self.assertEqual([checks[i].status for i in ("schedule", "origins", "last-run")], ["SKIP"] * 3)

    def test_dnf_automatic_timer_with_apply_updates_yes_passes(self):
        text = fixture("rocky-9-broken").replace("conf_apply_updates=no", "conf_apply_updates=yes")
        self.assertEqual({c.id: c for c in evaluate(text, "h").checks}["schedule"].status, "PASS")

    def test_bad_input(self):
        self.assertIn("not unattended-upgrades-check collector output", evaluate("hello", "h").error)
        truncated = fixture("ubuntu-24.04-healthy").split("## livepatch")[0]
        self.assertIn("incomplete", evaluate(truncated, "h").error)
        self.assertIn("no 'now=' timestamp", evaluate("# uuc-collector 1\n## meta\n## end\n", "h").error)
        odd = fixture("ubuntu-24.04-healthy").replace('ID=ubuntu', 'ID=ubuntu\nVERSION_ID=').replace('VERSION_ID="24.04"\n', "")
        self.assertEqual(evaluate(odd, "h").error, "")  # an empty VERSION_ID is handled, not a crash
        no_pm = "# uuc-collector 1\n## meta\nnow=1\n## os-release\nPRETTY_NAME=Arch Linux\n## end\n"
        rep = evaluate(no_pm, "h")
        self.assertIn("neither apt nor dnf", rep.error)
        self.assertEqual(rep.status, "ERROR")


class UnitTests(unittest.TestCase):
    def test_origin_patterns_match_like_unattended_upgrades(self):
        security = {"o": "Debian", "a": "oldoldstable-security", "n": "bullseye-security", "l": "Debian-Security"}
        self.assertFalse(origin_matches("origin=Debian,codename=bullseye,label=Debian-Security", security))
        self.assertTrue(origin_matches("origin=Debian,codename=bullseye-security,label=Debian-Security", security))
        self.assertTrue(origin_matches("o=Deb*,a=*-security", security))
        self.assertTrue(origin_matches("o=Debian,site=deb.debian.org", security))  # site is not collected
        self.assertFalse(origin_matches("bogus=1", security))

    def test_legacy_allowed_origins(self):
        self.assertEqual(legacy_origin("Ubuntu:noble-security"), "o=Ubuntu,a=noble-security")
        self.assertEqual(legacy_origin("Ubuntu noble"), "o=Ubuntu,a=noble")
        self.assertEqual(legacy_origin("LP-PPA-a\\:b:noble"), "o=LP-PPA-a:b,a=noble")

    def test_periodic_intervals(self):
        cases = {"1": 1, "0": None, "7": 7, "12h": 0.5, "always": 0.0, "": None, "x": None}
        for value, days in cases.items():
            self.assertEqual(periodic_days(value), days, value)

    def test_log_runs(self):
        runs = uu_runs([
            "2026-11-13 01:20:00,000 INFO Starting unattended upgrades script",
            "2026-11-13 01:20:09,000 INFO All upgrades installed",
            " continuation line",
            "2026-11-14 01:20:00,000 ERROR Lock file is already taken, exiting",
            "2026-11-15 01:20:00,000 INFO Starting unattended upgrades script",
        ], "-0500")
        self.assertEqual([r.outcome for r in runs], ["ok", "error", "incomplete"])
        self.assertEqual(runs[0].start, 1794550800)  # 2026-11-13 06:20 UTC
        self.assertEqual(runs[1].errors, ["Lock file is already taken, exiting"])

    def test_kernel_order_and_systemd_time(self):
        self.assertLess(natural_key("6.8.0-49-generic"), natural_key("6.8.0-149-generic"))
        self.assertLess(natural_key("5.14.0-503.11.1.el9_5.x86_64"), natural_key("5.14.0-570.17.1.el9_6.x86_64"))
        self.assertLess(natural_key("6.12.48+deb13-amd64"), natural_key("6.12.57+deb13-amd64"))
        self.assertEqual(systemd_time("Sat 2026-11-14 06:20:00 UTC"), 1794637200)
        self.assertIsNone(systemd_time(""))
        self.assertIsNone(systemd_time("n/a"))


if __name__ == "__main__":
    unittest.main()
