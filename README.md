# Is unattended-upgrades (or dnf-automatic) actually patching your servers?

`unattended-upgrades-check` (`uuc`) answers that for one server or a whole fleet, ten servers at a time, in seconds each.
It runs 12 read-only checks over SSH on Ubuntu, Debian, AlmaLinux and Rocky Linux and gives each
server PASS, WARN or FAIL, with the reason and the fix. Nothing is installed on the servers, no
root is needed, and nothing on them is changed.

```sh
pipx install git+https://github.com/HostCrust/unattended-upgrades-check
uuc check web-01 web-02
```

"Installed and enabled" is not "patching". unattended-upgrades and dnf-automatic fail silently: an
empty allowed-origins list, a disabled timer, a dpkg lock, a held package or a reboot nobody did
all look fine until you check. This tool checks.

## What you get

Output for three example servers (synthetic data, trimmed):

```text
$ uuc check web-01 web-02 db-01
OK    web-01  (Ubuntu 24.04.5 LTS)
  PASS  Auto-update tool installed    unattended-upgrades 2.9.1+nmu4ubuntu1 is installed
  PASS  Last successful run           last successful run 2 h ago (2026-11-14 06:20 UTC)
  ...

FAIL  web-02  (Ubuntu 22.04.5 LTS)
  PASS  Auto-update tool installed    unattended-upgrades 2.8ubuntu1 is installed
  FAIL  Scheduled to run and install  apt-daily-upgrade.timer is disabled/inactive
                                      fix: sudo systemctl unmask apt-daily-upgrade.timer; sudo systemctl enable --now apt-daily-upgrade.timer
  FAIL  Security updates allowed      Allowed-Origins and Origins-Pattern are empty: unattended-upgrades runs but installs nothing
  FAIL  Last successful run           the last run, 6 days ago (2026-11-08 06:30 UTC), failed: Lock could not be acquired (another package manager running?)
  WARN  Held or excluded packages     held: nginx-core (these never get automatic updates)
  WARN  Security updates waiting      5 security update(s) waiting: libssl3, openssl, curl, libcurl4, sudo; package lists refreshed 3 h ago
  FAIL  Reboot required               reboot required for 12 days (since 2026-11-02 08:00 UTC), for linux-base, linux-image-5.15.0-126-generic
  WARN  Services needing restart      2 service(s) still run replaced library code: cron.service, ssh.service
  FAIL  Running kernel                running 5.15.0-122-generic, but 5.15.0-126-generic was installed 12 days ago: its fixes are not active until a reboot
  WARN  Live kernel patching          Canonical Livepatch is installed but not enabled
  PASS  OS end of life                security support until 2027-06-01 (endoflife.date, 2026-11-14)

FAIL  db-01  (Rocky Linux 9.5 (Blue Onyx))
  FAIL  Scheduled to run and install  dnf-automatic.timer runs but apply_updates is not yes: updates are only downloaded or announced, never installed
                                      fix: set apply_updates = yes in /etc/dnf/automatic.conf, or sudo systemctl enable --now dnf-automatic-install.timer
  ...

3 host(s): 1 OK, 2 FAIL
```

Add `--html report.html` for one self-contained page with a host-by-check matrix, `--json report.json`
for scripts, and `--prometheus uuc.prom` for monitoring.

## The 12 checks, and how each one fails silently

| # | Check | What it reads (apt / dnf) | How it fails silently | Result |
|---|---|---|---|---|
| 1 | **Installed** | `unattended-upgrades` / `dnf-automatic` package | Minimal and custom images often ship without it. | FAIL if missing |
| 2 | **Scheduled to run and install** | `apt-daily.timer` and `apt-daily-upgrade.timer`, `APT::Periodic::Update-Package-Lists` and `::Unattended-Upgrade` (via `apt-config dump`) / `dnf-automatic(-install).timer`, `apply_updates` | The package is installed but a timer is disabled or masked, a periodic value is `"0"`, or dnf-automatic runs with `apply_updates = no` (its default), so it only downloads. | FAIL if it never installs; WARN if it runs less than daily |
| 3 | **Security updates allowed** | `Unattended-Upgrade::Allowed-Origins` / `Origins-Pattern`, matched against the archives apt knows, the way unattended-upgrades matches them / `upgrade_type` | An empty origins list installs nothing ([Ubuntu Pro docs][pro]). An old codename-based pattern stopped matching the Debian security archive when it was renamed to `<codename>-security` in Debian 11 ([release notes 5.1.3][deb11]). Ubuntu Pro ESM enabled but not allowed. | FAIL if no security archive is matched; WARN if ESM is not allowed |
| 4 | **Last successful run** | apt's `upgrade-stamp`, the unattended-upgrades log and stamp, the list-refresh stamps / `dnf-automatic` service result and timer | The job runs but fails every day (lock, conffile prompt, broken repo), or package lists stop refreshing, so no new updates are seen. | WARN after 2 days, FAIL after 7, FAIL if the last run failed |
| 5 | **Package manager errors** | `/var/lib/dpkg/updates`, `dpkg --audit`, log and journal errors from the last 14 days | "dpkg was interrupted" or a half-installed package blocks every later install. | FAIL for dpkg state; WARN for log errors |
| 6 | **Held or excluded packages** | `apt-mark showhold`, `Package-Blacklist` / dnf versionlock list, `exclude=` | A hold added for one upgrade years ago keeps that package unpatched forever. | WARN |
| 7 | **Security updates waiting** | `apt list --upgradable` (security pockets) / `dnf -C updateinfo list --security`, from the local cache only | Updates are available but skipped; on apt, FAIL if they were already there at the last successful run. | WARN, or FAIL as described |
| 8 | **Reboot required** | `/var/run/reboot-required` and its package list, and since when / `dnf needs-restarting -r` | Updates install fine, but the fixed kernel or libc only takes effect after a reboot nobody schedules. | WARN, FAIL after 7 days |
| 9 | **Services needing restart** | `needrestart -b` (list mode) / `dnf needs-restarting -s` | Long-running services keep the old, vulnerable library in memory. | WARN |
| 10 | **Running kernel** | `uname -r` against the newest kernel in `/boot` | A newer kernel is installed but not running. | WARN, FAIL after 7 days (WARN if Livepatch is active) |
| 11 | **Live kernel patching** | `/sys/kernel/livepatch`, `canonical-livepatch status`, `kpatch list` | Livepatch is installed but not enabled, or the kernel is not covered. | WARN if installed but off; SKIP if not used |
| 12 | **OS end of life** | `/etc/os-release` against bundled [endoflife.date][eol] data | The job works perfectly, but the release no longer gets security updates. | FAIL after the end date, WARN within 180 days (or while Ubuntu Pro ESM covers it) |

A check is SKIP when it does not apply (for example, kernel checks in a container) or a tool is
missing. SKIP never changes a host's overall result.

## How it works

1. `uuc check HOST` runs `ssh -o BatchMode=yes HOST 'sh -s'` and pipes in [`collect.sh`](collect.sh),
   a short POSIX shell script you can read in two minutes (`uuc script` prints it).
2. `collect.sh` prints the state above as plain text: no hostnames, IP addresses, user names or
   machine IDs. It is read-only and offline. It never runs `apt update`, `dnf makecache`, an
   install, or a restart. apt runs with its on-disk cache file turned off, and dnf runs with
   `-C` (cache only). When run as root, dnf may append to its own log in `/var/log`.
3. The CLI parses that text on your machine and applies the 12 checks. Python 3.9+, standard
   library only, nothing fetched at run time.

**Without root** most checks work. The unattended-upgrades log, the journal, other users'
processes and the dnf cache need root (or the `adm` group on Debian/Ubuntu). The report names each
check that was limited. `--sudo` runs the collector with `sudo -n`, which never prompts.

**Already have the output?** Run the collector any way you like and check the files later:

```sh
ssh web-01 'sh -s' < collect.sh > web-01.txt
uuc parse web-01.txt web-02.txt --html report.html
```

## Usage

```text
uuc check HOST... [-f HOSTS_FILE] [--ssh-config] [--sudo] [-o SSH_OPTION] [-j N] [--timeout SEC]
                  [--html FILE] [--json FILE|-] [--prometheus FILE] [--no-color]
uuc parse FILE... [--html FILE] [--json FILE|-] [--prometheus FILE]
uuc script
```

- **Hosts** are anything `ssh` accepts: `web-01`, `admin@10.0.0.5`, or an alias from `~/.ssh/config`.
  `-f hosts.txt` reads one per line (`#` comments). `--ssh-config` checks every `Host` alias in
  `~/.ssh/config` (patterns such as `*` are skipped). Your ssh config, keys and agent are used as usual.
- **Parallel**: 10 hosts at a time by default (`-j`), 120 s limit per host (`--timeout`).
- **Exit codes**, for cron and monitoring: `0` all OK, `1` a warning, `2` a failure, `3` a host
  could not be checked (a failure still returns 2).

Daily from cron, with a report and a Prometheus textfile for node_exporter:

```sh
15 7 * * * uuc check -f /etc/uuc/hosts --html /var/www/uuc.html --prometheus /var/lib/node_exporter/uuc.prom >/dev/null
```

Metrics: `uuc_host_status`, `uuc_check_status{check=...}`, `uuc_pending_security_updates`,
`uuc_reboot_required`, `uuc_kernel_outdated`, `uuc_last_success_timestamp_seconds`,
`uuc_os_eol_timestamp_seconds`, `uuc_collected_timestamp_seconds`, each with a `host` label.

## FAQ

### How can I check that unattended-upgrades is actually working on all my Ubuntu servers?

Seeing the package installed or the service enabled does not prove updates are being installed.
Check that (1) `apt-daily.timer` and `apt-daily-upgrade.timer` are enabled and active,
(2) `apt-config dump | grep Periodic` shows `Update-Package-Lists "1"` and `Unattended-Upgrade "1"`,
(3) the allowed origins include your `-security` pocket, and that it is in your apt sources,
(4) `/var/log/unattended-upgrades/unattended-upgrades.log` shows a recent run that ended with
"All upgrades installed" or "No packages found that can be upgraded", and (5) no security updates
are left waiting. `uuc check --ssh-config` does all of this, and the other checks in the table, for
every server in `~/.ssh/config` at once.

### How do I find which Linux servers need a reboot or a service restart after updates?

On Debian and Ubuntu, `/var/run/reboot-required` exists when a reboot is needed, and
`/var/run/reboot-required.pkgs` lists the packages that asked for it. `needrestart -b` lists services
still running old library code. On AlmaLinux, Rocky Linux and RHEL, `dnf needs-restarting -r` says
whether a reboot is needed and `dnf needs-restarting -s` lists services to restart. Also compare
`uname -r` with the newest kernel in `/boot`. `uuc check` reports all of these per server, including
how many days the reboot has been pending.

### Where is the unattended-upgrades log?

`/var/log/unattended-upgrades/unattended-upgrades.log` (each run's decisions and errors) and
`/var/log/unattended-upgrades/unattended-upgrades-dpkg.log` (dpkg output). The systemd side is in
`journalctl -u apt-daily.service -u apt-daily-upgrade.service`, and every apt transaction is in
`/var/log/apt/history.log`. On Ubuntu the log directory is readable by root and the `adm` group only.

### Does dnf-automatic install security updates only?

Only if you set `upgrade_type = security` in `/etc/dnf/automatic.conf`. The default, `default`, means
all available updates. And dnf-automatic installs nothing at all unless `apply_updates = yes`
(the default is no) or you use `dnf-automatic-install.timer`, which installs regardless of that
setting ([dnf-automatic docs][dnf]). `uuc check` reports which timer is on and what it will do.

### Does it change anything on my servers?

No. See [How it works](#how-it-works) and [SECURITY.md](SECURITY.md). A test fails the build if a
command that could change a server is added to `collect.sh`.

## Compared with other ways

| Option | What it is | When to use it instead |
|---|---|---|
| By hand | The commands in the FAQ, on each server | One or two servers |
| Ubuntu Pro client: `pro api u.unattended_upgrades.status.v1` | Reports whether unattended-upgrades is configured to run, per [Canonical's docs][pro] | Ubuntu only, one host at a time; no reboot, kernel, held-package or EOL checks |
| [Landscape][landscape] | Canonical's management product for Ubuntu: a client on each machine and a server (self-hosted or SaaS); part of Ubuntu Pro | You want central patching and compliance for an Ubuntu estate |
| [PatchMon][patchmon] | Open-source (AGPL-3.0) patch-monitoring platform: an agent on each host reports to a PatchMon server | You want an always-on dashboard of pending updates across many OSes |
| [check_unattended_upgrades][nagios] | Nagios plugin | You already run Nagios/Icinga and only use Debian/Ubuntu |
| [needrestart][needrestart] / `dnf needs-restarting` | Restart detection on one host | You only need the restart part |

They do more; this is a 2-minute check that needs nothing installed. We have not tested whether
Landscape or PatchMon verify the auto-update job itself (timers, origins, last result); their
descriptions above come from their own pages (November 2026).

**Need CVE-level proof?** This tool tells you whether the patching *job* works. To see which CVEs are
really still open on a server, taking distro backports into account, use
[HostCrust Patch Proof](https://github.com/HostCrust/patch-proof).

## Limits

- Supported: Ubuntu 20.04+, Debian 11+, AlmaLinux 8+, Rocky Linux 8+ (other apt/dnf systems run,
  but the end-of-life check is skipped). Tested with synthetic fixtures for all four and on a real
  Ubuntu 24.04 server.
- "Security updates waiting" is only as fresh as the server's package lists; the report shows how
  old they are. On apt it counts upgradable packages whose candidate version comes from a
  `-security` pocket, so the count can differ from what unattended-upgrades would pick.
- Systems without systemd: the timer checks are skipped and the report says so. Cron-only
  setups are not checked.
- KernelCare and other live-patching products are not detected, except through `/sys/kernel/livepatch`.
- End-of-life dates are bundled ([endoflife.date][eol], retrieved 2026-11-14) and never fetched at
  run time; update the tool to refresh them.

## Development

```sh
python3 -m unittest discover -s tests -t .    # offline, no servers needed
```

Fixtures in [`tests/fixtures/`](tests/fixtures/) are synthetic collector outputs for healthy and broken
Ubuntu, Debian, AlmaLinux and Rocky Linux hosts. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. Copyright 2026 DigiRDP, LLC (HostCrust). End-of-life data from endoflife.date (MIT),
see [NOTICE](NOTICE).

[pro]: https://documentation.ubuntu.com/pro-client/en/docs/explanations/how_to_interpret_output_of_unattended_upgrades/
[deb11]: https://www.debian.org/releases/bullseye/amd64/release-notes.en.txt
[dnf]: https://dnf.readthedocs.io/en/latest/automatic.html
[eol]: https://endoflife.date
[landscape]: https://ubuntu.com/landscape
[patchmon]: https://github.com/PatchMon/PatchMon
[nagios]: https://github.com/Josef-Friedrich/check_unattended_upgrades
[needrestart]: https://github.com/liske/needrestart

Want this checked every day for every server, with receipts? HostCrust (launching soon): https://hostcrust.com
