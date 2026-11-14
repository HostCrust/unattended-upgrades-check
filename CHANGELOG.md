# Changelog

## 1.0.1 (unreleased)

- Services check: when needrestart reports systemd itself (`systemd-manager`), the suggested fix is now
  `sudo systemctl daemon-reexec` instead of a `systemctl restart systemd-manager` that would fail.

## 1.0.0 (14 Nov 2026)

- First release: 12 read-only checks over SSH for unattended-upgrades and dnf-automatic, with text, HTML, JSON
  and Prometheus output.
