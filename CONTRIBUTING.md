# Contributing

Issues and pull requests are welcome. Small, focused changes are easiest to review.

- **Run the tests** (Python 3.9+, no servers or network needed):
  `python3 -m unittest discover -s tests -t .`
- **Keep `collect.sh` read-only, POSIX `sh` and short** (under 200 lines). It must never
  change a server; the tests check this. Edit `collect.sh` at the top level, then copy it to
  `unattended_upgrades_check/collect.sh` (a test checks that both are identical).
- **New or changed checks need a fixture.** Fixtures in `tests/fixtures/` are synthetic:
  never paste real collector output from a server you don't own, and remove hostnames, IPs
  and package names that identify a customer from anything you share.
- **No runtime dependencies.** Standard library only.
- **End-of-life data** (`unattended_upgrades_check/eol.json`) comes from
  [endoflife.date](https://endoflife.date); update the `retrieved` date when you refresh it.

By contributing you agree that your contribution is licensed under Apache-2.0.
Security issues: see [SECURITY.md](SECURITY.md).
