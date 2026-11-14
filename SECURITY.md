# Security policy

Please report security problems privately to **hello@hostcrust.com**, not in a public issue.
Include the version (`uuc --version`), what you ran and what happened. We aim to reply within
3 working days and to ship a fix, with credit if you want it, before details are made public.

## Design, for reviewers

- `collect.sh` is read-only and offline: it installs, updates, refreshes and restarts nothing,
  and never runs `apt update` or `dnf makecache`. A test (`tests/test_cli.py`) fails if a
  command that could change a server is added. When run as root, `dnf` may append to its own
  log in `/var/log`; nothing else is written.
- `uuc check` runs `ssh -o BatchMode=yes HOST 'sh -s'` and pipes in the bundled `collect.sh`;
  `--sudo` uses `sudo -n` (it never asks for a password). Host names that start with `-` or
  contain shell characters are refused, so a hosts file cannot inject ssh options.
- The collector prints no hostnames, IP addresses, user names or machine IDs. Journal lines
  are trimmed of their hostname field; Livepatch output is filtered of machine-ID lines.
- The HTML report is one file with no scripts and no external requests (its Content Security
  Policy is `default-src 'none'`); every value from a server is HTML-escaped.
- No runtime dependencies beyond the Python standard library; nothing is fetched at run time.
