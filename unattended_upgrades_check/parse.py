"""Parse the collector's output (collect.sh) into sections, with small typed helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MAGIC = "# uuc-collector 1"


class CollectError(ValueError):
    """The text is not complete collector output."""


def natural_key(text: str) -> list:
    """Sort key that compares digit runs as numbers: 6.8.0-49 < 6.8.0-149."""
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", text)]


def systemd_time(value: str | None) -> int | None:
    """'Sat 2026-11-14 06:35:12 UTC' (the collector sets TZ=UTC) -> epoch seconds."""
    m = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", value or "")
    if not m:
        return None
    return int(datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())


@dataclass
class Run:
    """One unattended-upgrades run, from its log."""

    start: int
    outcome: str = "incomplete"  # "ok", "error" or "incomplete"
    errors: list = field(default_factory=list)


_LOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (\w+) (.*)$")
_RUN_OK = ("All upgrades installed", "No packages found that can be upgraded", "Packages that were upgraded")


def uu_runs(lines: list[str], utc_offset: str) -> list[Run]:
    """Split the unattended-upgrades log into runs. Times in the log are local; utc_offset is '+0100'."""
    offset = timedelta()
    m = re.fullmatch(r"([+-])(\d\d)(\d\d)", utc_offset or "")
    if m:
        offset = timedelta(hours=int(m.group(2)), minutes=int(m.group(3))) * (-1 if m.group(1) == "-" else 1)
    runs: list[Run] = []
    for line in lines:
        hit = _LOG_LINE.match(line)
        if not hit:
            continue  # continuation lines (package lists, dpkg output)
        stamp, level, msg = hit.groups()
        ts = int((datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S") - offset).replace(tzinfo=timezone.utc).timestamp())
        if msg.startswith("Starting unattended upgrades script"):
            runs.append(Run(ts))
        elif level == "ERROR" or "conffile prompt" in msg:
            # Some errors (e.g. "Lock file is already taken") are logged before "Starting ...".
            if not runs or runs[-1].outcome == "ok":
                runs.append(Run(ts))
            runs[-1].outcome = "error"
            runs[-1].errors.append(msg.strip())
        elif runs and runs[-1].outcome == "incomplete" and msg.startswith(_RUN_OK):
            runs[-1].outcome = "ok"
    return runs


class Facts:
    """Collector output split into ``## name`` sections."""

    def __init__(self, text: str):
        if MAGIC not in text:
            raise CollectError("not unattended-upgrades-check collector output (no '# uuc-collector 1' line)")
        self.sections: dict[str, list[str]] = {}
        current = None
        for line in text.splitlines():
            if line.startswith("## "):
                current = line[3:].strip()
                self.sections.setdefault(current, [])
            elif current is not None:
                self.sections[current].append(line)
        if "end" not in self.sections:
            raise CollectError("collector output is incomplete (no '## end' line): the run was cut short")
        self.meta = self.kv("meta")
        self.os = {}
        for line in self.lines("os-release"):
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                self.os[key.strip()] = value.strip().strip("\"'")
        if not self.meta.get("now", "").isdigit():
            raise CollectError("collector output has no 'now=' timestamp")
        self.now = int(self.meta["now"])
        self.root = self.meta.get("uid") == "0"
        self.container = self.meta.get("container", "none") not in ("", "none")

    def has(self, name: str) -> bool:
        return name in self.sections

    def lines(self, name: str) -> list[str]:
        return self.sections.get(name, [])

    def kv(self, name: str) -> dict[str, str]:
        """key=value lines of a section (the last value wins)."""
        return dict(line.split("=", 1) for line in self.lines(name) if "=" in line)

    def values(self, name: str, key: str) -> list[str]:
        """All values of a repeated key, e.g. every 'hold=' line."""
        prefix = key + "="
        return [line[len(prefix):] for line in self.lines(name) if line.startswith(prefix)]

    def number(self, name: str, key: str) -> int | None:
        value = self.kv(name).get(key, "").strip()
        return int(value) if value.isdigit() else None

    def units(self) -> dict[str, dict[str, str]] | None:
        """systemd unit properties by unit name; None when systemd is not running."""
        if not self.has("systemd"):
            return None
        units, block = {}, {}
        for line in self.lines("systemd") + [""]:
            if "=" in line:
                key, value = line.split("=", 1)
                block[key] = value
            elif block:
                units[block.get("Id", "")] = block
                block = {}
        return units

    def apt_config(self) -> dict[str, list[str]]:
        """apt-config dump lines: 'Key "value";' -> {key: [values]} (list items keep their trailing '::')."""
        conf: dict[str, list[str]] = {}
        for line in self.lines("apt-config"):
            m = re.match(r'^(\S+) "(.*)";$', line)
            if m:
                conf.setdefault(m.group(1), []).append(m.group(2))
        return conf

    def archives(self) -> list[dict[str, str]]:
        """Archives apt knows from its local lists: 'v=24.04,o=Ubuntu,a=noble-security,...'."""
        out = []
        for line in self.lines("apt-archives"):
            fields = dict(tok.split("=", 1) for tok in line.split(",") if "=" in tok)
            if fields.get("o"):
                out.append(fields)
        return out
