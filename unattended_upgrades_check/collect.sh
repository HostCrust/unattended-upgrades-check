#!/bin/sh
# unattended-upgrades-check collector, v1. Apache-2.0.
# https://github.com/HostCrust/unattended-upgrades-check
#
# Read-only and offline. It installs, updates, refreshes and restarts nothing:
# no "apt update", no "dnf makecache", no network. Package queries use the local
# cache only (apt with its on-disk cache file disabled, dnf with -C). When run as
# root, dnf may append to its own log in /var/log; nothing else is written.
# Works without root; the report says which checks were limited.
# Prints update state only: no hostname, IP address, user names or machine IDs.
#
# Usage:  sh collect.sh
#         ssh host 'sh -s' < collect.sh

echo "# uuc-collector 1"
echo "## meta"
echo "now=$(date +%s)"
# The zone the unattended-upgrades log is written in (read before switching to UTC).
echo "utc_offset=$(env -u TZ date +%z)"
LC_ALL=C TZ=UTC PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
export LC_ALL TZ PATH

has() { command -v "$1" >/dev/null 2>&1; }
# Bound every package-manager query, so a held lock cannot hang the run.
run() { if has timeout; then timeout 60 "$@"; else "$@"; fi; }
mtime() { stat -c %Y "$1" 2>/dev/null; }

ME=$(id -u)
JOURNAL=no
if [ "$ME" = 0 ] || id -Gn 2>/dev/null | grep -qwE 'adm|systemd-journal'; then JOURNAL=yes; fi
BOOT=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
echo "uid=$ME"
echo "journal=$JOURNAL"
echo "boot=$BOOT"
[ -d /run/systemd/system ] && echo "systemd=yes"
has systemd-detect-virt && echo "container=$(systemd-detect-virt -c 2>/dev/null)"

echo "## os-release"
cat /etc/os-release 2>/dev/null

echo "## kernel"
echo "running=$(uname -r)"
for f in /boot/vmlinuz-*; do
    # Rescue images are skipped: their file name holds the machine ID.
    case $f in *rescue*) continue ;; esac
    # Inode change time = when this kernel was installed.
    [ -e "$f" ] && echo "image=$(stat -c %Z "$f") ${f#/boot/vmlinuz-}"
done

if [ -d /run/systemd/system ]; then
    echo "## systemd"
    systemctl show -p Id,LoadState,UnitFileState,ActiveState,Result,LastTriggerUSec \
        -p NextElapseUSecRealtime,ExecMainExitTimestamp,ExecMainStatus \
        apt-daily.timer apt-daily-upgrade.timer apt-daily-upgrade.service \
        dnf-automatic.timer dnf-automatic-install.timer dnf-automatic-download.timer \
        dnf-automatic-notifyonly.timer dnf-automatic.service dnf-automatic-install.service 2>/dev/null
fi

if has apt-config && has dpkg-query; then
    echo "## apt"
    echo "uu=$(dpkg-query -W -f='${db:Status-Abbrev}${Version}' unattended-upgrades 2>/dev/null)"
    # apt.systemd.daily touches these after a successful list update / unattended-upgrade run;
    # unattended-upgrades writes its own stamp when a run completes, failed or not.
    for s in update-stamp update-success-stamp upgrade-stamp unattended-upgrades-stamp; do
        t=$(mtime "/var/lib/apt/periodic/$s") && echo "$s=$t"
    done
    [ -n "$(ls -A /var/lib/dpkg/updates 2>/dev/null)" ] && echo "dpkg_interrupted=yes"
    dpkg --audit 2>/dev/null | head -n 20 | sed 's/^/audit=/'
    apt-mark showhold 2>/dev/null | head -n 50 | sed 's/^/hold=/'
    if [ -e /var/run/reboot-required ]; then
        echo "reboot_required=$(mtime /var/run/reboot-required)"
        sort -u /var/run/reboot-required.pkgs 2>/dev/null | head -n 20 | sed 's/^/reboot_pkg=/'
    fi

    echo "## apt-config"
    apt-config dump 2>/dev/null |
        grep -E '^(APT::Periodic::|Unattended-Upgrade::(Allowed-Origins|Origins-Pattern|Package-Blacklist|Automatic-Reboot))'

    # Empty Dir::Cache::*pkgcache makes apt build its cache in memory instead of on disk.
    NOCACHE="-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache="
    echo "## apt-archives"
    # shellcheck disable=SC2086
    run apt-cache $NOCACHE policy 2>/dev/null | sed -n 's/^ *release //p' | sort -u | head -n 60
    echo "## apt-upgradable"
    # shellcheck disable=SC2086
    run apt $NOCACHE list --upgradable 2>/dev/null |
        awk -F/ 'NF > 1 { n++; if ($2 ~ /-security/ && s++ < 200) print $1 }
                 END { print "total=" n+0; print "security=" s+0 }'

    echo "## uu-log"
    L=/var/log/unattended-upgrades/unattended-upgrades.log
    if [ -r "$L" ]; then echo "log=yes"; tail -n 300 "$L"
    elif [ "$ME" = 0 ]; then echo "log=missing"
    else echo "log=no-permission"; fi
fi

if has dnf && has rpm; then
    echo "## dnf"
    v=$(rpm -q --qf '%{VERSION}-%{RELEASE}' dnf-automatic 2>/dev/null) && echo "automatic=$v"
    grep -E '^[[:space:]]*(upgrade_type|apply_updates|download_updates|reboot)[[:space:]]*=' \
        /etc/dnf/automatic.conf 2>/dev/null | tr -d ' \t' | sed 's/^/conf_/'
    grep -vE '^[[:space:]]*(#|$)' /etc/dnf/plugins/versionlock.list 2>/dev/null | head -n 50 | sed 's/^/lock=/'
    grep -iE '^[[:space:]]*exclude(pkgs)?[[:space:]]*=' /etc/dnf/dnf.conf 2>/dev/null |
        sed 's/^[^=]*=[[:space:]]*/exclude=/'
    echo "last_install=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -n 1)"
    out=$(run dnf -C -q needs-restarting -r 2>&1)
    echo "reboot_exit=$?"
    # When the reboot became needed: the first install after boot of a package that asks for one.
    for p in $(echo "$out" | sed -n 's/^ *\* //p'); do rpm -q --qf '%{INSTALLTIME}\n' "$p" 2>/dev/null; done |
        sort -n | awk -v b="${BOOT:-0}" '$1 > b { print "reboot_since=" $1; exit }'
    echo "$out" | head -n 20 | sed 's/^/reboot_out=/'

    echo "## dnf-security"
    out=$(run dnf -C -q updateinfo list --security 2>&1)
    echo "exit=$?"
    echo "$out" | head -n 300
fi

echo "## services"
if has needrestart; then
    echo "tool=needrestart"
    # -b: batch output; -r l: list only, never restart anything.
    run needrestart -b -r l 2>/dev/null | grep '^NEEDRESTART-' | head -n 60
elif has dnf; then
    echo "tool=needs-restarting"
    run dnf -C -q needs-restarting -s 2>&1 | head -n 40
fi

echo "## livepatch"
for d in /sys/kernel/livepatch/*; do
    [ -d "$d" ] && echo "module=${d##*/} $(cat "$d/enabled" 2>/dev/null)"
done
for c in canonical-livepatch kpatch; do
    has "$c" || continue
    if [ "$c" = kpatch ]; then out=$(run kpatch list 2>&1); else out=$(run canonical-livepatch status 2>&1); fi
    echo "client=$c exit=$?"
    echo "$out" | grep -viE 'machine.?id|token' | head -n 20 | sed 's/^/| /'
done

echo "## journal"
if [ "$JOURNAL" = yes ] && has journalctl; then
    echo "readable=yes"
    # Error lines of the update jobs in the last 14 days; field 2 (the hostname) is dropped.
    run journalctl -q --no-pager -o short-iso --since '14 days ago' -u apt-daily.service \
        -u apt-daily-upgrade.service -u dnf-automatic.service -u dnf-automatic-install.service 2>/dev/null |
        grep -iE 'error|fail|interrupted|broken|\block\b' | cut -d ' ' -f 1,3- | tail -n 30
else
    echo "readable=no"
fi
echo "## end"
