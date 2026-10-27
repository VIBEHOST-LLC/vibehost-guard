#!/bin/sh
# Removes the torrent guard. Staff only.
set -u
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vibehost-guard-tick.timer vibehost-guard.service >/dev/null 2>&1
    rm -f /etc/systemd/system/vibehost-guard.service /etc/systemd/system/vibehost-guard-tick.service \
        /etc/systemd/system/vibehost-guard-tick.timer
    systemctl daemon-reload >/dev/null 2>&1
fi
rm -f /etc/cron.d/vibehost-guard

for t in iptables ip6tables; do
    command -v $t >/dev/null 2>&1 || continue
    for h in INPUT OUTPUT FORWARD DOCKER-USER; do
        while $t -w -D $h -j VH_GUARD >/dev/null 2>&1; do :; done
    done
    $t -w -F VH_GUARD >/dev/null 2>&1
    $t -w -X VH_GUARD >/dev/null 2>&1
done

rm -rf /usr/local/lib/vibehost-guard /etc/vibehost-guard
echo "vibehost-guard: removed"
