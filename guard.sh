#!/bin/sh
# Torrent guard. Usage: guard.sh <code> | apply | tick
set -u

VERSION=1
API="${VH_GUARD_API:-https://api.vibehost.net/api/v1/guard}"
LIB=/usr/local/lib/vibehost-guard
CONF_DIR=/etc/vibehost-guard
CONF="$CONF_DIR/agent.conf"
CHAIN=VH_GUARD

# name|pattern
SIGNATURES='bt-handshake|BitTorrent protocol
dht-query|d1:ad2:id20:
dht-reply|d1:rd2:id20:
dht-get-peers|9:get_peers
dht-announce|13:announce_peer
dht-find-node|9:find_node
tracker-info-hash|info_hash=
tracker-peer-id|peer_id=
tracker-announce|/announce?
tracker-scrape|/scrape?
lsd|BT-SEARCH
magnet|urn:btih:'
UDP_TRACKER_HEX='|0000041727101980|'

log() { echo "vibehost-guard: $*" >&2; }

tables() {
    command -v iptables >/dev/null 2>&1 && echo iptables
    command -v ip6tables >/dev/null 2>&1 && echo ip6tables
}

hooks() {
    echo INPUT
    echo OUTPUT
    echo FORWARD
    $1 -n -L DOCKER-USER >/dev/null 2>&1 && echo DOCKER-USER
}

apply_table() {
    t=$1
    $t -w -N $CHAIN 2>/dev/null || $t -w -F $CHAIN || return 1
    # only the first 4 KB of a connection
    $t -w -A $CHAIN -m connbytes --connbytes 4097: --connbytes-dir both --connbytes-mode bytes -j RETURN || return 1
    echo "$SIGNATURES" | while IFS='|' read -r name pattern; do
        [ -n "$name" ] || continue
        $t -w -A $CHAIN -m string --algo bm --string "$pattern" -m comment --comment "vh:$name" -j DROP || exit 1
    done || return 1
    $t -w -A $CHAIN -p udp -m string --algo bm --hex-string "$UDP_TRACKER_HEX" -m comment --comment "vh:udp-tracker" -j DROP || return 1
    hook_table "$t"
}

hook_table() {
    t=$1
    for h in $(hooks "$t"); do
        $t -w -C "$h" -j $CHAIN >/dev/null 2>&1 || $t -w -I "$h" 1 -j $CHAIN || return 1
    done
}

intact_table() {
    t=$1
    want=$(echo "$SIGNATURES" | grep -c '|')
    have=$($t -w -S $CHAIN 2>/dev/null | grep -c -- '--comment "\{0,1\}vh:')
    [ "$have" -eq $((want + 1)) ] || return 1
    for h in $(hooks "$t"); do
        $t -w -C "$h" -j $CHAIN >/dev/null 2>&1 || return 1
    done
}

apply() {
    rc=0
    found=
    for t in $(tables); do
        found=1
        if ! apply_table "$t"; then
            log "$t: rules not applied (no string/connbytes match in this kernel?)"
            rc=1
        fi
    done
    [ -n "$found" ] || { log "iptables not found"; return 1; }
    return $rc
}

ensure() {
    rc=0
    for t in $(tables); do
        intact_table "$t" || apply_table "$t" || rc=1
    done
    return $rc
}

counters() {
    for t in $(tables); do
        $t -w -nvxL $CHAIN 2>/dev/null
    done | awk '/vh:/ { for (i = 1; i <= NF; i++) if ($i ~ /^vh:/) { n[substr($i, 4)] += $1 } }
        END { s = ""; for (k in n) { s = s (s == "" ? "" : ",") "\"" k "\":" n[k] }; print s }'
}

os_name() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-linux}-${VERSION_ID:-}"
    else
        uname -s
    fi
}

post() {
    url=$1 body=$2 token=${3:-}
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$token" ]; then
            curl -fsS -m 20 -X POST -H 'Content-Type: application/json' -H "X-Agent-Token: $token" -d "$body" "$url"
        else
            curl -fsS -m 20 -X POST -H 'Content-Type: application/json' -d "$body" "$url"
        fi
    else
        if [ -n "$token" ]; then
            wget -q -T 20 -O - --header='Content-Type: application/json' --header="X-Agent-Token: $token" --post-data="$body" "$url"
        else
            wget -q -T 20 -O - --header='Content-Type: application/json' --post-data="$body" "$url"
        fi
    fi
}

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsS -m 60 -o "$2" "$1"; else wget -q -T 60 -O "$2" "$1"; fi
}

json_field() {
    sed -n "s/.*\"$1\" *: *\"\{0,1\}\([^\",}]*\).*/\1/p" | head -n 1
}

# install only what is missing
install_packages() {
    fw=
    dl=
    command -v iptables >/dev/null 2>&1 || fw=iptables
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || dl=curl
    [ -n "$fw$dl" ] || return 0
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -q $fw $dl >/dev/null 2>&1 \
            || { apt-get update -q >/dev/null 2>&1 && apt-get install -y -q $fw $dl >/dev/null 2>&1; }
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q ${fw:+iptables-nft} $dl >/dev/null 2>&1 || dnf install -y -q $fw $dl >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q $fw $dl >/dev/null 2>&1
    elif command -v zypper >/dev/null 2>&1; then
        zypper -n -q in $fw $dl >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk add -q ${fw:+iptables ip6tables} $dl >/dev/null 2>&1
    fi
    command -v iptables >/dev/null 2>&1
}

install_units() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        cat > /etc/systemd/system/vibehost-guard.service <<EOF
[Unit]
Description=VibeHost torrent guard
After=network-pre.target firewalld.service ufw.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$LIB/guard.sh apply

[Install]
WantedBy=multi-user.target
EOF
        cat > /etc/systemd/system/vibehost-guard-tick.service <<EOF
[Unit]
Description=VibeHost torrent guard check

[Service]
Type=oneshot
ExecStart=$LIB/guard.sh tick
EOF
        cat > /etc/systemd/system/vibehost-guard-tick.timer <<EOF
[Unit]
Description=VibeHost torrent guard check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable vibehost-guard.service >/dev/null 2>&1
        systemctl enable --now vibehost-guard-tick.timer >/dev/null 2>&1
    else
        mkdir -p /etc/cron.d
        cat > /etc/cron.d/vibehost-guard <<EOF
@reboot root $LIB/guard.sh apply
*/5 * * * * root $LIB/guard.sh tick
EOF
    fi
}

enroll() {
    code=$1
    answer=$(post "$API/enroll" "{\"code\":\"$code\",\"os\":\"$(os_name)\",\"version\":$VERSION}") || return 1
    token=$(echo "$answer" | json_field token)
    [ -n "$token" ] || return 1
    umask 077
    mkdir -p "$CONF_DIR"
    printf 'VIBEHOST_GUARD_TOKEN=%s\n' "$token" > "$CONF"
}

install_guard() {
    code=$1
    [ "$(id -u)" -eq 0 ] || { log "run as root"; exit 1; }
    # stdin may still hold the rest of this script (curl | sh)
    install_packages </dev/null || { log "could not install iptables"; exit 1; }
    mkdir -p "$LIB"
    if [ "$0" != "$LIB/guard.sh" ]; then
        if [ -f "$0" ]; then cp "$0" "$LIB/guard.sh"; else fetch "$API/guard.sh" "$LIB/guard.sh" || exit 1; fi
    fi
    chmod 755 "$LIB/guard.sh"
    install_units
    if apply; then echo "vibehost-guard: torrent traffic is blocked"; else exit 1; fi
    if [ -n "$code" ]; then
        if enroll "$code"; then echo "vibehost-guard: linked to VibeHost"; else log "torrent traffic is blocked, but the server is not linked to VibeHost: the command is used or expired, take it again from the server card"; fi
    fi
    tick >/dev/null 2>&1 || true
}

tick() {
    VIBEHOST_GUARD_TOKEN=
    [ -r "$CONF" ] && . "$CONF"
    ok=true
    ensure || ok=false
    [ -n "$VIBEHOST_GUARD_TOKEN" ] || return 0
    body="{\"version\":$VERSION,\"rulesOk\":$ok,\"os\":\"$(os_name)\",\"counters\":{$(counters)}}"
    answer=$(post "$API/heartbeat" "$body" "$VIBEHOST_GUARD_TOKEN") || return 0
    latest=$(echo "$answer" | json_field version)
    if [ -n "$latest" ] && [ "$latest" -gt "$VERSION" ] 2>/dev/null; then
        if fetch "$API/guard.sh" "$LIB/guard.sh.new" && sh -n "$LIB/guard.sh.new"; then
            chmod 755 "$LIB/guard.sh.new" && mv "$LIB/guard.sh.new" "$LIB/guard.sh" && "$LIB/guard.sh" apply
        else
            rm -f "$LIB/guard.sh.new"
        fi
    fi
}

case "${1:-}" in
    apply) apply ;;
    tick) tick ;;
    *) install_guard "${1:-}" ;;
esac
