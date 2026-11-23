#!/bin/sh
# Torrent guard. Usage: guard.sh <code> | apply | tick | scan | vpn
set -u

VERSION=11
API="${VH_GUARD_API:-https://api.vibehost.net/api/v1/guard}"
LIB=/usr/local/lib/vibehost-guard
CONF_DIR=/etc/vibehost-guard
CONF="$CONF_DIR/agent.conf"
CHAIN=VH_GUARD
DPI_MODE_FILE="$CONF_DIR/dpi.mode"
DPI_BIN="$LIB/vh-dpid"
DPI_RUN=/run/vibehost-guard-dpid
DPI_STATS="$DPI_RUN/stats"
DPI_PID="$DPI_RUN/pid"
SCAN_LIST="$DPI_RUN/scan"
SCAN_MODE_FILE="$CONF_DIR/scan.mode"
SCAN_CHAIN=VH_GUARD_SCAN
SCAN_VITAL=' 53 80 123 443 853 '
DPI_FLOWS="$DPI_RUN/flows"
VPN_DIR=/run/vibehost-guard
VPN_USERS="$VPN_DIR/vpn.users"
VPN_SEEN="$VPN_DIR/vpn.seen"
VPN_OFFSETS="$VPN_DIR/vpn.offsets"
VPN_CUT_IPS="$VPN_DIR/vpn.cutips"
VPN_CUT="$CONF_DIR/vpn.cut"
VPN_SHARED="$CONF_DIR/vpn.shared"
DPI_BIT=0x100000
DPI_PACKETS=12
DPI_BYTES=512
DPI_SHA_AMD64=c20901dc83257b7399aff05b2b8440326e6248ec9376ed842d731dace3238364
DPI_SHA_ARM64=30e9330a5e79a80c2551047f7cad315364f3f32fdffeb185979e79193c1e485e

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
SIGNATURES_LOOSE='tracker-info-hash tracker-peer-id tracker-announce tracker-scrape magnet'
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

signatures() {
    if [ "$(dpi_mode)" = enforce ] && dpi_running && $1 -w -S $CHAIN 2>/dev/null | grep -q -- vhdpi-tap; then
        echo "$SIGNATURES" | while IFS='|' read -r name pattern; do
            case " $SIGNATURES_LOOSE " in *" $name "*) ;; *) echo "$name|$pattern" ;; esac
        done
    else
        echo "$SIGNATURES"
    fi
}

tap_rule() {
    $1 -w $2 $CHAIN ${3:-} -m connbytes --connbytes 1:$DPI_PACKETS --connbytes-dir both --connbytes-mode packets \
        -m limit --limit 10000/s --limit-burst 10000 -m comment --comment vhdpi-tap \
        -j NFLOG --nflog-group 4711 --nflog-size $DPI_BYTES 2>/dev/null \
        || log "$1: no copies for the analyser, the string rules stay"
}

apply_dpi_rules() {
    t=$1
    mode=$(dpi_mode)
    if [ "$mode" = enforce ]; then
        $t -w -A $CHAIN -m connmark --mark $DPI_BIT/$DPI_BIT -m comment --comment vhdpi-drop -j DROP || return 1
    fi
    [ "$mode" = off ] || tap_rule "$t" -A
    return 0
}

apply_table() {
    t=$1
    $t -w -N $CHAIN 2>/dev/null || $t -w -F $CHAIN || return 1
    $t -w -N $SCAN_CHAIN 2>/dev/null || $t -w -F $SCAN_CHAIN || return 1
    $t -w -A $CHAIN -m comment --comment vhscan -j $SCAN_CHAIN || return 1
    scan_fill "$t"
    apply_dpi_rules "$t" || return 1
    $t -w -A $CHAIN -m connbytes --connbytes 4097: --connbytes-dir both --connbytes-mode bytes -j RETURN || return 1
    signatures "$t" | while IFS='|' read -r name pattern; do
        [ -n "$name" ] || continue
        $t -w -A $CHAIN -m string --algo bm --string "$pattern" -m comment --comment "vh:$name" -j DROP || exit 1
    done || return 1
    $t -w -A $CHAIN -p udp -m string --algo bm --hex-string "$UDP_TRACKER_HEX" -m comment --comment "vh:udp-tracker" -j DROP || return 1
    hook_table "$t"
}

jumps() {
    $1 -w -S "$2" 2>/dev/null | grep -c -- "-j $CHAIN\$"
}

hook_table() {
    t=$1
    for h in $(hooks "$t"); do
        n=$(jumps "$t" "$h")
        while [ "$n" -gt 1 ]; do
            $t -w -D "$h" -j $CHAIN || return 1
            n=$((n - 1))
        done
        [ "$n" -eq 1 ] || $t -w -I "$h" 1 -j $CHAIN || return 1
    done
}

intact_table() {
    t=$1
    [ "$($t -w -S $CHAIN 2>/dev/null | grep -c -- "-j $SCAN_CHAIN")" -eq 1 ] || return 1
    want=$(signatures "$t" | grep -c '|')
    have=$($t -w -S $CHAIN 2>/dev/null | grep -c -- '--comment "\{0,1\}vh:')
    [ "$have" -eq $((want + 1)) ] || return 1
    want=0
    [ "$(dpi_mode)" = enforce ] && want=1
    [ "$($t -w -S $CHAIN 2>/dev/null | grep -c -- vhdpi-drop)" -eq "$want" ] || return 1
    have=$($t -w -S $CHAIN 2>/dev/null | grep -c -- vhdpi-tap)
    if [ "$(dpi_mode)" = off ]; then
        [ "$have" -eq 0 ] || return 1
    elif [ "$have" -eq 0 ]; then
        tap_rule "$t" -I 1
    fi
    for h in $(hooks "$t"); do
        [ "$(jumps "$t" "$h")" -eq 1 ] || return 1
    done
}

lock() {
    [ -z "${VH_GUARD_LOCKED:-}" ] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    d=/run
    [ -d "$d" ] && [ -w "$d" ] || d=/tmp
    exec 9>"$d/vibehost-guard.lock"
    flock -w 120 9 2>/dev/null || flock -n 9 2>/dev/null || true
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
        if intact_table "$t"; then
            scan_fill "$t"
        else
            apply_table "$t" || rc=1
        fi
    done
    return $rc
}

scan_mode() {
    m=detect
    [ -r "$SCAN_MODE_FILE" ] && m=$(cat "$SCAN_MODE_FILE" 2>/dev/null)
    case "$m" in off|detect|block) echo "$m" ;; *) echo detect ;; esac
}

scan_fill() {
    t=$1
    $t -w -F $SCAN_CHAIN 2>/dev/null || return 0
    vpn_cut_fill "$t"
    [ "$(scan_mode)" = block ] && [ -r "$SCAN_LIST" ] || return 0
    now=$(date +%s)
    n=0
    while read -r kind value until; do
        [ "$n" -lt 256 ] || break
        case "$until" in ''|*[!0-9]*) continue ;; esac
        [ "$until" -gt "$now" ] || continue
        case "$kind" in
            src)
                case "$value" in
                    *:*) [ "$t" = ip6tables ] || continue
                         case "$value" in *[!0-9a-fA-F:]*) continue ;; esac ;;
                    *) [ "$t" = iptables ] || continue
                       case "$value" in *[!0-9.]*|'') continue ;; esac ;;
                esac
                $t -w -A $SCAN_CHAIN -s "$value" -m conntrack --ctstate NEW \
                    -m comment --comment vhscan-src -j DROP 2>/dev/null && n=$((n + 1))
                ;;
            port)
                case "$value" in ''|*[!0-9]*) continue ;; esac
                [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || continue
                case "$SCAN_VITAL" in *" $value "*) continue ;; esac
                $t -w -A $SCAN_CHAIN -p tcp --syn --dport "$value" -m addrtype --src-type LOCAL \
                    -m comment --comment vhscan-port -j DROP 2>/dev/null && n=$((n + 1))
                ;;
        esac
    done < "$SCAN_LIST"
    return 0
}

scan_sync() {
    for t in $(tables); do
        if $t -w -n -L $SCAN_CHAIN >/dev/null 2>&1; then scan_fill "$t"; else ensure; fi
    done
}

scan_rules() {
    for t in $(tables); do
        $t -w -S $SCAN_CHAIN 2>/dev/null
    done | grep -c -- 'vhscan-'
}

scan_write_units() {
    cat > /etc/systemd/system/vibehost-guard-scan.path <<EOF
[Unit]
Description=VibeHost guard: the analyser's list of scanners changed

[Path]
PathModified=$SCAN_LIST

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/vibehost-guard-scan.service <<EOF
[Unit]
Description=VibeHost guard: block or release scanners

[Service]
Type=oneshot
ExecStart=$LIB/guard.sh scan
EOF
}

scan_remove_units() {
    for u in scan vpn; do
        [ -f /etc/systemd/system/vibehost-guard-$u.path ] || continue
        systemctl disable --now vibehost-guard-$u.path >/dev/null 2>&1
        rm -f /etc/systemd/system/vibehost-guard-$u.path /etc/systemd/system/vibehost-guard-$u.service
    done
}

vpn_write_units() {
    cat > /etc/systemd/system/vibehost-guard-vpn.path <<EOF
[Unit]
Description=VibeHost guard: the analyser judged new torrent connections

[Path]
PathModified=$DPI_FLOWS

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/vibehost-guard-vpn.service <<EOF
[Unit]
Description=VibeHost guard: which VPN user made them

[Service]
Type=oneshot
Nice=10
ExecStart=$LIB/guard.sh vpn
EOF
}

VPN_AWK='
function private(a) {
    return a ~ /^10\./ || a ~ /^192\.168\./ || a ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ \
        || a ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ || a ~ /^f[cd][0-9a-f]*:/
}
function hex(s,   h, i) {
    h = ""
    for (i = 1; i <= length(s) && i <= 96; i++) h = h sprintf("%02x", ord[substr(s, i, 1)])
    return h
}
function unhex(h,   s, i) {
    s = ""
    for (i = 1; i < length(h); i += 2) s = s chr[substr(h, i, 2)]
    return s
}
function hostport(a) {
    if (a ~ /^\[/) { host = substr(a, 2); sub(/\].*/, "", host); port = a; sub(/.*\]:/, "", port); return }
    host = a; sub(/:[0-9]+$/, "", host); port = a; sub(/.*:/, "", port)
}
function inport(tag) {
    return tag ~ /^inbound-[0-9]+$/ ? substr(tag, 9) + 0 : 0
}
function pad4(g) {
    while (length(g) < 4) g = "0" g
    return g
}
function expand6(a,   p, l, r, nl, nr, L, R, i, out) {
    p = index(a, "::")
    if (p) { l = substr(a, 1, p - 1); r = substr(a, p + 2) } else { l = a; r = "" }
    nl = l == "" ? 0 : split(l, L, ":")
    nr = r == "" ? 0 : split(r, R, ":")
    out = ""
    for (i = 1; i <= nl; i++) out = out (out == "" ? "" : ":") pad4(L[i])
    for (i = 0; i < 8 - nl - nr; i++) out = out (out == "" ? "" : ":") "0000"
    for (i = 1; i <= nr; i++) out = out (out == "" ? "" : ":") pad4(R[i])
    return out
}
function norm(a) {
    a = tolower(a)
    if (a ~ /^::ffff:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return substr(a, 8)
    return index(a, ":") ? expand6(a) : a
}
function v4(b1, b2, b3, b4) {
    return hv[b1] "." hv[b2] "." hv[b3] "." hv[b4]
}
function procip(h,   i, w, out) {
    h = tolower(substr(h, 1, index(h, ":") - 1))
    if (length(h) == 8) return v4(substr(h, 7, 2), substr(h, 5, 2), substr(h, 3, 2), substr(h, 1, 2))
    out = ""
    for (i = 0; i < 4; i++) {
        w = substr(h, i * 8 + 1, 8)
        out = out (i ? ":" : "") substr(w, 7, 2) substr(w, 5, 2) ":" substr(w, 3, 2) substr(w, 1, 2)
    }
    if (substr(out, 1, 30) == "0000:0000:0000:0000:0000:ffff:")
        return v4(substr(out, 31, 2), substr(out, 33, 2), substr(out, 36, 2), substr(out, 38, 2))
    return out
}
function record(proto, name, tag, src,   k, n, i, ids) {
    if (name == "") return
    if (tag != "") tags[name] = tag
    if (src != "") {
        src = norm(src)
        if (!((name, src) in seenip)) { seenip[name, src] = 1; nip[src]++ }
    }
    k = proto " " host " " port
    if (!(k in key)) return
    n = split(key[k], ids, " ")
    for (i = 1; i <= n; i++) {
        if (ids[i] in owner) continue
        owner[ids[i]] = name
        count[name]++
        kind[name] = mode
    }
}
BEGIN {
    for (i = 1; i < 256; i++) { c = sprintf("%c", i); ord[c] = i; chr[sprintf("%02x", i)] = c }
    for (i = 0; i < 256; i++) hv[sprintf("%02x", i)] = i
    while ((getline l < sharedfile) > 0) {
        if (split(l, f, " ") >= 2 && f[2] + 0 >= now - 604800) shared[f[1]] = f[2]
    }
    while ((getline l < peersfile) > 0) {
        if (split(l, f, " ") >= 4 && f[4] == "01") peer[procip(f[3])] = 1
    }
    while ((getline l < flows) > 0) {
        if (split(l, f, " ") < 6 || f[6] + 0 <= since + 0) continue
        id++
        key[f[1] " " f[4] " " f[5]] = key[f[1] " " f[4] " " f[5]] " " id
        key[f[1] " " f[2] " " f[3]] = key[f[1] " " f[2] " " f[3]] " " id
        if (private(f[2]) && !private(f[4])) fwd[id] = f[2]
        else if (private(f[4]) && !private(f[2])) fwd[id] = f[4]
    }
    nflows = id
    while ((getline l < cutfile) > 0) {
        if (split(l, f, " ") < 3 || f[3] + 0 <= now + 0) continue
        nm = unhex(f[1]); cut[nm] = f[3]; cutkind[nm] = f[2]
    }
    while ((getline l < oldcut) > 0) {
        if (split(l, f, " ") < 5) continue
        nm = unhex(f[5])
        if (nm in cut) line[f[1] " " f[2]] = cut[nm] " " f[4] " " f[5]
    }
}
/^#xray$/ { mode = "xray"; next }
/^#sing$/ { mode = "sing"; next }
mode == "xray" {
    a = index($0, " accepted "); e = index($0, "email: ")
    if (!a || !e) next
    name = substr($0, e + 7); sub(/[ \r]+$/, "", name)
    rest = substr($0, a + 10); dest = rest; sub(/ .*/, "", dest)
    proto = dest; sub(/:.*/, "", proto); hostport(substr(dest, length(proto) + 2))
    tag = ""
    if (index(rest, "[")) { tag = substr(rest, index(rest, "[") + 1); sub(/ (>>|->).*/, "", tag) }
    src = ""
    if (index($0, " from ")) {
        src = substr($0, index($0, " from ") + 6); sub(/ .*/, "", src); sub(/^(tcp|udp):/, "", src)
        if (src ~ /^\[/) { src = substr(src, 2); sub(/\].*/, "", src) } else sub(/:[0-9]+$/, "", src)
    }
    record(proto, name, tag, src)
    next
}
mode == "sing" {
    if (!match($0, /\]: \[[^]]+\] inbound (packet )?connection (to|from) /)) next
    seg = substr($0, RSTART + 4, RLENGTH - 4)
    name = substr(seg, 1, index(seg, "]") - 1)
    addr = substr($0, RSTART + RLENGTH); sub(/ .*/, "", addr)
    hostport(addr)
    if (seg ~ / from $/) { from[name] = host; next }
    tag = ""
    if (match($0, /inbound\/[a-z0-9-]+\[[^]]*\]/)) { tag = substr($0, RSTART, RLENGTH); sub(/^[^[]*\[/, "", tag); sub(/\]$/, "", tag) }
    record(seg ~ /packet/ ? "udp" : "tcp", name, tag, (name in from) ? from[name] : "")
    next
}
END {
    for (id = 1; id <= nflows; id++) {
        if ((id in owner) || !(id in fwd)) continue
        nm = fwd[id]; count[nm]++; kind[nm] = "fwd"
    }
    for (s in nip) if (nip[s] >= 2) shared[s] = now
    for (s in shared) print s, shared[s] > sharedout
    for (k in seenip) {
        split(k, q, SUBSEP)
        has[q[1]] = 1
        if (q[2] in shared) continue
        open[q[1]] = 1
        if (q[2] in peer) live[q[1]] = 1
    }
    for (nm in count) {
        via = !(nm in has) || kind[nm] == "fwd" ? "-" : !(nm in open) ? "r" : peerok && !(nm in live) ? "p" : "-"
        printf "%s %s %s %d %s\n", hex(nm), kind[nm], (nm in tags) ? hex(tags[nm]) : "-", count[nm], via > found
    }
    for (nm in cut) {
        if (cutkind[nm] == "fwd") { line[nm " 0"] = cut[nm] " fwd " hex(nm); continue }
        for (k in seenip) {
            split(k, q, SUBSEP)
            if (q[1] != nm || (q[2] in shared) || (peerok && !(q[2] in peer))) continue
            line[q[2] " " inport(tags[nm])] = cut[nm] " " cutkind[nm] " " hex(nm)
        }
    }
    for (k in line) {
        split(k, q, " ")
        if (!(q[1] in shared)) print k, line[k] > cutout
    }
}'

vpn_logs() {
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in xray*|v2ray*|rw-core*) k=xray ;; sing-box*) k=sing ;; *) continue ;; esac
        for fd in "$d"/fd/*; do
            f=$(readlink "$fd" 2>/dev/null) || continue
            case "$k:$f" in xray:/*access*|sing:/*.log) echo "$k $fd" ;; esac
        done
    done
}

vpn_peers() {
    seen=
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in xray*|v2ray*|rw-core*|sing-box*) ;; *) continue ;; esac
        ns=$(readlink "$d/ns/net" 2>/dev/null) || continue
        case " $seen " in *" $ns "*) continue ;; esac
        seen="$seen $ns"
        cat "$d/net/tcp" "$d/net/tcp6" 2>/dev/null
    done
}

vpn_cores() {
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in xray*|v2ray*|rw-core*|sing-box*) echo x ;; esac
    done | wc -l
}

vpn_chunks() {
    : > "$VPN_DIR/vpn.log"
    : > "$VPN_OFFSETS.new"
    vpn_logs | while read -r kind fd; do
        id=$(stat -L -c '%d:%i' "$fd" 2>/dev/null) || continue
        grep -q "^$id " "$VPN_OFFSETS.new" && continue
        size=$(stat -L -c '%s' "$fd" 2>/dev/null) || continue
        echo "$id $size" >> "$VPN_OFFSETS.new"
        [ "$1" = read ] || continue
        prev=$(sed -n "s/^$id //p" "$VPN_OFFSETS" 2>/dev/null)
        case "$prev" in ''|*[!0-9]*) prev=$((size > 4194304 ? size - 4194304 : 0)) ;; esac
        [ "$prev" -le "$size" ] || prev=0
        from=$((prev > 2097152 ? prev - 2097152 : 0))
        [ $((size - from)) -le 33554432 ] || from=$((size - 33554432))
        echo "#$kind" >> "$VPN_DIR/vpn.log"
        tail -c +$((from + 1)) "$fd" 2>/dev/null | head -c $((size - from)) >> "$VPN_DIR/vpn.log"
        echo >> "$VPN_DIR/vpn.log"
    done
    mv -f "$VPN_OFFSETS.new" "$VPN_OFFSETS"
}

vpn_run() {
    mkdir -p "$VPN_DIR" && chmod 700 "$VPN_DIR"
    now=$(date +%s)
    since=$(cat "$VPN_SEEN" 2>/dev/null)
    case "$since" in ''|*[!0-9]*) since=0 ;; esac
    fresh=0
    [ -r "$DPI_FLOWS" ] && fresh=$(awk -v s="$since" '$6 > s' "$DPI_FLOWS" | wc -l)
    if [ "$fresh" -gt 0 ] || [ -s "$VPN_CUT" ]; then vpn_chunks read; else vpn_chunks skip; fi
    : > "$VPN_DIR/vpn.found"
    : > "$VPN_DIR/vpn.news"
    : > "$VPN_SHARED.new"
    vpn_peers > "$VPN_DIR/vpn.peers"
    peerok=0
    [ -s "$VPN_DIR/vpn.peers" ] && peerok=1
    LC_ALL=C awk -v flows="$DPI_FLOWS" -v since="$since" -v now="$now" -v cutfile="$VPN_CUT" \
        -v oldcut="$VPN_CUT_IPS" -v found="$VPN_DIR/vpn.found" -v cutout="$VPN_CUT_IPS.new" \
        -v sharedfile="$VPN_SHARED" -v sharedout="$VPN_SHARED.new" -v peersfile="$VPN_DIR/vpn.peers" \
        -v peerok="$peerok" "$VPN_AWK" "$VPN_DIR/vpn.log"
    rm -f "$VPN_DIR/vpn.log" "$VPN_DIR/vpn.peers"
    mv -f "$VPN_SHARED.new" "$VPN_SHARED"
    touch "$VPN_CUT_IPS.new"
    if ! cmp -s "$VPN_CUT_IPS.new" "$VPN_CUT_IPS"; then
        mv -f "$VPN_CUT_IPS.new" "$VPN_CUT_IPS"
        scan_sync
    else
        rm -f "$VPN_CUT_IPS.new"
    fi
    [ "$fresh" -gt 0 ] || return 0
    awk '{ if ($6 > m) m = $6 } END { print m + 0 }' "$DPI_FLOWS" > "$VPN_SEEN"
    LC_ALL=C awk -v now="$now" -v old="$VPN_USERS" -v news="$VPN_DIR/vpn.news" '
        BEGIN { while ((getline l < old) > 0) { split(l, f, " "); u[f[1]] = l; n[f[1]] = f[4]; first[f[1]] = f[5]; last[f[1]] = f[6] } }
        {
            if (!($1 in u) || last[$1] < now - 86400) print $1 > news
            u[$1] = $1 " " $2 " " $3 " " (n[$1] + $4) " " (($1 in first) ? first[$1] : now) " " now " " ($5 == "" ? "-" : $5)
        }
        END { for (h in u) { split(u[h], f, " "); if (f[6] >= now - 604800) print u[h] } }
    ' "$VPN_DIR/vpn.found" > "$VPN_USERS.new" && mv -f "$VPN_USERS.new" "$VPN_USERS"
}

vpn_cut_fill() {
    t=$1
    [ -r "$VPN_CUT_IPS" ] || return 0
    now=$(date +%s)
    n=0
    while read -r ip port until kind rest; do
        [ "$n" -lt 256 ] || break
        case "$until" in ''|*[!0-9]*) continue ;; esac
        [ "$until" -gt "$now" ] || continue
        case "$port" in ''|*[!0-9]*) continue ;; esac
        case "$ip" in
            *:*) [ "$t" = ip6tables ] || continue
                 case "$ip" in *[!0-9a-fA-F:]*) continue ;; esac ;;
            *) [ "$t" = iptables ] || continue
               case "$ip" in *[!0-9.]*|'') continue ;; esac ;;
        esac
        if [ "$kind" = fwd ]; then
            $t -w -A $SCAN_CHAIN -s "$ip" -m comment --comment vhuser -j DROP 2>/dev/null
        elif [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            $t -w -A $SCAN_CHAIN -s "$ip" -p tcp --dport "$port" -m comment --comment vhuser -j DROP 2>/dev/null
            $t -w -A $SCAN_CHAIN -s "$ip" -p udp --dport "$port" -m comment --comment vhuser -j DROP 2>/dev/null
        else
            $t -w -A $SCAN_CHAIN -s "$ip" -p tcp ! --dport 22 -m addrtype --dst-type LOCAL \
                -m comment --comment vhuser -j DROP 2>/dev/null
            $t -w -A $SCAN_CHAIN -s "$ip" ! -p tcp -m addrtype --dst-type LOCAL -m comment --comment vhuser -j DROP 2>/dev/null
        fi
        n=$((n + 1))
    done < "$VPN_CUT_IPS"
}

vpn_panels() {
    {
        { [ -d /usr/local/x-ui ] || [ -f /etc/x-ui/x-ui.db ]; } && echo 3x-ui
        [ -d /usr/local/s-ui ] && echo s-ui
        [ -d /opt/hiddify-manager ] && echo hiddify
        { [ -d /opt/marzban ] || [ -d /var/lib/marzban ]; } && echo marzban
        { [ -d /opt/pasarguard ] || [ -d /var/lib/pasarguard ]; } && echo pasarguard
        [ -d /var/lib/marzneshin ] && echo marzneshin
        [ -d /opt/remnanode ] && echo remnawave
        if command -v docker >/dev/null 2>&1; then
            { command -v timeout >/dev/null 2>&1 && timeout 5 docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null; } \
                | tr 'A-Z' 'a-z' | while read -r n i; do
                case "$n $i" in
                    *3x-ui*|*x-ui*) echo 3x-ui ;; *marzban*) echo marzban ;; *pasarguard*) echo pasarguard ;;
                    *marzneshin*) echo marzneshin ;; *remnanode*|*remnawave*) echo remnawave ;; *hiddify*) echo hiddify ;;
                    *amnezia*) echo amnezia ;; *wg-easy*) echo wg-easy ;; *shadowbox*|*outline*) echo outline ;;
                    *s-ui*) echo s-ui ;;
                esac
            done
        fi
        for u in /sys/class/net/*/uevent; do
            case "$(cat "$u" 2>/dev/null)" in *DEVTYPE=wireguard*) echo wireguard ;; *DEVTYPE=amneziawg*) echo amneziawg ;; esac
        done
        for d in /proc/[0-9]*; do
            case "$(cat "$d/comm" 2>/dev/null)" in openvpn) echo openvpn ;; ocserv*) echo openconnect ;; esac
        done
    } | sort -u | head -n 16 | tr '\n' ',' | sed 's/,$//'
}

vpn_report() {
    cores=$(vpn_cores)
    log=
    if [ "$cores" -gt 0 ]; then
        if [ -n "$(vpn_logs)" ]; then log=ok; else log=none; fi
    fi
    users=
    if [ -r "$VPN_USERS" ]; then
        users=$(sort -k6,6nr "$VPN_USERS" | awk -v now="$(date +%s)" \
            '$6 >= now - 86400 && n < 32 { printf "%s%s:%s:%s:%s:%s:%s:%s", (n++ ? ";" : ""), $1, $2, $3, $4, $5, $6, ($7 == "" ? "-" : $7) }')
    fi
    cut=
    if [ -s "$VPN_CUT" ]; then
        cut=$(awk -v now="$(date +%s)" -v ips="$VPN_CUT_IPS" '
            BEGIN { while ((getline l < ips) > 0) { split(l, f, " "); if (f[3] + 0 > now) n[f[5]]++ } }
            $3 + 0 > now && k < 64 { printf "%s%s:%d", (k++ ? ";" : ""), $1, n[$1] }' "$VPN_CUT")
    fi
    printf '"panels":"%s","log":"%s","users":"%s","cut":"%s"' "$(vpn_panels)" "$log" "$users" "$cut"
}

vpn_cut_save() {
    echo "$1" | tr ';' '\n' | awk -F: 'NF == 3 && $1 ~ /^[0-9a-f]+$/ && $2 ~ /^[a-z]+$/ && $3 ~ /^[0-9]+$/ { print $1, $2, $3 }' \
        > "$VPN_CUT.new"
    if cmp -s "$VPN_CUT.new" "$VPN_CUT" 2>/dev/null; then
        rm -f "$VPN_CUT.new"
        return 1
    fi
    mv -f "$VPN_CUT.new" "$VPN_CUT"
}

counters() {
    for t in $(tables); do
        $t -w -nvxL $CHAIN 2>/dev/null
    done | awk '/vh:/ { for (i = 1; i <= NF; i++) if ($i ~ /^vh:/) { n[substr($i, 4)] += $1 } }
        END { s = ""; for (k in n) { s = s (s == "" ? "" : ",") "\"" k "\":" n[k] }; print s }'
}

dpi_mode() {
    m=off
    [ -r "$DPI_MODE_FILE" ] && m=$(cat "$DPI_MODE_FILE" 2>/dev/null)
    case "$m" in shadow|enforce) echo "$m" ;; *) echo off ;; esac
}

dpi_running() {
    [ -n "$(find "$DPI_STATS" -mmin -3 2>/dev/null)" ]
}

dpi_tapped() {
    for t in $(tables); do
        $t -w -S $CHAIN 2>/dev/null | grep -q -- vhdpi-tap && return 0
    done
    return 1
}

dpi_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
    esac
}

dpi_install_binary() {
    arch=$(dpi_arch)
    case "$arch" in
        amd64) wanted=$DPI_SHA_AMD64 ;;
        arm64) wanted=$DPI_SHA_ARM64 ;;
        *) return 1 ;;
    esac
    [ -x "$DPI_BIN" ] && [ "$(cat "$DPI_BIN.sha" 2>/dev/null)" = "$wanted" ] && return 0
    command -v sha256sum >/dev/null 2>&1 && command -v gunzip >/dev/null 2>&1 || return 1
    tmp="$LIB/vh-dpid.gz.new"
    fetch "$API/bin/vh-dpid-$arch.gz" "$tmp" || { rm -f "$tmp"; return 1; }
    [ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$wanted" ] || { log "analyser download does not match"; rm -f "$tmp"; return 1; }
    gunzip -c "$tmp" > "$DPI_BIN.new" && chmod 755 "$DPI_BIN.new" || { rm -f "$tmp" "$DPI_BIN.new"; return 1; }
    rm -f "$tmp"
    dpi_stop
    mv "$DPI_BIN.new" "$DPI_BIN" && echo "$wanted" > "$DPI_BIN.sha"
    cat > "$LIB/NOTICE" <<EOF
vh-dpid is built on nDPI by ntop.org, LGPLv3 (https://github.com/ntop/nDPI).
Sources and the build, to relink against another nDPI: https://github.com/VIBEHOST-LLC/vibehost-guard
EOF
}

dpi_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

dpi_write_unit() {
    cat > /etc/systemd/system/vibehost-guard-dpid.service <<EOF
[Unit]
Description=VibeHost torrent guard analyser
After=network-pre.target vibehost-guard.service

[Service]
ExecStart=$DPI_BIN --mode $1 --stats $DPI_STATS --scan $SCAN_LIST --flows $DPI_FLOWS
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=2 3
DynamicUser=yes
RuntimeDirectory=vibehost-guard-dpid
RuntimeDirectoryMode=0755
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
Nice=10
CPUQuota=25%
MemoryMax=96M

[Install]
WantedBy=multi-user.target
EOF
}

dpi_stop() {
    if dpi_systemd; then
        systemctl stop vibehost-guard-dpid.service >/dev/null 2>&1
    elif [ -r "$DPI_PID" ]; then
        kill "$(cat "$DPI_PID")" 2>/dev/null
        rm -f "$DPI_PID"
    fi
    rm -f "$DPI_STATS" "$SCAN_LIST" "$DPI_FLOWS"
}

dpi_start() {
    if command -v modprobe >/dev/null 2>&1; then
        modprobe -q nfnetlink_log 2>/dev/null
        modprobe -q nf_conntrack_netlink 2>/dev/null
    fi
    if dpi_systemd; then
        dpi_write_unit "$1"
        scan_write_units
        vpn_write_units
        systemctl daemon-reload
        systemctl enable vibehost-guard-dpid.service >/dev/null 2>&1
        systemctl restart vibehost-guard-dpid.service >/dev/null 2>&1
        systemctl enable --now vibehost-guard-scan.path >/dev/null 2>&1
        systemctl enable --now vibehost-guard-vpn.path >/dev/null 2>&1
    else
        mkdir -p "$DPI_RUN"
        if [ -r "$DPI_PID" ] && kill "$(cat "$DPI_PID")" 2>/dev/null; then
            n=0
            while kill -0 "$(cat "$DPI_PID")" 2>/dev/null && [ $n -lt 10 ]; do sleep 1; n=$((n + 1)); done
        fi
        nohup "$DPI_BIN" --mode "$1" --stats "$DPI_STATS" --scan "$SCAN_LIST" --flows "$DPI_FLOWS" >/dev/null 2>&1 9>&- &
        echo $! > "$DPI_PID"
    fi
}

dpi_current() {
    if dpi_systemd; then
        grep -q -- '--flows' /etc/systemd/system/vibehost-guard-dpid.service 2>/dev/null \
            && [ -f /etc/systemd/system/vibehost-guard-vpn.path ]
    else
        tr '\0' ' ' < "/proc/$(cat "$DPI_PID" 2>/dev/null)/cmdline" 2>/dev/null | grep -q -- '--flows'
    fi
}

dpi_alive() {
    if dpi_systemd; then
        systemctl is-active --quiet vibehost-guard-dpid.service
    else
        [ -r "$DPI_PID" ] && kill -0 "$(cat "$DPI_PID")" 2>/dev/null
    fi
}

dpi_sync() {
    mode=$(dpi_mode)
    if [ "$mode" = off ]; then
        if dpi_systemd && [ -f /etc/systemd/system/vibehost-guard-dpid.service ]; then
            systemctl disable vibehost-guard-dpid.service >/dev/null 2>&1
            dpi_stop
            scan_remove_units
            rm -f /etc/systemd/system/vibehost-guard-dpid.service
            systemctl daemon-reload
        elif ! dpi_systemd; then
            dpi_stop
        fi
        return 0
    fi
    dpi_install_binary || return 1
    running_mode=$(sed -n 's/.*"mode":"\([a-z]*\)".*/\1/p' "$DPI_STATS" 2>/dev/null)
    if ! dpi_alive || ! dpi_current || { [ -n "$running_mode" ] && [ "$running_mode" != "$mode" ]; }; then
        dpi_start "$mode"
    fi
}

dpi_report() {
    mode=$(dpi_mode)
    if [ "$mode" = off ]; then
        printf '"state":"off"'
    elif dpi_running && dpi_tapped; then
        printf '"state":"running",%s' "$(cat "$DPI_STATS" 2>/dev/null)"
    else
        printf '"state":"unavailable","mode":"%s","arch":"%s"' "$mode" "$(uname -m | tr -cd 'a-z0-9_')"
    fi
}

os_name() {
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "${ID:-linux}-${VERSION_ID:-}"
    else
        uname -s
    fi
}

cpu_report() {
    m=$(awk -F': *' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null)
    [ -n "$m" ] || m=$(lscpu 2>/dev/null | awk -F': *' '/^Model name/ { print $2; exit }')
    m=$(printf '%s' "$m" | tr -cd 'A-Za-z0-9 ()@._,+/-' | cut -c1-96)
    n=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    printf '"model":"%s","cores":%s' "$m" "$n"
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
    dpi_sync </dev/null || true
    ok=true
    ensure || ok=false
    [ -n "$VIBEHOST_GUARD_TOKEN" ] || return 0
    vpn_run </dev/null || true
    body="{\"version\":$VERSION,\"rulesOk\":$ok,\"os\":\"$(os_name)\",\"counters\":{$(counters)},\"dpi\":{$(dpi_report)},\"scan\":{\"mode\":\"$(scan_mode)\",\"rules\":$(scan_rules)},\"vpn\":{$(vpn_report)},\"cpu\":{$(cpu_report)}}"
    answer=$(post "$API/heartbeat" "$body" "$VIBEHOST_GUARD_TOKEN") || return 0
    wanted=$(echo "$answer" | json_field dpi)
    case "$wanted" in off|shadow|enforce)
        if [ "$wanted" != "$(dpi_mode)" ]; then
            mkdir -p "$CONF_DIR"
            echo "$wanted" > "$DPI_MODE_FILE"
            dpi_sync </dev/null || true
            [ "$wanted" = off ] || sleep 6
            ensure || true
        fi
        ;;
    esac
    scan=$(echo "$answer" | json_field scan)
    case "$scan" in off|detect|block)
        if [ "$scan" != "$(scan_mode)" ]; then
            mkdir -p "$CONF_DIR"
            echo "$scan" > "$SCAN_MODE_FILE"
            scan_sync
        fi
        ;;
    esac
    mkdir -p "$CONF_DIR"
    if vpn_cut_save "$(echo "$answer" | json_field vpnCut)"; then vpn_run </dev/null || true; fi
    latest=$(echo "$answer" | json_field version)
    if [ -n "$latest" ] && [ "$latest" -gt "$VERSION" ] 2>/dev/null; then
        if fetch "$API/guard.sh" "$LIB/guard.sh.new" && sh -n "$LIB/guard.sh.new"; then
            chmod 755 "$LIB/guard.sh.new" && mv "$LIB/guard.sh.new" "$LIB/guard.sh" && VH_GUARD_LOCKED=1 "$LIB/guard.sh" apply
        else
            rm -f "$LIB/guard.sh.new"
        fi
    fi
}

case "${1:-}" in
    apply) lock; apply ;;
    tick) lock; tick ;;
    scan) lock; scan_sync ;;
    vpn) lock; vpn_run; if [ -s "$VPN_DIR/vpn.news" ]; then tick; fi ;;
    *) lock; install_guard "${1:-}" ;;
esac
