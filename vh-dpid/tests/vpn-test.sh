#!/bin/sh
# VPN users on a real kernel: vh-dpid lists a torrent connection the server itself opened, as Xray does for
# its users, and guard.sh names the user from a fake Xray's access log and cuts it off. An address two users
# share (a bridge, HAProxy) or one not connected to the core (PROXY protocol) is never cut.
# Run as root in a privileged container with iptables, iproute2, python3: sh tests/vpn-test.sh <vh-dpid> <guard.sh>
set -u
BIN=${1:-/vh-dpid}
GUARD=${2:-/guard.sh}
W=/tmp/vpn-test
fail=0

ok() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

cleanup() {
    pkill -x vh-dpid 2>/dev/null
    pkill -f "$W/peer.py" 2>/dev/null
    pkill -f "$W/hold.py" 2>/dev/null
    pkill -x xray-linux-amd 2>/dev/null
    ip netns del vhs 2>/dev/null
    for h in INPUT OUTPUT; do iptables -D $h -j VH_GUARD 2>/dev/null; done
    iptables -F VH_GUARD 2>/dev/null; iptables -X VH_GUARD 2>/dev/null
    iptables -F VH_GUARD_SCAN 2>/dev/null; iptables -X VH_GUARD_SCAN 2>/dev/null
}
trap cleanup EXIT
cleanup
rm -rf "$W"; mkdir -p "$W/run" "$W/conf" "$W/xlog"

ip netns add vhs
ip link add vs0 type veth peer name vs1
ip link set vs1 netns vhs
ip addr add 203.0.113.1/24 dev vs0; ip link set vs0 up
ip netns exec vhs ip addr add 203.0.113.2/24 dev vs1; ip netns exec vhs ip link set vs1 up
ip netns exec vhs ip link set lo up
for a in 198.51.100.50 198.51.100.70; do ip netns exec vhs ip addr add $a/32 dev vs1; done
ip route add 198.51.100.0/24 dev vs0

iptables -N VH_GUARD
iptables -N VH_GUARD_SCAN
iptables -A VH_GUARD -j VH_GUARD_SCAN
iptables -A VH_GUARD -m connbytes --connbytes 1:12 --connbytes-dir both --connbytes-mode packets \
    -j NFLOG --nflog-group 4711 --nflog-size 512
iptables -I INPUT 1 -j VH_GUARD
iptables -I OUTPUT 1 -j VH_GUARD

cat > "$W/peer.py" <<'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 6881)); s.listen(5)
while True:
    c, _ = s.accept()
    try:
        c.recv(4096); c.sendall(b"\x13BitTorrent protocol" + b"\0" * 48); c.recv(4096)
    except OSError:
        pass
    c.close()
EOF
ip netns exec vhs python3 "$W/peer.py" &

# Users connected to the core: alice from her own address, carol and dave through one bridge address.
cat > "$W/hold.py" <<'EOF'
import socket, sys, time
held = []
if sys.argv[1] == "listen":
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("203.0.113.1", 443)); s.listen(16)
    while True:
        held.append(s.accept()[0])
for src in sys.argv[2:]:
    c = socket.socket(); c.bind((src, 0)); c.connect(("203.0.113.1", 443)); held.append(c)
time.sleep(600)
EOF
python3 "$W/hold.py" listen &
sleep 1
ip netns exec vhs python3 "$W/hold.py" connect 198.51.100.50 198.51.100.70 &
sleep 1

"$BIN" --mode shadow --stats "$W/run/stats" --flows "$W/run/flows" &
sleep 2

# The connection Xray would open for its user: from the server itself to the peer.
python3 - <<'EOF'
import socket
s = socket.create_connection(("203.0.113.2", 6881), timeout=5)
s.sendall(b"\x13BitTorrent protocol" + b"\0" * 8 + b"A" * 40)
try:
    s.recv(4096)
except OSError:
    pass
s.close()
EOF

n=0
while [ ! -s "$W/run/flows" ] && [ $n -lt 40 ]; do sleep 1; n=$((n + 1)); done
if grep -q "^tcp 203.0.113.1 [0-9]* 203.0.113.2 6881 " "$W/run/flows" 2>/dev/null; then
    ok "the server's own torrent connection is listed"
else
    bad "the server's own torrent connection is listed: $(cat "$W/run/flows" 2>/dev/null)"
fi
[ "$(stat -c %a "$W/run/flows" 2>/dev/null)" = 600 ] && ok "the list is readable by root only" || bad "the list is readable by root only"

# A fake Xray holding its access log open, and the line it wrote for the connection.
echo "2026/11/19 10:00:00 from 198.51.100.50:51234 accepted tcp:203.0.113.2:6881 [inbound-443 >> direct] email: alice" \
    > "$W/xlog/access.log"
echo "2026/11/19 10:00:01 from 198.51.100.60:4000 accepted tcp:www.example.com:443 [inbound-443 >> direct] email: bob" \
    >> "$W/xlog/access.log"
python3 -c 'import ctypes, time; ctypes.CDLL(None).prctl(15, b"xray-linux-amd", 0, 0, 0); time.sleep(600)'     3>>"$W/xlog/access.log" &
sleep 1

sed '/^case "\${1:-}" in/,$d' "$GUARD" > "$W/guard-lib.sh"
. "$W/guard-lib.sh"
DPI_FLOWS="$W/run/flows"
CONF_DIR="$W/conf"
VPN_DIR="$W/state"
VPN_USERS="$VPN_DIR/vpn.users"
VPN_SEEN="$VPN_DIR/vpn.seen"
VPN_OFFSETS="$VPN_DIR/vpn.offsets"
VPN_CUT_IPS="$VPN_DIR/vpn.cutips"
VPN_CUT="$CONF_DIR/vpn.cut"
VPN_SHARED="$CONF_DIR/vpn.shared"
SCAN_MODE_FILE="$CONF_DIR/scan.mode"
tables() { echo iptables; }

vpn_run
if grep -q "^$(hex alice) xray $(hex inbound-443) 1 " "$VPN_USERS" 2>/dev/null; then
    ok "the torrent connection is matched to alice"
else
    bad "the torrent connection is matched to alice: $(cat "$VPN_USERS" 2>/dev/null)"
fi
grep -q "$(hex bob)" "$VPN_USERS" 2>/dev/null && bad "bob, who only browsed, is not named" || ok "bob, who only browsed, is not named"
[ -s "$VPN_DIR/vpn.news" ] && ok "a new user asks for a report now" || bad "a new user asks for a report now"
case "$(vpn_report)" in *"\"log\":\"ok\""*"$(hex alice):xray:"*) ok "the report names alice in hex" ;;
    *) bad "the report names alice in hex: $(vpn_report)" ;; esac

vpn_cut_save "$(hex alice):xray:$(($(date +%s) + 600))" && vpn_run
if iptables -S VH_GUARD_SCAN | grep -q -- "-s 198.51.100.50/32 -p tcp -m tcp --dport 443 .*vhuser"; then
    ok "cut off: alice's address is dropped on the inbound's port"
else
    bad "cut off: alice's address is dropped on the inbound's port: $(iptables -S VH_GUARD_SCAN)"
fi
iptables -S VH_GUARD_SCAN | grep -q 198.51.100.60 && bad "bob is not cut off" || ok "bob is not cut off"

case "$(vpn_report)" in *"\"cut\":\"$(hex alice):1\""*) ok "the report counts alice's dropped address" ;;
    *) bad "the report counts alice's dropped address: $(vpn_report)" ;; esac

vpn_cut_save "" ; vpn_run
iptables -S VH_GUARD_SCAN | grep -q vhuser && bad "released when the cut is lifted" || ok "released when the cut is lifted"

# carol torrents through the bridge dave also uses; erin's address came over PROXY protocol and is not
# connected to the core.
sleep 1
now=$(date +%s)
printf 'tcp 203.0.113.1 40001 203.0.113.9 6881 %s\ntcp 203.0.113.1 40002 203.0.113.10 6881 %s\n' "$now" "$now" \
    > "$W/run/flows2"
DPI_FLOWS="$W/run/flows2"
cat >> "$W/xlog/access.log" <<EOF
2026/11/19 10:01:00 from 198.51.100.70:5000 accepted tcp:203.0.113.9:6881 [inbound-443 >> direct] email: carol
2026/11/19 10:01:01 from 198.51.100.70:5001 accepted tcp:www.example.com:443 [inbound-443 >> direct] email: dave
2026/11/19 10:01:02 from 198.51.100.80:5002 accepted tcp:203.0.113.10:6881 [inbound-443 >> direct] email: erin
EOF
vpn_run
grep -q "^$(hex carol) xray .* r$" "$VPN_USERS" && ok "carol is marked as behind a shared address" \
    || bad "carol is marked as behind a shared address: $(cat "$VPN_USERS")"
grep -q "^$(hex erin) xray .* p$" "$VPN_USERS" && ok "erin is marked as not connected to the core" \
    || bad "erin is marked as not connected to the core: $(cat "$VPN_USERS")"
grep -q "^$(hex alice) xray .* -$" "$VPN_USERS" && ok "alice stays a direct user" || bad "alice stays a direct user"
grep -q "^198.51.100.70 " "$VPN_SHARED" && ok "the bridge address is remembered" || bad "the bridge address is remembered"
case "$(vpn_report)" in *"$(hex carol):xray:"*":r"*) ok "the report says carol comes through a bridge" ;;
    *) bad "the report says carol comes through a bridge: $(vpn_report)" ;; esac

until=$(($(date +%s) + 600))
vpn_cut_save "$(hex carol):xray:$until;$(hex erin):xray:$until" && vpn_run
iptables -S VH_GUARD_SCAN | grep -q 198.51.100.70 && bad "the bridge address is not cut" || ok "the bridge address is not cut"
iptables -S VH_GUARD_SCAN | grep -q 198.51.100.80 && bad "an address not connected to the core is not cut" \
    || ok "an address not connected to the core is not cut"
case "$(vpn_report)" in *"\"cut\":\"$(hex carol):0;$(hex erin):0\""*) ok "the report says nothing was dropped for them" ;;
    *) bad "the report says nothing was dropped for them: $(vpn_report)" ;; esac

exit $fail
