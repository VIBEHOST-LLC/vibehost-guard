#!/bin/sh
# guard.sh v5 against a stand-in for our API, on a real kernel: the mode from the report, the rule
# profiles, the way back when the analyser dies, and scans caught and blocked. Run as root in a
# privileged container with iproute2: the VPN user is a network namespace behind NAT.
#   guard-test.sh <guard.sh> <vh-dpid.gz>
set -u
SCRIPT=$1
GZ=$2
LIB=/usr/local/lib/vibehost-guard
API_DIR=/tmp/api
fail=0

ok() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

mkdir -p "$API_DIR/bin"
cp "$GZ" "$API_DIR/bin/vh-dpid-amd64.gz"
cat > /tmp/api.py <<'EOF'
import http.server, json, os
MODE = "/tmp/api/mode"
SCAN = "/tmp/api/scan"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype="application/json"):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = "/tmp/api/" + self.path.split("/guard/")[-1]
        if not os.path.isfile(path):
            self.send_response(404); self.end_headers(); return
        self._send(open(path, "rb").read(), "application/octet-stream")
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.endswith("/enroll"):
            self._send(b'{"token":"t"}'); return
        open("/tmp/api/last-report", "wb").write(body)
        self._send(json.dumps({"version": 3, "dpi": open(MODE).read().strip(),
                               "scan": open(SCAN).read().strip()}).encode())
http.server.HTTPServer(("127.0.0.1", 9099), H).serve_forever()
EOF
echo off > "$API_DIR/mode"
echo detect > "$API_DIR/scan"
python3 /tmp/api.py &
API_PID=$!
sleep 1
export VH_GUARD_API=http://127.0.0.1:9099/api/v1/guard

tick() { "$LIB/guard.sh" tick; }
rules() { iptables -S VH_GUARD 2>/dev/null; }
has() { rules | grep -q -- "$1"; }
# The first one: "mode" is also in the scan object, after the analyser's.
report() { grep -o "\"$1\":\"[a-z]*\"" "$API_DIR/last-report" | head -n 1 | cut -d'"' -f4; }

sh "$SCRIPT" somecode >/dev/null 2>&1
[ -x "$LIB/guard.sh" ] && ok "installed" || bad "not installed"

echo "--- off: exactly the old rules"
tick
has vh:tracker-peer-id && ok "off: full string rules" || bad "off: strings missing"
has vhdpi && bad "off: analyser rules present" || ok "off: no analyser rules"
[ ! -e "$LIB/vh-dpid" ] && ok "off: nothing downloaded" || bad "off: downloaded the analyser"
[ "$(report state)" = off ] && ok "off: reported" || bad "off: report says '$(report state)'"

echo "--- shadow: it reads, the strings keep cutting"
echo shadow > "$API_DIR/mode"
tick
[ -x "$LIB/vh-dpid" ] && ok "shadow: analyser installed" || bad "shadow: no analyser"
has vhdpi-tap && ok "shadow: copies go to it" || bad "shadow: no tap rule"
has vhdpi-drop && bad "shadow: must not drop by mark" || ok "shadow: no drop by mark"
has vh:tracker-peer-id && ok "shadow: full string rules stay" || bad "shadow: strings gone"
pgrep -x vh-dpid >/dev/null && ok "shadow: running" || bad "shadow: not running"
tick
[ "$(report state)" = running ] && ok "shadow: reported running" || bad "shadow: report says '$(report state)'"
[ "$(report mode)" = shadow ] && ok "shadow: reports its mode" || bad "shadow: mode '$(report mode)'"

echo "--- enforce: the loose strings go"
echo enforce > "$API_DIR/mode"
tick
has vhdpi-drop && ok "enforce: drop by mark" || bad "enforce: no drop rule"
tick
has vh:tracker-peer-id && bad "enforce: loose strings stayed" || ok "enforce: loose strings gone"
has vh:magnet && bad "enforce: magnet stayed" || ok "enforce: magnet gone"
has vh:bt-handshake && ok "enforce: handshake rule stays" || bad "enforce: handshake rule gone"
has vh:dht-query && ok "enforce: DHT rule stays" || bad "enforce: DHT rule gone"
pgrep -x vh-dpid | head -n 1 > /tmp/pid1
tick
[ "$(pgrep -x vh-dpid | head -n 1)" = "$(cat /tmp/pid1)" ] && ok "enforce: a check does not restart it" || bad "enforce: restarted on a check"

echo "--- analyser dies: the strings are back at the next check"
pkill -9 -x vh-dpid
rm -f /run/vibehost-guard-dpid/stats
"$LIB/guard.sh" apply
has vh:tracker-peer-id && ok "dead: full strings back at once on apply" || bad "dead: strings not back"
tick
pgrep -x vh-dpid >/dev/null && ok "dead: a check restarts it" || bad "dead: not restarted"

echo "--- someone flushes the rules"
iptables -F VH_GUARD
tick
has vh:bt-handshake && ok "flushed: rules restored" || bad "flushed: not restored"

echo "--- scans: caught in detect, cut in block, never on a vital port"
cat > /tmp/scan.py <<'EOF'
import socket, sys, time
net, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
for i in range(1, n + 1):
    s = socket.socket(); s.setblocking(False)
    try: s.connect_ex(("%s.%d" % (net, i), port))
    except OSError: pass
    socks.append(s)
time.sleep(5)
EOF
scanrules() { iptables -S VH_GUARD_SCAN 2>/dev/null; }
listed() { grep -q -- "$1" /run/vibehost-guard-dpid/scan 2>/dev/null; }
echo shadow > "$API_DIR/mode"
tick
has "-j VH_GUARD_SCAN" && ok "scan: the chain hangs off VH_GUARD" || bad "scan: no jump to VH_GUARD_SCAN"
# TEST-NET addresses: nobody answers, nobody is bothered.
python3 /tmp/scan.py 198.51.100 2222 150
python3 /tmp/scan.py 198.51.101 443 150
sleep 15
listed "port 2222" && ok "scan: the server's scan of 2222 is listed" || bad "scan: 2222 not listed: $(cat /run/vibehost-guard-dpid/scan 2>/dev/null)"
listed "port 443 " && bad "scan: a vital port is listed" || ok "scan: 443 is never listed"
"$LIB/guard.sh" scan
scanrules | grep -q -- "-j DROP" && bad "scan: detect must not cut" || ok "scan: detect cuts nothing"
sleep 31
tick
grep -q '"scanEvents":[1-9]' "$API_DIR/last-report" && ok "scan: reported" || bad "scan: no scanEvents in the report"
grep -q '"scan":{"mode":"detect"' "$API_DIR/last-report" && ok "scan: mode reported" || bad "scan: mode not reported"

echo block > "$API_DIR/scan"
tick
scanrules | grep -q -- "--dport 2222" && ok "block: 2222 cut for the server" || bad "block: no rule for 2222"
scanrules | grep -q -- "--dport 443" && bad "block: 443 cut" || ok "block: 443 left alone"
python3 /tmp/scan.py 198.51.102 2222 3
[ "$(iptables -nvxL VH_GUARD_SCAN | awk '/vhscan-port/ {s += $1} END {print s + 0}')" -gt 0 ] \
    && ok "block: new tries to 2222 are dropped" || bad "block: nothing dropped"

# A VPN user behind NAT, scanning port 3333.
ip netns add vpn && ip link add vh0 type veth peer name vh1 && ip link set vh1 netns vpn \
    && ip addr add 10.9.0.1/24 dev vh0 && ip link set vh0 up \
    && ip netns exec vpn ip addr add 10.9.0.2/24 dev vh1 && ip netns exec vpn ip link set vh1 up \
    && ip netns exec vpn ip link set lo up && ip netns exec vpn ip route add default via 10.9.0.1 \
    && sysctl -qw net.ipv4.ip_forward=1 && iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -j MASQUERADE \
    || bad "vpn: namespace not set up"
ip netns exec vpn python3 /tmp/scan.py 192.0.2 3333 150
sleep 15
listed "src 10.9.0.2" && ok "vpn: the user is listed as a scanner" || bad "vpn: user not listed: $(cat /run/vibehost-guard-dpid/scan 2>/dev/null)"
"$LIB/guard.sh" scan
scanrules | grep -q -- "-s 10.9.0.2" && ok "vpn: the user is cut" || bad "vpn: no rule for the user"
scanrules | grep -q -- "--dport 3333" && bad "vpn: the server is blamed for the user" || ok "vpn: the server keeps 3333"

echo detect > "$API_DIR/scan"
tick
scanrules | grep -q -- "-j DROP" && bad "detect again: rules left" || ok "detect again: everything released"
echo block > "$API_DIR/scan"
tick
iptables -F VH_GUARD_SCAN
"$LIB/guard.sh" scan
scanrules | grep -q -- "-s 10.9.0.2" && ok "flushed: the list is put back" || bad "flushed: not restored"
echo detect > "$API_DIR/scan"
tick
ip netns del vpn 2>/dev/null

echo "--- tampered download is refused"
echo off > "$API_DIR/mode"
tick
sleep 1
pgrep -x vh-dpid >/dev/null && bad "off: still running: $(pgrep -x vh-dpid | wc -l)" || ok "off: analyser stopped"
has vhdpi && bad "off: analyser rules left" || ok "off: analyser rules removed"
has vh:tracker-peer-id && ok "off: full strings back" || bad "off: strings missing"
rm -f "$LIB/vh-dpid" "$LIB/vh-dpid.sha"
echo garbage | gzip -c > "$API_DIR/bin/vh-dpid-amd64.gz"
echo shadow > "$API_DIR/mode"
tick
[ ! -e "$LIB/vh-dpid" ] && ok "tampered: not installed" || bad "tampered: installed"
has vh:tracker-peer-id && ok "tampered: strings still work" || bad "tampered: strings gone"
tick
[ "$(report state)" = unavailable ] && ok "tampered: reported unavailable" || bad "tampered: report says '$(report state)'"

kill $API_PID 2>/dev/null
[ "$fail" = 0 ] && echo ALL PASSED
exit $fail
