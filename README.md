# vibehost-guard

Drops BitTorrent traffic on a Linux server: iptables string match on the first 4 KB of each connection,
and the [vh-dpid](vh-dpid/README.md) analyser, built on nDPI by ntop.org.

```sh
curl -fsSL https://api.vibehost.net/api/v1/guard/guard.sh | sh -s <code>
```

- `guard.sh apply` - reapply rules (boot)
- `guard.sh tick` - restore rules and report (every 5 min)
- `guard.sh scan` - apply the analyser's list of scanners (when it changes)
- `guard.sh vpn` - name the VPN user behind the analyser's torrent connections (when it judges new ones)
- `remove-guard.sh` - remove everything (staff only)
