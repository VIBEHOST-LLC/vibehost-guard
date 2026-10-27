# vibehost-guard

Drops BitTorrent traffic on a Linux server (iptables string match, first 4 KB of each connection).

```sh
curl -fsSL https://api.vibehost.net/api/v1/guard/guard.sh | sh -s <code>
```

- `guard.sh apply` - reapply rules (boot)
- `guard.sh tick` - restore rules and report (every 5 min)
- `remove-guard.sh` - remove everything (staff only)
