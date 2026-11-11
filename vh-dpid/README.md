# vh-dpid

The analyser of the torrent guard. It reads copies of the first packets of each connection and marks the
connections it judges BitTorrent; a rule of `guard.sh` drops what carries the mark. Traffic never waits
for it: if it stops, nothing changes on the network.

It stores no payload and sends none anywhere. What leaves the server is counts and port numbers.

## How it decides

| Tier | What | Action |
|---|---|---|
| Strong | The protocol's own bytes in their place: handshake, DHT, tracker request, UDP tracker, LSD, handshake in uTP | Blocks; the peer is remembered for 30 min, the source for 15 |
| Weak | The library says BitTorrent, nothing confirms it | Blocks only if this source or peer had a strong hit; otherwise only counted. The server's own address confirms it only between client ports (1024 and up on both ends) |
| Ignored | Guessed from a port or an address | Never blocks |

TLS, QUIC and DNS are never judged.

## Scans

The same copies show outbound port scans. A try is a TCP SYN leaving the server, or leaving a private address
behind it (a VPN user, a container); its answer is a SYN-ACK or a reset coming back. A reset, or no answer in
3 seconds, is a failure. A source with failures to 100 different addresses, or 200 different address:port
pairs, within a minute is a scanner for the next 15 minutes, but only if at least half of its tries in that
minute failed. A proxy or a VPN whose users all leave from the server's own address fails a few hundred tries a
minute as well, but among thousands that are answered, so it is not a scanner. Inbound tries, and tries from
public addresses routed through the server, are not ours to judge.

With `--scan <file>` the scanners are written to that file, one per line: `src <address> <until>` for a VPN
user or a container, `port <n> <until>` for a port the server itself scanned (never 53, 80, 123, 443, 853),
`<until>` in Unix seconds. `guard.sh` blocks them only when VibeHost sets the scan mode to `block`. The stats
file carries `scanFailed`, `scanEvents`, `scanActive` and `scanPorts`: counts and port numbers, no address.

## Build

```sh
docker buildx build --platform linux/amd64 --target out -o out/amd64 .
docker buildx build --platform linux/arm64 --target out -o out/arm64 .
```

`out/<arch>/vh-dpid.gz` is what servers download; its SHA-256 goes into `guard.sh`. The build runs
`scan_test.c`, the scan watch on made-up traffic, and fails if it does.

## Tests

```sh
# On a real kernel, as root in a privileged container, with iptables, iproute2, python3, conntrack-tools, procps:
sh tests/live-test.sh ./vh-dpid
sh tests/guard-test.sh guard.sh vh-dpid.gz
```

## License

vh-dpid is LGPL-3.0-or-later, see `COPYING`. It links statically against
[nDPI](https://github.com/ntop/nDPI) by ntop.org (LGPLv3), in `NDPI_LICENSE_FOR_PROFIT_LGPL` mode: the
dual-licensed dissectors are not used. To relink against a modified nDPI, change `NDPI_REF` or the source
tree in the `Dockerfile` and build. nDPI is a registered trademark of ntop.org; this project is not
affiliated with or endorsed by ntop.
