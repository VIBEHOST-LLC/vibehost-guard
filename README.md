# vibehost-guard

Drops BitTorrent traffic on VibeHost customer Linux servers and reports to the VibeHost API that it is in place.

## Install

Run as root with the code from the server card (bot or panel):

```sh
curl -fsSL https://api.vibehost.net/api/v1/guard/guard.sh | sh -s <code>
```

OVH installs and new Hetzner VPS get it automatically.

## How it works

- iptables / ip6tables chain `VH_GUARD`, hooked into `INPUT`, `OUTPUT`, `FORWARD` and `DOCKER-USER`.
- Only the first 4 KB of each connection are inspected (`connbytes`), so VPN throughput is not affected.
- String matches: BitTorrent handshake, DHT, HTTP tracker requests, UDP tracker, LSD, magnet links.
- Encrypted BitTorrent (MSE) is not fully caught.

## On the server

| Path | What |
|---|---|
| `/usr/local/lib/vibehost-guard/guard.sh` | the script |
| `/etc/vibehost-guard/agent.conf` | agent token (0600) |
| `vibehost-guard.service` | applies rules at boot |
| `vibehost-guard-tick.timer` | every 5 min: restore rules, report |

Without systemd, `/etc/cron.d/vibehost-guard` is used instead.

## Commands

- `guard.sh <code>` - install and link to VibeHost
- `guard.sh apply` - reapply rules
- `guard.sh tick` - restore rules and report

## API

| Endpoint | |
|---|---|
| `GET /api/v1/guard/guard.sh` | the script |
| `POST /api/v1/guard/enroll` | one-time code -> agent token |
| `POST /api/v1/guard/heartbeat` | `X-Agent-Token`, rules state and counters; answers the latest version |

A heartbeat answering a higher `VERSION` makes the agent download and apply the new script.

## Backend

Lives in `telegram-bot`, not here:

- `server/guard/` - service, controller, installer, entity
- `scheduler/GuardSweepScheduler` - staff alerts
- migrations `V159`-`V161`
- bot: server cards, `/admin guard`; panel: `TorrentGuardStatus`, admin dashboard card

The served script is `telegram-bot/src/main/resources/guard/guard.sh`. Copy changes there and deploy.

## Removal

`remove-guard.sh` removes units, rules and files. Staff only, do not publish.

## Tested

Ubuntu 22.04 / 24.04, Debian 12, Alma 9, Rocky 9.
