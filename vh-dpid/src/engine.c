/*
 * vh-dpid decision engine. See engine.h.
 *
 * Three tiers, so that a wrong answer from a heuristic cannot cut somebody off:
 *   strong   our own check of the protocol's bytes at their fixed place: blocks, and is remembered
 *   weak     the library says BitTorrent but we cannot confirm it: blocks only if this source or
 *            peer had a strong hit recently, otherwise it is only counted
 *   ignored  anything guessed from a port or an address
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#include "engine.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "ndpi_api.h"
#include "scan.h"

#define FLOW_BUCKETS (1u << 16)
#define MAX_FLOWS 65536u
/* Each one under analysis costs the library's flow struct, about 1.3 KB. */
#define MAX_ANALYSED 16384u
#define FLOW_IDLE_MS (120u * 1000u)

#define PEER_TTL_MS (30u * 60u * 1000u)
#define SOURCE_TTL_MS (15u * 60u * 1000u)
#define PEER_SLOTS 8192u
#define SOURCE_SLOTS 2048u
#define PORT_SLOTS 256u
#define PROBE 8u

/* Ports below this are services, never a torrent client's: never remembered, never tainted. */
#define FIRST_CLIENT_PORT 1024

typedef struct flow {
    struct flow *next;
    struct ndpi_flow_struct *analysis;  /* NULL once decided */
    vh_tuple tuple;                     /* as first seen */
    uint64_t last_ms;
    uint32_t last_packet;               /* hash of the last copy */
    uint16_t packets;
    char hook;
    uint8_t pending;                    /* blocked, but not carried out yet */
    uint8_t reason;
} flow;

typedef struct {
    uint8_t key[18];
    uint64_t expires_ms;
} memory_slot;

typedef struct {
    memory_slot *slots;
    uint32_t size;
} memory;

struct vh_engine {
    struct ndpi_detection_module_struct *ndpi;
    vh_verdict_fn fn;
    void *user;
    flow *buckets[FLOW_BUCKETS];
    uint32_t flow_count;
    uint32_t analysed;
    memory peers, sources, udp_ports;
    vh_scan *scan;
    vh_stats stats;
    uint8_t scratch[VH_TAP_BYTES];
};

/* ---- small helpers ---- */

static uint32_t mix(const uint8_t *b, size_t n, uint32_t h) {
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
    return h;
}

static size_t addr_len(int family) {
    return family == AF_INET ? 4 : 16;
}

static int find(const uint8_t *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++) {
        if (hay[i] == (uint8_t) needle[0] && memcmp(hay + i, needle, m) == 0) return 1;
    }
    return 0;
}

static int starts(const uint8_t *p, size_t n, const char *prefix) {
    size_t m = strlen(prefix);
    return n >= m && memcmp(p, prefix, m) == 0;
}

/* ---- memories: fixed tables, the oldest entry of a probe run makes way ---- */

static int memory_init(memory *m, uint32_t size) {
    m->slots = calloc(size, sizeof(memory_slot));
    m->size = size;
    return m->slots ? 0 : -1;
}

static void memory_key(uint8_t key[18], int family, const uint8_t *addr, uint16_t port) {
    memset(key, 0, 18);
    if (addr) memcpy(key, addr, addr_len(family));
    key[16] = (uint8_t) (port >> 8);
    key[17] = (uint8_t) port;
}

static void memory_put(memory *m, const uint8_t key[18], uint64_t expires_ms) {
    uint32_t h = mix(key, 18, 2166136261u);
    memory_slot *oldest = NULL;
    for (uint32_t i = 0; i < PROBE; i++) {
        memory_slot *s = &m->slots[(h + i) % m->size];
        if (memcmp(s->key, key, 18) == 0) {
            s->expires_ms = expires_ms;
            return;
        }
        if (oldest == NULL || s->expires_ms < oldest->expires_ms) oldest = s;
    }
    memcpy(oldest->key, key, 18);
    oldest->expires_ms = expires_ms;
}

static int memory_has(const memory *m, const uint8_t key[18], uint64_t now_ms) {
    uint32_t h = mix(key, 18, 2166136261u);
    for (uint32_t i = 0; i < PROBE; i++) {
        const memory_slot *s = &m->slots[(h + i) % m->size];
        if (s->expires_ms > now_ms && memcmp(s->key, key, 18) == 0) return 1;
    }
    return 0;
}

/* ---- the top ports table: only a port number and a count ever leave this server ---- */

static void count_port(vh_port_count *table, uint16_t port) {
    vh_port_count *lowest = &table[0];
    for (int i = 0; i < VH_TOP_PORTS; i++) {
        if (table[i].port == port && table[i].hits) {
            table[i].hits++;
            return;
        }
        if (table[i].hits < lowest->hits) lowest = &table[i];
    }
    lowest->port = port;
    lowest->hits = 1;
}

/* ---- signatures ---- */

static const char BT_HANDSHAKE[] = "\x13" "BitTorrent protocol";
#define BT_HANDSHAKE_LEN 20

/* A tracker request's first line. A page merely mentioning these words is not a GET of them. */
static int http_tracker_request(const uint8_t *p, size_t n) {
    if (!starts(p, n, "GET /")) return 0;
    size_t line = 0;
    while (line < n && p[line] != '\r' && p[line] != '\n') line++;
    if (!find(p, line, "info_hash=")) return 0;
    return find(p, line, "peer_id=") || find(p, line, "/scrape?");
}

int vh_strong_signature(uint8_t proto, const uint8_t *p, size_t n) {
    if (proto == IPPROTO_TCP) {
        if (n >= BT_HANDSHAKE_LEN && memcmp(p, BT_HANDSHAKE, BT_HANDSHAKE_LEN) == 0) return 1;
        return http_tracker_request(p, n);
    }
    if (proto != IPPROTO_UDP) return 0;

    /* DHT: a bencoded dictionary with a 20-byte node id. A reply may start with its "ip" key. */
    if (n > 12 && p[0] == 'd') {
        size_t head = n < 64 ? n : 64;
        if (starts(p, n, "d1:ad2:id20:") || find(p, head, "1:rd2:id20:")) return 1;
    }
    /* UDP tracker connect request: the protocol's fixed magic number and action 0. */
    static const uint8_t MAGIC[12] = {0, 0, 4, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0};
    if (n == 16 && memcmp(p, MAGIC, sizeof MAGIC) == 0) return 1;
    /* Local peer discovery. */
    if (starts(p, n, "BT-SEARCH * HTTP/1.1")) return 1;
    /* uTP carrying the handshake: version 1, a data packet, the handshake after its header. */
    if (n >= 20 + BT_HANDSHAKE_LEN && (p[0] & 0x0f) == 1 && (p[0] >> 4) == 0) {
        size_t limit = n < 96 ? n : 96;
        for (size_t i = 20; i + BT_HANDSHAKE_LEN <= limit; i++) {
            if (memcmp(p + i, BT_HANDSHAKE, BT_HANDSHAKE_LEN) == 0) return 1;
        }
    }
    return 0;
}

/* Never judged: TLS, QUIC, DNS. The LGPL build of the library has no dissectors for them. */
static int exempt_payload(const vh_tuple *t, const uint8_t *p, size_t n) {
    if (t->sport == 53 || t->dport == 53) return 1;
    if (n == 0) return 0;
    if (t->proto == IPPROTO_TCP) {
        return n >= 6 && p[0] == 0x16 && p[1] == 3 && p[2] <= 4;
    }
    return (t->sport == 443 || t->dport == 443) && (p[0] & 0xc0) == 0xc0;
}

/* ---- addresses: who is the source, who the peer ---- */

static int is_private(int family, const uint8_t *a) {
    if (family == AF_INET) {
        return a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16) || (a[0] == 192 && a[1] == 168)
            || (a[0] == 100 && (a[1] & 0xc0) == 64);
    }
    return (a[0] & 0xfe) == 0xfc;
}

static int is_group(int family, const uint8_t *a) {
    if (family == AF_INET) return (a[0] & 0xf0) == 0xe0 || a[0] == 255;
    return a[0] == 0xff;
}

/*
 * Which side is ours, 1 for src. Local traffic: the hook says. Forwarded: the VPN user or container
 * is the private side, else whoever started the connection.
 */
static int src_is_ours(const vh_tuple *t, char hook) {
    if (hook == VH_HOOK_OUTPUT) return 1;
    if (hook == VH_HOOK_INPUT) return 0;
    int s = is_private(t->family, t->src), d = is_private(t->family, t->dst);
    return s == d ? 1 : s;
}

/* ---- flows ---- */

static uint32_t flow_hash(const vh_tuple *t) {
    /* Both directions land in the same bucket. */
    size_t al = addr_len(t->family);
    uint32_t a = mix(t->src, al, 2166136261u) ^ mix((const uint8_t *) &t->sport, 2, 2166136261u);
    uint32_t b = mix(t->dst, al, 2166136261u) ^ mix((const uint8_t *) &t->dport, 2, 2166136261u);
    return (a + b + t->proto) & (FLOW_BUCKETS - 1);
}

static int same_flow(const vh_tuple *x, const vh_tuple *y) {
    if (x->family != y->family || x->proto != y->proto) return 0;
    size_t al = addr_len(x->family);
    if (x->sport == y->sport && x->dport == y->dport && memcmp(x->src, y->src, al) == 0
        && memcmp(x->dst, y->dst, al) == 0) return 1;
    return x->sport == y->dport && x->dport == y->sport && memcmp(x->src, y->dst, al) == 0
        && memcmp(x->dst, y->src, al) == 0;
}

static void finish(vh_engine *e, flow *f) {
    if (f->analysis) {
        ndpi_free_flow(f->analysis);
        f->analysis = NULL;
        e->analysed--;
    }
}

static flow *flow_get(vh_engine *e, const vh_tuple *t, char hook, uint64_t now_ms, int *created) {
    uint32_t h = flow_hash(t);
    *created = 0;
    for (flow *f = e->buckets[h]; f; f = f->next) {
        if (same_flow(&f->tuple, t)) return f;
    }
    if (e->flow_count >= MAX_FLOWS || e->analysed >= MAX_ANALYSED) {
        vh_engine_sweep(e, now_ms);
        if (e->flow_count >= MAX_FLOWS || e->analysed >= MAX_ANALYSED) {
            e->stats.overflow++;
            return NULL;
        }
    }
    flow *f = calloc(1, sizeof(flow));
    if (!f) return NULL;
    f->analysis = ndpi_calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
    if (!f->analysis) {
        free(f);
        return NULL;
    }
    f->tuple = *t;
    f->hook = hook;
    f->next = e->buckets[h];
    e->buckets[h] = f;
    e->flow_count++;
    e->analysed++;
    e->stats.flows++;
    *created = 1;
    return f;
}

void vh_engine_sweep(vh_engine *e, uint64_t now_ms) {
    vh_scan_tick(e->scan, now_ms);
    for (uint32_t i = 0; i < FLOW_BUCKETS; i++) {
        flow **link = &e->buckets[i];
        while (*link) {
            flow *f = *link;
            if (f->last_ms + FLOW_IDLE_MS < now_ms) {
                *link = f->next;
                finish(e, f);
                free(f);
                e->flow_count--;
            } else {
                link = &f->next;
            }
        }
    }
}

/* ---- parsing ---- */

typedef struct {
    vh_tuple tuple;
    uint8_t tcp_flags;
    const uint8_t *payload;
    size_t payload_len;
} parsed;

/*
 * The copy is cut at VH_TAP_BYTES while its headers still give the full length. The library trusts
 * the headers, so it gets a copy whose lengths say what it really has.
 */
static int parse(vh_engine *e, const uint8_t *in, size_t len, parsed *out, const uint8_t **l3, size_t *l3_len) {
    if (len > VH_TAP_BYTES) len = VH_TAP_BYTES;
    if (len < 20) return -1;
    memcpy(e->scratch, in, len);
    uint8_t *p = e->scratch;
    size_t off;
    uint8_t proto;
    memset(&out->tuple, 0, sizeof out->tuple);

    if ((p[0] >> 4) == 4) {
        off = (size_t) (p[0] & 0x0f) * 4;
        if (off < 20 || len < off) return -1;
        /* A later fragment has no ports: nothing to read. */
        if ((((p[6] & 0x1f) << 8) | p[7]) != 0) return -1;
        proto = p[9];
        out->tuple.family = AF_INET;
        memcpy(out->tuple.src, p + 12, 4);
        memcpy(out->tuple.dst, p + 16, 4);
        uint16_t total = htons((uint16_t) len);
        memcpy(p + 2, &total, 2);
    } else if ((p[0] >> 4) == 6) {
        if (len < 40) return -1;
        out->tuple.family = AF_INET6;
        memcpy(out->tuple.src, p + 8, 16);
        memcpy(out->tuple.dst, p + 24, 16);
        uint16_t pl = htons((uint16_t) (len - 40));
        memcpy(p + 4, &pl, 2);
        proto = p[6];
        off = 40;
        /* Extension headers. */
        while (proto == 0 || proto == 43 || proto == 44 || proto == 60) {
            if (len < off + 8) return -1;
            if (proto == 44) {
                if ((((p[off + 2] << 8) | p[off + 3]) & 0xfff8) != 0) return -1;
                proto = p[off];
                off += 8;
            } else {
                uint8_t next = p[off];
                off += ((size_t) p[off + 1] + 1) * 8;
                proto = next;
            }
        }
    } else {
        return -1;
    }

    out->tuple.proto = proto;
    out->tcp_flags = 0;
    if (proto == IPPROTO_TCP) {
        if (len < off + 20) return -1;
        size_t hl = (size_t) (p[off + 12] >> 4) * 4;
        if (hl < 20 || len < off + hl) return -1;
        out->tcp_flags = p[off + 13];
        out->payload = p + off + hl;
        out->payload_len = len - off - hl;
    } else if (proto == IPPROTO_UDP) {
        if (len < off + 8) return -1;
        uint16_t udp = htons((uint16_t) (len - off));
        memcpy(p + off + 4, &udp, 2);
        out->payload = p + off + 8;
        out->payload_len = len - off - 8;
    } else {
        return -1;
    }
    out->tuple.sport = (uint16_t) ((p[off] << 8) | p[off + 1]);
    out->tuple.dport = (uint16_t) ((p[off + 2] << 8) | p[off + 3]);
    *l3 = p;
    *l3_len = len;
    return 0;
}

/* ---- the decision ---- */

static void block(vh_engine *e, flow *f, vh_reason reason) {
    e->stats.reasons[reason]++;
    f->reason = (uint8_t) reason;
    f->pending = e->fn && !e->fn(&f->tuple, reason, e->user);
    finish(e, f);
}

static void remember_strong(vh_engine *e, const flow *f, int ours_is_src, uint64_t now_ms) {
    const vh_tuple *t = &f->tuple;
    const uint8_t *ours = ours_is_src ? t->src : t->dst;
    const uint8_t *peer = ours_is_src ? t->dst : t->src;
    uint16_t our_port = ours_is_src ? t->sport : t->dport;
    uint16_t peer_port = ours_is_src ? t->dport : t->sport;
    uint8_t key[18];

    /* Whichever service runs below 1024 is somebody's server, not a torrent client. */
    if (peer_port >= FIRST_CLIENT_PORT && !is_group(t->family, peer)) {
        memory_key(key, t->family, peer, peer_port);
        memory_put(&e->peers, key, now_ms + PEER_TTL_MS);
    }
    /* The source: forwarded it is one VPN user; local it only corroborates, see below. */
    memory_key(key, t->family, ours, f->hook == VH_HOOK_FORWARD ? 0 : 1);
    memory_put(&e->sources, key, now_ms + SOURCE_TTL_MS);

    /* The server itself is never tainted whole, only the UDP socket that said it is a client. */
    if (f->hook != VH_HOOK_FORWARD && t->proto == IPPROTO_UDP && our_port >= FIRST_CLIENT_PORT) {
        memory_key(key, t->family, NULL, our_port);
        memory_put(&e->udp_ports, key, now_ms + SOURCE_TTL_MS);
    }
}

static int peer_known(const vh_engine *e, const flow *f, int ours_is_src, uint64_t now_ms) {
    const vh_tuple *t = &f->tuple;
    uint8_t key[18];
    memory_key(key, t->family, ours_is_src ? t->dst : t->src, ours_is_src ? t->dport : t->sport);
    return memory_has(&e->peers, key, now_ms);
}

static int source_marked(const vh_engine *e, const flow *f, int ours_is_src, uint64_t now_ms) {
    const vh_tuple *t = &f->tuple;
    uint8_t key[18];
    memory_key(key, t->family, ours_is_src ? t->src : t->dst, f->hook == VH_HOOK_FORWARD ? 0 : 1);
    return memory_has(&e->sources, key, now_ms);
}

static int udp_port_marked(const vh_engine *e, const flow *f, int ours_is_src, uint64_t now_ms) {
    const vh_tuple *t = &f->tuple;
    uint8_t key[18];
    if (f->hook == VH_HOOK_FORWARD || t->proto != IPPROTO_UDP) return 0;
    memory_key(key, t->family, NULL, ours_is_src ? t->sport : t->dport);
    return memory_has(&e->udp_ports, key, now_ms);
}

static int counts_as_bittorrent(struct ndpi_proto_stack *stack, ndpi_confidence_t confidence) {
    if (!ndpi_stack_contains(stack, NDPI_PROTOCOL_BITTORRENT)) return 0;
    return confidence != NDPI_CONFIDENCE_UNKNOWN && confidence != NDPI_CONFIDENCE_MATCH_BY_PORT
        && confidence != NDPI_CONFIDENCE_MATCH_BY_IP;
}

void vh_engine_packet(vh_engine *e, const uint8_t *packet, size_t len, char hook, uint64_t now_ms) {
    parsed in;
    const uint8_t *l3;
    size_t l3_len;
    e->stats.packets++;
    if (parse(e, packet, len, &in, &l3, &l3_len) != 0) return;
    /* Before the flow table: a scan's thousands of one-packet tries must be seen even when it is full. */
    vh_scan_packet(e->scan, &in.tuple, in.tcp_flags, hook, now_ms);

    int created;
    flow *f = flow_get(e, &in.tuple, hook, now_ms, &created);
    if (!f) return;
    f->last_ms = now_ms;
    if (!f->analysis) {
        if (f->pending && e->fn(&f->tuple, (vh_reason) f->reason, e->user)) f->pending = 0;
        return;
    }
    /* A docker packet passes the rule twice, from FORWARD and DOCKER-USER; the library must see it once. */
    uint32_t seen = mix(l3, l3_len, 2166136261u);
    if (!created && seen == f->last_packet) return;
    f->last_packet = seen;
    f->packets++;

    const vh_tuple *t = &f->tuple;
    int ours_is_src = src_is_ours(t, f->hook);
    uint16_t peer_port = ours_is_src ? t->dport : t->sport;

    if (created) {
        if (peer_known(e, f, ours_is_src, now_ms)) {
            block(e, f, VH_PEER);
            return;
        }
        if (udp_port_marked(e, f, ours_is_src, now_ms)) {
            block(e, f, VH_UDP_PORT);
            return;
        }
    }

    if (vh_strong_signature(t->proto, in.payload, in.payload_len)) {
        count_port(e->stats.strong_ports, peer_port);
        remember_strong(e, f, ours_is_src, now_ms);
        block(e, f, VH_STRONG);
        return;
    }
    if (exempt_payload(t, in.payload, in.payload_len)) {
        e->stats.exempt++;
        finish(e, f);
        return;
    }

    ndpi_protocol p = ndpi_detection_process_packet(e->ndpi, f->analysis, l3, (unsigned short) l3_len, now_ms, NULL);
    if (counts_as_bittorrent(&p.protocol_stack, f->analysis->confidence)) {
        /*
         * The server's own address is the source of every local proxy user at once, so its mark
         * confirms a weak hit only between client ports: obfuscated traffic to or from a service
         * (Telegram's MTProto on 443, a proxy listening on 443) is random bytes the library
         * sometimes calls BitTorrent, and it is somebody else's.
         */
        uint16_t our_port = ours_is_src ? t->sport : t->dport;
        int source_confirms = source_marked(e, f, ours_is_src, now_ms)
            && (f->hook == VH_HOOK_FORWARD
                || (peer_port >= FIRST_CLIENT_PORT && our_port >= FIRST_CLIENT_PORT));
        if (peer_known(e, f, ours_is_src, now_ms) || source_confirms) {
            block(e, f, VH_WEAK_CONFIRMED);
        } else {
            e->stats.weak_alone++;
            count_port(e->stats.weak_ports, peer_port);
            finish(e, f);
        }
        return;
    }
    if (ndpi_stack_get_upper_proto(&p.protocol_stack) != NDPI_PROTOCOL_UNKNOWN) {
        /* Recognised as something else: SSH, a game, WireGuard. Left alone from here on. */
        finish(e, f);
        return;
    }
    if (f->packets >= VH_TAP_PACKETS) {
        /* Encrypted BitTorrent looks like nothing at all; a marked VPN user's noise is not given the benefit of the doubt. */
        if (f->hook == VH_HOOK_FORWARD && peer_port >= FIRST_CLIENT_PORT && source_marked(e, f, ours_is_src, now_ms)) {
            block(e, f, VH_TAINTED);
        } else {
            finish(e, f);
        }
    }
}

/* ---- life cycle ---- */

vh_engine *vh_engine_new(vh_verdict_fn fn, void *user) {
    vh_engine *e = calloc(1, sizeof(vh_engine));
    if (!e) return NULL;
    e->fn = fn;
    e->user = user;
    /* We are a for-profit project: only the LGPL dissectors, see README. */
    e->ndpi = ndpi_init_detection_module(NULL, NDPI_LICENSE_FOR_PROFIT_LGPL);
    e->scan = vh_scan_new();
    if (!e->ndpi || !e->scan || memory_init(&e->peers, PEER_SLOTS) || memory_init(&e->sources, SOURCE_SLOTS)
        || memory_init(&e->udp_ports, PORT_SLOTS)) {
        vh_engine_free(e);
        return NULL;
    }
    /* What we do not read need not sit in memory. */
    ndpi_set_config(e->ndpi, NULL, "flow_risk_lists.load", "0");
    ndpi_set_config(e->ndpi, "any", "ip_list.load", "0");
    ndpi_set_config(e->ndpi, NULL, "dpi.guess_on_giveup", "0");
    ndpi_set_config(e->ndpi, "bittorrent", "metadata.hash", "0");
    if (ndpi_finalize_initialization(e->ndpi) != 0) {
        vh_engine_free(e);
        return NULL;
    }
    return e;
}

void vh_engine_free(vh_engine *e) {
    if (!e) return;
    for (uint32_t i = 0; i < FLOW_BUCKETS; i++) {
        flow *f = e->buckets[i];
        while (f) {
            flow *next = f->next;
            finish(e, f);
            free(f);
            f = next;
        }
    }
    if (e->ndpi) ndpi_exit_detection_module(e->ndpi);
    vh_scan_free(e->scan);
    free(e->peers.slots);
    free(e->sources.slots);
    free(e->udp_ports.slots);
    free(e);
}

const vh_stats *vh_engine_stats(const vh_engine *e) {
    return &e->stats;
}

const struct vh_scan *vh_engine_scan(const vh_engine *e) {
    return e->scan;
}

const char *vh_reason_name(vh_reason r) {
    switch (r) {
        case VH_STRONG: return "strong";
        case VH_WEAK_CONFIRMED: return "weak_confirmed";
        case VH_PEER: return "peer";
        case VH_UDP_PORT: return "udp_port";
        case VH_TAINTED: return "tainted";
        default: return "unknown";
    }
}
