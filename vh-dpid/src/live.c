/*
 * vh-dpid: reads the copies our NFLOG rule sends and, in enforce mode, sets one bit of the conntrack
 * mark on a connection the engine judged BitTorrent; a rule of guard.sh drops what carries the bit.
 * Traffic never waits for this process: if it stops, nothing changes on the network.
 *
 *   vh-dpid --mode shadow|enforce --stats <file> [--scan <file>] [--flows <file>]
 *
 * With --scan it also keeps <file> listing the sources it judged to be scanning, for guard.sh to block
 * when VibeHost says so: "src <address> <until>" for a VPN user or a container, "port <n> <until>" for a
 * port the server itself scanned (never a web, DNS or time port), <until> in Unix seconds.
 *
 * With --flows it keeps <file> (0600) listing the connections judged BitTorrent in the last 10 minutes,
 * "<tcp|udp> <src> <sport> <dst> <dport> <unix>", for guard.sh to tell which VPN user made them.
 *
 * Exit codes: 3 - this kernel cannot do it (no nfnetlink_log, no ctnetlink, not allowed).
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "engine.h"
#include "scan.h"

#define NFLOG_GROUP 4711
/* The rule copies VH_TAP_BYTES; this is its room in the netlink message. */
#define COPY_RANGE VH_TAP_BYTES
#define VH_CT_BIT 0x00100000u
#define STATS_EVERY_MS 30000u
#define SWEEP_EVERY_MS 10000u
#define PORTS_REPORTED 8

static volatile sig_atomic_t stop;
static int enforce;
static struct mnl_socket *ct_sock;
static unsigned int ct_portid, ct_seq;
static uint64_t marked, mark_failed;
static const char *scan_path;
static uint64_t scan_written = UINT64_MAX;
static const char *flows_path;

#define FLOWS_KEPT 512
#define FLOWS_FOR_MS (10u * 60u * 1000u)
#define FLOWS_EVERY_MS 30000u

static struct {
    vh_tuple t;
    uint64_t at_ms;
    long long wall;
} flows[FLOWS_KEPT];
static size_t flows_next;
static int flows_changed;
static uint64_t verdict_now;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

static void on_signal(int s) {
    (void) s;
    stop = 1;
}

/* ---- conntrack mark ---- */

static void put_tuple(struct nlmsghdr *nlh, int attr, const vh_tuple *t, int swap) {
    const uint8_t *src = swap ? t->dst : t->src, *dst = swap ? t->src : t->dst;
    uint16_t sport = swap ? t->dport : t->sport, dport = swap ? t->sport : t->dport;
    struct nlattr *tuple = mnl_attr_nest_start(nlh, attr);
    struct nlattr *ip = mnl_attr_nest_start(nlh, CTA_TUPLE_IP);
    if (t->family == AF_INET) {
        mnl_attr_put(nlh, CTA_IP_V4_SRC, 4, src);
        mnl_attr_put(nlh, CTA_IP_V4_DST, 4, dst);
    } else {
        mnl_attr_put(nlh, CTA_IP_V6_SRC, 16, src);
        mnl_attr_put(nlh, CTA_IP_V6_DST, 16, dst);
    }
    mnl_attr_nest_end(nlh, ip);
    struct nlattr *proto = mnl_attr_nest_start(nlh, CTA_TUPLE_PROTO);
    mnl_attr_put_u8(nlh, CTA_PROTO_NUM, t->proto);
    mnl_attr_put_u16(nlh, CTA_PROTO_SRC_PORT, htons(sport));
    mnl_attr_put_u16(nlh, CTA_PROTO_DST_PORT, htons(dport));
    mnl_attr_nest_end(nlh, proto);
    mnl_attr_nest_end(nlh, tuple);
}

/* 0, or the errno the kernel answered. */
static int mark_with(const vh_tuple *t, int attr, int swap) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++ct_seq;
    struct nfgenmsg *g = mnl_nlmsg_put_extra_header(nlh, sizeof *g);
    g->nfgen_family = (uint8_t) t->family;
    g->version = NFNETLINK_V0;
    g->res_id = 0;
    put_tuple(nlh, attr, t, swap);
    /* With the mask only our bit moves: wg-quick, kube-proxy and the customer's own marks stay. */
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(VH_CT_BIT));
    mnl_attr_put_u32(nlh, CTA_MARK_MASK, htonl(VH_CT_BIT));
    if (mnl_socket_sendto(ct_sock, nlh, nlh->nlmsg_len) < 0) return errno;
    int n = (int) mnl_socket_recvfrom(ct_sock, buf, sizeof buf);
    if (n < 0) return errno;
    return mnl_cb_run(buf, (size_t) n, ct_seq, ct_portid, NULL, NULL) < 0 ? errno : 0;
}

/*
 * The copy shows a forwarded packet after DNAT and before SNAT, so the addresses we saw may be the
 * connection's original tuple or its reply tuple, in either direction.
 */
static int mark_flow(const vh_tuple *t) {
    static const struct { int attr; int swap; } tries[] = {
        {CTA_TUPLE_ORIG, 0}, {CTA_TUPLE_ORIG, 1}, {CTA_TUPLE_REPLY, 0}, {CTA_TUPLE_REPLY, 1},
    };
    for (size_t i = 0; i < sizeof tries / sizeof tries[0]; i++) {
        if (mark_with(t, tries[i].attr, tries[i].swap) == 0) {
            marked++;
            return 1;
        }
    }
    mark_failed++;
    return 0;
}

static void remember_flow(const vh_tuple *t) {
    /* A verdict the kernel could not carry out yet is asked again on the next packet. */
    for (size_t k = 1; k <= 32; k++) {
        size_t i = (flows_next + FLOWS_KEPT - k) % FLOWS_KEPT;
        if (flows[i].at_ms && !memcmp(&flows[i].t, t, sizeof *t)) return;
    }
    flows[flows_next].t = *t;
    flows[flows_next].at_ms = verdict_now ? verdict_now : 1;
    flows[flows_next].wall = (long long) time(NULL);
    flows_next = (flows_next + 1) % FLOWS_KEPT;
    flows_changed = 1;
}

static int on_verdict(const vh_tuple *t, vh_reason reason, void *user) {
    (void) reason;
    (void) user;
    if (flows_path) remember_flow(t);
    return enforce ? mark_flow(t) : 1;
}

static void write_flows(uint64_t now) {
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", flows_path) >= (int) sizeof tmp) return;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return;
    }
    for (size_t i = 0; i < FLOWS_KEPT; i++) {
        if (!flows[i].at_ms || now - flows[i].at_ms > FLOWS_FOR_MS) continue;
        const vh_tuple *t = &flows[i].t;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        if (!inet_ntop(t->family, t->src, src, sizeof src) || !inet_ntop(t->family, t->dst, dst, sizeof dst)) continue;
        fprintf(f, "%s %s %u %s %u %lld\n", t->proto == IPPROTO_UDP ? "udp" : "tcp", src, t->sport, dst, t->dport,
                flows[i].wall);
    }
    fclose(f);
    if (rename(tmp, flows_path) == 0) flows_changed = 0;
}

/* ---- the stats file guard.sh reports: counts and port numbers, never an address ---- */

static void write_ports(FILE *f, const char *name, const vh_port_count *table) {
    int used[VH_TOP_PORTS] = {0};
    fprintf(f, ",\"%s\":{", name);
    int first = 1;
    for (int n = 0; n < PORTS_REPORTED; n++) {
        int best = -1;
        for (int i = 0; i < VH_TOP_PORTS; i++) {
            if (!used[i] && table[i].hits && (best < 0 || table[i].hits > table[best].hits)) best = i;
        }
        if (best < 0) break;
        used[best] = 1;
        fprintf(f, "%s\"%u\":%llu", first ? "" : ",", table[best].port, (unsigned long long) table[best].hits);
        first = 0;
    }
    fputc('}', f);
}

/* ---- the scanners guard.sh may block ---- */

#define MAX_SCANNERS 256

/* A port the server must keep reaching whatever it did: web, DNS, time. */
static int vital_port(uint16_t p) {
    return p == 53 || p == 80 || p == 123 || p == 443 || p == 853;
}

static void write_scan(const vh_engine *e, uint64_t now) {
    if (!scan_path) return;
    static vh_scanner list[MAX_SCANNERS];
    uint64_t version;
    size_t n = vh_scan_list(vh_engine_scan(e), list, MAX_SCANNERS, &version);
    if (version == scan_written) return;
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", scan_path) >= (int) sizeof tmp) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    long long wall = (long long) time(NULL);
    for (size_t i = 0; i < n; i++) {
        long long until = wall + (long long) ((list[i].until_ms - now) / 1000);
        if (!list[i].local) {
            char addr[INET6_ADDRSTRLEN];
            if (inet_ntop(list[i].family, list[i].addr, addr, sizeof addr)) fprintf(f, "src %s %lld\n", addr, until);
            continue;
        }
        for (int k = 0; k < list[i].nports; k++) {
            if (!vital_port(list[i].ports[k])) fprintf(f, "port %u %lld\n", list[i].ports[k], until);
        }
    }
    fclose(f);
    if (rename(tmp, scan_path) == 0) scan_written = version;
}

static void write_stats(const char *path, const vh_engine *e, uint64_t lost) {
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int) sizeof tmp) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    const vh_stats *s = vh_engine_stats(e);
    fprintf(f, "\"mode\":\"%s\",\"packets\":%llu,\"flows\":%llu,\"strong\":%llu,\"weakConfirmed\":%llu,\"peer\":%llu,"
               "\"udpPort\":%llu,\"tainted\":%llu,\"weakAlone\":%llu,\"exempt\":%llu,\"overflow\":%llu,\"lost\":%llu,"
               "\"marked\":%llu,\"markFailed\":%llu",
            enforce ? "enforce" : "shadow",
            (unsigned long long) s->packets, (unsigned long long) s->flows,
            (unsigned long long) s->reasons[VH_STRONG], (unsigned long long) s->reasons[VH_WEAK_CONFIRMED],
            (unsigned long long) s->reasons[VH_PEER], (unsigned long long) s->reasons[VH_UDP_PORT],
            (unsigned long long) s->reasons[VH_TAINTED], (unsigned long long) s->weak_alone,
            (unsigned long long) s->exempt, (unsigned long long) s->overflow, (unsigned long long) lost,
            (unsigned long long) marked, (unsigned long long) mark_failed);
    write_ports(f, "strongPorts", s->strong_ports);
    write_ports(f, "weakPorts", s->weak_ports);
    static vh_scanner active[MAX_SCANNERS];
    const vh_scan_stats *sc = vh_scan_stats_of(vh_engine_scan(e));
    fprintf(f, ",\"scanFailed\":%llu,\"scanEvents\":%llu,\"scanActive\":%zu",
            (unsigned long long) sc->failed, (unsigned long long) sc->events,
            vh_scan_list(vh_engine_scan(e), active, MAX_SCANNERS, NULL));
    write_ports(f, "scanPorts", sc->ports);
    fclose(f);
    rename(tmp, path);
}

/* ---- NFLOG ---- */

static int log_config(struct mnl_socket *sock, unsigned int portid, uint16_t res_id, int attr_type,
                      const void *data, size_t len) {
    static unsigned int seq;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++seq;
    struct nfgenmsg *g = mnl_nlmsg_put_extra_header(nlh, sizeof *g);
    g->nfgen_family = AF_UNSPEC;
    g->version = NFNETLINK_V0;
    g->res_id = htons(res_id);
    mnl_attr_put(nlh, (uint16_t) attr_type, len, data);
    if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) return -1;
    int n = (int) mnl_socket_recvfrom(sock, buf, sizeof buf);
    if (n < 0) return -1;
    return mnl_cb_run(buf, (size_t) n, seq, portid, NULL, NULL) < 0 ? -1 : 0;
}

typedef struct {
    vh_engine *engine;
    uint64_t now;
} rx;

static int attr_cb(const struct nlattr *a, void *data) {
    const struct nlattr **tb = data;
    if (mnl_attr_type_valid(a, NFULA_MAX) > 0) tb[mnl_attr_get_type(a)] = a;
    return MNL_CB_OK;
}

static int packet_cb(const struct nlmsghdr *nlh, void *data) {
    rx *r = data;
    const struct nlattr *tb[NFULA_MAX + 1] = {NULL};
    mnl_attr_parse(nlh, sizeof(struct nfgenmsg), attr_cb, tb);
    if (!tb[NFULA_PAYLOAD]) return MNL_CB_OK;
    /* Both interfaces: forwarded. Only the way in: for us. Only the way out: from us. */
    char hook = VH_HOOK_FORWARD;
    if (!tb[NFULA_IFINDEX_OUTDEV]) hook = VH_HOOK_INPUT;
    else if (!tb[NFULA_IFINDEX_INDEV]) hook = VH_HOOK_OUTPUT;
    vh_engine_packet(r->engine, mnl_attr_get_payload(tb[NFULA_PAYLOAD]), mnl_attr_get_payload_len(tb[NFULA_PAYLOAD]),
                     hook, r->now);
    return MNL_CB_OK;
}

static struct mnl_socket *open_log(unsigned int *portid) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    if (!sock) return NULL;
    if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) goto fail;
    *portid = mnl_socket_get_portid(sock);
    struct nfulnl_msg_config_cmd bind_cmd = {.command = NFULNL_CFG_CMD_BIND};
    if (log_config(sock, *portid, NFLOG_GROUP, NFULA_CFG_CMD, &bind_cmd, sizeof bind_cmd) < 0) goto fail;
    struct nfulnl_msg_config_mode mode = {.copy_range = htonl(COPY_RANGE), .copy_mode = NFULNL_COPY_PACKET};
    if (log_config(sock, *portid, NFLOG_GROUP, NFULA_CFG_MODE, &mode, sizeof mode) < 0) goto fail;
    /* One packet per message: we want the verdict now, not when a batch fills. */
    uint32_t one = htonl(1);
    if (log_config(sock, *portid, NFLOG_GROUP, NFULA_CFG_QTHRESH, &one, sizeof one) < 0) goto fail;
    /* A burst overflows into lost copies, never into lost traffic. */
    int size = 4 * 1024 * 1024;
    setsockopt(mnl_socket_get_fd(sock), SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof size);
    int on = 1;
    mnl_socket_setsockopt(sock, NETLINK_NO_ENOBUFS, &on, sizeof on);
    return sock;
fail:
    mnl_socket_close(sock);
    return NULL;
}

int main(int argc, char **argv) {
    const char *stats_path = NULL;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--mode")) enforce = !strcmp(argv[i + 1], "enforce");
        else if (!strcmp(argv[i], "--stats")) stats_path = argv[i + 1];
        else if (!strcmp(argv[i], "--scan")) scan_path = argv[i + 1];
        else if (!strcmp(argv[i], "--flows")) flows_path = argv[i + 1];
    }
    if (!stats_path) {
        fprintf(stderr, "usage: vh-dpid --mode shadow|enforce --stats <file> [--scan <file>] [--flows <file>]\n");
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, SIG_IGN);

    unsigned int log_portid;
    struct mnl_socket *log_sock = open_log(&log_portid);
    if (!log_sock) {
        fprintf(stderr, "vh-dpid: cannot read NFLOG group %d: %s\n", NFLOG_GROUP, strerror(errno));
        return 3;
    }
    ct_sock = mnl_socket_open(NETLINK_NETFILTER);
    if (!ct_sock || mnl_socket_bind(ct_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
        fprintf(stderr, "vh-dpid: cannot open ctnetlink: %s\n", strerror(errno));
        return 3;
    }
    ct_portid = mnl_socket_get_portid(ct_sock);

    vh_engine *engine = vh_engine_new(on_verdict, NULL);
    if (!engine) {
        fprintf(stderr, "vh-dpid: cannot start the engine\n");
        return 1;
    }

    static char buf[65536];
    struct pollfd pfd = {.fd = mnl_socket_get_fd(log_sock), .events = POLLIN};
    uint64_t next_stats = 0, next_sweep = now_ms() + SWEEP_EVERY_MS, next_flows = 0, lost = 0;
    rx r = {.engine = engine};

    while (!stop) {
        int ready = poll(&pfd, 1, 5000);
        r.now = now_ms();
        verdict_now = r.now;
        if (ready > 0) {
            int n = (int) mnl_socket_recvfrom(log_sock, buf, sizeof buf);
            if (n < 0) {
                if (errno == ENOBUFS) lost++;
                else if (errno != EINTR && errno != EAGAIN) break;
            } else {
                mnl_cb_run(buf, (size_t) n, 0, log_portid, packet_cb, &r);
            }
        }
        if (r.now >= next_sweep) {
            vh_engine_sweep(engine, r.now);
            write_scan(engine, r.now);
            next_sweep = r.now + SWEEP_EVERY_MS;
        }
        if (flows_path && flows_changed && r.now >= next_flows) {
            write_flows(r.now);
            next_flows = r.now + FLOWS_EVERY_MS;
        }
        if (r.now >= next_stats) {
            write_stats(stats_path, engine, lost);
            next_stats = r.now + STATS_EVERY_MS;
        }
    }
    write_stats(stats_path, engine, lost);
    vh_engine_free(engine);
    mnl_socket_close(log_sock);
    mnl_socket_close(ct_sock);
    return 0;
}
