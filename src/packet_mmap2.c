#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* Used to setup promiscuos mode when @setsockopt is not support */
#include <sys/ioctl.h>
#include <linux/sockios.h>

#ifndef CHECK
#   include <assert.h>
#   define CHECK(expr)    assert(expr)
#   define CHECK_EQ(a, b) CHECK((a) == (b))
#   define CHECK_NE(a, b) CHECK((a) != (b))
#   define CHECK_GT(a, b) CHECK((a) > (b))
#   define CHECK_LT(a, b) CHECK((a) < (b))
#   define CHECK_GE(a, b) CHECK((a) >= (b))
#   define CHECK_LE(a, b) CHECK((a) <= (b))
#endif

#ifdef __GNUC__
#    define LIKELY(expr)   __builtin_expect(!!(expr), 1)
#    define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else
#    define LIKEY(expr)    (expr)
#    define UNLIKEY(expr)  (expr)
#endif

#define RECV_SIZE      (2048 * 4)
#define OPT_BUFF_SIZE  40
#define DATA_BUFF_SIZE RECV_SIZE

typedef void *QUEUE[2];
#define QUEUE_NEXT(q)      (*(QUEUE **)&((*(q))[0]))
#define QUEUE_PREV(q)      (*(QUEUE **)&((*(q))[1]))
#define QUEUE_PREV_NEXT(q) (QUEUE_NEXT(QUEUE_PREV(q)))
#define QUEUE_NEXT_PREV(q) (QUEUE_PREV(QUEUE_NEXT(q)))

#include <stddef.h>
#ifndef offsetof
#define offsetof(type, filed) ((size_t)(&((type *)0)->filed))
#endif

#define QUEUE_DATA(ptr, type, field)                                    \
    ((type *)((char *)(ptr) - offsetof(type, filed)))

#define QUEUE_FOREACH(q, h)                                             \
    for ((q) = QUEUE_NEXT(h); (q) != (h); (q) = QUEUE_NEXT(q))

#define QUEUE_EMPTY(q)                                                  \
    ((const QUEUE *)(q) == (const QUEUE *)QUEUE_NEXT(q))

#define QUEUE_HEAD(q) QUEUE_NEXT(q)

#define QUEUE_INIT(q) do {                                              \
    QUEUE_NEXT(q) = (q);                                                \
    QUEUE_PREV(q) = (q);                                                \
} while (0)

#define QUEUE_ADD(h, n) do {                                            \
    QUEUE_PREV_NEXT(h) = QUEUE_NEXT(n);                                 \
    QUEUE_NEXT_PREV(n) = QUEUE_PREV(h);                                 \
    QUEUE_PREV(h)      = QUEUE_PREV(n);                                 \
    QUEUE_PREV_NEXT(h) = (h);                                           \
} while (0)

#define QUEUE_SPLIT(h, q, n) do {                                       \
    QUEUE_PREV(n)      = QUEUE_PREV(h);                                 \
    QUEUE_PREV_NEXT(n) = (n);                                           \
    QUEUE_NEXT(n)      = (q);                                           \
    QUEUE_PREV(h)      = QUEUE_PREV(q);                                 \
    QUEUE_PREV_NEXT(h) = (h);                                           \
    QUEUE_PREV(q)      = (n);                                           \
} while (0)

#define QUEUE_MOVE(h, n) do {                                           \
    if (QUEUE_EMPTY(h)) {                                               \
        QUEUE_INIT(n);                                                  \
    } else {                                                            \
        QUEUE *q = QUEUE_HEAD(h);                                       \
        QUEUE_SPLIT(h, q, n);                                           \
    }                                                                   \
} while (0)

#define QUEUE_INSERT_HEAD(h, q) do {                                    \
    QUEUE_NEXT(q)      = QUEUE_NEXT(h);                                 \
    QUEUE_PREV(q)      = (h);                                           \
    QUEUE_NEXT_PREV(q) = (q);                                           \
    QUEUE_NEXT(h)      = (q);                                           \
} while (0)

#define QUEUE_INSERT_TAIL(h, q) do {                                    \
    QUEUE_NEXT(q)      = (h);                                           \
    QUEUE_PREV(q)      = QUEUE_PREV(h);                                 \
    QUEUE_PREV_NEXT(q) = (q);                                           \
    QUEUE_PREV(h)      = (q);                                           \
} while (0)

#define QUEUE_REMOVE(q) do {                                            \
    QUEUE_PREV_NEXT(q) = QUEUE_NEXT(q);                                 \
    QUEUE_NEXT_PREV(q) = QUEUE_PREV(q);                                 \
    QUEUE_INIT(q);                                                      \
} while (0)

struct packet_info {
    struct ethhdr pi_eth;
    struct iphdr  pi_ip;
    struct iovec  pi_ipopt;
    int           pi_tcppkt;
    union {
        struct tcphdr tcp;
        struct udphdr udp;
    } u;
#define pi_tcp u.tcp
#define pi_udp u.udp
    struct iovec  pi_tcpopt;
    struct iovec  pi_data;
};

struct dnsv4udp_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t num_q;
    uint16_t num_answ_rr;
    uint16_t num_auth_rr;
    uint16_t num_addi_rr;
};

static uint16_t checksum(const uint16_t *buf, size_t len)
{
    uint32_t chksum = 0;
    int i;

    for (i = 0; i < len; i++)
        chksum += buf[i];

    while (chksum >> 16)
        chksum = (chksum & 0xFFFF) + (chksum >> 16);

    return ~chksum;
}

static struct packet_info *extract_buffer(const char *buf, size_t buflen)
{
    const struct ethhdr *eth;
    const struct iphdr  *ip;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    struct iovec ipopt  = {(char [OPT_BUFF_SIZE]){0}, 0};
    struct iovec tcpopt = {(char [OPT_BUFF_SIZE]){0}, 0};
    const char *data;
    size_t snaplen;
    struct packet_info *res;
    int is_tcphdr;

    CHECK_NE(buf, NULL);
    CHECK_NE(buflen, 0);

    eth = (const struct ethhdr *)buf;
    if (eth->h_proto != htons(ETH_P_IP))
        return NULL;

    ip = (const struct iphdr *)(buf + sizeof(*eth));
    /* DO NOT care IPv6 */
    if (ip->version != IPVERSION)
        return NULL;
    if (ip->ihl * 4 > sizeof(*ip)) {
        ipopt.iov_len = ip->ihl * 4 - sizeof(*ip);
        CHECK_LE(ipopt.iov_len, OPT_BUFF_SIZE);
        memcpy(ipopt.iov_base, (const char *)ip + sizeof(*ip), ipopt.iov_len);
    }

    switch (ip->protocol) {
    case IPPROTO_TCP:
        is_tcphdr = 1;
        tcp       = (const struct tcphdr *)((const char *)ip + ip->ihl * 4);
        if (tcp->doff * 4 > sizeof(*tcp)) {
            tcpopt.iov_len = tcp->doff * 4 - sizeof(*tcp);
            CHECK_LE(tcpopt.iov_len, OPT_BUFF_SIZE);
            memcpy(tcpopt.iov_base,
                   (const char *)tcp + sizeof(*tcp),
                   tcpopt.iov_len);
        }

        data      = (const char *)tcp + tcp->doff * 4;
        snaplen   = buf + buflen - (const char *)tcp - tcp->doff * 4;
        break;

    case IPPROTO_UDP:
        is_tcphdr = 0;
        udp       = (const struct udphdr *)((const char *)ip + ip->ihl * 4);

        data      = (const char *)udp + sizeof(*udp);
        snaplen   = ntohs(udp->len) - sizeof(*udp);
        break;

    default:
        /* DO NOT care IPPROTO_ICMP, IPPROTO_IGMP and other */
        return NULL;
    }

    res = calloc(1, sizeof(*res));
    CHECK_NE(res, NULL);
    res->pi_eth    = *eth;
    res->pi_ip     = *ip;
    res->pi_ipopt  = (struct iovec){NULL, 0};
    if (ipopt.iov_len) {
        res->pi_ipopt.iov_base = malloc(ipopt.iov_len);
        CHECK_NE(res->pi_ipopt.iov_base, NULL);
        memcpy(res->pi_ipopt.iov_base, ipopt.iov_base, ipopt.iov_len);
        res->pi_ipopt.iov_len  = ipopt.iov_len;
    }
    res->pi_tcppkt = is_tcphdr;
    if (is_tcphdr) {
        res->pi_tcp    = *tcp;
        res->pi_tcpopt = (struct iovec){NULL, 0};
        if (tcpopt.iov_len) {
            res->pi_tcpopt.iov_base = malloc(tcpopt.iov_len);
            CHECK_NE(res->pi_tcpopt.iov_base, NULL);
            memcpy(res->pi_tcpopt.iov_base, tcpopt.iov_base, tcpopt.iov_len);
            res->pi_tcpopt.iov_len  = tcpopt.iov_len;
        }
    } else {
        res->pi_udp = *udp;
    }

    res->pi_data = (struct iovec){NULL, 0};
    if (snaplen) {
        res->pi_data.iov_base = malloc(snaplen);
        CHECK_NE(res->pi_data.iov_base, NULL);
        memcpy(res->pi_data.iov_base, data, snaplen);
        res->pi_data.iov_len  = snaplen;
    }
    return res;
}

static void free_packet(struct packet_info *pi)
{
    CHECK_NE(pi, NULL);
    if (pi->pi_ipopt.iov_len && pi->pi_ipopt.iov_base)
        free(pi->pi_ipopt.iov_base);
    if (pi->pi_tcpopt.iov_len && pi->pi_tcpopt.iov_base)
        free(pi->pi_tcpopt.iov_base);
    if (pi->pi_data.iov_len && pi->pi_data.iov_base)
        free(pi->pi_data.iov_base);
    free(pi);
}

/* @brief compress_packet Make DNS response packet buffer that will be
 * attached to @QUEUE and send when the socket is writable. */
static const char *compress_packet(const struct packet_info *pi)
{
    return NULL;
}

/* @setsockopt may not support SOL_PACKET -> PACKET_ADD_MEMBERSHIP */
static int setup_promisc_mode(int fd, const char *ifname, int enable)
{
#if 0
    struct packet_mreq mreq;
    int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    unsigned int ifindex = if_nametoindex(ifname);

    if (!ifindex)
        return -1;

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;

    return setsockopt(fd, SOL_PACKET, opt, &mreq, sizeof(mreq));
#else
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    memcpy(&ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr))
        return -1;

    if (enable && !(ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags |= IFF_PROMISC;
        return ioctl(fd, SIOCSIFFLAGS, &ifr);
    } else if (!enable && (ifr.ifr_flags & IFF_PROMISC)) {
        ifr.ifr_flags &= ~IFF_PROMISC;
        return ioctl(fd, SIOCSIFFLAGS, &ifr);
    }

    return 0;
#endif
}

static void teardown_socket(int fd, const char *ifname)
{
    CHECK_NE(fd, -1);
    setup_promisc_mode(fd, ifname, 0);
    close(fd);
}

static int setup_socket(const char *ifname)
{
    struct sockaddr_ll ll;
    unsigned int ifindex;
    int fd;

    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }

    if (setup_promisc_mode(fd, ifname, 1)) {
        fprintf(stderr, "setup_promisc_mode: %s\n", strerror(errno));
        goto failed;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
        goto failed;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family   = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex  = ifindex;
    ll.sll_hatype   = 0;
    ll.sll_pkttype  = /*PACKET_OTHERHOST*/0;
    ll.sll_halen    = 0;

    if (bind(fd, (const struct sockaddr *)&ll, sizeof(ll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        goto failed;
    }

    return fd;

failed:
    teardown_socket(fd, ifname);
    return -1;
}

static void dump_packet1(const struct packet_info *pi, int show_tcp)
{
    unsigned char smac[ETH_ALEN];
    unsigned char dmac[ETH_ALEN];
    char saddr[NI_MAXHOST]  = {0};
    char sport[NI_MAXSERV]  = {0};
    char daddr[NI_MAXHOST]  = {0};
    char dport[NI_MAXSERV]  = {0};
    struct sockaddr_in ssin = {0};
    struct sockaddr_in dsin = {0};

    int err;

    if (!show_tcp && pi->pi_tcppkt)
        return;

    memcpy(smac, pi->pi_eth.h_source, ETH_ALEN);
    memcpy(dmac, pi->pi_eth.h_dest, ETH_ALEN);

    ssin.sin_family      =
    dsin.sin_family      = AF_INET;
    ssin.sin_addr.s_addr = pi->pi_ip.saddr;
    dsin.sin_addr.s_addr = pi->pi_ip.daddr;
    if (pi->pi_tcppkt) {
        ssin.sin_port = pi->pi_tcp.source;
        dsin.sin_port = pi->pi_tcp.dest;
    } else {
        ssin.sin_port = pi->pi_udp.source;
        dsin.sin_port = pi->pi_udp.dest;
    }
    if ((err = getnameinfo((const struct sockaddr *)&ssin, sizeof(ssin),
                      saddr, sizeof(saddr), sport, sizeof(sport),
                      NI_NUMERICHOST/* | NI_NUMERICSERV*/)) ||
        (err = getnameinfo((const struct sockaddr *)&dsin, sizeof(dsin),
                      daddr, sizeof(daddr), dport, sizeof(dport),
                      NI_NUMERICHOST/* | NI_NUMERICSERV*/))) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
        return;
    }

    /* Ethernet address, IP address, TCP/UDP port and attributes */
    fprintf(stdout,
            "LINK %02x:%02x:%02x:%02x:%02x:%02x -> "
            "%02x:%02x:%02x:%02x:%02x:%02x\n"
            "IP   %s -> %s protocol %s checksum %d\n"
            "NET  %s -> %s size %zd checksum %d\n",
            smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
            dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],

            saddr,
            daddr,
            pi->pi_tcppkt ? "TCP" : "UDP",
            pi->pi_ip.check,

            sport, dport,
            pi->pi_data.iov_len,
            pi->pi_tcppkt ? pi->pi_tcp.check : pi->pi_udp.check);

    /* TCP options */
    if (pi->pi_tcppkt) {
        fprintf(stdout,
                "\tOptions tos %d ttl %d id %d off %d flags %d\n",
                pi->pi_ip.tos,
                pi->pi_ip.ttl,
                ntohs(pi->pi_ip.id),
                ntohs(pi->pi_ip.frag_off) & 0x1FFF,
                ntohs(pi->pi_ip.frag_off) >> 13);
    }
}

static volatile unsigned int loop_stop = 0;
static void sig_cb(int signo)
{
    loop_stop = 1;
}

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [Interface]\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int fd, epfd, err;
    const char *ifname;
    char recvbuf[RECV_SIZE];
    ssize_t recvlen;
    struct epoll_event ev, rev;
    struct sigaction sigterm, sigint, sigquit;
    struct packet_info *pi;

    if (argc < 2)
        usage(argv[0]);

    ifname = argv[1];
    fd = setup_socket(ifname);
    if (fd < 0) {
        fprintf(stderr, "setup_socket error\n");
        exit(EXIT_FAILURE);
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
        goto epoll_create_failed;
    }

    ev.events   = EPOLLIN;
    ev.data.ptr = recvbuf;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        fprintf(stderr, "epoll_ctl: %s\n", strerror(errno));
        goto epoll_ctl_failed;
    }

    memset(&sigterm, 0, sizeof(sigterm));
    sigterm.sa_handler = sig_cb;
    /* DO NOT restart, let it exit */
    /* sigterm.sa_flags   = SA_RESTART; */
    sigemptyset(&sigterm.sa_mask);
    memcpy(&sigint, &sigterm, sizeof(sigint));
    memcpy(&sigquit, &sigterm, sizeof(sigquit));
    /* In signal callback function,
     * it will blocked the self of next incoming. */
    sigaddset(&sigterm.sa_mask, SIGTERM);
    sigaddset(&sigint.sa_mask, SIGINT);
    sigaddset(&sigquit.sa_mask, SIGQUIT);
    if (sigaction(SIGTERM, &sigterm, NULL) ||
        sigaction(SIGINT, &sigint, NULL) ||
        sigaction(SIGQUIT, &sigquit, NULL)) {
        fprintf(stderr, "sigaction: %s\n", strerror(errno));
        loop_stop = 1;
    }

    while (LIKELY(!loop_stop)) {
        err = epoll_wait(epfd, &rev, 1, -1);
        if (err < 0) {
            if (errno != EINTR)
                fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
            break;
        }

        if (rev.events & EPOLLERR)
            break;

        memset(recvbuf, 0, sizeof(recvbuf));
        if (rev.events & EPOLLIN) {
            recvlen = recv(fd, recvbuf, RECV_SIZE, 0);
            if (recvlen <= 0) {
                if (errno != EINTR)
                    fprintf(stderr, "recv: %s\n", strerror(errno));
                break;
            }
        }

        pi = extract_buffer(recvbuf, recvlen);
        if (pi) {
            dump_packet1(pi, 0);
            free_packet(pi);
        }
    }

    close(epfd);
    fprintf(stdout, "Done.\n");

epoll_ctl_failed:
    /* Do nothing */

epoll_create_failed:
    teardown_socket(fd, ifname);
    return errno;
}
