#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/uio.h>
#include <sys/user.h>
#include <errno.h>

#ifndef CHECK
#   define CHECK(expr) assert(expr)
#   define CHECK_EQ(a, b) CHECK((a) == (b))
#   define CHECK_NE(a, b) CHECK((a) != (b))
#   define CHECK_GE(a, b) CHECK((a) > (b))
#   define CHECK_LE(a, b) CHECK((a) < (b))
#endif

#ifndef LIKELY
#   define LIKELY(expr) __builtin_expect(!!(expr), 1)
#endif

#ifndef UNLIKELY
#   define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#endif

static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [Interface]\n", name);
    exit(EXIT_FAILURE);
}

static int setup_promisc_mode(int fd, int ifindex, int enable)
{
    struct packet_mreq mreq;
    int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;

    return setsockopt(fd, SOL_PACKET, opt, &mreq, sizeof(mreq));
}

static int setup_socket(int ifindex)
{
    struct sockaddr_ll ll;
    struct packet_mreq mreq;
    int fd;

    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family   = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex  = ifindex;
    ll.sll_hatype   = 0;
    ll.sll_pkttype  = 0;
    ll.sll_halen    = 0;

    if (bind(fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (setup_promisc_mode(fd, ifindex, 1) < 0) {
        fprintf(stderr, "setup_promisc: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void dump_packet(const char *buf, size_t buflen)
{
    const struct ethhdr *eth = NULL;
    const struct iphdr *ip   = NULL;
    const struct tcphdr *tcp = NULL;
    const struct udphdr *udp = NULL;

    const char *smac         = NULL;
    const char *dmac         = NULL;
    char sbuf[NI_MAXHOST]    = {0};
    char sport[NI_MAXSERV]   = {0};
    char dbuf[NI_MAXHOST]    = {0};
    char dport[NI_MAXSERV]   = {0};
    struct sockaddr_in sa    = {0};
    struct sockaddr_in da    = {0};
    ssize_t snaplen          = 0;

    int err, is_tcphdr;

    eth  = (struct ethhdr *)buf;
    CHECK_EQ(eth->h_proto, htons(ETH_P_IP));
    smac = (const char *)eth->h_source;
    dmac = (const char *)eth->h_dest;

    ip = (struct iphdr *)(buf + sizeof(*eth));
    sa.sin_family      = ip->version == IPVERSION ? AF_INET : AF_INET6;
    da.sin_family      = ip->version == IPVERSION ? AF_INET : AF_INET6;
    sa.sin_addr.s_addr = ip->saddr;
    da.sin_addr.s_addr = ip->daddr;
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((const char *)ip + (ip->ihl * 4));
        sa.sin_port = tcp->source;
        da.sin_port = tcp->dest;
        is_tcphdr   = 1;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)((const char *)ip + (ip->ihl * 4));
        sa.sin_port = udp->source;
        da.sin_port = udp->dest;
        is_tcphdr   = 0;
    } else {
        /* example as IPPROTO_ICMP, IPPROTO_IGMP */
        return;
    }

    snaplen = (const char *)(buf + buflen)
            - (const char *)(ip) - (ip->ihl * 4)
            - (is_tcphdr ? sizeof(*tcp) : sizeof(*udp));

    if ((err = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
                      sbuf, sizeof(sbuf), sport, sizeof(sport),
                      NI_NUMERICHOST | NI_NUMERICSERV)) ||
        (err = getnameinfo((const struct sockaddr *)&da, sizeof(da),
                      dbuf, sizeof(dbuf), dport, sizeof(dport),
                      NI_NUMERICHOST | NI_NUMERICSERV))) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
        return;
    }

    fprintf(stdout,
            "[%02x:%02x:%02x:%02x:%02x:%02x] %s:%s -> "
            "[%02x:%02x:%02x:%02x:%02x:%02x] %s:%s (%s) Received %zd Bytes\n",
            smac[0] & 0xFF, smac[1] & 0xFF, smac[2] & 0xFF,
            smac[3] & 0xFF, smac[4] & 0xFF, smac[5] & 0xFF,
            sbuf, sport,
            dmac[0] & 0xFF, dmac[1] & 0xFF, dmac[2] & 0xFF,
            dmac[3] & 0xFF, dmac[4] & 0xFF, dmac[5] & 0xFF,
            dbuf, dport,
            is_tcphdr ? "TCP" : "UDP",
            snaplen);
}

static void teardown_socket(int fd, int ifindex)
{
    CHECK_NE(fd, -1);
    setup_promisc_mode(fd, ifindex, 0);
    close(fd);
}

static volatile unsigned int loop_stop = 0;
static void sig_cb(int signo)
{
    loop_stop = 1;
}

int main(int argc, char *argv[])
{
    int fd, epfd, ifindex, err;
    const char *ifname;
    char recvbuf[2048];
    ssize_t recvlen;
    struct epoll_event ev, rev;
    struct sigaction sigterm, sigint, sigquit;

    if (argc < 2)
        usage(argv[0]);

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fd = setup_socket(ifindex);
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
    sigterm.sa_flags   = SA_RESTART;
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
        do
           err = epoll_wait(epfd, &rev, 1, -1);
        while (err < 0 && errno == EINTR);
        if (err < 0) {
            fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
            break;
        }

        if (rev.events & EPOLLERR)
            break;

        if (rev.events & EPOLLIN) {
            do
                recvlen = recv(fd, recvbuf, 2048, 0);
            while (err < 0 && errno == EINTR);
            if (err <= 0) {
                fprintf(stderr, "recv: %s\n", strerror(errno));
                break;
            }
        }

        dump_packet(recvbuf, recvlen);
    }

epoll_ctl_failed:
    /* Do nothing */

epoll_create_failed:
    teardown_socket(fd, ifindex);
    return errno;
}
