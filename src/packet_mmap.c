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

#define NOTDIR(path) (strrchr(path, '/') ? strrchr(path, '/') + 1: (path))

struct ring {
    struct iovec *rd;
    uint8_t *map;
    struct tpacket_req req;
};


static void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [Interface]\n", name);
    exit(EXIT_FAILURE);
}

static int setup_socket(struct ring *ring, const char *ifname)
{
    struct sockaddr_ll ll;
    unsigned int frame_size = PAGE_SIZE;
    unsigned int block_size = PAGE_SIZE * 10;
    unsigned int block_num  = 10;
    unsigned int ifindex;
    int err, fd, idx;

    CHECK_NE(ring, NULL);
    CHECK_NE(ifname, NULL);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        goto socket_failed;
    }

    memset(ring, 0, sizeof(*ring));
    ring->req.tp_block_size = block_size;
    ring->req.tp_frame_size = frame_size;
    ring->req.tp_block_nr   = block_num;
    ring->req.tp_frame_nr   = (block_size * block_num) / frame_size;

    err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                     &ring->req, sizeof(ring->req));
    if (err < 0) {
        fprintf(stderr, "setsockopt: %s\n", strerror(errno));
        goto setsockopt_failed;
    }

    ring->map = mmap(NULL, block_size * block_num,
                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
                     fd, 0);
    if (ring->map == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        goto mmap_failed;
    }

    ring->rd = calloc(block_num, sizeof(*ring->rd));
    CHECK_NE(ring->rd, NULL);
    for (idx = 0; idx < block_num; idx++) {
        ring->rd[idx].iov_base = ring->map + (idx * block_size);
        ring->rd[idx].iov_len  = block_size;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
        goto ifindex_failed;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family   = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex  = ifindex;
    ll.sll_hatype   = 0;
    ll.sll_pkttype  = 0;
    ll.sll_halen    = 0;

    err = bind(fd, (struct sockaddr *)&ll, sizeof(ll));
    if (err < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        goto bind_failed;
    }

    return fd;

bind_failed:
ifindex_failed:
    munmap(ring->map, block_num * block_size);

mmap_failed:
setsockopt_failed:
    close(fd);

socket_failed:
    return -1;
}

static void display(struct tpacket_hdr *tp)
{
    struct ethhdr *eth = NULL;
    struct iphdr *ip   = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    char smac[ETH_ALEN]    = {0};
    char dmac[ETH_ALEN]    = {0};
    char sbuf[NI_MAXHOST]  = {0};
    char sport[NI_MAXSERV] = {0};
    char dbuf[NI_MAXHOST]  = {0};
    char dport[NI_MAXSERV] = {0};
    struct sockaddr_in sa  = {0};
    struct sockaddr_in da  = {0};

    int err;

    eth = (struct ethhdr *)((uint8_t *)tp + tp->tp_mac);
    CHECK_EQ(eth->h_proto, htons(ETH_P_IP));
    memcpy(smac, eth->h_source, ETH_ALEN);
    memcpy(dmac, eth->h_dest, ETH_ALEN);

    ip = (struct iphdr *)((uint8_t *)tp + tp->tp_net);

    memset(&sa, 0, sizeof(sa));
    memset(&da, 0, sizeof(sa));
    sa.sin_family      = ip->version == IPVERSION ? AF_INET : AF_INET6;
    da.sin_family      = ip->version == IPVERSION ? AF_INET : AF_INET6;
    sa.sin_addr.s_addr = ip->saddr;
    da.sin_addr.s_addr = ip->daddr;
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((uint8_t *)ip + (ip->ihl * 4));
        sa.sin_port = tcp->source;
        da.sin_port = tcp->dest;
    } else {
        udp = (struct udphdr *)((uint8_t *)ip + (ip->ihl * 4));
        sa.sin_port = udp->source;
        da.sin_port = udp->dest;
    }
    err = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
                      sbuf, sizeof(sbuf), sport, sizeof(sport),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (err) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
        return;
    }

    err = getnameinfo((const struct sockaddr *)&da, sizeof(da),
                      dbuf, sizeof(dbuf), dport, sizeof(dport),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (err) {
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
        return;
    }

    fprintf(stdout,
            "[%02x:%02x:%02x:%02x:%02x:%02x] %s:%s ->"
            "[%02x:%02x:%02x:%02x:%02x:%02x] %s:%s Received %d Bytes\n",
            smac[0] & 0xFF, smac[1] & 0xFF, smac[2] & 0xFF,
            smac[3] & 0xFF, smac[4] & 0xFF, smac[5] & 0xFF,
            sbuf, sport,
            dmac[0] & 0xFF, dmac[1] & 0xFF, dmac[2] & 0xFF,
            dmac[3] & 0xFF, dmac[4] & 0xFF, dmac[5] & 0xFF,
            dbuf, dport,
            tp->tp_snaplen);
}

static void flush_packet(struct tpacket_hdr *tp)
{
    CHECK_NE(tp, NULL);
    tp->tp_status = TP_STATUS_KERNEL;
}

static struct tpacket_hdr *get_next_tpacket(struct ring *ring)
{
    struct tpacket_hdr *tp;
    size_t frames_per_block;
    size_t frame_size;
    uint8_t *block_base;
    static unsigned int block_offset = 0;
    static unsigned int frame_offset = 0;

    CHECK_NE(ring, NULL);
    frames_per_block = ring->req.tp_block_size / ring->req.tp_frame_size;
    frame_size       = ring->req.tp_frame_size;
    block_base       = (uint8_t *)ring->rd[block_offset].iov_base;
    tp               = (struct tpacket_hdr *)(block_base +
                                             (frame_offset * frame_size));

    frame_offset++;
    if (frame_offset == frames_per_block) {
        frame_offset = 0;
        block_offset = (block_offset + 1) % ring->req.tp_block_nr;
    }

    return tp;
}

static void teardown_socket(struct ring *ring, int fd)
{
    CHECK_NE(ring, NULL);
    CHECK_NE(fd, -1);

    munmap(ring->map, ring->req.tp_block_nr * ring->req.tp_block_size);
    free(ring->rd);
    close(fd);
}

static volatile unsigned int loop_stop = 0;
static void sig_cb(int signo)
{
    loop_stop = 1;
}

int main(int argc, char *argv[])
{
    int fd, epfd, err;
    struct ring ring;
    struct tpacket_hdr *tp;
    const char *ifname;
    struct epoll_event ev, rev;
    struct sigaction sigterm, sigint, sigquit;

    if (argc < 2)
        usage(NOTDIR(argv[0]));

    ifname = argv[1];
    fd = setup_socket(&ring, ifname);
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
    ev.data.ptr = &ring;
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
        goto sigaction_failed;
    }

    while (LIKELY(!loop_stop)) {
        tp = get_next_tpacket(&ring);

        if (tp->tp_status == TP_STATUS_KERNEL) {
            do
                err = epoll_wait(epfd, &rev, 1, -1);
            while (err < 0 && errno == EINTR);
            if (err < 0) {
                fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
                goto epoll_wait_failed;
            }
        }

        if (tp->tp_status & TP_STATUS_USER)
            display(tp);

        flush_packet(tp);
    }

    errno = 0;

sigaction_failed:
    /* Do nothing */

epoll_wait_failed:
    /* Do nothing */

epoll_ctl_failed:
    close(epfd);

epoll_create_failed:
    teardown_socket(&ring, fd);
    return errno;
}
