#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
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

#define RECV_SIZE     (2048 * 32)
#define OPT_BUFF_SIZE 40
#define BUFFER_SIZE   2048

struct packet_info {
    struct ethhdr pi_eth;
    struct iphdr *pi_ip;
    int pi_tcphdr;
    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
    } __u;
#define pi_tcp __u.tcp
#define pi_udp __u.udp
    struct iovec pi_data;
};

struct dnsv4udp_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t num_q;
    uint16_t num_answ_rr;
    uint16_t num_auth_rr;
    uint16_t num_addi_rr;
};

#define QR 0x0001
#define OPCODE_MASK 0x001E
#define AA 0x0020
#define TC 0x0040
#define RD 0x0080
#define RA 0x0100
#define ROPCODE_MASK 0xF000

struct dnsv4udp_respond_packet {
    struct iovec data;
    int (*make)(struct dnsv4udp_respond_packet *,
                const struct packet_info *);
    void (*free)(struct dnsv4udp_respond_packet *);
};

#define INIT_DNSV4UDP_RESPOND_PACKET(p) do {                            \
    (p)->data = (struct iovec){NULL, 0};                                \
    (p)->make = dnsresp_make;                                           \
    (p)->free = dnsresp_free;                                           \
} while (0)

static uint16_t checksum_by_magic(uint32_t saddr, uint32_t daddr,
                                  uint16_t len, uint16_t proto,
                                  const uint16_t *buf, size_t size)
{
    uint64_t chksum = 0;
    size_t i;

    CHECK_NE(buf, NULL);
    if (!size)
        return 0;

    chksum += (saddr & 0xFFFF);
    chksum += (saddr >> 16);
    chksum += (daddr & 0xFFFF);
    chksum += (daddr >> 16);
    chksum += len;
    chksum += proto;

    for (i = 0; i < size; i++)
        chksum += buf[i];

    chksum = (chksum & 0xFFFF) + (chksum >> 16);
    chksum += (chksum >> 16);

    return ~chksum;
}

static uint16_t checksum(const uint16_t *buf, size_t size)
{
    return checksum_by_magic(0, 0, 0, 0, buf, size);
}

static int dnsresp_make(struct dnsv4udp_respond_packet *resp,
                         const struct packet_info *pi)
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct dnsv4udp_hdr *dns;
    const char *domains, *glass;
    size_t dlen;
    char *rawbuf, *data;
    size_t offset;
    uint32_t addr, ttl  = htonl(30);

    CHECK_NE(resp, NULL);
    CHECK_NE(pi, NULL);

    dns = (struct dnsv4udp_hdr *)pi->pi_data.iov_base;
    if (dns->flags != 0x0001) {
        /* It is DNS respond packet */
        errno = -110;
        return -1;
    }

    domains = (const char *)pi->pi_data.iov_base + sizeof(*dns);
    dlen    = strlen(domains);
    if (!dlen) {
        errno = -111;
        return -1;
    }

    glass   = domains + dlen + 1;
    if (memcmp(glass, "\x00\x01", 2) && memcmp(glass, "\x00\x0C", 2)) {
        errno = -112;
        return -1;
    }

    rawbuf = calloc(BUFFER_SIZE, 1);
    CHECK_NE(rawbuf, NULL);
    eth    = (struct ethhdr *)(rawbuf);
    ip     = (struct iphdr *)(rawbuf + sizeof(*eth));
    udp    = (struct udphdr *)(rawbuf + sizeof(*eth) + sizeof(*ip));
    data   = rawbuf + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

    /* Make DNS Respond packet */
    dns    = (struct dnsv4udp_hdr *)data;

    memcpy(data, pi->pi_data.iov_base, sizeof(*dns));
    offset = sizeof(*dns);
    dns->num_answ_rr = htons(1);
    dns->flags       = 0x8081;
    memcpy(data + offset, domains, dlen + 1);
    offset += dlen + 1;
    memcpy(data + offset, "\x00\x01\x00\x01", 4);
    offset += 4;
    memcpy(data + offset, "\xC0\x0C\x00\x01\x00\x01", 6);
    offset += 6;
    memcpy(data + offset, &ttl, sizeof(ttl));
    offset += sizeof(ttl);
    memcpy(data + offset, "\x00\x04", 2);
    offset += 2;
    if (!memcmp(glass, "\x00\x01", 2)) {/* A */
        inet_pton(AF_INET, "192.168.43.1", &addr);
        memcpy(data + offset, &addr, sizeof(addr));
        offset += sizeof(addr);
    } else {/* PTR */
        memcpy(data + offset, "192.168.43.1", 13);
        offset += 13;
    }

    /* Make UDP header */
    memcpy(&udp->dest, &pi->pi_udp->source, sizeof(udp->dest));
    memcpy(&udp->source, &pi->pi_udp->dest, sizeof(udp->source));
    udp->len   = htons(sizeof(*udp) + offset);
    udp->check = 0;

    /* Make IP header */
    ip->version  = IPVERSION;
    ip->ihl      = sizeof(*ip) / 4;
    ip->tos      = 0xC0;
    ip->tot_len  = htons(sizeof(*ip) + sizeof(*udp) + offset);
    ip->id       = 0;
    ip->frag_off = 0;
    ip->ttl      = 30;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0;
    memcpy(&ip->daddr, &pi->pi_ip->saddr, sizeof(ip->daddr));
    memcpy(&ip->saddr, &pi->pi_ip->daddr, sizeof(ip->daddr));

    /* Make Ethernet header */
    memcpy(eth->h_dest, pi->pi_eth.h_source, ETH_ALEN);
    memcpy(eth->h_source, pi->pi_eth.h_dest, ETH_ALEN);
    memcpy(&eth->h_proto, &pi->pi_eth.h_proto, sizeof(eth->h_proto));

    /* Make checksum */
    udp->check = checksum_by_magic(ip->saddr, ip->daddr,
                                   udp->len, ip->protocol << 8,
                                   (const uint16_t *)udp,
                                   ntohs(udp->len) / 2 + ntohs(udp->len) % 2);
    ip->check  = checksum((const uint16_t *)ip, ip->ihl * 2);
    resp->data.iov_len  = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + offset;
    resp->data.iov_base = rawbuf;

    return 0;
}

static void dnsresp_free(struct dnsv4udp_respond_packet *rp)
{
    CHECK_NE(rp, NULL);
    free(rp->data.iov_base);
}

static struct packet_info *extract_buffer(const char *buf, size_t buflen)
{
    const struct ethhdr *eth;
    const struct iphdr  *ip;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const char *data;
    size_t snaplen;
    uint16_t ncs, tcs;
    size_t rawlen;
    char rawbuf[RECV_SIZE]  = {0};
    struct packet_info *res;
    int is_tcphdr;

    CHECK_NE(buf, NULL);
    CHECK_NE(buflen, 0);

    eth = (const struct ethhdr *)buf;
    if ((const char *)eth + sizeof(*eth) >= buf + buflen) {
        errno = -100;
        return NULL;
    }
    if (eth->h_proto != htons(ETH_P_IP)) {
        errno = -101;
        return NULL;
    }

    ip = (const struct iphdr *)(buf + sizeof(*eth));
    if ((const char *)ip + sizeof(*ip) >= buf + buflen) {
        errno = -102;
        return NULL;
    }
    /* DO NOT care IPv6 */
    if (ip->version != IPVERSION) {
        errno = -103;
        return NULL;
    }

    switch (ip->protocol) {
    case IPPROTO_TCP:
        is_tcphdr = 1;
        tcp       = (const struct tcphdr *)((const char *)ip + ip->ihl * 4);
        if ((const char *)tcp + sizeof(*tcp) > buf + buflen) {
            errno = -104;
            return NULL;
        }
        data      = (const char *)tcp + tcp->doff * 4;
        snaplen   = ntohs(ip->tot_len) - ip->ihl * 4 - tcp->doff * 4;
        if (data + snaplen != buf + buflen) {
            errno = -105;
            return NULL;
        }
        break;

    case IPPROTO_UDP:
        is_tcphdr = 0;
        udp       = (const struct udphdr *)((const char *)ip + ip->ihl * 4);
        if ((const char *)udp + sizeof(*udp) > buf + buflen) {
            errno = -106;
            return NULL;
        }
        data      = (const char *)udp + sizeof(*udp);
        snaplen   = ntohs(ip->tot_len) - ip->ihl * 4 - sizeof(*udp);
        if (data + snaplen != buf + buflen) {
            errno = -107;
            return NULL;
        }
        break;

    default:
        errno = -108;
        /* DO NOT care IPPROTO_ICMP, IPPROTO_IGMP and other */
        return NULL;
    }

    /* IP and TCP/UDP reverse checksum,
     * if result is not 0 that mean packet broken */
    if (is_tcphdr) {
        rawlen = tcp->doff * 4;
        memcpy(rawbuf, tcp, rawlen);
    } else {
        rawlen = sizeof(*udp);
        memcpy(rawbuf, udp, rawlen);
    }
    /* 0 bytes UDP packet is valid */
    if (snaplen) {
        memcpy(rawbuf + rawlen, data, snaplen);
        rawlen += snaplen;
    }
    ncs = checksum((const uint16_t *)ip, ip->ihl * 2);
    tcs = checksum_by_magic(ip->saddr, ip->daddr,
                            htons(rawlen), ip->protocol << 8,
                            (const uint16_t *)&rawbuf,
                            rawlen / 2 + rawlen % 2);
    if (ncs || tcs){
        fprintf(stderr,
                "ncs or tcs reverse checksum invalid[ncs %u tcs %u]\n",
                ncs, tcs);
        errno = -109;
        return NULL;
    }

    res = calloc(1, sizeof(*res));
    CHECK_NE(res, NULL);
    res->pi_eth = *eth;
    res->pi_ip  = malloc(ip->ihl * 4);
    CHECK_NE(res->pi_ip, NULL);
    memcpy(res->pi_ip, ip, ip->ihl * 4);
    res->pi_tcphdr = is_tcphdr;
    if (is_tcphdr) {
        res->pi_tcp = malloc(tcp->doff * 4);
        CHECK_NE(res->pi_tcp, NULL);
        memcpy(res->pi_tcp, tcp, tcp->doff * 4);
    } else {
        res->pi_udp = malloc(sizeof(*udp));
        CHECK_NE(res->pi_udp, NULL);
        memcpy(res->pi_udp, udp, sizeof(*udp));
    }
    if (snaplen) {
        res->pi_data.iov_base = calloc(snaplen + snaplen % 2, 1);
        CHECK_NE(res->pi_data.iov_base, NULL);
        memcpy(res->pi_data.iov_base, data, snaplen);
        res->pi_data.iov_len  = snaplen;
    }
    return res;
}

static void free_packet(struct packet_info *pi)
{
    CHECK_NE(pi, NULL);
    CHECK_NE(pi->pi_ip, NULL);
    CHECK_NE(pi->pi_tcp, NULL);

    free(pi->pi_ip);
    free(pi->pi_tcp);
    if (pi->pi_data.iov_len && pi->pi_data.iov_base)
        free(pi->pi_data.iov_base);
    free(pi);
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

static void dump_dnspacket(const char *buf, size_t buflen)
{
    const struct dnsv4udp_hdr *hdr;
    const char *ptr;
    char domain[1024] = {0};
    uint16_t req_type, req_class;
    unsigned int flen;

    CHECK_NE(buf, NULL);

    hdr = (const struct dnsv4udp_hdr *)buf;
    fprintf(stderr,
            "\tid %u flags %x num_q %u num_answ_rr %u "
            "num_auth_rr %u num_addi_rr %u\n",
            ntohs(hdr->id), ntohs(hdr->flags),
            ntohs(hdr->num_q), ntohs(hdr->num_answ_rr),
            ntohs(hdr->num_auth_rr), ntohs(hdr->num_addi_rr));

    /* DNS request */
    if ((ntohs(hdr->flags) & QR) == 0) {
        ptr       = (const char *)hdr + sizeof(*hdr);
        req_type  = ((uint16_t *)(ptr + strlen(ptr) + 1))[0];
        req_class = ((uint16_t *)(ptr + strlen(ptr) + 1))[1];


        while ((flen = (int)*ptr)) {
            ptr++;
            strncat(domain, ptr, flen);
            strncat(domain, ".", 1);
            ptr += flen;
        }

        fprintf(stderr,
                "\tRequest Type %x Request class %x "
                "Request domain %s\n",
                ntohs(req_type), ntohs(req_class), domain);
    }
}

static void dump_packet1(const struct packet_info *pi)
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

    memcpy(smac, pi->pi_eth.h_source, ETH_ALEN);
    memcpy(dmac, pi->pi_eth.h_dest, ETH_ALEN);

    ssin.sin_family      =
    dsin.sin_family      = AF_INET;
    ssin.sin_addr.s_addr = pi->pi_ip->saddr;
    dsin.sin_addr.s_addr = pi->pi_ip->daddr;
    if (pi->pi_tcphdr) {
        ssin.sin_port = pi->pi_tcp->source;
        dsin.sin_port = pi->pi_tcp->dest;
    } else {
        ssin.sin_port = pi->pi_udp->source;
        dsin.sin_port = pi->pi_udp->dest;
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
            "DATA-LINK %02x:%02x:%02x:%02x:%02x:%02x -> "
            "%02x:%02x:%02x:%02x:%02x:%02x proto %s\n"

            "NETWORK   %-17s -> %-17s proto %s tos %x tot_len %d "
            "ihl %u ttl %u id %u off %u flags %u checksum %u\n"

            "TRANPORT  %-17s -> %-17s size %zd checksum %u\n",

            smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
            dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
            pi->pi_eth.h_proto == htons(ETH_P_IP) ? "IP" : "Unknown",

            saddr, daddr,
            pi->pi_tcphdr ? "TCP" : "UDP",
            pi->pi_ip->tos,
            ntohs(pi->pi_ip->tot_len),
            pi->pi_ip->ihl,
            pi->pi_ip->ttl,
            ntohs(pi->pi_ip->id),
            ntohs(pi->pi_ip->frag_off) & 0x1FFF,
            ntohs(pi->pi_ip->frag_off) >> 13,
            pi->pi_ip->check,

            sport, dport,
            pi->pi_data.iov_len,
            pi->pi_tcphdr ? pi->pi_tcp->check : pi->pi_udp->check);

    /* TCP options */
    if (pi->pi_tcphdr) {
        fprintf(stdout, "\tSeq %u AckSeq %u doff %u fin %u syn %u "
                "rst %u psh %u ack %u urg %u win %u urg_ptr %u\n",
                ntohs(pi->pi_tcp->seq),
                ntohs(pi->pi_tcp->ack_seq),
                pi->pi_tcp->doff,
                pi->pi_tcp->fin,
                pi->pi_tcp->syn,
                pi->pi_tcp->rst,
                pi->pi_tcp->psh,
                pi->pi_tcp->ack,
                pi->pi_tcp->urg,
                ntohs(pi->pi_tcp->window),
                ntohs(pi->pi_tcp->urg_ptr));
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
        recvlen = 0;
        err     = epoll_wait(epfd, &rev, 1, -1);
        if (err < 0) {
            if (errno != EINTR)
                fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
            break;
        }

        if (rev.events & EPOLLERR)
            break;

        memset(recvbuf, 0, sizeof(recvbuf));
        if (rev.events & EPOLLIN) {
            recvlen = recv(fd, recvbuf, RECV_SIZE - 2, 0);
            if (recvlen <= 0) {
                if (errno != EINTR)
                    fprintf(stderr, "recv: %s\n", strerror(errno));
                break;
            }
        }

        pi = extract_buffer(recvbuf, recvlen);
        if (pi) {
            /* UDP packet and DNS request */
            if (!pi->pi_tcphdr && ntohs(pi->pi_udp->dest) == 53) {
                struct dnsv4udp_respond_packet pkt;
                INIT_DNSV4UDP_RESPOND_PACKET(&pkt);

                if (!pkt.make(&pkt, pi)) {
                    struct packet_info *pi2 = extract_buffer(pkt.data.iov_base,
                            pkt.data.iov_len);

                    if (pi2) {
                        fprintf(stderr, "CAPTURE PACKET:\n");
                        dump_packet1(pi);
                        dump_dnspacket(pi->pi_data.iov_base,
                                       pi->pi_data.iov_len);

                        fprintf(stderr, "CONSTRUCTOR PACKET:\n");
                        dump_packet1(pi2);
                        dump_dnspacket(pi2->pi_data.iov_base,
                                       pi2->pi_data.iov_len);
                        free_packet(pi2);
                    }

                    send(fd, pkt.data.iov_base, pkt.data.iov_len, 0);
                    pkt.free(&pkt);
                }

            }
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
