#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define INVALIED_FD -1
#define MAX_RECV_SIZE 2048
#define MAX_SEND_SIZE 2048

#include <assert.h>
#ifndef CHECK_EQ
#define CHECK_EQ(a, b) assert((a) == (b))
#endif
#ifndef CHECK_NE
#define CHECK_NE(a, b) assert((a) != (b))
#endif

struct dnsv4udp_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t num_q;
    uint16_t num_answ_rr;
    uint16_t num_auth_rr;
    uint16_t num_addi_rr;
};

int main(void) {
    while (!g_loop_stop) {
        struct sockaddr_in src_addr = {0};
        socklen_t addr_len = sizeof(src_addr);
        char rbuf[MAX_RECV_SIZE] = {0};
        char sbuf[MAX_RECV_SIZE] = {0};
        ssize_t recv_size;
        ssize_t send_size = 0;

        recv_size = recvfrom(srv.GetFd(),
                             rbuf,
                             MAX_RECV_SIZE - 1,
                             0,
                             reinterpret_cast<struct sockaddr *>(&src_addr),
                             &addr_len);
        std::cout << std::string(rbuf) << std::endl;

        if (recv_size < 0 && errno != EINTR) {
            std::cout << "recvfrom: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        // Datagram sockets in various domains permit zero-length datagrams
        // But NOT processing in here
        if (!recv_size)
            continue;

        errno = 0;

        struct dnsv4udp_hdr *hd = reinterpret_cast<struct dnsv4udp_hdr *>(rbuf);
        char *data = rbuf + sizeof(*hd);
#if 1
        if (hd->flags != 0x0001)
            continue;

        const char *name = data;
        if (!strlen(name))
            continue;

        data += strlen(name) + 1;
        if (memcmp(data, "\x00\x01", 2) && memcmp(data, "\x00\x1C", 2))
            continue;
#else
    memset(hd, 'X', sizeof(*hd));
    const char *name = "For Test";
#endif
        // Build answer packet
        hd   = reinterpret_cast<struct dnsv4udp_hdr *>(sbuf);
        data = sbuf;
        memcpy(sbuf, rbuf, sizeof(*hd));

        uint32_t ttl    = htonl(30);
        uint32_t local  = 0;
        ssize_t offset  = 0;
        hd->num_answ_rr = htons(1);
        hd->flags       = 0x8081;
        offset          += sizeof(*hd);
        memcpy(data + offset, name, strlen(name) + 1);
        offset          += strlen(name) + 1;
        memcpy(data + offset, "\x00\x01\x00\x01", 4);
        offset          += 4;
        memcpy(data + offset, "\xC0\x0C\x00\x01\x00\x01", 6);
        offset          += 6;
        memcpy(data + offset, &ttl, sizeof(ttl));
        offset          += sizeof(ttl);
        memcpy(data + offset, "\x00\x04", 2);
        offset          += 2;
        inet_pton(AF_INET, "192.168.43.1", &local);
        memcpy(data + offset, &local, sizeof(local));
        offset          += sizeof(local);

        send_size = sendto(srv.GetFd(),
                           sbuf,
                           offset,
                           0,
                           reinterpret_cast<const struct sockaddr *>(&src_addr),
                           addr_len);
        if (send_size < 0 && errno != EINTR) {
            std::cout << "sendto: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        std::cout << "Warning: Send "
                  << offset
                  << "("
                  << send_size
                  << ")"
                  << std::endl;

        errno = 0;
    }

    return 0;
}
