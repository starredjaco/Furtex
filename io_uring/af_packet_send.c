#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "iouring_utils.h"

static uint16_t cksum(const void *buf, size_t len)
{
    const uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int uring_socket_af_packet(struct uring *u)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode   = IORING_OP_SOCKET;
    sqe->fd       = AF_PACKET;
    sqe->off      = (uint64_t)SOCK_RAW;
    sqe->len      = (uint32_t)htons(ETH_P_IP);
    sqe->rw_flags = 0;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    return (int)cqe.res;
}

int main(int argc, char *argv[])
{
    if (argc < 5) {
        fprintf(stderr,
            "usage: %s <iface> <src-mac xx:xx:xx:xx:xx:xx>"
            " <dst-mac xx:xx:xx:xx:xx:xx> <payload>\n",
            argv[0]);
        return 1;
    }

    const char *iface   = argv[1];
    const char *src_mac = argv[2];
    const char *dst_mac = argv[3];
    const char *payload = argv[4];

    struct uring u = {};
    if (uring_init(&u, 8) < 0) { fprintf(stderr, "io_uring init failed\n"); return 1; }

    int sockfd = uring_socket_af_packet(&u);
    if (sockfd < 0) {
        fprintf(stderr, "SOCKET: %d (%s)\n", sockfd, strerror(-sockfd));
        uring_free(&u);
        return 1;
    }

    int ifindex = (int)if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = ifindex,
    };
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return 1;
    }

    uint8_t smac[6], dmac[6];
    sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &smac[0], &smac[1], &smac[2], &smac[3], &smac[4], &smac[5]);
    sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dmac[0], &dmac[1], &dmac[2], &dmac[3], &dmac[4], &dmac[5]);

    size_t plen = strlen(payload);
    size_t frame_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + plen;
    uint8_t *frame = calloc(1, frame_len);

    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest,   dmac, 6);
    memcpy(eth->h_source, smac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(frame + sizeof(struct ethhdr));
    ip->version  = 4;
    ip->ihl      = 5;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_RAW;
    ip->tot_len  = htons((uint16_t)(sizeof(struct iphdr) + plen));
    ip->check    = cksum(ip, sizeof(struct iphdr));

    memcpy(frame + sizeof(struct ethhdr) + sizeof(struct iphdr), payload, plen);

    struct iovec iov = { .iov_base = frame, .iov_len = frame_len };
    struct sockaddr_ll dst = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = ifindex,
        .sll_halen   = 6,
    };
    memcpy(dst.sll_addr, dmac, 6);

    struct msghdr msg = {
        .msg_name    = &dst,
        .msg_namelen = sizeof(dst),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    struct io_uring_cqe cqe;
    sqe->opcode   = IORING_OP_SENDMSG;
    sqe->fd       = sockfd;
    sqe->addr     = (uint64_t)(uintptr_t)&msg;
    sqe->msg_flags = 0;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);

    if ((int)cqe.res < 0)
        fprintf(stderr, "SENDMSG: %d (%s)\n", cqe.res, strerror(-(int)cqe.res));
    else
        fprintf(stderr, "[*] sent %d bytes on %s\n", cqe.res, iface);

    free(frame);
    close(sockfd);
    uring_free(&u);
    return (int)cqe.res < 0 ? 1 : 0;
}
