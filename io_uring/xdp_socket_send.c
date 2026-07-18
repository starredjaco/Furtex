#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "iouring_utils.h"

#define UMEM_SIZE    (1 << 20)
#define FRAME_SIZE   4096
#define RING_SIZE    4

struct xsk {
    int fd;
    void *umem;

    struct xdp_ring_offset tx_off;
    void *tx_map;
    uint32_t *tx_prod;
    uint32_t *tx_cons;
    struct xdp_desc *tx_desc;

    struct xdp_ring_offset cr_off;
    void *cr_map;
    uint32_t *cr_prod;
    uint32_t *cr_cons;
    uint64_t *cr_desc;
};

static int xsk_create_via_uring(struct uring *u)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    struct io_uring_cqe cqe;
    sqe->opcode   = IORING_OP_SOCKET;
    sqe->fd       = AF_XDP;
    sqe->off      = (uint64_t)SOCK_RAW;
    sqe->len      = 0;
    sqe->rw_flags = 0;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    return (int)cqe.res;
}

static int xsk_setup(struct xsk *x, const char *iface, uint32_t queue)
{
    int ifindex = (int)if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return -1; }

    x->umem = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (x->umem == MAP_FAILED) { perror("mmap umem"); return -1; }

    struct xdp_umem_reg umem_reg = {
        .addr       = (uint64_t)(uintptr_t)x->umem,
        .len        = UMEM_SIZE,
        .chunk_size = FRAME_SIZE,
        .headroom   = 0,
    };
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg)) < 0) {
        perror("setsockopt XDP_UMEM_REG"); return -1;
    }

    uint32_t cr_size = RING_SIZE;
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cr_size, sizeof(cr_size)) < 0) {
        perror("XDP_UMEM_COMPLETION_RING"); return -1;
    }

    uint32_t fr_size = RING_SIZE;
    if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fr_size, sizeof(fr_size)) < 0) {
        perror("XDP_UMEM_FILL_RING"); return -1;
    }

    uint32_t tx_size = RING_SIZE;
    if (setsockopt(x->fd, SOL_XDP, XDP_TX_RING, &tx_size, sizeof(tx_size)) < 0) {
        perror("XDP_TX_RING"); return -1;
    }

    struct xdp_mmap_offsets offsets;
    socklen_t optlen = sizeof(offsets);
    if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) < 0) {
        perror("XDP_MMAP_OFFSETS"); return -1;
    }

    size_t tx_map_size = offsets.tx.desc + RING_SIZE * sizeof(struct xdp_desc);
    x->tx_map = mmap(NULL, tx_map_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, x->fd, XDP_PGOFF_TX_RING);
    if (x->tx_map == MAP_FAILED) { perror("mmap tx ring"); return -1; }
    x->tx_prod = (uint32_t *)((uint8_t *)x->tx_map + offsets.tx.producer);
    x->tx_cons = (uint32_t *)((uint8_t *)x->tx_map + offsets.tx.consumer);
    x->tx_desc = (struct xdp_desc *)((uint8_t *)x->tx_map + offsets.tx.desc);

    size_t cr_map_size = offsets.cr.desc + RING_SIZE * sizeof(uint64_t);
    x->cr_map = mmap(NULL, cr_map_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, x->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (x->cr_map == MAP_FAILED) { perror("mmap cr ring"); return -1; }
    x->cr_prod = (uint32_t *)((uint8_t *)x->cr_map + offsets.cr.producer);
    x->cr_cons = (uint32_t *)((uint8_t *)x->cr_map + offsets.cr.consumer);
    x->cr_desc = (uint64_t *)((uint8_t *)x->cr_map + offsets.cr.desc);

    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_ifindex  = (uint32_t)ifindex,
        .sxdp_queue_id = queue,
        .sxdp_flags    = XDP_COPY,
    };
    if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        perror("bind AF_XDP"); return -1;
    }

    return 0;
}

static int xsk_send_frame(struct xsk *x, const void *data, size_t len)
{
    if (len > FRAME_SIZE) len = FRAME_SIZE;

    uint64_t addr = 0;
    memcpy((uint8_t *)x->umem + addr, data, len);

    uint32_t prod = *x->tx_prod;
    x->tx_desc[prod & (RING_SIZE - 1)].addr = addr;
    x->tx_desc[prod & (RING_SIZE - 1)].len  = (uint32_t)len;
    __sync_synchronize();
    *x->tx_prod = prod + 1;

    struct sockaddr_xdp addr_dummy = { .sxdp_family = AF_XDP };
    if (sendto(x->fd, NULL, 0, MSG_DONTWAIT,
               (struct sockaddr *)&addr_dummy, sizeof(addr_dummy)) < 0
        && errno != ENOBUFS && errno != EAGAIN) {
        perror("sendto (xsk kick)");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <iface> <hex-frame> [queue-id]\n"
            "  hex-frame: raw Ethernet frame bytes as hex string, e.g. ffffffffffff...\n"
            "  queue-id: NIC RX/TX queue index (default 0)\n",
            argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *hexframe = argv[2];
    uint32_t queue = argc >= 4 ? (uint32_t)atoi(argv[3]) : 0;

    size_t hexlen = strlen(hexframe);
    if (hexlen & 1) { fprintf(stderr, "[-] odd hex length\n"); return 1; }
    size_t framelen = hexlen / 2;
    uint8_t *frame = malloc(framelen);
    for (size_t i = 0; i < framelen; i++) {
        unsigned byte;
        sscanf(hexframe + i * 2, "%02x", &byte);
        frame[i] = (uint8_t)byte;
    }

    struct uring u = {};
    if (uring_init(&u, 8) < 0) { fprintf(stderr, "io_uring init\n"); return 1; }

    struct xsk x = {};
    x.fd = xsk_create_via_uring(&u);
    if (x.fd < 0) {
        fprintf(stderr, "SOCKET AF_XDP: %d (%s)\n", x.fd, strerror(-x.fd));
        return 1;
    }
    fprintf(stderr, "[*] AF_XDP socket fd=%d (created via io_uring, no __x64_sys_socket)\n", x.fd);

    if (xsk_setup(&x, iface, queue) < 0) return 1;

    if (xsk_send_frame(&x, frame, framelen) < 0) return 1;

    fprintf(stderr, "[*] frame queued for TX on %s queue %u (xsk_sendmsg path, not inet_sendmsg)\n",
            iface, queue);

    free(frame);
    uring_free(&u);
    return 0;
}
