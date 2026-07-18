#pragma once
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

struct uring {
    int fd;
    uint32_t sq_entries;
    uint32_t cq_entries;

    void    *sq_ring;
    size_t   sq_ring_sz;
    uint32_t *sq_head;
    uint32_t *sq_tail;
    uint32_t *sq_mask;
    uint32_t *sq_array;

    uint32_t *cq_head;
    uint32_t *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;

    struct io_uring_sqe *sqes;
    size_t   sqes_sz;
};

static inline int io_uring_setup_raw(unsigned entries, struct io_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_enter_raw(int fd, unsigned to_submit,
                                     unsigned min_complete, unsigned flags)
{
    return (int)syscall(__NR_io_uring_enter, fd, to_submit,
                        min_complete, flags, NULL, 0);
}

static int uring_init(struct uring *u, unsigned entries)
{
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    u->fd = io_uring_setup_raw(entries, &p);
    if (u->fd < 0) return -errno;

    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
        close(u->fd);
        return -ENOSYS;
    }

    size_t sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_ring_sz = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    size_t ring_sz    = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;

    void *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE,
                      u->fd, IORING_OFF_SQ_RING);
    if (ring == MAP_FAILED) { close(u->fd); return -errno; }

    u->sq_ring    = ring;
    u->sq_ring_sz = ring_sz;

    u->sq_head  = (uint32_t *)((char *)ring + p.sq_off.head);
    u->sq_tail  = (uint32_t *)((char *)ring + p.sq_off.tail);
    u->sq_mask  = (uint32_t *)((char *)ring + p.sq_off.ring_mask);
    u->sq_array = (uint32_t *)((char *)ring + p.sq_off.array);

    u->cq_head  = (uint32_t *)((char *)ring + p.cq_off.head);
    u->cq_tail  = (uint32_t *)((char *)ring + p.cq_off.tail);
    u->cq_mask  = (uint32_t *)((char *)ring + p.cq_off.ring_mask);
    u->cqes     = (struct io_uring_cqe *)((char *)ring + p.cq_off.cqes);

    u->sq_entries = p.sq_entries;
    u->cq_entries = p.cq_entries;

    u->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    u->sqes = mmap(NULL, u->sqes_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE,
                   u->fd, IORING_OFF_SQES);
    if (u->sqes == MAP_FAILED) {
        munmap(ring, ring_sz);
        close(u->fd);
        return -errno;
    }

    return 0;
}

static void uring_free(struct uring *u)
{
    munmap(u->sqes, u->sqes_sz);
    munmap(u->sq_ring, u->sq_ring_sz);
    close(u->fd);
}

static struct io_uring_sqe *uring_get_sqe(struct uring *u)
{
    uint32_t tail = *u->sq_tail;
    uint32_t head = __atomic_load_n(u->sq_head, __ATOMIC_ACQUIRE);
    if (tail - head >= u->sq_entries) return NULL;

    struct io_uring_sqe *sqe = &u->sqes[tail & *u->sq_mask];
    memset(sqe, 0, sizeof(*sqe));
    u->sq_array[tail & *u->sq_mask] = tail & *u->sq_mask;
    __atomic_store_n(u->sq_tail, tail + 1, __ATOMIC_RELEASE);
    return sqe;
}

static int uring_submit_wait(struct uring *u, unsigned min_complete)
{
    uint32_t tail = *u->sq_tail;
    uint32_t head = __atomic_load_n(u->sq_head, __ATOMIC_ACQUIRE);
    unsigned to_submit = tail - head;
    return io_uring_enter_raw(u->fd, to_submit, min_complete,
                              min_complete ? IORING_ENTER_GETEVENTS : 0);
}

static int uring_peek_cqe(struct uring *u, struct io_uring_cqe *out)
{
    uint32_t head = __atomic_load_n(u->cq_head, __ATOMIC_ACQUIRE);
    if (head == *u->cq_tail) return -EAGAIN;
    *out = u->cqes[head & *u->cq_mask];
    __atomic_store_n(u->cq_head, head + 1, __ATOMIC_RELEASE);
    return 0;
}
