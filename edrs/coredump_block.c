#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

static int write_file(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return n < 0 ? -1 : 0;
}

static void cmd_self(void)
{
    if (write_file("/proc/self/coredump_filter", "0\n") == 0)
        printf("[+] coredump_filter=0   - no memory regions will be dumped\n");
    else
        perror("/proc/self/coredump_filter");

    if (prctl(PR_SET_DUMPABLE, 0) == 0)
        printf("[+] PR_SET_DUMPABLE=0   - /proc/self/mem not readable by debuggers\n");
    else
        perror("prctl SET_DUMPABLE");

    if (prctl(PR_SET_PTRACER, 0) == 0)
        printf("[+] PR_SET_PTRACER=0    - ptrace from other processes blocked\n");
    else
        perror("prctl SET_PTRACER");

    struct rlimit rl = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &rl) == 0)
        printf("[+] RLIMIT_CORE=0       - core dump size limit set to 0 bytes\n");
    else
        perror("setrlimit RLIMIT_CORE");

    printf("[*] this process is now resistant to:\n");
    printf("    - core dump generation\n");
    printf("    - /proc/PID/mem reading by gdb/strace/EDR memory scanners\n");
    printf("    - ptrace attachment from non-root processes\n");
}

static void cmd_pid(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/coredump_filter", (int)pid);
    if (write_file(path, "0\n") == 0)
        printf("[+] PID %d coredump_filter=0\n", (int)pid);
    else
        fprintf(stderr, "[!] %s: %s\n", path, strerror(errno));
}

static void cmd_system(void)
{
    if (write_file("/proc/sys/kernel/core_pattern", "|/bin/false\n") == 0)
        printf("[+] core_pattern set to |/bin/false - all core dumps discarded system-wide\n");
    else
        perror("/proc/sys/kernel/core_pattern (requires root)");

    if (write_file("/proc/sys/fs/suid_dumpable", "0\n") == 0)
        printf("[+] suid_dumpable=0 - setuid processes will not dump core\n");
}

static void cmd_madv(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("/proc/self/maps"); return; }

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (madvise((void *)start, end - start, MADV_DONTDUMP) == 0) count++;
    }
    fclose(f);
    printf("[+] MADV_DONTDUMP applied to %d VMAs - excluded from all core dumps\n", count);
}

static void cmd_show(void)
{
    char buf[64];
    FILE *f;

    f = fopen("/proc/self/coredump_filter", "r");
    if (f) { fgets(buf, sizeof(buf), f); fclose(f);
        printf("  coredump_filter: %s", buf); }

    int dump = prctl(PR_GET_DUMPABLE);
    printf("  dumpable:        %d (%s)\n", dump,
           dump == 0 ? "no - mem protected" : dump == 1 ? "yes" : "suid");

    f = fopen("/proc/sys/kernel/core_pattern", "r");
    if (f) { fgets(buf, sizeof(buf), f); fclose(f);
        printf("  core_pattern:    %s", buf); }

    f = fopen("/proc/sys/kernel/core_uses_pid", "r");
    if (f) { fgets(buf, sizeof(buf), f); fclose(f);
        printf("  core_uses_pid:   %s", buf); }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <self|madv|pid|system|show>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "self") == 0) cmd_self();
    else if (strcmp(argv[1], "madv") == 0) cmd_madv();
    else if (strcmp(argv[1], "pid") == 0 && argc >= 3) cmd_pid((pid_t)atoi(argv[2]));
    else if (strcmp(argv[1], "system") == 0) cmd_system();
    else if (strcmp(argv[1], "show") == 0) cmd_show();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
