#define _GNU_SOURCE
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#define MAX_PHDRS 64

typedef struct {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
} KcoreSeg;

static KcoreSeg segs[MAX_PHDRS];
static int nseg = 0;
static int kcore_fd = -1;

static int kcore_open(void)
{
    kcore_fd = open("/proc/kcore", O_RDONLY);
    if (kcore_fd < 0) {
        if (errno == EACCES || errno == EPERM)
            fprintf(stderr, "[!] /proc/kcore: permission denied - need root\n");
        else
            perror("/proc/kcore");
        return -1;
    }

    Elf64_Ehdr ehdr;
    if (pread(kcore_fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        perror("pread ehdr"); return -1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[!] /proc/kcore: not ELF\n"); return -1;
    }

    if (ehdr.e_phnum > MAX_PHDRS) {
        fprintf(stderr, "[!] too many phdrs: %d\n", ehdr.e_phnum); return -1;
    }

    for (int i = 0; i < ehdr.e_phnum && nseg < MAX_PHDRS; i++) {
        Elf64_Phdr phdr;
        off_t phoff = (off_t)ehdr.e_phoff + (off_t)i * sizeof(Elf64_Phdr);
        if (pread(kcore_fd, &phdr, sizeof(phdr), phoff) != sizeof(phdr)) continue;
        if (phdr.p_type != PT_LOAD || phdr.p_filesz == 0) continue;

        segs[nseg].vaddr  = phdr.p_vaddr;
        segs[nseg].offset = phdr.p_offset;
        segs[nseg].filesz = phdr.p_filesz;
        nseg++;
    }
    return 0;
}

static int kcore_read(uint64_t vaddr, void *buf, size_t len)
{
    for (int i = 0; i < nseg; i++) {
        if (vaddr >= segs[i].vaddr &&
            vaddr + len <= segs[i].vaddr + segs[i].filesz) {
            off_t off = (off_t)(segs[i].offset + (vaddr - segs[i].vaddr));
            if (pread(kcore_fd, buf, len, off) == (ssize_t)len)
                return 0;
        }
    }
    return -1;
}

static uint64_t kallsyms_addr(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) { perror("/proc/kallsyms"); return 0; }

    char line[256], sym[128], type[4];
    uint64_t addr = 0, found = 0;
    while (fgets(line, sizeof(line), f) && !found) {
        if (sscanf(line, "%lx %3s %127s", &addr, type, sym) < 3) continue;
        if (strcmp(sym, name) == 0) found = addr;
    }
    fclose(f);
    return found;
}

typedef enum {
    HOOK_NONE,
    HOOK_FTRACE_NOP,
    HOOK_FTRACE_CALL,
    HOOK_JMP,
    HOOK_INT3,
    HOOK_UNKNOWN,
} HookType;

static HookType classify(const uint8_t *b)
{

    if (b[0] == 0x0f && b[1] == 0x1f && b[2] == 0x44 && b[3] == 0x00 && b[4] == 0x00)
        return HOOK_FTRACE_NOP;

    if (b[0] == 0xe8) return HOOK_FTRACE_CALL;

    if (b[0] == 0xe9) return HOOK_JMP;

    if (b[0] == 0xcc) return HOOK_INT3;
    return HOOK_NONE;
}

static const char *hook_desc(HookType h, const uint8_t *b, uint64_t vaddr)
{
    static char buf[128];
    switch (h) {
    case HOOK_FTRACE_NOP:
        return "nop (ftrace placeholder - no active hook)";
    case HOOK_FTRACE_CALL: {
        int32_t rel;
        memcpy(&rel, b + 1, 4);
        uint64_t target = vaddr + 5 + (int64_t)rel;
        snprintf(buf, sizeof(buf),
                 "CALL (ftrace hook active → 0x%lx) [register_ftrace_function]", target);
        return buf;
    }
    case HOOK_JMP: {
        int32_t rel;
        memcpy(&rel, b + 1, 4);
        uint64_t target = vaddr + 5 + (int64_t)rel;
        snprintf(buf, sizeof(buf),
                 "JMP  0x%lx  [!INLINE PATCH - NOT via ftrace, NOT in kprobe_events]",
                 target);
        return buf;
    }
    case HOOK_INT3:
        return "INT3 [kprobe breakpoint active]";
    default:
        return "normal prologue (no hook)";
    }
}

static void inspect_fn(const char *name)
{
    uint64_t addr = kallsyms_addr(name);
    if (!addr) {
        printf("  %-40s  addr=0 (not exported or zero - run as root)\n", name);
        return;
    }

    uint8_t bytes[16];
    if (kcore_read(addr, bytes, sizeof(bytes)) < 0) {
        printf("  %-40s  0x%lx  [kcore read failed]\n", name, addr);
        return;
    }

    static const uint8_t endbr64[4] = {0xf3, 0x0f, 0x1e, 0xfa};
    const uint8_t *b  = bytes;
    uint64_t       va = addr;
    if (memcmp(b, endbr64, 4) == 0) { b += 4; va += 4; }

    HookType h = classify(b);
    printf("  %-40s  0x%lx  %s\n", name, addr, hook_desc(h, b, va));

    if (h == HOOK_JMP) {
        printf("    bytes: ");
        for (int i = 0; i < 8; i++) printf("%02x ", bytes[i]);
        printf("\n");
        printf("    remedy: kmod_unload unload <module> (clean exit restores bytes)\n");
        printf("            if clean fails: kmod_unload unload <module> --force\n");
        printf("            [!] force skips exit fn - inline bytes stay until reboot\n");
    }
}

static const char *default_targets[] = {
    "__x64_sys_openat",
    "__x64_sys_execve",
    "__x64_sys_execveat",
    "__x64_sys_connect",
    "__x64_sys_accept",
    "__x64_sys_accept4",
    "__x64_sys_read",
    "__x64_sys_write",
    "__x64_sys_unlink",
    "__x64_sys_unlinkat",
    "do_filp_open",
    "vfs_open",
    "security_file_open",
    "security_bprm_check",
    "tcp_v4_connect",
    "tcp_v6_connect",
    "inet_stream_connect",
    "udp_sendmsg",
    "ip_local_out",
    "do_exit",
    "wake_up_new_task",
    "copy_process",
    NULL
};

static void cmd_scan_all(void)
{
    printf("[*] scanning kernel function prologues for inline patches\n");
    printf("    (JMP = inline patch; CALL = ftrace hook; NOP = no hook)\n\n");
    printf("  %-40s  %-18s  %s\n", "function", "address", "hook type");
    printf("  %s\n",
           "----------------------------------------------------------------------");

    for (int i = 0; default_targets[i]; i++)
        inspect_fn(default_targets[i]);
}

static void cmd_fn(const char *name)
{
    printf("[*] inspecting: %s\n", name);
    inspect_fn(name);
}

static void cmd_enabled_ftrace(void)
{
    printf("[*] ftrace enabled_functions (shows register_ftrace_function hooks):\n");

    const char *paths[] = {
        "/sys/kernel/tracing/enabled_functions",
        "/sys/kernel/debug/tracing/enabled_functions",
        NULL
    };
    FILE *f = NULL;
    for (int i = 0; paths[i]; i++) {
        f = fopen(paths[i], "r");
        if (f) break;
    }
    if (!f) {
        printf("  [!] not accessible - need root + tracefs mounted\n");
        printf("  [*] note: functions NOT listed here but showing JMP in kcore\n"
               "      are patched DIRECTLY (not via ftrace) - worst case\n");
        return;
    }
    char line[256];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        printf("  %s", line); n++;
    }
    fclose(f);
    printf("  total: %d functions with ftrace hooks\n", n);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scan|fn|ftrace>\n", argv[0]);
        return 1;
    }

    if (kcore_open() < 0) return 1;

    if (strcmp(argv[1], "scan") == 0)
        cmd_scan_all();
    else if (strcmp(argv[1], "fn") == 0 && argc >= 3)
        cmd_fn(argv[2]);
    else if (strcmp(argv[1], "ftrace") == 0)
        cmd_enabled_ftrace();
    else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }

    close(kcore_fd);
    return 0;
}
