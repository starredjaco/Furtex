#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

static uintptr_t find_lib_base(pid_t pid, const char *libname)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, libname)) continue;
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        if (sscanf(line, "%lx", &base) == 1) break;
    }
    fclose(f);
    return base;
}

static uintptr_t find_own_lib_base(const char *libname)
{
    return find_lib_base(getpid(), libname);
}

static uintptr_t find_syscall_gadget(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    uintptr_t gadget = 0;
    while (fgets(line, sizeof(line), f) && !gadget) {
        if (!strstr(line, "libc") || !strstr(line, "r-xp")) continue;
        uintptr_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        char mem_path[64];
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);
        int fd = open(mem_path, O_RDONLY);
        if (fd < 0) continue;
        size_t sz = end - start;
        unsigned char *buf = malloc(sz);
        if (!buf) { close(fd); continue; }
        ssize_t rd = pread(fd, buf, sz, (off_t)start);
        close(fd);
        if (rd > 0) {
            for (ssize_t i = 0; i < rd - 1; i++) {
                if (buf[i] == 0x0f && buf[i+1] == 0x05) {
                    gadget = start + i;
                    break;
                }
            }
        }
        free(buf);
    }
    fclose(f);
    return gadget;
}

static uintptr_t remote_dlopen(pid_t pid, const char *so_path)
{
    struct user_regs_struct regs, saved_regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) < 0) {
        perror("PTRACE_GETREGS"); return 0;
    }
    memcpy(&regs, &saved_regs, sizeof(regs));

    uintptr_t self_libc   = find_own_lib_base("libc");
    uintptr_t target_libc = find_lib_base(pid, "libc");
    if (!self_libc || !target_libc) {
        fprintf(stderr, "[!] failed to locate libc in target\n"); return 0;
    }

    void *self_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!self_dlopen) {
        fprintf(stderr, "[!] dlopen not found: %s\n", dlerror());
        return 0;
    }

    uintptr_t dlopen_offset = (uintptr_t)self_dlopen - self_libc;
    uintptr_t target_dlopen = target_libc + dlopen_offset;

    uintptr_t gadget = find_syscall_gadget(pid);
    if (!gadget) { fprintf(stderr, "[!] no syscall gadget found\n"); return 0; }

    printf("[*] self   libc base: 0x%lx  dlopen: %p\n", self_libc, self_dlopen);
    printf("[*] target libc base: 0x%lx  dlopen: 0x%lx\n", target_libc, target_dlopen);
    printf("[*] syscall gadget: 0x%lx\n", gadget);

    regs.rax = 9;
    regs.rdi = 0;
    regs.rsi = 0x10000;
    regs.rdx = 7;
    regs.r10 = 0x22;
    regs.r8  = (unsigned long long)-1;
    regs.r9  = 0;
    regs.orig_rax = (unsigned long long)-1;
    regs.rip = gadget;
    regs.rsp = saved_regs.rsp - 128;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) { perror("SETREGS mmap"); return 0; }
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) { perror("SINGLESTEP"); return 0; }
    int ws;
    waitpid(pid, &ws, 0);
    struct user_regs_struct after_mmap;
    ptrace(PTRACE_GETREGS, pid, NULL, &after_mmap);
    uintptr_t rwx_page = after_mmap.rax;
    if ((long long)rwx_page < 0) {
        fprintf(stderr, "[!] mmap failed: %lld\n", (long long)rwx_page); return 0;
    }
    printf("[*] RWX region mmap'd at 0x%lx (64 KB)\n", rwx_page);

    size_t path_len = strlen(so_path) + 1;
    unsigned char full_sc[512] = {};
    size_t sc_off = 0;
    uintptr_t str_addr = rwx_page + 512;

    full_sc[sc_off++] = 0x48; full_sc[sc_off++] = 0xbf;
    memcpy(full_sc + sc_off, &str_addr, 8); sc_off += 8;

    full_sc[sc_off++] = 0xbe;
    uint32_t rtld_lazy = 1;
    memcpy(full_sc + sc_off, &rtld_lazy, 4); sc_off += 4;

    full_sc[sc_off++] = 0x49; full_sc[sc_off++] = 0xbb;
    memcpy(full_sc + sc_off, &target_dlopen, 8); sc_off += 8;
    full_sc[sc_off++] = 0x41; full_sc[sc_off++] = 0xff; full_sc[sc_off++] = 0xd3;

    full_sc[sc_off++] = 0xcc;

    while (sc_off < 512) full_sc[sc_off++] = 0x90;

    char target_mem_path[64];
    snprintf(target_mem_path, sizeof(target_mem_path), "/proc/%d/mem", (int)pid);
    int mem_fd = open(target_mem_path, O_RDWR);
    if (mem_fd < 0) { perror("open /proc/PID/mem"); return 0; }
    if (pwrite(mem_fd, full_sc, 512, (off_t)rwx_page) != 512) {
        perror("pwrite shellcode"); close(mem_fd); return 0;
    }
    if (pwrite(mem_fd, so_path, path_len, (off_t)str_addr) != (ssize_t)path_len) {
        perror("pwrite so_path"); close(mem_fd); return 0;
    }
    close(mem_fd);

    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rip = rwx_page;
    regs.rsp = rwx_page + 0x10000 - 0x10;
    regs.orig_rax = (unsigned long long)-1;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("PTRACE_SETREGS dlopen"); return 0;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) { perror("PTRACE_CONT"); return 0; }
    waitpid(pid, &ws, 0);

    if (WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGTRAP) {
        struct user_regs_struct post;
        ptrace(PTRACE_GETREGS, pid, NULL, &post);
        printf("[+] dlopen returned handle: 0x%llx\n", (unsigned long long)post.rax);
    } else {
        printf("[!] unexpected stop: status=0x%x\n", ws);
    }

    memcpy(&regs, &saved_regs, sizeof(regs));
    regs.rax = 11;
    regs.rdi = rwx_page;
    regs.rsi = 0x10000;
    regs.orig_rax = (unsigned long long)-1;
    regs.rip = gadget;
    regs.rsp = saved_regs.rsp - 128;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, &ws, 0);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) < 0)
        perror("restore regs");

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4 || strcmp(argv[1], "inject") != 0) {
        fprintf(stderr, "usage: %s inject [args]\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[2]);
    const char *so_path = argv[3];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH"); return 1;
    }
    printf("[*] attached to PID %d\n", (int)pid);

    int wstatus;
    waitpid(pid, &wstatus, 0);

    remote_dlopen(pid, so_path);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[*] detached\n");
    return 0;
}
