#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void print_ns_link(const char *type)
{
    char path[64], target[128];
    snprintf(path, sizeof(path), "/proc/self/ns/%s", type);
    ssize_t n = readlink(path, target, sizeof(target)-1);
    if (n > 0) { target[n] = '\0'; printf("  ns/%-8s → %s\n", type, target); }
    else printf("  ns/%-8s → (unavailable)\n", type);
}

static void cmd_info(void)
{
    printf("[*] current namespace links (Falco reads these for ns correlation):\n");
    static const char *types[] = {
        "pid", "mnt", "net", "uts", "ipc", "user", "cgroup", NULL
    };
    for (int i = 0; types[i]; i++)
        print_ns_link(types[i]);
    printf("\n[*] pid=%d  ppid=%d  uid=%d\n",
           (int)getpid(), (int)getppid(), (int)getuid());
}

static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (n < 0) ? -1 : 0;
}

static void cmd_user_new(int run_shell)
{

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) < 0) {
        perror("unshare CLONE_NEWUSER");
        return;
    }

    char map[64];

    write_file("/proc/self/setgroups", "deny");

    snprintf(map, sizeof(map), "0 %d 1\n", (int)uid);
    if (write_file("/proc/self/uid_map", map) < 0)
        fprintf(stderr, "[!] uid_map: %s\n", strerror(errno));

    snprintf(map, sizeof(map), "0 %d 1\n", (int)gid);
    if (write_file("/proc/self/gid_map", map) < 0)
        fprintf(stderr, "[!] gid_map: %s\n", strerror(errno));

    printf("[+] new user namespace: uid=%d inside (was %d outside)\n",
           (int)getuid(), (int)uid);
    printf("[*] Falco sees proc.uid = 0 for this process now\n");
    printf("[*] uid=0 rules fire, but container-root exemptions may apply\n");

    if (run_shell) {
        printf("[*] spawning shell in user namespace:\n");
        char *sh_argv[] = { "/bin/sh", NULL };
        char *sh_envp[] = { "PATH=/bin:/usr/bin:/sbin:/usr/sbin", "PS1=\\u@ns# ", NULL };
        execve("/bin/sh", sh_argv, sh_envp);
        perror("execve");
    }
}

static void cmd_net_new(void)
{
    if (unshare(CLONE_NEWNET) < 0) { perror("unshare CLONE_NEWNET"); return; }

    printf("[+] new network namespace created\n");
    printf("[*] only loopback (lo) is visible inside\n");
    printf("[*] Falco's network rules that check:\n");
    printf("    fd.rip, fd.l4proto, fd.sport, fd.dport\n");
    printf("    see this network namespace's sockets\n");
    printf("[*] host network connections from this process are invisible to\n");
    printf("    external monitors watching host network - all traffic is namespaced\n");

    system("ip link set lo up 2>/dev/null");

    printf("[*] spawning shell in new network namespace:\n");
    char *sh_argv[] = { "/bin/sh", NULL };
    char *sh_envp[] = { "PATH=/bin:/usr/bin:/sbin:/usr/sbin", NULL };
    execve("/bin/sh", sh_argv, sh_envp);
    perror("execve");
}

static void cmd_mount_new(void)
{

    if (unshare(CLONE_NEWNS) < 0) { perror("unshare CLONE_NEWNS"); return; }

    printf("[+] new mount namespace\n");
    printf("[*] existing mounts inherited; now we can alter them without affecting host\n");

    if (mount("proc", "/proc", "proc",
              MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) == 0) {
        printf("[+] /proc remounted (private view)\n");
        printf("[*] Falco enrichment that reads /proc/<pid>/ may fail for\n");
        printf("    processes outside this mount namespace\n");
    } else {
        fprintf(stderr, "[!] remount /proc: %s\n", strerror(errno));
        printf("[*] mount ns isolation still active (just no proc remount)\n");
    }

    printf("[*] info after new mount ns:\n");
    cmd_info();
}

static void cmd_all_new(void)
{

    printf("[*] unsharing all namespaces:\n");

    struct { int flag; const char *name; } ns_list[] = {
        { CLONE_NEWNS,   "mount" },
        { CLONE_NEWUTS,  "uts" },
        { CLONE_NEWIPC,  "ipc" },
        { CLONE_NEWNET,  "net" },
        { CLONE_NEWPID,  "pid" },
        { 0, NULL }
    };

    for (int i = 0; ns_list[i].flag; i++) {
        if (unshare(ns_list[i].flag) == 0)
            printf("  [+] CLONE_NEW%-6s ok\n", ns_list[i].name);
        else
            fprintf(stderr, "  [!] CLONE_NEW%-6s: %s\n", ns_list[i].name, strerror(errno));
    }

    printf("[*] CLONE_NEWPID: children of this process run as pid 1 in new ns\n");
    printf("[*] Falco sees their host PID but enrichment may fail for /proc lookups\n");

    printf("[*] namespace state:\n");
    cmd_info();

    printf("[*] spawning shell in all-new namespaces:\n");
    printf("[*] child pid in new PID ns = 1 (despite host pid being higher)\n");
    char *sh_argv[] = { "/bin/sh", NULL };
    char *sh_envp[] = {
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
        "PS1=\\u@pivot# ",
        NULL
    };
    pid_t child = fork();
    if (child < 0) { perror("fork"); return; }
    if (child == 0) {
        execve("/bin/sh", sh_argv, sh_envp);
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);
    printf("[*] shell exited: %d\n", WEXITSTATUS(status));
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s info         show current namespace links\n"
            "  %s all-new      unshare all ns + exec shell inside (needs CAP_SYS_ADMIN)\n"
            "  %s net-new      new network namespace (only loopback) + shell\n"
            "  %s mount-new    new mount namespace + remount /proc\n"
            "  %s user-new     new user namespace (unprivileged, uid 0 inside)\n"
            "  %s userns-shell user namespace then exec /bin/sh as uid 0\n"
            "\nwhy this matters for Falco:\n"
            "  Falco enriches events with /proc/<pid>/ lookups using the global mount ns.\n"
            "  After ns_pivot, the process is in different namespaces:\n"
            "  - New net ns: fd.{rip,rport,sport} resolve differently\n"
            "  - New pid ns: proc.pid is a new PID namespace ID, not host PID\n"
            "  - New mount ns: Falco's /proc-based fd.name resolution may fail\n"
            "  This breaks rules that rely on proc enrichment being consistent.\n"
            "\nrequires: CAP_SYS_ADMIN for most; user-new is unprivileged\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if      (strcmp(argv[1], "info")        == 0) cmd_info();
    else if (strcmp(argv[1], "all-new")     == 0) cmd_all_new();
    else if (strcmp(argv[1], "net-new")     == 0) cmd_net_new();
    else if (strcmp(argv[1], "mount-new")   == 0) cmd_mount_new();
    else if (strcmp(argv[1], "user-new")    == 0) cmd_user_new(0);
    else if (strcmp(argv[1], "userns-shell")== 0) cmd_user_new(1);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
