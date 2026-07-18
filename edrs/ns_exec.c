#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int write_file(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return (n < 0) ? -1 : 0;
}

static void setup_user_ns(uid_t uid, gid_t gid)
{
    char buf[64];

    snprintf(buf, sizeof(buf), "0 %u 1\n", uid);
    if (write_file("/proc/self/uid_map", buf) < 0) {
        perror("uid_map");
    }

    if (write_file("/proc/self/setgroups", "deny") < 0) {
        perror("setgroups");
    }

    snprintf(buf, sizeof(buf), "0 %u 1\n", gid);
    if (write_file("/proc/self/gid_map", buf) < 0) {
        perror("gid_map");
    }
}

static void remount_proc(void)
{
    if (mount("none", "/proc", NULL, MS_PRIVATE | MS_REC, NULL) < 0) return;
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
}

static void cmd_user(char *const argv[])
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) < 0) { perror("unshare NEWUSER"); return; }
    setup_user_ns(uid, gid);

    printf("[*] new user namespace  (appears as uid=0 inside)\n");
    execvp(argv[0], argv);
    perror("execvp");
}

static void cmd_full(int hide_proc, char *const argv[])
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    int flags = CLONE_NEWUSER | CLONE_NEWNS;
    if (unshare(flags) < 0) { perror("unshare NEWUSER|NEWNS"); return; }
    setup_user_ns(uid, gid);

    if (hide_proc) {
        remount_proc();
        printf("[*] /proc remounted in new mount namespace\n");
    }

    printf("[*] new user+mount namespace\n");
    execvp(argv[0], argv);
    perror("execvp");
}

static void cmd_pid(int hide_proc, char *const argv[])
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) < 0) { perror("unshare NEWUSER"); return; }
    setup_user_ns(uid, gid);

    if (unshare(CLONE_NEWNS | CLONE_NEWPID) < 0) {
        perror("unshare NEWNS|NEWPID"); return;
    }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return; }

    if (child == 0) {
        if (hide_proc) remount_proc();
        printf("[*] new user+mount+pid namespace  (this process is PID 1 inside)\n");
        execvp(argv[0], argv);
        perror("execvp");
        _exit(1);
    }

    int status;
    waitpid(child, &status, 0);
}

static void cmd_ptrace_block(void)
{
    if (prctl(PR_SET_DUMPABLE, 0) < 0) { perror("prctl SET_DUMPABLE"); return; }
    printf("[+] PR_SET_DUMPABLE=0  - ptrace from other processes blocked\n");
    printf("[*] combined with PR_SET_PTRACER=0 to block even privileged ptrace:\n");
    printf("    prctl(PR_SET_PTRACER, 0) - (done next)\n");
    if (prctl(PR_SET_PTRACER, 0) < 0) perror("prctl SET_PTRACER (optional)");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <user|full|full-hide|pid|pid-hide|ptrace-block>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "user") == 0) {
        cmd_user(argv + 2);

    } else if (strcmp(argv[1], "full") == 0) {
        cmd_full(0, argv + 2);

    } else if (strcmp(argv[1], "full-hide") == 0) {
        cmd_full(1, argv + 2);

    } else if (strcmp(argv[1], "pid") == 0) {
        cmd_pid(0, argv + 2);

    } else if (strcmp(argv[1], "pid-hide") == 0) {
        cmd_pid(1, argv + 2);

    } else if (strcmp(argv[1], "ptrace-block") == 0) {
        cmd_ptrace_block();

    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
