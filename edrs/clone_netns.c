#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int write_file(const char *path, const char *str)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, str, strlen(str));
    close(fd);
    return n < 0 ? -1 : 0;
}

static void setup_user_ns(uid_t uid, gid_t gid)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "0 %u 1\n", uid);
    write_file("/proc/self/uid_map", buf);
    write_file("/proc/self/setgroups", "deny");
    snprintf(buf, sizeof(buf), "0 %u 1\n", gid);
    write_file("/proc/self/gid_map", buf);
}

static int lo_up(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) { close(sock); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int r = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);
    return r;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <shell|exec>\n", argv[0]);
        return 1;
    }

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER) < 0) { perror("unshare NEWUSER"); return 1; }
    setup_user_ns(uid, gid);

    if (unshare(CLONE_NEWNET) < 0) { perror("unshare NEWNET"); return 1; }

    if (lo_up() < 0) perror("[warn] lo up");
    else printf("[*] loopback up in new netns\n");

    printf("[*] new network namespace - host monitoring blind to this netns\n");

    char **cmd;
    char *shell_argv[] = { "/bin/bash", NULL };

    if (strcmp(argv[1], "shell") == 0) {
        cmd = shell_argv;
    } else if (strcmp(argv[1], "exec") == 0) {
        cmd = argv + 2;
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }

    execvp(cmd[0], cmd);
    perror("execvp");
    return 1;
}
