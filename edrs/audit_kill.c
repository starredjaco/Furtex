#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

struct audit_msg {
    struct nlmsghdr  hdr;
    struct audit_status status;
};

static int audit_sock(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    return fd;
}

static int audit_send(int fd, uint16_t type, const struct audit_status *s)
{
    struct audit_msg msg = {};
    msg.hdr.nlmsg_len   = NLMSG_LENGTH(sizeof(struct audit_status));
    msg.hdr.nlmsg_type  = type;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.hdr.nlmsg_seq   = (uint32_t)getpid();
    msg.hdr.nlmsg_pid   = (uint32_t)getpid();
    if (s) msg.status = *s;

    struct sockaddr_nl dest = { .nl_family = AF_NETLINK };
    ssize_t n = sendto(fd, &msg, msg.hdr.nlmsg_len, 0,
                       (struct sockaddr *)&dest, sizeof(dest));
    return (n < 0) ? -1 : 0;
}

static int audit_recv_status(int fd, struct audit_status *out)
{
    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) { perror("recv"); return -1; }

    struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
    if (hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
        if (err->error) {
            errno = -err->error;
            perror("audit");
            return -1;
        }
        return 0;
    }
    if (hdr->nlmsg_type == AUDIT_GET && out)
        memcpy(out, NLMSG_DATA(hdr), sizeof(*out));
    return 0;
}

static void cmd_status(int fd)
{
    if (audit_send(fd, AUDIT_GET, NULL) < 0) return;

    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) { perror("recv"); return; }

    struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
    if (hdr->nlmsg_type != AUDIT_GET) {
        fprintf(stderr, "[!] unexpected nlmsg_type %u\n", hdr->nlmsg_type);
        return;
    }

    struct audit_status *s = (struct audit_status *)NLMSG_DATA(hdr);
    printf("[*] audit status:\n");
    printf("    enabled     = %u\n", s->enabled);
    printf("    failure     = %u\n", s->failure);
    printf("    pid         = %u\n", s->pid);
    printf("    rate_limit  = %u\n", s->rate_limit);
    printf("    backlog_lim = %u\n", s->backlog_limit);
    printf("    lost        = %u\n", s->lost);
    printf("    backlog     = %u\n", s->backlog);
}

static void cmd_disable(int fd)
{
    struct audit_status s = {
        .mask    = AUDIT_STATUS_ENABLED,
        .enabled = 0,
    };
    if (audit_send(fd, AUDIT_SET, &s) < 0) return;
    if (audit_recv_status(fd, NULL) < 0) return;
    printf("[+] audit disabled (enabled=0)\n");
}

static void cmd_set_pid(int fd, uint32_t pid)
{
    struct audit_status s = {
        .mask = AUDIT_STATUS_PID,
        .pid  = pid,
    };
    if (audit_send(fd, AUDIT_SET, &s) < 0) return;
    if (audit_recv_status(fd, NULL) < 0) return;
    printf("[+] audit daemon PID set to %u (0 = no daemon)\n", pid);
}

static void cmd_rate_zero(int fd)
{
    struct audit_status s = {
        .mask       = AUDIT_STATUS_RATE_LIMIT,
        .rate_limit = 1,
    };
    if (audit_send(fd, AUDIT_SET, &s) < 0) return;
    if (audit_recv_status(fd, NULL) < 0) return;
    printf("[+] rate_limit=1 event/sec - audit log effectively silenced\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <status|disable|unpid|throttle>\n", argv[0]);
        return 1;
    }

    int fd = audit_sock();
    if (fd < 0) return 1;

    if (strcmp(argv[1], "status") == 0) {
        cmd_status(fd);
    } else if (strcmp(argv[1], "disable") == 0) {
        cmd_disable(fd);
    } else if (strcmp(argv[1], "unpid") == 0) {
        cmd_set_pid(fd, 0);
    } else if (strcmp(argv[1], "throttle") == 0) {
        cmd_rate_zero(fd);
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
