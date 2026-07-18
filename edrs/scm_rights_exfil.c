#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void send_fd(int sock, int fd)
{
    char dummy = 0;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    union {
        struct cmsghdr cm;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0)
        perror("sendmsg");
}

static int recv_fd(int sock)
{
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    union {
        struct cmsghdr cm;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsg_buf;

    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = &cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };

    if (recvmsg(sock, &msg, 0) < 0) {
        perror("recvmsg");
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "[-] no SCM_RIGHTS in message\n");
        return -1;
    }

    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }

    if (child == 0) {

        close(sv[0]);
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
            perror("open");
            _exit(1);
        }
        send_fd(sv[1], fd);
        close(fd);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);
    int fd = recv_fd(sv[0]);
    close(sv[0]);

    if (fd < 0) return 1;

    fprintf(stderr, "[*] received fd=%d (no do_filp_open in this pid)\n", fd);

    struct stat st;
    if (fstat(fd, &st) == 0 && lseek(fd, 0, SEEK_SET) == 0) {
        char buf[65536];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            fwrite(buf, 1, (size_t)n, stdout);
    }

    close(fd);
    return 0;
}
