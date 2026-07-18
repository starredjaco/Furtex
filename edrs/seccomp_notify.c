#define _GNU_SOURCE
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV  _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND  _IOWR('!', 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, __u64)
#endif

static int install_notif_filter(void)
{
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)__builtin_offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,  0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open,    0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = {
        .len    = (unsigned short)(sizeof(prog) / sizeof(prog[0])),
        .filter = prog,
    };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    return (int)syscall(__NR_seccomp,
                        SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        &fprog);
}

static void supervisor_loop(int notif_fd, int dry_run)
{
    struct seccomp_notif     req;
    struct seccomp_notif_resp resp;

    printf("[supervisor] watching openat/open syscalls (dry_run=%d)\n", dry_run);
    printf("[supervisor] format: pid  nr  arg0(path_ptr)\n");

    for (;;) {
        memset(&req, 0, sizeof(req));
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == ENOENT) break;
            perror("NOTIF_RECV"); break;
        }

        char path[512] = {};
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/mem", (int)req.pid);
        int mem = open(maps_path, O_RDONLY);
        if (mem >= 0) {
            pread(mem, path, sizeof(path)-1, (off_t)req.data.args[1]);
            close(mem);
        }

        printf("[+] pid=%-6d nr=%-6lld path=%s\n",
               (int)req.pid, (long long)req.data.nr, path);

        memset(&resp, 0, sizeof(resp));
        resp.id    = req.id;
        resp.error = 0;
        resp.val   = 0;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
            if (errno == ENOENT) continue;
            perror("NOTIF_SEND"); break;
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s watch [args]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "watch") == 0 && argc >= 3) {

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
            perror("socketpair"); return 1;
        }

        pid_t child = fork();
        if (child < 0) { perror("fork"); return 1; }

        if (child == 0) {
            close(sv[0]);

            int notif_fd = install_notif_filter();
            if (notif_fd < 0) {
                perror("seccomp NOTIF"); _exit(1);
            }

            char cmsgbuf[CMSG_SPACE(sizeof(int))];
            struct iovec iov = { .iov_base = "x", .iov_len = 1 };
            struct msghdr mh = {
                .msg_iov    = &iov,
                .msg_iovlen = 1,
                .msg_control    = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
            };
            struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
            cm->cmsg_level = SOL_SOCKET;
            cm->cmsg_type  = SCM_RIGHTS;
            cm->cmsg_len   = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cm), &notif_fd, sizeof(int));

            if (sendmsg(sv[1], &mh, 0) < 0) {
                perror("sendmsg SCM_RIGHTS"); _exit(1);
            }
            close(sv[1]);

            execvp(argv[2], argv + 2);
            perror("execvp"); _exit(1);
        }

        close(sv[1]);

        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        char dummy;
        struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
        struct msghdr mh = {
            .msg_iov    = &iov,
            .msg_iovlen = 1,
            .msg_control    = cmsgbuf,
            .msg_controllen = sizeof(cmsgbuf),
        };
        if (recvmsg(sv[0], &mh, 0) <= 0) {
            fprintf(stderr, "[!] failed to receive notif fd via SCM_RIGHTS\n"); return 1;
        }
        close(sv[0]);

        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        if (!cm || cm->cmsg_type != SCM_RIGHTS) {
            fprintf(stderr, "[!] no SCM_RIGHTS in message\n"); return 1;
        }
        int local_notif_fd;
        memcpy(&local_notif_fd, CMSG_DATA(cm), sizeof(int));

        supervisor_loop(local_notif_fd, 0);
        close(local_notif_fd);

        int status;
        waitpid(child, &status, 0);
        return WEXITSTATUS(status);
    }

    fprintf(stderr, "unknown: %s\n", argv[1]);
    return 1;
}
