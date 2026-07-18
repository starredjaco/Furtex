#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int copy_self_to_memfd(void)
{
    int src = open("/proc/self/exe", O_RDONLY);
    if (src < 0) { perror("/proc/self/exe"); return -1; }

    int mfd = (int)syscall(__NR_memfd_create, "exe", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mfd < 0) { perror("memfd_create"); close(src); return -1; }

    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        const char *p = buf;
        while (n > 0) {
            ssize_t w = write(mfd, p, (size_t)n);
            if (w < 0) { perror("write memfd"); close(src); return -1; }
            p += w; n -= w;
        }
    }
    close(src);
    return mfd;
}

static void do_delete(char *argv[], char *envp[])
{
    if (unlink("/proc/self/exe") < 0 && errno != EPERM) {
        perror("[!] unlink /proc/self/exe");
    }

    char self_path[512];
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if (n > 0) {
        self_path[n] = '\0';
        char *del = strstr(self_path, " (deleted)");
        if (del) *del = '\0';

        if (unlink(self_path) < 0)
            fprintf(stderr, "[warn] unlink %s: %s\n", self_path, strerror(errno));
        else
            printf("[+] deleted: %s\n", self_path);
    }

    printf("[*] running from memory; /proc/%d/exe now shows '(deleted)'\n",
           (int)getpid());
    printf("[*] PID %d still alive - binary is gone from disk\n", (int)getpid());

    if (argv[0]) {
        printf("[*] sleeping 5s then re-exec'ing self from memfd...\n");
        sleep(5);

        int mfd = copy_self_to_memfd();
        if (mfd >= 0) {
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);
            char *new_argv[] = { fd_path, "payload", NULL };
            execve(fd_path, new_argv, envp);
            perror("fexecve");
        }
    }
}

static void run_payload(void)
{
    printf("[payload] running from memfd - no binary on disk\n");
    printf("[payload] PID=%d  ppid=%d\n", (int)getpid(), (int)getppid());

    char buf[64];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (n > 0) { buf[n] = '\0'; printf("[payload] /proc/self/exe = %s\n", buf); }

    for (;;) {
        printf("[payload] still alive. Press Ctrl-C to exit.\n");
        sleep(10);
    }
}

int main(int argc, char *argv[], char *envp[])
{
    if (argc >= 2 && strcmp(argv[1], "payload") == 0) {
        run_payload();
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload|delete|reexec>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "delete") == 0 || strcmp(argv[1], "reexec") == 0) {
        do_delete(argv, envp);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
