#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static void overwrite_argv(char *argv0, const char *name)
{
    size_t avlen = strlen(argv0);
    size_t nlen  = strlen(name);
    size_t cplen = nlen < avlen ? nlen : avlen;
    memcpy(argv0, name, cplen);
    memset(argv0 + cplen, '\0', avlen - cplen);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <kthread|self <name>|spoof <name> -- <cmd> [args...]>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "kthread") == 0) {
        prctl(PR_SET_NAME, "kworker/u4:2");
        overwrite_argv(argv[0], "kworker/u4:2");
        prctl(PR_SET_DUMPABLE, 0);
        printf("[+] masquerading as kworker/u4:2\n");
        for (;;) pause();
        return 0;
    }

    if (strcmp(argv[1], "self") == 0 && argc >= 3) {
        const char *name = argv[2];
        prctl(PR_SET_NAME, name);
        overwrite_argv(argv[0], name);
        printf("[+] renamed to '%s'\n", name);
        for (;;) pause();
        return 0;
    }

    if (strcmp(argv[1], "spoof") == 0 && argc >= 5) {
        const char *name = argv[2];
        int sep = -1;
        for (int i = 3; i < argc; i++)
            if (strcmp(argv[i], "--") == 0) { sep = i; break; }
        if (sep < 0 || sep + 1 >= argc) {
            fprintf(stderr, "[!] missing -- before command\n"); return 1;
        }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }

        if (pid == 0) {
            prctl(PR_SET_NAME, name);
            char **cmd = argv + sep + 1;
            const char *path = cmd[0];
            cmd[0] = (char *)name;   /* argv[0] seen in /proc/PID/cmdline post-exec */
            execvp(path, cmd);
            perror("execvp"); _exit(1);
        }

        printf("[*] child PID %d spoofed as '%s'\n", pid, name);
        int st;
        waitpid(pid, &st, 0);
        return WEXITSTATUS(st);
    }

    fprintf(stderr, "unknown: %s\n", argv[1]);
    return 1;
}
