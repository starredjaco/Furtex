#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

static void guardian_loop(pid_t child)
{

    prctl(PR_SET_DUMPABLE, 0);

    for (;;) {
        int status;
        pid_t p = waitpid(child, &status, 0);
        if (p < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(status)) {

            exit(WEXITSTATUS(status));
        }

        if (WIFSIGNALED(status)) {

            int sig = WTERMSIG(status);
            signal(sig, SIG_DFL);
            kill(getpid(), sig);
            exit(128 + sig);
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == SIGTRAP) {
                ptrace(PTRACE_CONT, child, NULL, (void *)0L);
                continue;
            }

            ptrace(PTRACE_CONT, child, NULL, (void *)(intptr_t)sig);
        }
    }
}

static void cmd_wrap(char **cmd_argv)
{
    pid_t child = fork();
    if (child < 0) { perror("fork"); exit(1); }

    if (child == 0) {

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME"); exit(1);
        }

        prctl(PR_SET_DUMPABLE, 0);

        execvp(cmd_argv[0], cmd_argv);
        perror(cmd_argv[0]);
        exit(127);
    }

    fprintf(stderr, "[*] guardian pid=%d  child pid=%d\n",
            (int)getpid(), (int)child);
    fprintf(stderr, "[*] ptrace(PTRACE_ATTACH, %d) → EPERM until child exits\n",
            (int)child);

    guardian_loop(child);
}

static void cmd_self(void)
{

    char *argv[] = { "/bin/sh", NULL };
    fprintf(stderr, "[*] spawning guarded shell - ptrace attachment blocked\n");
    cmd_wrap(argv);
}

static void cmd_status(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return; }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = atoi(line + 10);
            printf("TracerPid: %d", tracer);
            if (tracer == 0)
                printf("  [!] NOT traced - PTRACE_ATTACH possible");
            else
                printf("  [+] traced by pid %d - PTRACE_ATTACH blocked", tracer);
            printf("\n");
        }
        if (strncmp(line, "State:", 6) == 0 ||
            strncmp(line, "Name:", 5) == 0)
            printf("%s", line);
    }
    fclose(f);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <wrap|shell|status>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "wrap") == 0 && argc >= 3) {
        cmd_wrap(argv + 2);
    } else if (strcmp(argv[1], "shell") == 0) {
        cmd_self();
    } else if (strcmp(argv[1], "status") == 0 && argc >= 3) {
        cmd_status((pid_t)atoi(argv[2]));
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
