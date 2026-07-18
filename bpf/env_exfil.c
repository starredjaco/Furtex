#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

static void dump_environ(pid_t pid, const char *filter)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    char *p = buf;
    char *end = buf + n;
    int matched = 0;

    while (p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 0) { p++; continue; }

        if (!filter || strstr(p, filter)) {
            if (!matched) {
                printf("[pid=%d] interesting env:\n", pid);
                matched = 1;
            }

            int is_secret = 0;
            const char *secrets[] = {
                "PASSWORD", "SECRET", "TOKEN", "API_KEY", "AWS_",
                "GITHUB_", "DATABASE_URL", "REDIS_URL", "PRIVATE_KEY",
                "OPENAI_", "ANTHROPIC_", "STRIPE_", "TWILIO_", NULL
            };
            for (int i = 0; secrets[i]; i++) {
                if (strstr(p, secrets[i])) { is_secret = 1; break; }
            }

            if (is_secret)
                printf("  [SECRET] %s\n", p);
            else
                printf("  %s\n", p);
        }
        p += len + 1;
    }
}

static void scan_all(const char *filter)
{
    DIR *d = opendir("/proc");
    if (!d) { perror("opendir /proc"); return; }

    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_type != DT_DIR) continue;
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 0) continue;
        dump_environ(pid, filter);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    const char *filter = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc)
            filter = argv[++i];
    }

    printf("[*] scanning /proc/*/environ for secrets");
    if (filter) printf(" (filter: %s)", filter);
    printf("\n");

    scan_all(filter);

    printf("[*] done\n");
    return 0;
}
