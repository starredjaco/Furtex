#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define PRELOAD_FILE "/etc/ld.so.preload"

static void cmd_show(void)
{
    FILE *f = fopen(PRELOAD_FILE, "r");
    if (!f) { fprintf(stderr, "[!] %s: %s\n", PRELOAD_FILE, strerror(errno)); return; }

    printf("[*] %s contents:\n", PRELOAD_FILE);
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        printf("  %s", line);
        n++;
    }
    if (!n) printf("  (empty)\n");
    fclose(f);
}

static void cmd_install(const char *so_path)
{
    struct stat st;
    if (stat(so_path, &st) < 0) {
        fprintf(stderr, "[!] cannot stat '%s': %s\n", so_path, strerror(errno));
        fprintf(stderr, "    continuing anyway (file may not exist yet)\n");
    }

    FILE *f = fopen(PRELOAD_FILE, "a");
    if (!f) { perror(PRELOAD_FILE); return; }
    fprintf(f, "%s\n", so_path);
    fclose(f);

    printf("[+] installed '%s' in %s\n", so_path, PRELOAD_FILE);
    printf("[*] all subsequent execve() calls will preload this .so\n");
    printf("[*] verify: cat %s\n", PRELOAD_FILE);
}

static void cmd_remove(const char *so_path)
{
    FILE *r = fopen(PRELOAD_FILE, "r");
    if (!r) { perror(PRELOAD_FILE); return; }

    char tmp_path[] = "/tmp/.ld_preload_XXXXXX";
    int tfd = mkstemp(tmp_path);
    if (tfd < 0) { perror("mkstemp"); fclose(r); return; }

    FILE *w = fdopen(tfd, "w");
    char line[512];
    int removed = 0;
    while (fgets(line, sizeof(line), r)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, so_path) == 0) { removed++; continue; }
        fprintf(w, "%s\n", line);
    }
    fclose(r);
    fclose(w);

    if (rename(tmp_path, PRELOAD_FILE) < 0) {
        perror("rename"); unlink(tmp_path); return;
    }
    chmod(PRELOAD_FILE, 0644);

    if (removed) printf("[+] removed '%s' from %s\n", so_path, PRELOAD_FILE);
    else printf("[!] '%s' not found in %s\n", so_path, PRELOAD_FILE);
}

static void cmd_clear(void)
{
    int fd = open(PRELOAD_FILE, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0) { perror(PRELOAD_FILE); return; }
    close(fd);
    printf("[+] %s cleared\n", PRELOAD_FILE);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <show|install|remove|clear>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "show") == 0) cmd_show();
    else if (strcmp(argv[1], "install") == 0 && argc >= 3) cmd_install(argv[2]);
    else if (strcmp(argv[1], "remove") == 0 && argc >= 3) cmd_remove(argv[2]);
    else if (strcmp(argv[1], "clear") == 0) cmd_clear();
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
