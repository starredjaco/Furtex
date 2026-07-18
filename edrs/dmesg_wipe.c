#define _GNU_SOURCE
#include <sys/klog.h>
#include <sys/syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define SYSLOG_ACTION_READ_ALL   3
#define SYSLOG_ACTION_CLEAR      5
#define SYSLOG_ACTION_SIZE_BUFFER 10

static void cmd_show(void)
{
    int sz = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
    if (sz <= 0) { perror("klogctl SIZE"); return; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) return;

    int n = klogctl(SYSLOG_ACTION_READ_ALL, buf, sz);
    if (n < 0) { perror("klogctl READ_ALL"); free(buf); return; }
    buf[n] = '\0';
    fwrite(buf, 1, (size_t)n, stdout);
    free(buf);
}

static void cmd_wipe(void)
{
    if (klogctl(SYSLOG_ACTION_CLEAR, NULL, 0) < 0) {
        perror("klogctl CLEAR"); return;
    }
    printf("[+] kernel ring buffer cleared\n");
    printf("[*] /dev/kmsg and dmesg now empty until next kernel message\n");
}

static void cmd_grep(const char *needle)
{
    int sz = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
    if (sz <= 0) { perror("klogctl SIZE"); return; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) return;

    int n = klogctl(SYSLOG_ACTION_READ_ALL, buf, sz);
    if (n < 0) { perror("klogctl READ_ALL"); free(buf); return; }
    buf[n] = '\0';

    char *line = buf;
    while (line < buf + n) {
        char *nl = strchr(line, '\n');
        if (!nl) break;
        *nl = '\0';
        if (strstr(line, needle)) printf("%s\n", line);
        line = nl + 1;
    }
    free(buf);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <wipe|show|grep>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "wipe") == 0) cmd_wipe();
    else if (strcmp(argv[1], "show") == 0) cmd_show();
    else if (strcmp(argv[1], "grep") == 0 && argc >= 3) cmd_grep(argv[2]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
