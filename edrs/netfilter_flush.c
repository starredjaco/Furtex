#define _GNU_SOURCE
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int has_binary(const char *name)
{
    const char *paths[] = { "/sbin/", "/usr/sbin/", "/bin/", "/usr/bin/", NULL };
    char full[256];
    for (int i = 0; paths[i]; i++) {
        snprintf(full, sizeof(full), "%s%s", paths[i], name);
        if (access(full, X_OK) == 0) return 1;
    }
    return 0;
}

static int run(const char *cmd)
{
    printf("  $ %s\n", cmd);
    int r = system(cmd);
    return WEXITSTATUS(r);
}

static void flush_nft(void)
{
    printf("[*] flushing nftables ruleset\n");
    run("nft flush ruleset");
}

static void flush_iptables(void)
{
    const char *tables[] = { "filter", "nat", "mangle", "raw", "security", NULL };

    printf("[*] flushing iptables\n");
    for (int i = 0; tables[i]; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "iptables -t %s -F 2>/dev/null", tables[i]);
        run(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -t %s -X 2>/dev/null", tables[i]);
        run(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -t %s -Z 2>/dev/null", tables[i]);
        run(cmd);
    }
    run("iptables -P INPUT ACCEPT 2>/dev/null");
    run("iptables -P OUTPUT ACCEPT 2>/dev/null");
    run("iptables -P FORWARD ACCEPT 2>/dev/null");
}

static void flush_ip6tables(void)
{
    const char *tables[] = { "filter", "mangle", "raw", "security", NULL };
    printf("[*] flushing ip6tables\n");
    for (int i = 0; tables[i]; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ip6tables -t %s -F 2>/dev/null", tables[i]);
        run(cmd);
        snprintf(cmd, sizeof(cmd), "ip6tables -t %s -X 2>/dev/null", tables[i]);
        run(cmd);
    }
    run("ip6tables -P INPUT ACCEPT 2>/dev/null");
    run("ip6tables -P OUTPUT ACCEPT 2>/dev/null");
    run("ip6tables -P FORWARD ACCEPT 2>/dev/null");
}

static void flush_ipset(void)
{
    if (!has_binary("ipset")) return;
    printf("[*] flushing ipsets\n");
    run("ipset flush 2>/dev/null");
    run("ipset destroy 2>/dev/null");
}

static void dump_rules(void)
{
    if (has_binary("nft")) run("nft list ruleset 2>/dev/null");
    else if (has_binary("iptables")) {
        run("iptables -L -n -v 2>/dev/null");
        run("iptables -t nat -L -n -v 2>/dev/null");
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <list|flush>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        dump_rules();
        return 0;
    }

    if (strcmp(argv[1], "flush") == 0) {
        if (has_binary("nft")) {
            flush_nft();
        } else {
            flush_iptables();
            flush_ip6tables();
        }
        flush_ipset();
        printf("[+] done - all netfilter rules flushed, policies ACCEPT\n");
        return 0;
    }

    fprintf(stderr, "unknown: %s\n", argv[1]);
    return 1;
}
