#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#define PAGE 4096

static void dump_maps_region(void *addr)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    uintptr_t target = (uintptr_t)addr;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2)
            if (target >= start && target < end) { printf("  %s", line); break; }
    }
    fclose(f);
}

static void demo_shellcode_hide(void)
{
    unsigned char nop_sled[] = {
        0x90, 0x90, 0x90, 0x90,
        0xb8, 0x01, 0x00, 0x00, 0x00,
        0xbf, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x8d, 0x35, 0x05, 0x00, 0x00, 0x00,
        0xba, 0x05, 0x00, 0x00, 0x00,
        0x0f, 0x05,
        0xc3,
        'h', 'i', '\n', '\0', '\0'
    };

    void *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return; }

    memcpy(page, nop_sled, sizeof(nop_sled));

    printf("[*] after mmap (rwx):\n");
    dump_maps_region(page);

    madvise(page, PAGE, MADV_DONTDUMP);

    printf("[+] mprotect PROT_NONE (hidden from memory scanners):\n");
    mprotect(page, PAGE, PROT_NONE);
    dump_maps_region(page);

    printf("[*] executing (mprotect RX briefly)...\n");
    mprotect(page, PAGE, PROT_READ | PROT_EXEC);
    void (*fn)(void) = (void (*)(void))page;
    fn();

    mprotect(page, PAGE, PROT_NONE);
    printf("[+] hidden again:\n");
    dump_maps_region(page);

    munmap(page, PAGE);
}

static void demo_dontdump(void)
{
    void *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return; }

    memset(page, 0xcc, PAGE);

    madvise(page, PAGE, MADV_DONTDUMP);
    printf("[+] MADV_DONTDUMP set on %p - excluded from core dump\n", page);

    printf("[*] maps entry:\n");
    dump_maps_region(page);

    madvise(page, PAGE, MADV_DODUMP);
    printf("[+] MADV_DODUMP restored\n");
    munmap(page, PAGE);
}

static void demo_name_vma(const char *name)
{
    void *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return; }

    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, page, PAGE, name);
    printf("[*] VMA named '%s':\n", name);
    dump_maps_region(page);
    munmap(page, PAGE);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hide|dontdump|name>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "hide") == 0) demo_shellcode_hide();
    else if (strcmp(argv[1], "dontdump") == 0) demo_dontdump();
    else if (strcmp(argv[1], "name") == 0 && argc >= 3) demo_name_vma(argv[2]);
    else { fprintf(stderr, "unknown: %s\n", argv[1]); return 1; }

    return 0;
}
