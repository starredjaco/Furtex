#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define SNAP_MAGIC 0x424F4653U
#define MAX_KEY_SZ 256
#define MAX_VAL_SZ 4096

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{ return (int)syscall(__NR_bpf, cmd, a, sz); }

static int prog_fd_by_id(uint32_t id)
{ union bpf_attr a={}; a.prog_id=id;
  return bpf_call(BPF_PROG_GET_FD_BY_ID,&a,BPF_ATTR_SZ(prog_id)); }

static int map_fd_by_id(uint32_t id)
{ union bpf_attr a={}; a.map_id=id;
  return bpf_call(BPF_MAP_GET_FD_BY_ID,&a,BPF_ATTR_SZ(map_id)); }

static int map_get_info(int fd, struct bpf_map_info *info)
{
    union bpf_attr a={};
    a.info.bpf_fd=(uint32_t)fd; a.info.info_len=sizeof(*info);
    a.info.info=(uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD,&a,BPF_ATTR_SZ(info));
}

static int prog_get_map_ids(uint32_t prog_id, uint32_t *ids, uint32_t maxids, uint32_t *n_out)
{
    int fd = prog_fd_by_id(prog_id);
    if (fd < 0) return -1;

    struct bpf_prog_info info = {};
    info.nr_map_ids = maxids;
    info.map_ids    = (uint64_t)(uintptr_t)ids;
    union bpf_attr ia={};
    ia.info.bpf_fd=(uint32_t)fd; ia.info.info_len=sizeof(info);
    ia.info.info=(uint64_t)(uintptr_t)&info;
    int r = bpf_call(BPF_OBJ_GET_INFO_BY_FD,&ia,BPF_ATTR_SZ(info));
    close(fd);
    if (r < 0) return -1;
    *n_out = info.nr_map_ids;
    return 0;
}

static uint32_t snapshot_one_map(int map_fd, const struct bpf_map_info *info, FILE *out)
{
    if (info->key_size > MAX_KEY_SZ || info->value_size > MAX_VAL_SZ) return 0;

    uint8_t *key  = calloc(1, info->key_size);
    uint8_t *nkey = calloc(1, info->key_size);
    uint8_t *val  = calloc(1, info->value_size);
    uint32_t count = 0;
    uint8_t *cur = NULL;

    for (;;) {
        union bpf_attr na={};
        na.map_fd=(uint32_t)map_fd; na.key=(uint64_t)(uintptr_t)cur;
        na.next_key=(uint64_t)(uintptr_t)nkey;
        if (bpf_call(BPF_MAP_GET_NEXT_KEY,&na,BPF_ATTR_SZ(next_key)) < 0) break;
        memcpy(key, nkey, info->key_size);
        cur = key;

        union bpf_attr la={};
        la.map_fd=(uint32_t)map_fd; la.key=(uint64_t)(uintptr_t)key;
        la.value=(uint64_t)(uintptr_t)val;
        if (bpf_call(BPF_MAP_LOOKUP_ELEM,&la,BPF_ATTR_SZ(value)) < 0) continue;

        fwrite(key, info->key_size, 1, out);
        fwrite(val, info->value_size, 1, out);
        count++;
    }

    free(key); free(nkey); free(val);
    return count;
}

static void cmd_save(uint32_t prog_id, const char *outpath)
{
    uint32_t map_ids[64] = {}, n_maps = 0;
    if (prog_get_map_ids(prog_id, map_ids, 64, &n_maps) < 0) {
        perror("prog map ids"); return;
    }
    printf("[*] prog id=%u has %u maps\n", prog_id, n_maps);

    FILE *f = fopen(outpath, "wb");
    if (!f) { perror("fopen"); return; }

    uint32_t magic = SNAP_MAGIC;
    fwrite(&magic, 4, 1, f);
    fwrite(&n_maps, 4, 1, f);

    for (uint32_t i = 0; i < n_maps; i++) {
        int fd = map_fd_by_id(map_ids[i]);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        if (map_get_info(fd, &info) < 0) { close(fd); continue; }
        if (info.key_size > MAX_KEY_SZ || info.value_size > MAX_VAL_SZ) {
            close(fd); continue;
        }

        fwrite(&info.id,          4, 1, f);
        fwrite(&info.type,        4, 1, f);
        fwrite(&info.key_size,    4, 1, f);
        fwrite(&info.value_size,  4, 1, f);

        long count_pos = ftell(f);
        uint32_t zero = 0;
        fwrite(&zero, 4, 1, f);

        uint32_t count = snapshot_one_map(fd, &info, f);

        long cur_pos = ftell(f);
        fseek(f, count_pos, SEEK_SET);
        fwrite(&count, 4, 1, f);
        fseek(f, cur_pos, SEEK_SET);

        printf("[*]   map id=%-5u name='%-16s' type=%-12u entries=%u\n",
               info.id, info.name, info.type, count);
        close(fd);
    }

    fclose(f);
    printf("[*] snapshot saved to %s\n", outpath);
}

static void cmd_restore(const char *inpath)
{
    FILE *f = fopen(inpath, "rb");
    if (!f) { perror("fopen"); return; }

    uint32_t magic = 0, n_maps = 0;
    fread(&magic, 4, 1, f);
    if (magic != SNAP_MAGIC) { fprintf(stderr, "bad magic\n"); fclose(f); return; }
    fread(&n_maps, 4, 1, f);

    uint8_t *key = malloc(MAX_KEY_SZ);
    uint8_t *val = malloc(MAX_VAL_SZ);

    for (uint32_t m = 0; m < n_maps; m++) {
        uint32_t map_id, map_type, key_sz, val_sz, n_entries;
        fread(&map_id,    4, 1, f);
        fread(&map_type,  4, 1, f);
        fread(&key_sz,    4, 1, f);
        fread(&val_sz,    4, 1, f);
        fread(&n_entries, 4, 1, f);

        if (key_sz > MAX_KEY_SZ || val_sz > MAX_VAL_SZ) {

            fseek(f, (long)(n_entries * (key_sz + val_sz)), SEEK_CUR);
            continue;
        }

        int fd = map_fd_by_id(map_id);
        if (fd < 0) {
            fprintf(stderr, "[-] map id=%u not found, skipping\n", map_id);
            fseek(f, (long)(n_entries * (key_sz + val_sz)), SEEK_CUR);
            continue;
        }

        uint32_t restored = 0;
        for (uint32_t e = 0; e < n_entries; e++) {
            fread(key, key_sz, 1, f);
            fread(val, val_sz, 1, f);
            union bpf_attr a={};
            a.map_fd=(uint32_t)fd; a.key=(uint64_t)(uintptr_t)key;
            a.value=(uint64_t)(uintptr_t)val; a.flags=BPF_ANY;
            if (bpf_call(BPF_MAP_UPDATE_ELEM,&a,BPF_ATTR_SZ(flags)) == 0) restored++;
        }
        printf("[*] map id=%u restored %u/%u entries\n", map_id, restored, n_entries);
        close(fd);
    }

    free(key); free(val);
    fclose(f);
    printf("[*] restore complete\n");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
            "usage:\n"
            "  %s save    <prog_id> <snapshot.bin>\n"
            "  %s restore <snapshot.bin>\n",
            argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "save") == 0 && argc >= 4)
        cmd_save((uint32_t)atoi(argv[2]), argv[3]);
    else if (strcmp(argv[1], "restore") == 0)
        cmd_restore(argv[2]);
    else
        fprintf(stderr, "unknown command\n");

    return 0;
}
