#define _GNU_SOURCE
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define BPF_ATTR_SZ(f) \
    (offsetof(union bpf_attr, f) + sizeof(((union bpf_attr *)0)->f))

static int bpf_call(int cmd, union bpf_attr *a, unsigned sz)
{ return (int)syscall(__NR_bpf, cmd, a, sz); }

static int map_fd_by_id(uint32_t id)
{ union bpf_attr a = {}; a.map_id = id;
  return bpf_call(BPF_MAP_GET_FD_BY_ID, &a, BPF_ATTR_SZ(map_id)); }

static int prog_fd_by_id(uint32_t id)
{ union bpf_attr a = {}; a.prog_id = id;
  return bpf_call(BPF_PROG_GET_FD_BY_ID, &a, BPF_ATTR_SZ(prog_id)); }

static int bpf_obj_pin(int fd, const char *path)
{
    union bpf_attr a = {};
    a.pathname = (uint64_t)(uintptr_t)path;
    a.bpf_fd   = (uint32_t)fd;
    return bpf_call(BPF_OBJ_PIN, &a, BPF_ATTR_SZ(bpf_fd));
}

static int bpf_obj_get(const char *path)
{
    union bpf_attr a = {};
    a.pathname = (uint64_t)(uintptr_t)path;
    return bpf_call(BPF_OBJ_GET, &a, BPF_ATTR_SZ(pathname));
}

static void cmd_pin_map(uint32_t id, const char *path)
{
    int fd = map_fd_by_id(id);
    if (fd < 0) { perror("map_fd"); return; }

    struct bpf_map_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info));

    if (bpf_obj_pin(fd, path) < 0) {
        perror("pin");
    } else {
        printf("[*] pinned map id=%u name='%s' -> %s\n", id, info.name, path);
    }
    close(fd);
}

static void cmd_pin_prog(uint32_t id, const char *path)
{
    int fd = prog_fd_by_id(id);
    if (fd < 0) { perror("prog_fd"); return; }

    struct bpf_prog_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;
    bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info));

    if (bpf_obj_pin(fd, path) < 0) {
        perror("pin");
    } else {
        printf("[*] pinned prog id=%u name='%s' -> %s\n", id, info.name, path);
    }
    close(fd);
}

static void cmd_get_map(const char *path)
{
    int fd = bpf_obj_get(path);
    if (fd < 0) { perror("obj_get"); return; }

    struct bpf_map_info info = {};
    union bpf_attr ia = {};
    ia.info.bpf_fd   = (uint32_t)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info     = (uint64_t)(uintptr_t)&info;

    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0) {
        printf("[*] got map from %s: id=%u name='%s' type=%u key=%uB val=%uB max=%u\n",
               path, info.id, info.name, info.type,
               info.key_size, info.value_size, info.max_entries);
    }
    close(fd);
}

static void cmd_unpin(const char *path)
{
    if (unlink(path) < 0)
        perror("unlink");
    else
        printf("[*] unpinned %s\n", path);
}

static void list_bpffs(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) { perror(dir); return; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(path, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            list_bpffs(path);
            continue;
        }

        int fd = bpf_obj_get(path);
        if (fd < 0) continue;

        struct bpf_map_info minfo = {};
        union bpf_attr ia = {};
        ia.info.bpf_fd = (uint32_t)fd; ia.info.info_len = sizeof(minfo);
        ia.info.info   = (uint64_t)(uintptr_t)&minfo;
        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0 && minfo.id > 0) {
            printf("  MAP  %s  id=%-5u name='%s'\n", path, minfo.id, minfo.name);
            close(fd); continue;
        }

        struct bpf_prog_info pinfo = {};
        ia.info.info_len = sizeof(pinfo); ia.info.info = (uint64_t)(uintptr_t)&pinfo;
        if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &ia, BPF_ATTR_SZ(info)) == 0 && pinfo.id > 0) {
            printf("  PROG %s  id=%-5u name='%s'\n", path, pinfo.id, pinfo.name);
        }
        close(fd);
    }
    closedir(d);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s pin-map  <map_id>  <bpffs_path>\n"
            "  %s pin-prog <prog_id> <bpffs_path>\n"
            "  %s get-map  <bpffs_path>\n"
            "  %s unpin    <bpffs_path>\n"
            "  %s list     [dir=/sys/fs/bpf]\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "pin-map") == 0 && argc >= 4) {
        cmd_pin_map((uint32_t)atoi(argv[2]), argv[3]);
    } else if (strcmp(argv[1], "pin-prog") == 0 && argc >= 4) {
        cmd_pin_prog((uint32_t)atoi(argv[2]), argv[3]);
    } else if (strcmp(argv[1], "get-map") == 0 && argc >= 3) {
        cmd_get_map(argv[2]);
    } else if (strcmp(argv[1], "unpin") == 0 && argc >= 3) {
        cmd_unpin(argv[2]);
    } else if (strcmp(argv[1], "list") == 0) {
        const char *dir = (argc >= 3) ? argv[2] : "/sys/fs/bpf";
        printf("[*] pinned BPF objects in %s:\n", dir);
        list_bpffs(dir);
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
