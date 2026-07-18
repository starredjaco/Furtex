#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define SHM_SIZE   256
#define CMD_OFF    4
#define CMD_MAX    124
#define OUT_OFF    128
#define OUT_MAX    128
#define FLAG_CMD   0x01
#define FLAG_OUT   0x02

static volatile int running = 1;
static void on_sig(int s) { (void)s; running = 0; }

static void msleep(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int run_cmd(const char *cmd, char *out, size_t out_max)
{
    FILE *p = popen(cmd, "r");
    if (!p) { snprintf(out, out_max, "popen error"); return -1; }
    size_t n = fread(out, 1, out_max - 1, p);
    out[n] = '\0';
    pclose(p);
    return (int)n;
}

static void *shm_open_map(const char *name, int create)
{
    int flags = create ? (O_CREAT | O_RDWR) : O_RDWR;
    int fd = shm_open(name, flags, 0600);
    if (fd < 0) { perror("shm_open"); return NULL; }

    if (create && ftruncate(fd, SHM_SIZE) < 0) {
        perror("ftruncate"); close(fd); return NULL;
    }

    void *m = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { perror("mmap"); return NULL; }
    return m;
}

static void run_agent(const char *shm_name)
{
    printf("[agent] shm /%s\n", shm_name);
    uint8_t *mem = shm_open_map(shm_name, 1);
    if (!mem) return;
    memset(mem, 0, SHM_SIZE);
    printf("[agent] waiting for commands\n");

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    while (running) {
        if (mem[0] & FLAG_CMD) {
            uint8_t cmd_len = mem[1];
            char cmd[CMD_MAX + 1] = {};
            memcpy(cmd, mem + CMD_OFF, cmd_len < CMD_MAX ? cmd_len : CMD_MAX);
            cmd[cmd_len < CMD_MAX ? cmd_len : CMD_MAX] = '\0';

            printf("[agent] cmd: %s\n", cmd);
            char out[OUT_MAX + 1] = {};
            int n = run_cmd(cmd, out, OUT_MAX);
            if (n < 0) n = 0;

            mem[2] = (uint8_t)(n & 0xff);
            mem[3] = (uint8_t)((n >> 8) & 0xff);
            memcpy(mem + OUT_OFF, out, (size_t)n);

            mem[1] = (uint8_t)n;
            __sync_synchronize();
            mem[0] = (mem[0] & ~FLAG_CMD) | FLAG_OUT;
        }
        msleep(100);
    }

    shm_unlink(shm_name);
    munmap(mem, SHM_SIZE);
    printf("[agent] exiting\n");
}

static void run_ctrl(const char *shm_name, const char *single_cmd)
{
    printf("[ctrl] shm /%s\n", shm_name);
    uint8_t *mem = shm_open_map(shm_name, 0);
    if (!mem) {
        fprintf(stderr, "[-] shm not found - agent running?\n");
        return;
    }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    char line[CMD_MAX];
    while (running) {

        if (single_cmd) {
            strncpy(line, single_cmd, CMD_MAX - 1);
            line[CMD_MAX - 1] = '\0';
        } else {
            printf("\033[32m[shm]>\033[0m "); fflush(stdout);
            if (!fgets(line, sizeof(line), stdin)) break;
            line[strcspn(line, "\n")] = '\0';
            if (!line[0]) continue;
            if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) break;
        }

        uint8_t cmd_len = (uint8_t)strlen(line);
        memcpy(mem + CMD_OFF, line, cmd_len);
        mem[1] = cmd_len;
        mem[0] = (mem[0] & ~FLAG_OUT) | FLAG_CMD;
        __sync_synchronize();

        int waited = 0;
        while ((mem[0] & FLAG_OUT) == 0 && running) {
            msleep(50); waited++;
            if (waited > 100) { printf("[-] timeout waiting for agent\n"); break; }
        }

        if (mem[0] & FLAG_OUT) {
            uint16_t out_len = (uint16_t)(mem[2] | (mem[3] << 8));
            if (out_len > OUT_MAX) out_len = OUT_MAX;
            char out[OUT_MAX + 1] = {};
            memcpy(out, mem + OUT_OFF, out_len);
            out[out_len] = '\0';
            printf("%s", out);
            if (out_len && out[out_len - 1] != '\n') printf("\n");
            mem[0] &= ~FLAG_OUT;
        }

        if (single_cmd) break;
    }

    munmap(mem, SHM_SIZE);
}

int main(int argc, char *argv[])
{
    const char *shm_name  = "svc.0";
    const char *mode      = NULL;
    const char *single_cmd = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--agent") == 0) mode = "agent";
        else if (strcmp(argv[i], "--ctrl")  == 0) mode = "ctrl";
        else if (strcmp(argv[i], "--name") == 0 && i+1 < argc)
            shm_name = argv[++i];
        else if (strcmp(argv[i], "--cmd")  == 0 && i+1 < argc)
            single_cmd = argv[++i];
    }

    if (!mode) {
        fprintf(stderr, "usage: %s [args]\n", argv[0]);
        return 1;
    }

    if (strcmp(mode, "agent") == 0) run_agent(shm_name);
    else                             run_ctrl(shm_name, single_cmd);
    return 0;
}
