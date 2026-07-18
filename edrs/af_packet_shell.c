#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#define SRC_PORT 49152
#define PKT_MAX  65536
#define CMD_MAX  4096
#define PROMPT   "$ "

static uint16_t cksum(const void *data, size_t len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t udp_cksum(uint32_t saddr, uint32_t daddr,
                           const struct udphdr *udp, size_t udplen)
{
    struct { uint32_t s, d; uint8_t z, proto; uint16_t len; } ph = {
        saddr, daddr, 0, IPPROTO_UDP, htons((uint16_t)udplen)
    };
    size_t total = sizeof(ph) + udplen;
    uint8_t *buf = calloc(1, total);
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udp, udplen);
    uint16_t r = cksum(buf, total);
    free(buf);
    return r;
}

static int get_iface(int sock, const char *iface, int *ifindex,
                     uint8_t *mac, uint32_t *src_ip)
{
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { perror("SIOCGIFADDR"); return -1; }
    *src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    return 0;
}

static int resolve_mac(const char *ip, uint8_t *mac_out)
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;

    char line[256];
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char entry_ip[32], hw[32];
        unsigned int flags;
        if (sscanf(line, "%31s %*s %x %31s", entry_ip, &flags, hw) != 3) continue;
        if (strcmp(entry_ip, ip) != 0 || !(flags & 0x2)) continue;

        unsigned int b[6];
        if (sscanf(hw, "%x:%x:%x:%x:%x:%x",
                   &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6) {
            for (int i = 0; i < 6; i++) mac_out[i] = (uint8_t)b[i];
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static void build_pkt(uint8_t *pkt, size_t *pkt_len,
                      const uint8_t *src_mac, const uint8_t *dst_mac,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t dst_port,
                      const void *payload, size_t plen)
{
    struct ethhdr *eth = (struct ethhdr *)pkt;
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest,   dst_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(*eth));
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons((uint16_t)(sizeof(*ip) + sizeof(struct udphdr) + plen));
    ip->id       = htons((uint16_t)(getpid() & 0xffff));
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = cksum(ip, sizeof(*ip));

    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(*eth) + sizeof(*ip));
    udp->source  = htons(SRC_PORT);
    udp->dest    = dst_port;
    udp->len     = htons((uint16_t)(sizeof(*udp) + plen));
    udp->check   = 0;
    memcpy(pkt + sizeof(*eth) + sizeof(*ip) + sizeof(*udp), payload, plen);
    udp->check   = udp_cksum(src_ip, dst_ip, udp, sizeof(*udp) + plen);

    *pkt_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + plen;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <listen|shell>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "listen") == 0 && argc >= 3) {
        int port = atoi(argv[2]);
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) { perror("socket"); return 1; }

        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons((uint16_t)port),
        };
        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind"); return 1;
        }
        printf("[*] listening UDP on port %d\n", port);

        char buf[CMD_MAX];
        for (;;) {
            printf(PROMPT); fflush(stdout);
            if (!fgets(buf, sizeof(buf), stdin)) break;
            buf[strcspn(buf, "\n")] = '\0';
            if (strcmp(buf, "exit") == 0) break;
        }
        close(sock);
        return 0;
    }

    if (strcmp(argv[1], "shell") == 0 && argc >= 4) {
        const char *dst_ip_str = argv[2];
        int         dst_port   = atoi(argv[3]);
        const char *iface      = argc >= 5 ? argv[4] : "eth0";

        int raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (raw < 0) { perror("AF_PACKET socket"); return 1; }

        int ifindex = 0;
        uint8_t  src_mac[6] = {};
        uint32_t src_ip = 0;
        if (get_iface(raw, iface, &ifindex, src_mac, &src_ip) < 0) return 1;

        uint32_t dst_ip = 0;
        if (inet_pton(AF_INET, dst_ip_str, &dst_ip) != 1) {
            fprintf(stderr, "[!] bad IP: %s\n", dst_ip_str); return 1;
        }

        uint8_t dst_mac[6];
        if (resolve_mac(dst_ip_str, dst_mac) < 0) {
            fprintf(stderr,
                "[!] %s not in ARP cache - ping it first or use broadcast\n",
                dst_ip_str);
            memset(dst_mac, 0xff, 6);
            printf("[*] using broadcast MAC ff:ff:ff:ff:ff:ff\n");
        } else {
            printf("[*] resolved %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
                   dst_ip_str,
                   dst_mac[0],dst_mac[1],dst_mac[2],
                   dst_mac[3],dst_mac[4],dst_mac[5]);
        }

        int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (recv_sock < 0) { perror("recv socket"); return 1; }
        struct sockaddr_in bind_sa = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons(SRC_PORT),
        };
        bind(recv_sock, (struct sockaddr *)&bind_sa, sizeof(bind_sa));

        struct sockaddr_ll sll = {
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_IP),
            .sll_ifindex  = ifindex,
            .sll_halen    = 6,
        };
        memcpy(sll.sll_addr, dst_mac, 6);

        printf("[*] raw packet shell -> %s:%d via %s (bypasses netfilter OUTPUT)\n",
               dst_ip_str, dst_port, iface);
        printf("[*] responses received on UDP port %d\n", SRC_PORT);
        printf("[*] type commands, empty line exits\n\n");

        uint8_t pkt[PKT_MAX];
        char    cmd[CMD_MAX];
        char    out[PKT_MAX];

        send(recv_sock, PROMPT, strlen(PROMPT), 0);

        for (;;) {
            printf(PROMPT); fflush(stdout);
            if (!fgets(cmd, sizeof(cmd), stdin)) break;
            cmd[strcspn(cmd, "\n")] = '\0';
            if (strlen(cmd) == 0) break;

            char payload[CMD_MAX + 4];
            size_t plen = (size_t)snprintf(payload, sizeof(payload), "%s\n", cmd);

            size_t pkt_len = 0;
            build_pkt(pkt, &pkt_len,
                      src_mac, dst_mac,
                      src_ip, dst_ip,
                      htons((uint16_t)dst_port),
                      payload, plen);

            if (sendto(raw, pkt, pkt_len, 0,
                       (struct sockaddr *)&sll, sizeof(sll)) < 0) {
                perror("sendto"); break;
            }

            struct pollfd pfd = { .fd = recv_sock, .events = POLLIN };
            if (poll(&pfd, 1, 5000) <= 0) {
                printf("[timeout]\n"); continue;
            }

            ssize_t n = recv(recv_sock, out, sizeof(out) - 1, 0);
            if (n > 0) { out[n] = '\0'; printf("%s", out); }
        }

        close(raw);
        close(recv_sock);
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
