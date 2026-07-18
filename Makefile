CC     = gcc
CFLAGS = -O2 -Wall -Wextra -I io_uring

URING_BINS = \
    io_uring/file_read \
    io_uring/file_write \
    io_uring/file_append \
    io_uring/net_connect \
    io_uring/net_reverse_shell \
    io_uring/multifile_read \
    io_uring/memfd_exec \
    io_uring/proc_inject \
    io_uring/pipe_splice \
    io_uring/inotify_bypass_watch \
    io_uring/dns_exfil \
    io_uring/af_packet_send \
    io_uring/xdp_socket_send

BPF_BINS = \
    bpf/map_recon \
    bpf/map_dumper \
    bpf/map_write \
    bpf/map_poison \
    bpf/prog_recon \
    bpf/pid_allowlist \
    bpf/edr_fin \
    bpf/lsm_check \
    bpf/bpf_persist \
    bpf/map_snapshot \
    bpf/env_exfil \
    bpf/bpf_link_detach \
    bpf/link_update \
    bpf/map_freeze \
    bpf/icmp_trigger

EBPF_RUNNERS = \
    ebpf/xdp_handler \
    ebpf/skf_c2_runner

FALCO_BINS = \
    techniques/uring_ops \
    techniques/ringbuf_overflow \
    techniques/rule_evade \
    techniques/kmod_unload \
    techniques/proc_ghost \
    techniques/exe_from_memfd_bypass \
    techniques/event_storm \
    techniques/proc_masquerade \
    techniques/cgroup_escape \
    techniques/ns_pivot \
    techniques/per_rule_bypass \
    techniques/bypass_file_rules \
    techniques/bypass_proc_rules

ALL_BINS = $(URING_BINS) $(BPF_BINS) $(EBPF_RUNNERS)

.PHONY: all uring bpf ebpf runners edrs techniques clean

all: $(ALL_BINS)
	$(MAKE) -C edrs all
	$(MAKE) techniques

uring:    $(URING_BINS)
bpf:      $(BPF_BINS)
runners:  $(EBPF_RUNNERS)

# io_uring targets (depend on iouring_utils.h)
$(URING_BINS): %: %.c io_uring/iouring_utils.h
	$(CC) $(CFLAGS) -o $@ $<

# BPF userspace tools
$(BPF_BINS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

# eBPF userspace runners (no iouring_utils dependency)
$(EBPF_RUNNERS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

# eBPF BPF-side programs (requires clang + libbpf headers + vmlinux.h)
ebpf:
	$(MAKE) -C ebpf

edrs:
	$(MAKE) -C edrs all

techniques: $(FALCO_BINS)

$(FALCO_BINS): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread -ldl

clean:
	rm -f $(ALL_BINS) $(FALCO_BINS)
	$(MAKE) -C edrs clean
	$(MAKE) -C ebpf clean

