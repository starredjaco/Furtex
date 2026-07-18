CC     = gcc
CFLAGS = -O2 -Wall -Wextra -I..

BINS_PRIV = \
    edr_recon           \
    bpf_prog_recon      \
    bpf_map_wipe        \
    bpf_detach_all      \
    tetragon_blind      \
    ftrace_enum         \
    lkm_unload          \
    lkm_inline_detect   \
    perf_bpf_kill       \
    module_recon        \
    cgroup_freeze       \
    oom_cage            \
    sysctl_blind        \
    audit_kill          \
    inotify_exhaust     \
    netfilter_flush     \
    dmesg_wipe          \
    ld_so_preload       \
    proc_hide           \
    mount_over          \
    log_wipe            \
    elf_infect          \
    proc_mem_inject     \
    ptrace_inject_so    \
    af_packet_shell     \
    icmp_tunnel         \
    livepatch_bypass         \
    event_flood              \
    livepatch_stack_blind    \
    lsm_authlink_blind       \
    bpf_fim_blind            \
    syscall_dispatch_bypass  \
    lsm_callback_bypass      \
    bpf_kprobe_bypass

BINS_UNPRIV = \
    uring_stealth       \
    openat2_bypass      \
    ptrace_selfguard    \
    plt_unhook          \
    fexecve_drop        \
    memfd_loader        \
    memfd_userexec      \
    hollow_proc         \
    argv_spoof          \
    clone_netns         \
    ns_exec             \
    splice_c2           \
    abstract_sock_c2    \
    udp_shell           \
    tls_shell           \
    dns_exfil_raw       \
    pidfd_steal         \
    vma_hide            \
    coredump_block      \
    seccomp_notify      \
    ipc_covert          \
    shared_mem_c2       \
    pipe_exfil          \
    proc_fd_scan        \
    proc_vm_inject      \
    self_delete         \
    time_stomp          \
    userland_persist    \
    env_scrape          \
    anon_shellcode      \
    ld_preload_inject   \
    ssh_agent_hijack    \
    fanotify_bypass     \
    ringbuf_flood       \
    log_evasion         \
    syscalltable_bypass \
    uring_recon_unpriv  \
    fd_steal_read       \
    mmap_read           \
    scm_rights_exfil    \
    splice_read

.PHONY: all priv unpriv clean

all:    $(BINS_PRIV) $(BINS_UNPRIV)
priv:   $(BINS_PRIV)
unpriv: $(BINS_UNPRIV)

edr_recon: edr_recon.c
	$(CC) $(CFLAGS) -o $@ $<

bpf_prog_recon: bpf_prog_recon.c
	$(CC) $(CFLAGS) -o $@ $<

bpf_map_wipe: bpf_map_wipe.c
	$(CC) $(CFLAGS) -o $@ $<

bpf_detach_all: bpf_detach_all.c
	$(CC) $(CFLAGS) -o $@ $<

tetragon_blind: tetragon_blind.c
	$(CC) $(CFLAGS) -o $@ $<

ftrace_enum: ftrace_enum.c
	$(CC) $(CFLAGS) -o $@ $<

lkm_unload: kmod_unload.c
	$(CC) $(CFLAGS) -o $@ $<

lkm_inline_detect: lkm_inline_detect.c
	$(CC) $(CFLAGS) -o $@ $<

perf_bpf_kill: perf_bpf_kill.c
	$(CC) $(CFLAGS) -o $@ $<

module_recon: module_recon.c
	$(CC) $(CFLAGS) -o $@ $<

cgroup_freeze: cgroup_freeze.c
	$(CC) $(CFLAGS) -o $@ $<

oom_cage: oom_cage.c
	$(CC) $(CFLAGS) -o $@ $<

sysctl_blind: sysctl_blind.c
	$(CC) $(CFLAGS) -o $@ $<

audit_kill: audit_kill.c
	$(CC) $(CFLAGS) -o $@ $<

inotify_exhaust: inotify_exhaust.c
	$(CC) $(CFLAGS) -o $@ $<

dmesg_wipe: dmesg_wipe.c
	$(CC) $(CFLAGS) -o $@ $<

log_wipe: log_wipe.c
	$(CC) $(CFLAGS) -o $@ $<

netfilter_flush: netfilter_flush.c
	$(CC) $(CFLAGS) -o $@ $<

af_packet_shell: af_packet_shell.c
	$(CC) $(CFLAGS) -o $@ $<

icmp_tunnel: icmp_tunnel.c
	$(CC) $(CFLAGS) -o $@ $<

ld_so_preload: ld_so_preload.c
	$(CC) $(CFLAGS) -o $@ $<

proc_hide: proc_hide.c
	$(CC) $(CFLAGS) -o $@ $<

mount_over: mount_over.c
	$(CC) $(CFLAGS) -o $@ $<

elf_infect: elf_infect.c
	$(CC) $(CFLAGS) -o $@ $<

proc_mem_inject: proc_mem_inject.c
	$(CC) $(CFLAGS) -o $@ $<

ptrace_inject_so: ptrace_inject_so.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

livepatch_bypass: livepatch_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

event_flood: event_flood.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

livepatch_stack_blind: livepatch_stack_blind.c
	$(CC) $(CFLAGS) -o $@ $<

lsm_authlink_blind: lsm_authlink_blind.c
	$(CC) $(CFLAGS) -o $@ $<

bpf_fim_blind: bpf_fim_blind.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

syscall_dispatch_bypass: syscall_dispatch_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

lsm_callback_bypass: lsm_callback_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

bpf_kprobe_bypass: bpf_kprobe_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

uring_stealth: uring_stealth.c
	$(CC) $(CFLAGS) -o $@ $<

openat2_bypass: openat2_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

uring_recon_unpriv: uring_recon_unpriv.c
	$(CC) $(CFLAGS) -o $@ $<

syscalltable_bypass: syscalltable_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

plt_unhook: plt_unhook.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

ld_preload_inject: ld_preload_inject.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

fanotify_bypass: fanotify_bypass.c
	$(CC) $(CFLAGS) -o $@ $<

pidfd_steal: pidfd_steal.c
	$(CC) $(CFLAGS) -o $@ $<

ptrace_selfguard: ptrace_selfguard.c
	$(CC) $(CFLAGS) -o $@ $<

argv_spoof: argv_spoof.c
	$(CC) $(CFLAGS) -o $@ $<

coredump_block: coredump_block.c
	$(CC) $(CFLAGS) -o $@ $<

vma_hide: vma_hide.c
	$(CC) $(CFLAGS) -o $@ $<

seccomp_notify: seccomp_notify.c
	$(CC) $(CFLAGS) -o $@ $<

fexecve_drop: fexecve_drop.c
	$(CC) $(CFLAGS) -o $@ $<

memfd_loader: memfd_loader.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

memfd_userexec: memfd_userexec.c
	$(CC) $(CFLAGS) -o $@ $<

hollow_proc: hollow_proc.c
	$(CC) $(CFLAGS) -o $@ $<

anon_shellcode: anon_shellcode.c
	$(CC) $(CFLAGS) -o $@ $<

clone_netns: clone_netns.c
	$(CC) $(CFLAGS) -o $@ $<

ns_exec: ns_exec.c
	$(CC) $(CFLAGS) -o $@ $<

splice_c2: splice_c2.c
	$(CC) $(CFLAGS) -o $@ $<

abstract_sock_c2: abstract_sock_c2.c
	$(CC) $(CFLAGS) -o $@ $<

udp_shell: udp_shell.c
	$(CC) $(CFLAGS) -o $@ $<

tls_shell: tls_shell.c
	$(CC) $(CFLAGS) -o $@ $<

dns_exfil_raw: dns_exfil.c
	$(CC) $(CFLAGS) -o $@ $<

ipc_covert: ipc_covert.c
	$(CC) $(CFLAGS) -o $@ $< -lrt

shared_mem_c2: shared_mem_c2.c
	$(CC) $(CFLAGS) -o $@ $< -lrt

pipe_exfil: pipe_exfil.c
	$(CC) $(CFLAGS) -o $@ $<

proc_fd_scan: proc_fd_scan.c
	$(CC) $(CFLAGS) -o $@ $<

proc_vm_inject: proc_vm_inject.c
	$(CC) $(CFLAGS) -o $@ $<

env_scrape: env_scrape.c
	$(CC) $(CFLAGS) -o $@ $<

ssh_agent_hijack: ssh_agent_hijack.c
	$(CC) $(CFLAGS) -o $@ $<

self_delete: self_delete.c
	$(CC) $(CFLAGS) -o $@ $<

time_stomp: time_stomp.c
	$(CC) $(CFLAGS) -o $@ $<

userland_persist: userland_persist.c
	$(CC) $(CFLAGS) -o $@ $<

ringbuf_flood: ringbuf_flood.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

log_evasion: log_evasion.c
	$(CC) $(CFLAGS) -o $@ $<

fd_steal_read: fd_steal_read.c
	$(CC) $(CFLAGS) -o $@ $<

mmap_read: mmap_read.c
	$(CC) $(CFLAGS) -o $@ $<

scm_rights_exfil: scm_rights_exfil.c
	$(CC) $(CFLAGS) -o $@ $<

splice_read: splice_read.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS_PRIV) $(BINS_UNPRIV) dns_exfil kmod_unload log
