# Privilege Reference

This document covers what requires root (or specific Linux capabilities) and what works as a normal unprivileged user, for each kernel subsystem and each tool in this repo.

Directories covered: `bpf/`  `ebpf/`  `io_uring/`  `edrs/`

## Tool privilege map

### io_uring/

All tools in this directory use `io_uring_enter(2)` directly. Basic io_uring operations have required no capabilities since io_uring was introduced in Linux 5.1; `IORING_SETUP_SQPOLL` is the only flag that required a privilege (before 5.13). All file and network operations go through io_uring's internal workqueue, which bypasses the `__x64_sys_*` entry points that EDRs hook. Two tools require network capabilities due to the socket families they use.

| Tool | Minimum privilege | Bypasses |
|---|---|---|
| `file_read` | none | kprobes on `__x64_sys_openat`, `__x64_sys_read` |
| `file_write` | none | kprobes on `__x64_sys_openat`, `__x64_sys_write` |
| `file_append` | none | kprobes on `__x64_sys_openat`, `__x64_sys_write` |
| `multifile_read` | none | kprobes on `__x64_sys_openat`, `__x64_sys_read` (batched) |
| `net_connect` | none | kprobes on `__x64_sys_socket`, `__x64_sys_connect`, `__x64_sys_sendto`, `__x64_sys_recvfrom` |
| `net_reverse_shell` | none | kprobes on `__x64_sys_connect`; socket created via plain `socket(2)` syscall; shell I/O runs normally after `execve` |
| `dns_exfil` | none | kprobes on `__x64_sys_socket`, `__x64_sys_sendmsg` |
| `pipe_splice` | none | kprobes on `__x64_sys_openat`, `__x64_sys_splice` |
| `inotify_bypass_watch` | none | kprobes on `__x64_sys_openat`, `__x64_sys_read`; does NOT bypass inotify at the VFS layer |
| `memfd_exec` | none | no `openat` event for the binary since it lives in memfd |
| `proc_inject` | none for own process; `CAP_SYS_PTRACE` or root for others | kprobes on `__x64_sys_openat`, `__x64_sys_read`, `__x64_sys_write`; needs ptrace permission on target |
| `af_packet_send` | `CAP_NET_RAW` | kprobes on `__x64_sys_socket`, `__x64_sys_sendmsg`; raw Ethernet frame sent via `AF_PACKET` |
| `xdp_socket_send` | `CAP_NET_ADMIN` | kprobes on `__x64_sys_socket` (via `IORING_OP_SOCKET`); packet data placed in XDP TX ring without `sendmsg` syscall; TX ring kick uses plain `sendto(NULL)` |

### bpf/ (all tools require CAP_BPF)

All tools in this directory perform `bpf(2)` syscall operations that require `CAP_BPF`. They enumerate, read, or modify kernel BPF objects owned by other processes such as the EDR. On kernels older than 5.8, `CAP_SYS_ADMIN` was required instead. `env_exfil` and `icmp_trigger` are the only exceptions.

| Tool | Operations | Minimum privilege |
|---|---|---|
| `prog_recon` | `BPF_PROG_GET_NEXT_ID` + `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` | `CAP_BPF` |
| `map_recon` | `BPF_MAP_GET_NEXT_ID` + `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` | `CAP_BPF` |
| `map_snapshot` | save: `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_GET_FD_BY_ID` + `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_LOOKUP_ELEM`; restore: adds `BPF_MAP_UPDATE_ELEM` | `CAP_BPF` |
| `map_dumper` | `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_LOOKUP_ELEM` | `CAP_BPF` |
| `map_write` | `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_UPDATE_ELEM` | `CAP_BPF` |
| `map_poison` | `BPF_MAP_GET_FD_BY_ID` + `BPF_MAP_LOOKUP_ELEM` + `BPF_MAP_UPDATE_ELEM` with crafted values | `CAP_BPF` |
| `bpf_link_detach` | `BPF_LINK_GET_NEXT_ID` + `BPF_LINK_GET_FD_BY_ID` + `BPF_LINK_DETACH` | `CAP_BPF` |
| `link_update` | `BPF_LINK_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_PROG_GET_FD_BY_ID` + `BPF_PROG_LOAD` (no-op) + `BPF_LINK_UPDATE` | `CAP_BPF` |
| `map_freeze` | `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_FREEZE` | `CAP_BPF` |
| `bpf_persist` | `BPF_MAP_GET_FD_BY_ID` + `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_PIN` to bpffs + `BPF_OBJ_GET` | `CAP_BPF` |
| `edr_fin` | `BPF_PROG_GET_NEXT_ID` + `BPF_PROG_GET_FD_BY_ID` + `BPF_MAP_GET_NEXT_ID` + `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` to classify EDR progs and maps | `CAP_BPF` |
| `lsm_check` | `BPF_PROG_GET_NEXT_ID` + `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` filter by `BPF_PROG_TYPE_LSM`; `BPF_MAP_GET_FD_BY_ID` + `BPF_MAP_LOOKUP_ELEM` + `BPF_MAP_UPDATE_ELEM` to test LSM map write enforcement | `CAP_BPF` |
| `pid_allowlist` | `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_UPDATE_ELEM` on map given by map_id argument | `CAP_BPF` |
| `env_exfil` | reads `/proc/*/environ` | none for own process; same UID or root for others |
| `icmp_trigger` | trigger sender: `AF_INET SOCK_RAW IPPROTO_ICMP`; daemon listener: `AF_PACKET SOCK_RAW` + `SO_ATTACH_FILTER`; no `bpf(2)` syscall | `CAP_NET_RAW` |

### ebpf/ (requires CAP_BPF plus a type-specific capability)

These are offensive BPF programs (`.bpf.c`) plus two userspace runners. The minimum capability depends on the program type.

| Program | BPF type | Attachment point | Minimum privilege |
|---|---|---|---|
| `exec.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_execve` | `CAP_BPF` + `CAP_PERFMON` |
| `fentry_open.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_openat` | `CAP_BPF` + `CAP_PERFMON` |
| `creds.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_openat` + `sys_exit_openat` + `sys_enter_read` + `sys_exit_read` | `CAP_BPF` + `CAP_PERFMON` |
| `keylog.bpf.c` | `TRACEPOINT` | `tracepoint/input/input__event` | `CAP_BPF` + `CAP_PERFMON` |
| `tty_sniff.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_write` + `sys_enter_read` | `CAP_BPF` + `CAP_PERFMON` |
| `proc_hide.bpf.c` | `KPROBE` + `KRETPROBE` | `kprobe/sys_getdents64` + `kretprobe/sys_getdents64` | `CAP_BPF` + `CAP_PERFMON` |
| `net.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_connect` | `CAP_BPF` + `CAP_PERFMON` |
| `net_hide.bpf.c` | `TRACEPOINT` | `tracepoint/syscalls/sys_enter_openat` + `sys_exit_openat` + `sys_enter_read` + `sys_exit_read` + `sys_enter_close` | `CAP_BPF` + `CAP_PERFMON` |
| `xdp_backdoor.bpf.c` | `XDP` | network interface | `CAP_BPF` + `CAP_NET_ADMIN` |
| `skf_c2_runner.c` | classic BPF (`SO_ATTACH_FILTER`) | `AF_INET SOCK_RAW IPPROTO_ICMP` | `CAP_NET_RAW` |
| `xdp_handler.c` | userspace runner for `xdp_backdoor` | `BPF_MAP_GET_FD_BY_ID` + `BPF_MAP_UPDATE_ELEM` (write own PID to pid map) + `BPF_MAP_LOOKUP_ELEM` + `BPF_MAP_UPDATE_ELEM` (read/reset trigger map) | `CAP_BPF` |

### edrs/ (mixed)

Selected tools with BPF or io_uring operations. For the full list of all edrs/ tools see [README.md](../README.md).

| Tool | Operations | Minimum privilege |
|---|---|---|
| `edr_recon` (BPF sections) | `BPF_PROG/MAP/LINK_GET_NEXT_ID` + `BPF_PROG/MAP/LINK_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` | `CAP_BPF` |
| `edr_recon` (tracefs sections) | read `/sys/kernel/tracing/*` | root (tracefs mount) |
| `bpf_prog_recon` | `BPF_PROG_GET_NEXT_ID` + `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` | `CAP_BPF` |
| `bpf_map_wipe` | `BPF_MAP_GET_NEXT_ID` + `BPF_MAP_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` + `BPF_MAP_UPDATE/DELETE_ELEM` | `CAP_BPF` |
| `bpf_detach_all` | `BPF_LINK_GET_NEXT_ID` + `BPF_LINK_GET_FD_BY_ID` + `BPF_LINK_DETACH` | `CAP_BPF` |
| `tetragon_blind` (detach phase) | `BPF_LINK_GET_NEXT_ID` + `BPF_LINK_GET_FD_BY_ID` + `BPF_LINK_DETACH` | `CAP_BPF` |
| `tetragon_blind` (freeze phase) | write `/sys/fs/cgroup/*/cgroup.freeze` | `CAP_SYS_ADMIN` |
| `perf_bpf_kill` | scans `/proc/*/fdinfo` to find perf-attached progs; `BPF_PROG_GET_FD_BY_ID` + `BPF_OBJ_GET_INFO_BY_FD` to classify; `kill(SIGKILL)` on owning process | `CAP_BPF`; root to kill other users' procs |
| `ringbuf_flood` | flood file open + fork + connect events to saturate EDR ringbuf; no BPF | none |
| `uring_stealth` | `io_uring_setup` + all ops | none |
| `openat2_bypass` | `openat2(2)`, `preadv2(2)`, `pwritev2(2)`, `statx(2)`, `copy_file_range(2)` | none |
| `uring_recon_unpriv` | io_uring opcodes to probe EDR blind spots | none |
| `ptrace_selfguard` | `PTRACE_TRACEME` + `PR_SET_DUMPABLE` | none |

## io_uring in depth

### How io_uring bypasses EDR hooks

`io_uring_enter(2)` is the single syscall that crosses into the kernel. The kernel workqueue (`iou-wq-<pid>`) then processes each SQE by calling internal functions rather than going through the normal syscall dispatch:

```
__x64_sys_openat   <- EDR kprobe here        io_openat2   <- workqueue calls this
__x64_sys_read     <- EDR kprobe here   vs   io_read
__x64_sys_write    <- EDR kprobe here        io_write
__x64_sys_connect  <- EDR kprobe here        io_connect
__x64_sys_sendmsg  <- EDR kprobe here        io_sendmsg
```

The EDR's kprobes on `__x64_sys_*` never execute. The `sys_enter_openat`, `sys_enter_read`, and similar raw tracepoints never fire either. Only `sys_enter_io_uring` fires, and most sensors do not parse SQE contents.

### All io_uring opcodes

All of these work without any privileges on any kernel that supports io_uring (5.1+). Normal file permissions still apply, but the EDR hook at `__x64_sys_openat` does not fire regardless.

File operations:

| Opcode | Equivalent syscall bypassed | Available since |
|---|---|---|
| `IORING_OP_OPENAT` | `openat(2)` via `__x64_sys_openat` | 5.6 |
| `IORING_OP_OPENAT2` | `openat2(2)` via `__x64_sys_openat2` | 5.6 |
| `IORING_OP_READ` | `read(2)` via `__x64_sys_read` | 5.1 |
| `IORING_OP_WRITE` | `write(2)` via `__x64_sys_write` | 5.1 |
| `IORING_OP_READ_FIXED` | `read(2)` with registered buffer | 5.1 |
| `IORING_OP_WRITE_FIXED` | `write(2)` with registered buffer | 5.1 |
| `IORING_OP_CLOSE` | `close(2)` | 5.3 |
| `IORING_OP_STATX` | `statx(2)` via `__x64_sys_statx` | 5.6 |
| `IORING_OP_FSYNC` | `fsync(2)` | 5.1 |
| `IORING_OP_FDATASYNC` | `fdatasync(2)` | 5.1 |
| `IORING_OP_FALLOCATE` | `fallocate(2)` | 5.6 |
| `IORING_OP_FADVISE` | `fadvise(2)` | 5.6 |
| `IORING_OP_MADVISE` | `madvise(2)` | 5.6 |
| `IORING_OP_UNLINKAT` | `unlinkat(2)` | 5.11 |
| `IORING_OP_RENAMEAT` | `renameat2(2)` | 5.11 |
| `IORING_OP_MKDIRAT` | `mkdirat(2)` | 5.15 |
| `IORING_OP_SYMLINKAT` | `symlinkat(2)` | 5.15 |
| `IORING_OP_LINKAT` | `linkat(2)` | 5.15 |
| `IORING_OP_GETXATTR` | `getxattr(2)` | 5.17 |
| `IORING_OP_SETXATTR` | `setxattr(2)` | 5.17 |

Network operations:

| Opcode | Equivalent syscall bypassed | Available since |
|---|---|---|
| `IORING_OP_SOCKET` | `socket(2)` via `__x64_sys_socket` | 5.19 |
| `IORING_OP_CONNECT` | `connect(2)` via `__x64_sys_connect` | 5.5 |
| `IORING_OP_ACCEPT` | `accept4(2)` via `__x64_sys_accept4` | 5.5 |
| `IORING_OP_SEND` | `send(2)` via `__x64_sys_sendto` | 5.6 |
| `IORING_OP_RECV` | `recv(2)` via `__x64_sys_recvfrom` | 5.6 |
| `IORING_OP_SENDMSG` | `sendmsg(2)` via `__x64_sys_sendmsg` | 5.3 |
| `IORING_OP_RECVMSG` | `recvmsg(2)` via `__x64_sys_recvmsg` | 5.3 |
| `IORING_OP_SEND_ZC` | `send(2)` zero-copy | 6.0 |
| `IORING_OP_SENDMSG_ZC` | `sendmsg(2)` zero-copy | 6.1 |
| `IORING_OP_SHUTDOWN` | `shutdown(2)` | 5.11 |

In-kernel data movement:

| Opcode | Equivalent syscall bypassed | Available since |
|---|---|---|
| `IORING_OP_SPLICE` | `splice(2)` via `__x64_sys_splice` | 5.7 |
| `IORING_OP_TEE` | `tee(2)` | 5.8 |
| `IORING_OP_PIPE` | `pipe2(2)` | 6.2 |

Registration operations (all unprivileged):

| Registration | What it does |
|---|---|
| `IORING_REGISTER_BUFFERS` | Pre-register fixed I/O buffers so READ_FIXED/WRITE_FIXED use indices |
| `IORING_REGISTER_FILES` | Pre-register fds so ops use a slot index with no per-op dup visible to hooks |
| `IORING_REGISTER_EVENTFD` | Register eventfd for completion notification |
| `IORING_REGISTER_IOWQ_AFF` | Set CPU affinity of io_uring workqueue threads |
| `IORING_REGISTER_IOWQ_MAX_WORKERS` | Tune workqueue thread count |

### SQPOLL, the one privileged io_uring flag

`IORING_SETUP_SQPOLL` creates a dedicated kernel thread that polls the submission ring without any `io_uring_enter` calls at all. This makes io_uring activity nearly invisible since even the single visible syscall disappears.

| Kernel | Requirement |
|---|---|
| before 5.11 | `CAP_SYS_ADMIN` required |
| 5.11 through 5.12 | Root or specific rlimit configuration |
| 5.13 and later | Fully unprivileged |

### What io_uring always bypasses

| Hook type | Why it is bypassed |
|---|---|
| kprobes on `__x64_sys_openat/read/write/connect/send/recv` | Workqueue calls `io_openat2`, `io_read`, etc. instead |
| `sys_enter_openat`, `sys_enter_read` and similar tracepoints | Raw tracepoint only fires for `io_uring_enter`, not per operation |
| `sys_call_table[__NR_openat]` LKM hooks | Workqueue bypasses syscall dispatch entirely |
| livepatch on `__do_sys_openat` | Not called by the workqueue path |
| auditd rules on specific syscall numbers | Audit events are tied to syscall entry and io_uring ops have no per-op entry |

### What io_uring does NOT bypass

| Hook type | Why it is not bypassed |
|---|---|
| kprobes on `do_filp_open`, `vfs_open`, `security_file_open` | These are at the VFS layer; `io_openat2` calls the same functions |
| BPF LSM hooks (`file_open`, `socket_connect`, etc.) | LSM sits below io_uring |
| fanotify `FAN_OPEN_PERM` | `fsnotify_open()` is called by `vfs_open` regardless of how the open was triggered |
| kprobes on `tcp_v4_connect`, `tcp_v6_connect` | Network layer functions called by both paths |
| kprobes on io_uring internals like `io_openat2`, `io_read`, `io_connect` | An EDR that specifically targets io_uring is not bypassed |
| `raw_tracepoint:io_uring:*` | Modern Tetragon and Falco can hook these |
| BPF fentry/fexit on `io_openat2`, `io_read`, etc. | Fentry fires at the start of any kernel function |

## eBPF capabilities

Linux 5.8 split the old monolithic `CAP_SYS_ADMIN` BPF requirement into dedicated capabilities. On older kernels everything still required `CAP_SYS_ADMIN`.

### Capability split introduced in Linux 5.8

| Capability | What it grants |
|---|---|
| `CAP_BPF` | Controls bpf(2) calls: create maps, enumerate all BPF objects, read or write any map, detach any link; loading programs requires CAP_BPF plus a type-specific capability for most program types |
| `CAP_PERFMON` | `perf_event_open(2)` with sensitive configs, attach BPF to perf events, access hardware counters |
| `CAP_NET_ADMIN` | XDP programs, TC qdisc BPF, cgroup socket programs |
| `CAP_MAC_ADMIN` | `BPF_PROG_TYPE_LSM` on hardened kernel configs |
| `CAP_SYS_ADMIN` | Everything above, the old catch-all that still works everywhere |

### BPF program types and what they require

| Program type | Load | Attach | Used by |
|---|---|---|---|
| `BPF_PROG_TYPE_SOCKET_FILTER` | none (1) | none via `SO_ATTACH_BPF` | rarely |
| `BPF_PROG_TYPE_KPROBE` | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | Elastic, older Falco, Tetragon |
| `BPF_PROG_TYPE_TRACEPOINT` | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | Falco classic, EDR-Theta |
| `BPF_PROG_TYPE_RAW_TRACEPOINT` | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | Falco modern_ebpf, Tetragon |
| `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE` | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | rare |
| `BPF_PROG_TYPE_PERF_EVENT` | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | older Falco, EDR-Theta (legacy) |
| `BPF_PROG_TYPE_LSM` | `CAP_BPF` + `CAP_MAC_ADMIN` | `CAP_BPF` + `CAP_MAC_ADMIN` | Tetragon, EDR-Theta endpoint |
| `BPF_PROG_TYPE_TRACING` (fentry/fexit) | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` + `CAP_PERFMON` | Tetragon, modern Falco, EDR-Theta |
| `BPF_PROG_TYPE_XDP` | `CAP_BPF` + `CAP_NET_ADMIN` | `CAP_BPF` + `CAP_NET_ADMIN` | Cilium, network sensors |
| `BPF_PROG_TYPE_SCHED_CLS` (TC) | `CAP_BPF` + `CAP_NET_ADMIN` | `CAP_BPF` + `CAP_NET_ADMIN` | Cilium |
| `BPF_PROG_TYPE_CGROUP_SKB` | `CAP_BPF` + `CAP_NET_ADMIN` | `CAP_NET_ADMIN` | Cilium |
| `BPF_PROG_TYPE_SK_MSG` | `CAP_BPF` + `CAP_NET_ADMIN` | `CAP_BPF` + `CAP_NET_ADMIN` | Cilium sockmap |
| `BPF_PROG_TYPE_FLOW_DISSECTOR` | `CAP_BPF` + `CAP_NET_ADMIN` | `CAP_BPF` + `CAP_NET_ADMIN` | network sensors |

(1) Only when `kernel.unprivileged_bpf_disabled=0`.

## BPF syscall operations

### Every bpf(2) command and what it requires

| BPF command | What it does | Requires |
|---|---|---|
| `BPF_PROG_LOAD` | Load a program | type-dependent, see table above |
| `BPF_MAP_CREATE` | Create a BPF map | `CAP_BPF`; or none for simple types if `unprivileged_bpf_disabled=0` |
| `BPF_PROG_GET_NEXT_ID` | Enumerate all loaded programs | `CAP_BPF` |
| `BPF_MAP_GET_NEXT_ID` | Enumerate all maps | `CAP_BPF` |
| `BPF_LINK_GET_NEXT_ID` | Enumerate all BPF links | `CAP_BPF` |
| `BPF_PROG_GET_FD_BY_ID` | Get an fd for a program by ID | `CAP_BPF` |
| `BPF_MAP_GET_FD_BY_ID` | Get an fd for a map by ID | `CAP_BPF` |
| `BPF_LINK_GET_FD_BY_ID` | Get an fd for a link by ID | `CAP_BPF` |
| `BPF_OBJ_GET_INFO_BY_FD` | Read prog/map/link metadata | `CAP_BPF` or own fd |
| `BPF_MAP_LOOKUP_ELEM` | Read a map entry | `CAP_BPF` or own map |
| `BPF_MAP_UPDATE_ELEM` | Write a map entry | `CAP_BPF` or own map |
| `BPF_MAP_DELETE_ELEM` | Delete a map entry | `CAP_BPF` or own map |
| `BPF_MAP_GET_NEXT_KEY` | Iterate map keys | `CAP_BPF` or own map |
| `BPF_LINK_CREATE` | Create a BPF link to attach a program | type-dependent |
| `BPF_LINK_UPDATE` | Swap the program in an existing link | `CAP_BPF` or own link |
| `BPF_LINK_DETACH` | Detach and destroy a link | `CAP_BPF` or own link |
| `BPF_OBJ_PIN` | Pin an object to the BPF filesystem | `CAP_BPF` |
| `BPF_OBJ_GET` | Get a pinned object | `CAP_BPF` or read permission on the pin path |
| `BPF_PROG_ATTACH` | Attach a program via the cgroup interface | `CAP_NET_ADMIN` or `CAP_BPF` + cgroup write |
| `BPF_PROG_DETACH` | Detach a program via the cgroup interface | same as attach |
| `BPF_PROG_QUERY` | Query which programs are attached | `CAP_NET_ADMIN` or cgroup read |
| `BPF_BTF_LOAD` | Load BTF type info | `CAP_BPF` |
| `BPF_PROG_TEST_RUN` | Test-run a loaded program | `CAP_BPF` or own prog |
| `BPF_ITER_CREATE` | Create a BPF iterator | `CAP_BPF` |
| `BPF_ENABLE_STATS` | Enable BPF runtime stats collection | `CAP_SYS_ADMIN` |

### sysctl settings that affect BPF privileges

| sysctl | Default | What it does |
|---|---|---|
| `kernel.unprivileged_bpf_disabled` | 0 on most distros; 1 on Ubuntu 20.04+ and hardened configs | When set to 1, only `CAP_BPF` or `CAP_SYS_ADMIN` can load any program or create maps |
| `kernel.bpf_jit_harden` | 0 | Setting 2 blinds JIT constants to protect against JIT spray; affects all users |
| `kernel.bpf_jit_kallsyms` | 0 | Setting 1 exposes JIT addresses in `/proc/kallsyms`, but root can see them anyway |
| `net.core.bpf_jit_enable` | 1 | Setting 0 forces interpreter mode; this is a performance tradeoff not a security one |
| `kernel.perf_event_paranoid` | 2 or 3 | Setting 3 blocks perf access for anyone without `CAP_PERFMON` |

### What unprivileged users can do with BPF

When `kernel.unprivileged_bpf_disabled=0`, which is the historical default, users without any capability can:

- Load `BPF_PROG_TYPE_SOCKET_FILTER` programs
- Create `HASH`, `ARRAY`, `PROG_ARRAY`, `PERF_EVENT_ARRAY` (limited), `STACK_TRACE`, `ARRAY_OF_MAPS`, `HASH_OF_MAPS`, `QUEUE`, `STACK`, and `RINGBUF` maps
- Attach a socket filter via `SO_ATTACH_BPF`

From an offensive standpoint with `unprivileged_bpf_disabled=0`, you can fill the per-user BPF object quota with maps to prevent the EDR from allocating new event maps, causing it to drop events silently. You can also allocate `BPF_MAP_TYPE_RINGBUF` maps to consume the kernel memory the EDR would need for its ring buffers.

### BPF map wipe methods by type

Different map types need different approaches to clear or corrupt their contents.

| Map type | How to wipe it | Notes |
|---|---|---|
| `BPF_MAP_TYPE_HASH` | `BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_DELETE_ELEM` for each key | Iterates and deletes; the map structure itself remains |
| `BPF_MAP_TYPE_LRU_HASH` | Same as HASH | LRU eviction may already be discarding old entries |
| `BPF_MAP_TYPE_ARRAY` | `BPF_MAP_UPDATE_ELEM` with zero-value for each index | Array maps cannot have entries deleted, only overwritten with zeros |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | `BPF_MAP_UPDATE_ELEM` with per-cpu zero buffer | One update writes all CPU slots at once |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | `BPF_MAP_DELETE_ELEM` for each cpu slot | Removes the perf event fd mappings; EDR loses its event stream |
| `BPF_MAP_TYPE_RINGBUF` | Cannot be zeroed via map operations | The consumer pointer is mmap'd by the EDR process. Best options: freeze the daemon so the ring fills and BPF programs start returning ENOSPC, or detach the BPF link that writes to it |
| `BPF_MAP_TYPE_PROG_ARRAY` | `BPF_MAP_DELETE_ELEM` for each slot | Removes tail-call targets; EDR program chains break |

### EDR BPF hooks and how to remove them

| Hook type | How it was attached | How to remove it |
|---|---|---|
| Any type via `BPF_LINK` | `BPF_LINK_CREATE` | `BPF_LINK_DETACH` with `CAP_BPF`; tools: `bpf_link_detach`, `bpf_detach_all` |
| `PERF_EVENT` via old perf API | `perf_event_open + PERF_EVENT_IOC_SET_BPF` | Kill the owning process; tool: `perf_bpf_kill` |
| `KPROBE` via old perf API | Same old perf API path | Kill the owning process |
| Any type via `BPF_PROG_ATTACH` on a cgroup | cgroup attach | `BPF_PROG_DETACH` with `CAP_NET_ADMIN` |
| Self-reinstalling daemon | Daemon reads ring buffer and reloads hooks | Freeze the daemon first with `tetragon_blind`, then detach |

## Quick reference

```
NO ROOT NEEDED
io_uring file/net ops       all IORING_OP_* except SQPOLL on kernel < 5.13
io_uring SQPOLL             no root on kernel 5.13 and later
openat2 / preadv2 / statx   alternative syscall numbers (nr 437 / 327 / 332)
splice(2)                   in-kernel data movement
memfd_create + fexecve      execute without on-disk binary
CLONE_NEWUSER+NEWNET        network namespace isolation (if userns allowed)
pidfd_getfd                 pass fds across processes without ptrace
PTRACE_TRACEME + guardian   blocks external ptrace attachment
PR_SET_DUMPABLE=0           blocks /proc/pid/mem and non-root ptrace
MADV_DONTDUMP               exclude VMA from core dumps
BPF SOCKET_FILTER load      if kernel.unprivileged_bpf_disabled=0
BPF map create              if kernel.unprivileged_bpf_disabled=0

CAP_BPF (or CAP_SYS_ADMIN on kernel before 5.8)
BPF_PROG_LOAD (most types)
BPF_PROG/MAP/LINK_GET_NEXT_ID     enumerate any BPF object
BPF_MAP_LOOKUP/UPDATE/DELETE      access others' maps
BPF_LINK_DETACH                   remove any BPF link

CAP_BPF + CAP_PERFMON
Load and attach: KPROBE, TRACEPOINT, RAW_TRACEPOINT, PERF_EVENT, TRACING (fentry/fexit)

CAP_BPF + CAP_NET_ADMIN
Load and attach: XDP, TC (SCHED_CLS), CGROUP_SKB

CAP_BPF + CAP_MAC_ADMIN
Load and attach: LSM (BPF_PROG_TYPE_LSM)

OTHER CAPABILITIES
cgroup freeze/thaw          CAP_SYS_ADMIN
kprobe_events write         root (tracefs)
delete_module               CAP_SYS_MODULE
/proc/kcore read            CAP_SYS_RAWIO
klogctl(CLEAR)              CAP_SYSLOG
NETLINK_AUDIT SET           CAP_AUDIT_CONTROL
AF_PACKET SOCK_RAW          CAP_NET_RAW  (af_packet_shell, icmp_trigger daemon)
AF_INET SOCK_RAW            CAP_NET_RAW  (skf_c2_runner, icmp_trigger sender)
iptables/nftables flush     CAP_NET_ADMIN
/proc/PID bind mount        CAP_SYS_ADMIN
oom_score_adj (other proc)  CAP_SYS_RESOURCE
ld.so.preload write         root (file is owned by root)
BPF_ENABLE_STATS            CAP_SYS_ADMIN
```

## Getting capabilities without full root

| Capability | How to acquire it |
|---|---|
| `CAP_NET_RAW` | SUID binary; `setcap cap_net_raw+ep ./tool` (needs file owner) |
| `CAP_BPF` + `CAP_PERFMON` | Ambient capabilities if the inheritable set allows; container escape |
| `CAP_NET_ADMIN` | Container with `--cap-add NET_ADMIN`; own network namespace |
| `CAP_SYS_ADMIN` | Namespace escape, container breakout, kernel exploit |
| `CAP_MAC_ADMIN` | Rarely granted standalone; usually comes with `CAP_SYS_ADMIN` |

To check what you currently have:

```bash
cat /proc/self/status | grep -E "^Cap(Prm|Eff|Bnd)"
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')
```
