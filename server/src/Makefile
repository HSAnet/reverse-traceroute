BPF_DIR := $(abspath bpf)
BPF_PROG := $(BPF_DIR)/traceroute.o

OUTDIR := .
server := $(OUTDIR)/augsburg-traceroute-server

.PHONY: all
all: $(server)

include tools.mk

$(server): traceroute.c $(LIBBPF) traceroute.skel.h
	clang-14 -Wall traceroute.c $(LIBBPF) $(INCLUDES) -o $@ -lelf -lz -static

traceroute.skel.h: $(BPF_PROG) $(BPFTOOL)
	$(BPFTOOL) gen skeleton $(BPF_PROG) > $@

$(BPF_PROG): $(patsubst %.c,%.bc, $(wildcard $(BPF_DIR)/*.c))
	llvm-link-14 $^ -o $(BPF_PROG).bc
	llc-14 -filetype obj $(BPF_PROG).bc -o $@

$(BPF_DIR)/%.bc: $(BPF_DIR)/%.c | $(LIBBPF)
	clang-14 -emit-llvm -target bpf -g $(INCLUDES) -O2 -Wall -c $< -o $@

clean::
	-find . -type f -name *.o -delete
	-find . -type f -name "*.bc" -delete
	-rm traceroute.skel.h
