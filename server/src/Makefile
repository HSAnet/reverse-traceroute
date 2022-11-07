BPF_DIR := $(abspath bpf)
BPF_PROG := $(BPF_DIR)/traceroute.o

.PHONY: all
all: augsburg-traceroute

include tools.mk

augsburg-traceroute: traceroute.c $(LIBBPF) traceroute.skel.h
	clang -Wall traceroute.c $(LIBBPF) $(INCLUDES) -o $@ -lelf -lz

traceroute.skel.h: $(BPF_PROG) $(BPFTOOL)
	$(BPFTOOL) gen skeleton $(BPF_PROG) > $@

$(BPF_PROG): $(patsubst %.c,%.bc, $(wildcard $(BPF_DIR)/*.c))
	llvm-link $^ -o $(BPF_PROG).bc
	llc -filetype obj $(BPF_PROG).bc -o $@

$(BPF_DIR)/%.bc: $(BPF_DIR)/%.c | $(LIBBPF)
	clang -emit-llvm -target bpf -g $(INCLUDES) -O2 -Wall -c $< -o $@

clean::
	-find . -type f -name *.o -delete
	-find . -type f -name "*.bc" -delete
	-rm augsburg-traceroute traceroute.skel.h
