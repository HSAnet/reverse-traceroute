BPF_DIR := bpf
BPF_PROG := $(BPF_DIR)/traceroute.o

ifeq ($(TRACEROUTE_AF), TRACEROUTE_V4)
suffix := v4
else ifeq ($(TRACEROUTE_AF), TRACEROUTE_V6)
suffix := v6
endif

OUTDIR := .
BUILD_DIR := build/$(suffix)
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
BPF_PROG := $(BUILD_DIR)/traceroute.o
SKELETON_DIR := $(BUILD_DIR)/include
skeleton := $(SKELETON_DIR)/traceroute.skel.h


server := $(OUTDIR)/augsburg-traceroute-server-$(suffix)

.PHONY: all
all:
	$(MAKE) server TRACEROUTE_AF=TRACEROUTE_V4
	$(MAKE) server TRACEROUTE_AF=TRACEROUTE_V6

include tools.mk

.PHONY: server
server: $(server)
$(server): traceroute.c $(skeleton) | $(LIBBPF)
	clang-14 -Wall traceroute.c $(LIBBPF) $(INCLUDES) -I$(SKELETON_DIR) -D$(TRACEROUTE_AF) -o $@ -lelf -lz -static

$(skeleton): $(BPF_PROG) | $(BPFTOOL) $(SKELETON_DIR)
	$(BPFTOOL) gen skeleton $(BPF_PROG) > $@

$(BPF_PROG): $(addprefix $(BPF_BUILD_DIR)/,$(patsubst %.c,%.bc, $(notdir $(wildcard $(BPF_DIR)/*.c))))
	llvm-link-14 $^ | llc-14 -filetype obj -o $@

$(BPF_BUILD_DIR)/%.bc: $(BPF_DIR)/%.c | $(BPF_BUILD_DIR) $(LIBBPF)
	clang-14 -emit-llvm -target bpf -D$(TRACEROUTE_AF) -g $(INCLUDES) -O2 -Wall -c $< -o $@

$(BUILD_DIR) $(BPF_BUILD_DIR) $(SKELETON_DIR):
	mkdir -p $@

clean::
	-rm -r build
