BPF_DIR := $(abspath bpf)
BPF_PROG := $(BPF_DIR)/traceroute.o

ifeq ($(TRACEROUTE_AF), TRACEROUTE_V4)
suffix := v4
else ifeq ($(TRACEROUTE_AF), TRACEROUTE_V6)
suffix := v6
endif

BUILD_DIR := $(abspath build)/$(suffix)
BPF_PROG := $(BUILD_DIR)/traceroute.o
SKELETON_DIR := $(BUILD_DIR)/include
skeleton := $(SKELETON_DIR)/traceroute.skel.h


server := augsburg-traceroute-server-$(suffix)

.PHONY: all
all:
	$(MAKE) server TRACEROUTE_AF=TRACEROUTE_V4
	$(MAKE) server TRACEROUTE_AF=TRACEROUTE_V6

include tools.mk

.PHONY: server
server: $(server)
$(server): traceroute.c $(skeleton) | $(LIBBPF)
	clang-14 -Wall traceroute.c $(LIBBPF) $(INCLUDES) -I$(SKELETON_DIR) -o $@ -lelf -lz -static

$(skeleton): $(BPF_PROG) | $(BPFTOOL) $(SKELETON_DIR)
	$(BPFTOOL) gen skeleton $(BPF_PROG) > $@

$(SKELETON_DIR):
	mkdir -p $@

export INCLUDES
.PHONY: $(BPF_PROG)
$(BPF_PROG): | $(LIBBPF)
	$(MAKE) -C $(BPF_DIR) BUILD_DIR=$(BUILD_DIR)/bpf BPF_PROG=$(BPF_PROG) TRACEROUTE_AF=$(TRACEROUTE_AF) bpf_prog

clean::
	-rm -r build
