ifeq ($(TRACEROUTE_AF), TRACEROUTE_V4)

$(info **************************)
$(info Using address family IPv4)
$(info **************************)
suffix = v4

else ifeq ($(TRACEROUTE_AF), TRACEROUTE_V6)

$(info **************************)
$(info Using address family IPv6)
$(info **************************)
suffix = v6

else

ifdef TRACEROUTE_AF
$(error TRACEROUTE_AF must be set to TRACEROUTE_V4|TRACEROUTE_V6)
endif

.PHONY: recurse
recurse:
	$(MAKE) TRACEROUTE_AF=TRACEROUTE_V4 $(MAKECMDGOALS)
	$(MAKE) TRACEROUTE_AF=TRACEROUTE_V6 $(MAKECMDGOALS)

-include recurse
endif


ifdef TRACEROUTE_AF

BPF_DIR := bpf
BPF_PROG := $(BPF_DIR)/traceroute.o

BUILD_DIR := build/$(suffix)
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
BPF_PROG := $(BUILD_DIR)/traceroute.o
SKELETON_DIR := $(BUILD_DIR)/include
skeleton := $(SKELETON_DIR)/traceroute.skel.h

OUTDIR := .
server := $(OUTDIR)/augsburg-traceroute-server-$(suffix)
test := $(OUTDIR)/test-$(suffix)

.PHONY: server
server: $(server)

include tools.mk
INCLUDES += -Icommon

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

.PHONY: test $(test)
test: $(test)
$(test):	
	$(CC) -Wall $(INCLUDES) -D$(TRACEROUTE_AF) test/test.c -o $@
	$(test)

.PHONY: clean
clean::
	-rm $(server) $(test)

else

.PHONY: clean
clean::
	-rm -r build

.PHONY: format
format:
	clang-format -i -style=file:.clang_format `find . -type f -name "*.[ch]" ! -name "utest.h"`

endif
