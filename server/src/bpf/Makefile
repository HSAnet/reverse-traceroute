.PHONY: bpf_prog
bpf_prog: $(BPF_PROG)

$(BPF_PROG): $(addprefix $(BUILD_DIR)/,$(patsubst %.c,%.bc, $(wildcard *.c)))
	llvm-link-14 $^ | llc-14 -filetype obj -o $@

$(BUILD_DIR)/%.bc: %.c | $(BUILD_DIR)
	clang-14 -emit-llvm -target bpf -D$(TRACEROUTE_AF) -g $(INCLUDES) -O2 -Wall -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@
