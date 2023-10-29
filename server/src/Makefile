CLANG := clang


ifndef TRACEROUTE_AF

$(info =================================)
$(info Target: $(MAKECMDGOALS))
$(info =================================)

.PHONY: recurse
recurse: do_recurse
	$(info **************************)
	$(info Using common targets      )
	$(info **************************)

.PHONY: do_recurse
do_recurse:
	-@$(MAKE) TRACEROUTE_AF=TRACEROUTE_V4 $(MAKECMDGOALS)
	-@$(MAKE) TRACEROUTE_AF=TRACEROUTE_V6 $(MAKECMDGOALS)

# Including recurse will force the recurse target to be run,
# allowing us to invoke the AF-specific variant of the Makefile
-include recurse

.PHONY: clean
clean:
	rm -rf build bin

.PHONY: format
format:
	clang-format -i -style=file:.clang_format `find . -type f -name "*.[ch]" ! -name "utest.h"`


else

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

$(error TRACEROUTE_AF must be set to TRACEROUTE_V4|TRACEROUTE_V6)

endif

PREFIX := /usr
BUILD_DIR := build/$(suffix)

BPF_SRC_DIR := bpf
BPF_BUILD_DIR := $(BUILD_DIR)/bpf
BPF_PROG := $(BUILD_DIR)/traceroute.o

SKELETON_DIR := $(BUILD_DIR)/include
skeleton := $(SKELETON_DIR)/traceroute.skel.h

server := augsburg-traceroute-server-$(suffix)
test := test-$(suffix)


.PHONY: server
server: $(server)


.PHONY: install
install:
	install -D $(server) $(DESTDIR)$(PREFIX)/sbin/$(server)

.PHONY: uninstall
uninstall:
	-rm -f $(DESTDIR)$(PREFIX)/sbin/$(server)

.PHONY: test $(test)
test: $(test)
$(test):	
	$(CLANG) $(INCLUDES) -D$(TRACEROUTE_AF) test/test.c -o $@
	./$(test)


include tools.mk

INCLUDES += -Icommon
CFLAGS = -Wall

$(server): traceroute.c $(skeleton) | $(LIBBPF)
	$(CLANG) $(CFLAGS) $(CPPFLAGS) traceroute.c $(LIBBPF) $(INCLUDES) -I$(SKELETON_DIR) -D$(TRACEROUTE_AF) -o $@ -lelf -lz

$(skeleton): $(BPF_PROG) | $(BPFTOOL) $(SKELETON_DIR)
	$(BPFTOOL) gen skeleton $(BPF_PROG) > $@

$(BPF_PROG): $(addprefix $(BPF_BUILD_DIR)/,$(patsubst %.c,%.o, $(notdir $(wildcard $(BPF_SRC_DIR)/*.c)))) | $(BPFTOOL)
	$(BPFTOOL) gen object $@ $^

$(BPF_BUILD_DIR)/%.o: $(BPF_SRC_DIR)/%.c | $(BPF_BUILD_DIR) $(LIBBPF)
	$(CLANG) -target bpf -D$(TRACEROUTE_AF) -g $(INCLUDES) -O2 -Wall -c $< -o $@

$(BUILD_DIR) $(BPF_BUILD_DIR) $(SKELETON_DIR):
	mkdir -p $@


.PHONY: clean
clean:
	rm -f $(server) $(test)


endif

.PHONY: distclean
distclean: clean
