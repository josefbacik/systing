# Builds the hooks libraries. They link libdl and libpthread, and the one with
# the backtraces libgcc_s, which jemalloc itself is linked with. libunwind is
# opened at runtime, when a program asks for the "libunwind" backtrace.
#
#   make             # both libraries, in this directory
#   make OUT=/dir    # both, in /dir
#   make hooks       # libsysting_heap_hooks.so: the backtraces and the responder
#   make responder   # libsysting_heap_responder.so: the responder alone
#
# README.md says which one a service needs.

CC ?= cc
CFLAGS ?= -O2 -g
OUT ?= .

HOOKS := $(OUT)/libsysting_heap_hooks.so
RESPONDER := $(OUT)/libsysting_heap_responder.so

COMMON_SRC := common/common.c
BACKTRACE_SRC := backtrace/backtrace.c backtrace/frame_pointer.c \
	backtrace/stack_range.c backtrace/python.c
RESPONDER_SRC := responder/responder.c
HDR := systing_heap_hooks.h common/common.h backtrace/frame_pointer.h \
	backtrace/python.h backtrace/py_offsets.h

# -z now: every function is bound when the library is loaded. One bound at its
# first call would be bound by the dynamic loader from inside malloc.
BUILD = $(CC) $(CFLAGS) -Wall -Wextra -fPIC -shared -fno-omit-frame-pointer \
	-Wl,-z,now

all: hooks responder

hooks: $(HOOKS)

responder: $(RESPONDER)

$(HOOKS): $(COMMON_SRC) $(BACKTRACE_SRC) $(RESPONDER_SRC) $(HDR)
	$(BUILD) -o $@ $(COMMON_SRC) $(BACKTRACE_SRC) $(RESPONDER_SRC) -ldl -lpthread -lgcc_s

$(RESPONDER): $(COMMON_SRC) $(RESPONDER_SRC) systing_heap_hooks.h common/common.h
	$(BUILD) -o $@ $(COMMON_SRC) $(RESPONDER_SRC) -ldl -lpthread

clean:
	rm -f $(HOOKS) $(RESPONDER)

.PHONY: all hooks responder clean
