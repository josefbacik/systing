# Builds libsysting_heap_hooks.so. It links only libdl and libpthread: libunwind is opened
# at runtime, when a program asks for the "libunwind" backtrace.
#
#   make            # ./libsysting_heap_hooks.so
#   make OUT=/dir   # /dir/libsysting_heap_hooks.so

CC ?= cc
CFLAGS ?= -O2 -g
OUT ?= .

LIB := $(OUT)/libsysting_heap_hooks.so

all: $(LIB)

SRC := systing_heap_hooks.c systing_heap_hooks_python.c
HDR := systing_heap_hooks.h systing_heap_hooks_python.h py_offsets.h

$(LIB): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -Wall -Wextra -fPIC -shared -fno-omit-frame-pointer \
		-o $@ $(SRC) -ldl -lpthread

clean:
	rm -f $(LIB)

.PHONY: all clean
