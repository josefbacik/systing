# Builds libsysting_heap_hooks.so. It links only libdl: libunwind is opened
# at runtime, when a program asks for the "libunwind" backtrace.
#
#   make            # ./libsysting_heap_hooks.so
#   make OUT=/dir   # /dir/libsysting_heap_hooks.so

CC ?= cc
CFLAGS ?= -O2 -g
OUT ?= .

LIB := $(OUT)/libsysting_heap_hooks.so

all: $(LIB)

$(LIB): systing_heap_hooks.c systing_heap_hooks.h
	$(CC) $(CFLAGS) -Wall -Wextra -fPIC -shared -fno-omit-frame-pointer \
		-o $@ systing_heap_hooks.c -ldl

clean:
	rm -f $(LIB)

.PHONY: all clean
