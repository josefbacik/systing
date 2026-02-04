// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_STRUCTS_H__
#define __BPF_LIB_STRUCTS_H__

#ifndef __cplusplus
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <ostream>
#endif

/**
 * Data passed through our perf buffers should have this at its
 * head. Implementations might vary, but typically we only have a type
 * field that is used for further processing.
 *
 * Message structs also must contain this struct _as the first field_ in their
 * definition, e.g. `system_message_t`, `struct pystacks_message`, which can be
 * found in `strobelight/bpf_lib/common/unified_structs.h`.
 *
 * Example valid content sent to userspace via BPF `perf_submit`:
 * |0---------PERF-BUFFER-BYTES----------------------------END|
 * | REQUEST_DATA |
 * | REQUEST_DATA_TRUNCATED |
 * | SAMPLE_EVENT (SYS_MESSAGE) |
 * | SAMPLE_EVENT (SYS_MESSAGE STROBEMETA_MESSAGE) |
 * | SAMPLE_EVENT (SYS_MESSAGE PY_MESSAGE STROBEMETA_MESSAGE) |
 *
 * Note: the above example seems to imply there's a structured ordering of
 * messages, but in reality, any order of messages is acceptable and will be
 * read correctly by userspace, e.g.:
 * ...
 * | SAMPLE_EVENT (SYS_MESSAGE PY_MESSAGE STROBEMETA_MESSAGE) |
 * ...
 * <-->
 * ...
 * | SAMPLE_EVENT (STROBEMETA_MESSAGE PY_MESSAGE SYS_MESSAGE) |
 * ...
 *
 * For more details about this (re-)design, please refer to the following Doc:
 * https://fburl.com/7o1f2k33
 *
 */
struct sample_header {
  uint16_t type;
  uint16_t len;
};

enum {
  BPF_LIB_PYSTACKS_MESSAGE = 5,
  BPF_LIB_TORCHSTACKS_MESSAGE = 7,
};

// @lint-ignore-every CLANGTIDY modernize-use-using
typedef uint64_t stackframe_t;

#define BPF_LIB_MAX_STACK_DEPTH 127
#define BPF_LIB_MAX_ASYNC_STACK_DEPTH 127
#define BPF_LIB_MAX_BYTES_PER_STACK \
  (BPF_LIB_MAX_STACK_DEPTH * sizeof(stackframe_t))

#define BPF_LIB_MAX_KERNEL_STACK_DEPTH 32

#define BPF_LIB_DEFAULT_MAP_SIZE 1024

#endif // __BPF_LIB_STRUCTS_H__
