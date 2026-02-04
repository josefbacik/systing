// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_STACK_READER_H__
#define __BPF_LIB_STACK_READER_H__

#ifndef __cplusplus
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <stddef.h>
#include <sys/types.h>
#include <cstdint>
#endif

// the sample was not of the same type as the handler
#define STACK_WALKER_INCORRECT_TYPE 1

// the sample was not valid / could not be unpacked
#define STACK_WALKER_INVALID_SAMPLE 2

// the run pointer was not valid
#define STACK_WALKER_INVALID_RUN 3

#define STACK_WALKER_SYMBOL_NOT_FOUND 4

#define STACK_WALKER_GARBLED_SYMBOL 5

#define STACK_WALKER_BUFFER_TOO_SMALL 6

#define STACK_WALKER_NO_LINE_INFORMATION std::numeric_limits<uint32_t>::max()

struct stack_walker_discovery_opts;

struct stack_walker_opts {
  size_t pidCount;
  pid_t* pids;
  bool manualSymbolRefresh;
};

// @lint-ignore-every CLANGTIDY modernize-use-using
typedef uint32_t symbol_id_t;

struct stack_walker_frame {
  symbol_id_t symbol_id;
  int32_t inst_idx;
};

#ifdef __cplusplus
extern "C" {

struct stack_walker {
  struct stack_walker_run* (*init)(
      struct bpf_object*,
      struct stack_walker_opts&,
      struct stack_walker_discovery_opts*);
  void (*free)(struct stack_walker_run*);

  int (*symbolize_function)(
      struct stack_walker_run* run,
      const struct stack_walker_frame& stackframe,
      char* function_name_buffer,
      size_t function_name_len);

  int (*symbolize_filename_line)(
      struct stack_walker_run* run,
      const struct stack_walker_frame& stackframe,
      char* filename_buffer,
      size_t filename_len,
      size_t& line_number);
};

typedef int (*load_stack_walker_func)(struct stack_walker*);

} // extern "C"
#endif // __cplusplus

#endif
