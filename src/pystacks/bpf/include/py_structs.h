// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PYTHON_STRUCTS_H__
#define __BPF_LIB_PYTHON_STRUCTS_H__

#ifdef __cplusplus
#include <linux/bpf.h>
#include <cstdint>
#endif

#include "stack_walker.h"
#include "structs.h"

#define BPF_LIB_PYSTACKS_CLASS_NAME_LEN 128
#define BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN 96
#define BPF_LIB_PYSTACKS_FILE_NAME_LEN 192
#define BPF_LIB_PYSTACKS_QUAL_NAME_LEN \
  (BPF_LIB_PYSTACKS_CLASS_NAME_LEN + BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN)

enum {
  PYSTACKS_SUCCESS = 0,
  PYSTACKS_ERROR = 1,
  PYSTACKS_NON_PY_PROCESS = 2,
  PYSTACKS_PROG_NOT_SUPPORTED = 3,
};

// Define qualname separately because PyPerf needs a way to search qualnames in
// a BPF_HASH
struct read_qualified_name {
  char value[BPF_LIB_PYSTACKS_QUAL_NAME_LEN];
  uintptr_t fault_addr; // != 0 if fault
};

struct read_file_name {
  char value[BPF_LIB_PYSTACKS_FILE_NAME_LEN];
  uintptr_t fault_addr; // != 0 if fault
};

// IMPORTANT: pystacks_symbol struct is used as the key to the 'symbols' bpf
// map. Be careful about adding fields as any increase cardinality can degrade
// symbol quality.
//
// pystacks_symbol file names and qualified names are normally read directly
// from bpf_py_probe.bpf.c in get_names(). If a page fault occurs when trying to
// read either string then the read must retried later in user space. When a
// page fault occurs the original string address is saved in the 'fault_addr'
// field and the originating process is saved in 'fault_pid'.
struct pystacks_symbol {
  struct read_file_name filename;
  struct read_qualified_name qualname;
  pid_t fault_pid; // != 0 if fault
};

struct pystacks_message {
  struct sample_header header;
  int64_t probe_time_ns;

  uint8_t thread_state_match;
  uint8_t gil_state;
  uint8_t pthread_id_match;

  uint8_t stack_status;
  uint8_t async_stack_status;

  bool last_frame_statically_compiled;

  uint64_t stack_len;
  uint64_t max_stack_depth;

  struct stack_walker_frame buffer[BPF_LIB_MAX_STACK_DEPTH];
};

struct pystacks_line_table {
  uint32_t first_line; // 0 for unknown
  uint32_t length;
  uintptr_t addr;
  pid_t pid;
};

#endif
