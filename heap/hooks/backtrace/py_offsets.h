/*
 * CPython struct offsets the Python backtrace reads, by minor version.
 *
 * Rendered from systing's pystacks offsets (heap/src/hook_offsets.rs): do not
 * edit. `cargo test -p systing-heap hook_offsets` fails when this file and
 * those offsets differ, and rewrites it when run with
 * SYSTING_HEAP_UPDATE_OFFSETS=1.
 */
#ifndef SYSTING_HEAP_PY_OFFSETS_H
#define SYSTING_HEAP_PY_OFFSETS_H

/* An offset this version does not have. */
#define SHH_PY_NO_OFFSET 9999

struct shh_py_offsets {
	int minor;
	int ts_frame;
	int cframe_current_frame;
	int frame_code;
	int frame_previous;
	int frame_instr;
	int frame_owner;
	int ob_type;
	int code_firstlineno;
	int code_filename;
	int code_qualname;
	int code_linetable;
	int code_adaptive;
	int code_firsttraceable;
	int str_length;
	int str_state;
	int str_ascii_size;
	int str_compact_size;
	int bytes_size;
	int bytes_data;
};

static const struct shh_py_offsets shh_py_offsets[] = {
	{
		.minor = 12,
		.ts_frame = 56,
		.cframe_current_frame = 0,
		.frame_code = 0,
		.frame_previous = 8,
		.frame_instr = 56,
		.frame_owner = 70,
		.ob_type = 8,
		.code_firstlineno = 68,
		.code_filename = 112,
		.code_qualname = 128,
		.code_linetable = 136,
		.code_adaptive = 192,
		.code_firsttraceable = 176,
		.str_length = 16,
		.str_state = 32,
		.str_ascii_size = 40,
		.str_compact_size = 56,
		.bytes_size = 16,
		.bytes_data = 32,
	},
	{
		.minor = 13,
		.ts_frame = 72,
		.cframe_current_frame = SHH_PY_NO_OFFSET,
		.frame_code = 0,
		.frame_previous = 8,
		.frame_instr = 56,
		.frame_owner = 70,
		.ob_type = 8,
		.code_firstlineno = 68,
		.code_filename = 112,
		.code_qualname = 128,
		.code_linetable = 136,
		.code_adaptive = 200,
		.code_firsttraceable = 184,
		.str_length = 16,
		.str_state = 32,
		.str_ascii_size = 40,
		.str_compact_size = 56,
		.bytes_size = 16,
		.bytes_data = 32,
	},
	{
		.minor = 14,
		.ts_frame = 72,
		.cframe_current_frame = SHH_PY_NO_OFFSET,
		.frame_code = 0,
		.frame_previous = 8,
		.frame_instr = 56,
		.frame_owner = 74,
		.ob_type = 8,
		.code_firstlineno = 68,
		.code_filename = 112,
		.code_qualname = 128,
		.code_linetable = 136,
		.code_adaptive = 208,
		.code_firsttraceable = 192,
		.str_length = 16,
		.str_state = 32,
		.str_ascii_size = 40,
		.str_compact_size = 56,
		.bytes_size = 16,
		.bytes_data = 32,
	},
};

#endif
