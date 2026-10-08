// SPDX-License-Identifier: GPL-2.0
/*
 * Python function trace (experimental): one event per entry to and exit from a
 * Python function, from uprobes on the interpreter itself. No ptrace and no
 * code of ours in the traced process; the kernel puts its breakpoints into
 * private copies of the probed code pages.
 *
 * Where the probes sit is decided in user space (src/python_function_trace):
 *
 *  - "dispatch" sites: the addresses the bytecode loop jumps to for the
 *    RESUME, RETURN_*, YIELD_VALUE and exception-handler opcodes, read out of
 *    the interpreter's own dispatch table. Every Python frame passes through
 *    them whether or not the call was inlined in the bytecode loop, so this
 *    works without perf trampolines (and with them). The frame is not in a
 *    register the ABI names there, so it is read from the thread state
 *    (PYFT_FRAME_TSTATE), found the way the stack walker finds it.
 *
 *  - "eval-frame" sites: entry to and return from _PyEval_EvalFrameDefault.
 *    That is one call per Python frame only while something has replaced the
 *    interpreter's frame evaluator -- which is what perf trampolines
 *    (-X perf, PYTHONPERFSUPPORT=1) do. The frame is the function's second
 *    argument (PYFT_FRAME_ARG2); the return is paired by stack pointer.
 *
 * Each attachment carries a cookie: the event kind in the low byte, where the
 * frame comes from in the next. One program serves every site.
 *
 * The symbol side is pystacks', compiled into this object as the task-stacks
 * recorder does: the names are read by get_names(), the id is the content
 * hash, the record rides ringbuf_pysym_events and user space marks an id
 * interned in pystacks_symbols. In front of that sits a cache keyed by the
 * code object's address, so the strings are read and hashed once per function
 * rather than once per call. These programs run in the traced thread's own
 * context with interrupts on, so unlike the sampler's probes they may update
 * a hash map: the locking rule in pystacks.bpf.c is about probes that run
 * with interrupts off, which these do not. That alone does not make the locks
 * safe, though: the kernel turns interrupts off itself before it waits for a
 * map's or a ring's lock, and on older kernels (the hash map's and ring's
 * locks changed in 6.15, the LRU lists' later) a waiter on a KVM guest with
 * paravirtual spinlocks can then halt with interrupts off. What keeps the
 * waits away is that user space traces one process at a time and, under its
 * GIL, one thread of it is in these programs at a time (and user space never
 * writes the cache), so nobody waits. That holds for one interpreter per
 * process: sub-interpreters with their own GIL run in parallel, and nothing
 * here detects them. Tracing more processes, or such a process, needs a ring
 * and a cache per producer first.
 */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "pystacks.bpf.c"

enum pyft_kind {
	PYFT_ENTER = 1,	  /* a frame starts or resumes running */
	PYFT_EXIT = 2,	  /* a frame returns */
	PYFT_YIELD = 3,	  /* a generator or coroutine frame suspends */
	PYFT_SYNC = 4,	  /* an exception handler starts in this frame */
	PYFT_EXIT_SP = 5, /* _PyEval_EvalFrameDefault returned (paired by sp) */
};

enum pyft_frame_source {
	PYFT_FRAME_TSTATE = 0, /* the thread state's current frame */
	PYFT_FRAME_ARG2 = 1,   /* the probed function's second argument */
	PYFT_FRAME_NONE = 2,   /* no frame: a return probe */
};

struct pyft_event {
	u64 ts;	       /* CLOCK_BOOTTIME ns */
	u64 frame;     /* the _PyInterpreterFrame, the identity events pair on */
	u64 symbol_id; /* pystacks symbol id; 0 where the kind needs none */
	u64 sp;	       /* eval-frame sites: the stack pointer after return */
	u32 tgid;
	u32 tid;
	u32 first_line; /* co_firstlineno */
	u8 kind;
	u8 pad[3];
};

/* Exposes the record type to the generated skeleton. */
struct pyft_event _pyft_event = {0};

enum pyft_counter {
	PYFT_C_EVENTS = 0,     /* events submitted */
	PYFT_C_DROPPED = 1,    /* the events ring was full */
	PYFT_C_NO_TSTATE = 2,  /* no thread state behind the TLS slot */
	PYFT_C_NO_FRAME = 3,   /* thread state without a current frame */
	PYFT_C_NO_CODE = 4,    /* the frame's code object could not be read */
	PYFT_C_SYM_SLOW = 5,   /* names read and hashed (cache miss) */
	PYFT_C_SYM_EMIT = 6,   /* symbol records sent to user space */
	PYFT_C_SYM_DROPPED = 7, /* the symbol ring was full */
	PYFT_NR_COUNTERS = 8,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PYFT_NR_COUNTERS);
	__type(key, u32);
	__type(value, u64);
} pyft_counters SEC(".maps");

/* Sized by user space before load. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024 * 1024);
} pyft_events SEC(".maps");

/*
 * A code object seen before, by process and address. The three words read
 * from the object on every call tell a live entry from an address the
 * allocator handed to another code object since.
 */
struct pyft_code_key {
	u64 code;
	u32 tgid;
	u32 pad;
};

struct pyft_code_val {
	u64 symbol_id;
	u64 filename; /* co_filename, the object's address */
	u64 qualname; /* co_qualname, the object's address */
	u64 last_emit; /* when its symbol record was last sent */
	u32 first_line;
	u32 interned; /* user space has the symbol: stop looking */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct pyft_code_key);
	__type(value, struct pyft_code_val);
} pyft_codes SEC(".maps");

/* A symbol user space has not acknowledged is sent again after this long. */
#define PYFT_REEMIT_NS (100ULL * 1000 * 1000)

static __always_inline void pyft_count(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&pyft_counters, &idx);

	if (v)
		*v += 1;
}

/*
 * Read the code object's names, hash them into the symbol id and, unless user
 * space already has that id, send the record. Returns the id, 0 on failure.
 */
static __noinline u64 pyft_intern(void *frame, void *code, pid_t tgid)
{
	struct sample_state_t *state = get_state();
	PyPidData *pid_data = bpf_map_lookup_elem(&pystacks_pid_config, &tgid);

	if (!state || !pid_data)
		return 0;

	pyft_count(PYFT_C_SYM_SLOW);
	state->offsets = pid_data->offsets;
	state->frame_ptr = frame;
	get_names(state, frame, code, false, NULL);

	symbol_id_t id = hash_symbol(&state->sym);

	if (bpf_map_lookup_elem(&pystacks_symbols, &id))
		return id;

	struct pystacks_symbol_record *rec =
		bpf_ringbuf_reserve(&ringbuf_pysym_events, sizeof(*rec), 0);
	if (!rec) {
		pyft_count(PYFT_C_SYM_DROPPED);
		return id;
	}
	rec->symbol_id = id;
	rec->sym = state->sym;
	rec->linetable = state->linetable;
	bpf_ringbuf_submit(rec, BPF_RB_NO_WAKEUP);
	pyft_count(PYFT_C_SYM_EMIT);
	return id;
}

/* The symbol id of the code object `frame` runs, through the cache. */
static __always_inline u64 pyft_symbol(void *frame, PyPidData *pid_data,
				       pid_t tgid, u64 now, u32 *first_line)
{
	const OffsetConfig *offsets = &pid_data->offsets;
	u64 code = 0;

	if (bpf_probe_read_user(&code, sizeof(code),
				frame + offsets->PyInterpreterFrame_code))
		return 0;
	/* 3.14 keeps the executable as a tagged reference. */
	code &= ~3ULL;
	if (!code)
		return 0;

	struct pyft_code_val seen = {};

	bpf_probe_read_user(&seen.filename, sizeof(seen.filename),
			    (void *)code + offsets->PyCodeObject_filename);
	bpf_probe_read_user(&seen.qualname, sizeof(seen.qualname),
			    (void *)code + offsets->PyCodeObject_qualname);
	bpf_probe_read_user(&seen.first_line, sizeof(seen.first_line),
			    (void *)code + offsets->PyCodeObject_firstlineno);
	*first_line = seen.first_line;

	struct pyft_code_key key = { .code = code, .tgid = tgid };
	struct pyft_code_val *val = bpf_map_lookup_elem(&pyft_codes, &key);

	if (val && val->filename == seen.filename &&
	    val->qualname == seen.qualname &&
	    val->first_line == seen.first_line) {
		if (val->interned)
			return val->symbol_id;
		if (bpf_map_lookup_elem(&pystacks_symbols, &val->symbol_id)) {
			val->interned = 1;
			return val->symbol_id;
		}
		if (now - val->last_emit < PYFT_REEMIT_NS)
			return val->symbol_id;
	}

	seen.symbol_id = pyft_intern(frame, (void *)code, tgid);
	if (!seen.symbol_id)
		return 0;
	seen.last_emit = now;
	bpf_map_update_elem(&pyft_codes, &key, &seen, BPF_ANY);
	return seen.symbol_id;
}

static __always_inline int pyft_handle(struct pt_regs *ctx)
{
	u64 cookie = bpf_get_attach_cookie(ctx);
	u8 kind = cookie & 0xff;
	u8 source = (cookie >> 8) & 0xff;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tgid = pid_tgid >> 32;

	PyPidData *pid_data = bpf_map_lookup_elem(&pystacks_pid_config, &tgid);
	if (!pid_data)
		return 0;

	u64 now = bpf_ktime_get_boot_ns();
	void *frame = NULL;
	u64 sp = 0;

	if (source == PYFT_FRAME_ARG2) {
		frame = (void *)PT_REGS_PARM2(ctx);
		sp = PT_REGS_SP(ctx);
#if __x86_64__
		/* The return address is still on the stack at entry. */
		sp += 8;
#endif
	} else if (source == PYFT_FRAME_TSTATE) {
		void *tstate = get_thread_state(pid_data, NULL);

		if (!tstate) {
			pyft_count(PYFT_C_NO_TSTATE);
			return 0;
		}
		frame = get_frame_ptr(tstate, &pid_data->offsets, false, NULL);
		if (!frame) {
			pyft_count(PYFT_C_NO_FRAME);
			return 0;
		}
	} else {
		sp = PT_REGS_SP(ctx);
	}

	u64 symbol_id = 0;
	u32 first_line = 0;

	if (kind == PYFT_ENTER || kind == PYFT_SYNC) {
		symbol_id = pyft_symbol(frame, pid_data, tgid, now, &first_line);
		if (!symbol_id) {
			pyft_count(PYFT_C_NO_CODE);
			return 0;
		}
	}

	/* No wakeup: user space polls the ring, so the traced thread never
	 * pays for waking the reader. */
	struct pyft_event *e =
		bpf_ringbuf_reserve(&pyft_events, sizeof(*e), 0);
	if (!e) {
		pyft_count(PYFT_C_DROPPED);
		return 0;
	}
	e->ts = now;
	e->frame = (u64)frame;
	e->symbol_id = symbol_id;
	e->sp = sp;
	e->tgid = tgid;
	e->tid = (u32)pid_tgid;
	e->first_line = first_line;
	e->kind = kind;
	e->pad[0] = e->pad[1] = e->pad[2] = 0;
	bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
	pyft_count(PYFT_C_EVENTS);
	return 0;
}

SEC("uprobe")
int pyft_site(struct pt_regs *ctx)
{
	return pyft_handle(ctx);
}

SEC("uretprobe")
int pyft_return(struct pt_regs *ctx)
{
	return pyft_handle(ctx);
}

char LICENSE[] SEC("license") = "GPL";
