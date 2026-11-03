// SPDX-License-Identifier: GPL-2.0
/*
 * The python-function-trace recorder: one event per entry to and exit from a
 * Python function, from uprobes on the interpreter itself. No ptrace and no
 * code of ours in the traced process; the kernel puts its breakpoints into
 * private copies of the probed code pages.
 *
 * Where the probes sit is decided in user space (src/python_function_trace):
 * the addresses the bytecode loop jumps to for the RESUME, RETURN_*,
 * YIELD_VALUE and exception-handler opcodes, read out of the interpreter's own
 * dispatch table. Every Python frame passes through them whether or not the
 * call was inlined in the bytecode loop, so this works with and without perf
 * trampolines. The frame is not in a register the ABI names there, so it is
 * read from the thread state, found the way the stack walker finds it.
 *
 * Each attachment carries the event kind as its cookie. One program serves
 * every site of every traced process.
 *
 * It shares the main object's state rather than keeping its own: userspace
 * points this object's target, pystacks and missed-event maps and its ring family
 * at the main object's before load (src/python_function_trace), so one target set
 * and one set of Python processes serve every recorder. Its probes check the
 * targets as every other recorder's do: a process that leaves a --cgroup target
 * stops being recorded at once, though it pays until its probes come out.
 *
 * The locking rule is pystacks.bpf.c's, and these programs keep it although
 * they run with interrupts on: the kernel turns interrupts off itself before
 * it waits for a map's or a ring's lock, so a waiter can halt the vCPU just as
 * a sampler's can. So, as the main object's samplers do, a probe takes no lock
 * another CPU is using: events and symbol records go to this CPU's ring
 * (cpu % pyft_nr_rings, the layout of plan_ringbufs()), the code cache is a
 * per-CPU array, and only user space writes the hash maps. How many processes
 * are traced does not matter to any of this, nor does how many GILs they have.
 *
 * Unlike a sampler these run with preemption on (migration off, so the CPU
 * stays the same), so two programs can be under way on one CPU, and the
 * per-CPU scratch and cache entry of one can change under the other. The only
 * place that writes either is pyft_slow_path(), and it runs alone on its CPU:
 * see pyft_busy.
 */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "pystacks.bpf.c"

#include "systing_shared.bpf.h"

enum pyft_kind {
	PYFT_ENTER = 1, /* a frame starts or resumes running */
	PYFT_EXIT = 2,	/* a frame returns */
	PYFT_YIELD = 3, /* a generator or coroutine frame suspends */
	PYFT_SYNC = 4,	/* an exception handler starts in this frame */
	PYFT_EXEC = 5,	/* the process replaced its image: its frames are gone */
};

struct pyft_event {
	struct task_info task;
	u64 ts;	       /* CLOCK_BOOTTIME ns */
	u64 frame;     /* the _PyInterpreterFrame, the identity events pair on */
	u64 symbol_id; /* pystacks symbol id; 0 where the kind needs none */
	u32 first_line; /* co_firstlineno */
	u8 kind;
	u8 pad[3];
};

/* Exposes the record type to the generated skeleton. */
struct pyft_event _pyft_event = {0};

enum pyft_counter {
	PYFT_C_EVENTS = 0,     /* events submitted */
	PYFT_C_NO_TSTATE = 1,  /* no thread state behind the TLS slot */
	PYFT_C_NO_FRAME = 2,   /* thread state without a current frame */
	PYFT_C_NO_CODE = 3,    /* the frame's code object could not be read */
	PYFT_C_SYM_SLOW = 4,   /* names read and hashed (cache miss) */
	PYFT_C_SYM_EMIT = 5,   /* symbol records sent to user space */
	PYFT_C_SYM_DROPPED = 6, /* the ring was full for a symbol record */
	PYFT_C_SYM_BUSY = 7,   /* a miss met another miss on its CPU */
	PYFT_C_BEGUN = 8,      /* entry and handler events submitted */
	PYFT_C_HITS = 9,       /* every run of the probe */
	PYFT_C_NOT_TARGETED = 10, /* the process is out of the target set */
	PYFT_C_NO_CONFIG = 11, /* pystacks has no config for the process */
	PYFT_NR_COUNTERS = 12,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PYFT_NR_COUNTERS);
	__type(key, u32);
	__type(value, u64);
} pyft_counters SEC(".maps");

/*
 * The rings: events and symbol records, told apart by their size. The outer map
 * is the main object's python_function_ringbufs (a family of RINGBUF_FAMILIES),
 * reused at load: this is its template, with its pollers and its sizes.
 */
#define PYFT_NR_RINGS_MAX 64

/* Set by user space before load: how many slots of the family are filled, and
 * how much data in a ring wakes its poller (tool_config.wakeup_data_size). */
const volatile u32 pyft_nr_rings = 1;
const volatile u64 pyft_wakeup_bytes = 0;

struct pyft_ring {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, PYFT_NR_RINGS_MAX);
	__type(key, u32);
	__array(values, struct pyft_ring);
} python_function_ringbufs SEC(".maps");

/* The main object's, reused at load: must match its definition. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MISSED_EVENT_MAX);
} missed_events SEC(".maps");

static __always_inline void pyft_missed(void)
{
	u32 idx = MISSED_PYTHON_FUNCTION_EVENT;
	u64 *v = bpf_map_lookup_elem(&missed_events, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* As the main object's get_ringbuf_flags(): the traced thread pays for a wakeup
 * only when its ring is half full. */
static __always_inline long pyft_ring_flags(void *rb)
{
	if (!pyft_wakeup_bytes)
		return 0;
	return bpf_ringbuf_query(rb, BPF_RB_AVAIL_DATA) >= pyft_wakeup_bytes ?
		       BPF_RB_FORCE_WAKEUP :
		       BPF_RB_NO_WAKEUP;
}

static __always_inline void pyft_task_info(struct task_info *info,
					   struct task_struct *task)
{
	info->tgidpid = bpf_get_current_pid_tgid();
	info->cgid = task_cg_id(task);
	bpf_get_current_comm(info->comm, sizeof(info->comm));
}

/* This CPU's ring. */
static __always_inline void *pyft_ring(void)
{
	u32 idx = bpf_get_smp_processor_id() % pyft_nr_rings;

	return bpf_map_lookup_elem(&python_function_ringbufs, &idx);
}

/*
 * A code object seen before on this CPU, direct-mapped by process and address.
 * The three words read from the object on every call tell a live entry from an
 * address the allocator handed to another code object since. A slot two code
 * objects share only costs misses.
 */
#define PYFT_CODE_SLOTS 4096

struct pyft_code_slot {
	u64 code;      /* 0: empty, or being written */
	u64 symbol_id;
	u64 filename;  /* co_filename, the object's address */
	u64 qualname;  /* co_qualname, the object's address */
	u64 last_emit; /* when its symbol record was last sent */
	u32 tgid;
	u32 first_line;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PYFT_CODE_SLOTS);
	__type(key, u32);
	__type(value, struct pyft_code_slot);
} pyft_codes SEC(".maps");

/*
 * Who on this CPU is in pyft_slow_path(). A program that finds it taken was
 * preempted into, or preempted, another's use of the per-CPU scratch: it
 * neither reads a name nor touches a cache entry, and its event goes without
 * (pairing copes with a lost event; a function that is called again gets its
 * name then). Atomic, since a preemption can fall between a read and a write.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} pyft_busy SEC(".maps");

/* A symbol user space has not acknowledged is sent again after this long. */
#define PYFT_REEMIT_NS (100ULL * 1000 * 1000)

static __always_inline void pyft_count(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&pyft_counters, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/*
 * Read the code object's names, hash them into the symbol id and, unless user
 * space already has that id, send the record. Returns the id, 0 on failure.
 */
static __noinline u64 pyft_intern(void *frame, void *code, pid_t tgid)
{
	struct sample_state_t *state = get_state();
	PyPidData *pid_data = bpf_map_lookup_elem(&pystacks_pid_config, &tgid);
	void *rb = pyft_ring();

	if (!state || !pid_data || !rb)
		return 0;

	pyft_count(PYFT_C_SYM_SLOW);
	state->offsets = pid_data->offsets;
	state->frame_ptr = frame;
	get_names(state, frame, code, false, NULL);

	symbol_id_t id = hash_symbol(&state->sym);

	if (bpf_map_lookup_elem(&pystacks_symbols, &id))
		return id;

	struct pystacks_symbol_record *rec =
		bpf_ringbuf_reserve(rb, sizeof(*rec), 0);
	if (!rec) {
		pyft_count(PYFT_C_SYM_DROPPED);
		return id;
	}
	rec->symbol_id = id;
	rec->sym = state->sym;
	rec->linetable = state->linetable;
	/* A wakeup, unlike an event, and a forced one, with events queued ahead of
	 * it: until user space has the name, the function pays to send it again. */
	bpf_ringbuf_submit(rec, BPF_RB_FORCE_WAKEUP);
	pyft_count(PYFT_C_SYM_EMIT);
	return id;
}

/*
 * A code object the cache cannot answer for: alone on this CPU, name it and
 * write its cache entry, with the address last so that nothing preempted into
 * the writes takes the entry for a whole one. Returns the id, 0 on failure.
 */
static __always_inline u64 pyft_slow_path(void *frame, void *code, pid_t tgid,
					  u64 now,
					  struct pyft_code_slot *slot,
					  const struct pyft_code_slot *seen)
{
	u32 *busy = bpf_map_lookup_elem(&pyft_busy, &zero);
	u64 id;

	if (!busy)
		return 0;
	if (__sync_lock_test_and_set(busy, 1)) {
		pyft_count(PYFT_C_SYM_BUSY);
		return 0;
	}
	id = pyft_intern(frame, code, tgid);
	if (id) {
		*(volatile u64 *)&slot->code = 0;
		slot->symbol_id = id;
		slot->filename = seen->filename;
		slot->qualname = seen->qualname;
		slot->last_emit = now;
		slot->tgid = tgid;
		slot->first_line = seen->first_line;
		/* volatile: the compiler keeps the two stores around these. */
		*(volatile u64 *)&slot->code = (u64)code;
	}
	__sync_lock_test_and_set(busy, 0);
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

	struct pyft_code_slot seen = {};

	bpf_probe_read_user(&seen.filename, sizeof(seen.filename),
			    (void *)code + offsets->PyCodeObject_filename);
	bpf_probe_read_user(&seen.qualname, sizeof(seen.qualname),
			    (void *)code + offsets->PyCodeObject_qualname);
	bpf_probe_read_user(&seen.first_line, sizeof(seen.first_line),
			    (void *)code + offsets->PyCodeObject_firstlineno);
	*first_line = seen.first_line;

	u32 idx = (u32)((code >> 4) ^ tgid) % PYFT_CODE_SLOTS;
	struct pyft_code_slot *slot = bpf_map_lookup_elem(&pyft_codes, &idx);

	if (!slot)
		return 0;
	/* The id first: an entry rewritten under this read then fails the
	 * comparison below, or was rewritten for this same code object. */
	u64 symbol_id = *(volatile u64 *)&slot->symbol_id;

	if (slot->code == code && slot->tgid == (u32)tgid &&
	    slot->filename == seen.filename &&
	    slot->qualname == seen.qualname &&
	    slot->first_line == seen.first_line) {
		/* User space has the symbol, or was told of it just now. */
		if (bpf_map_lookup_elem(&pystacks_symbols, &symbol_id) ||
		    now - slot->last_emit < PYFT_REEMIT_NS)
			return symbol_id;
	}
	return pyft_slow_path(frame, (void *)code, tgid, now, slot, &seen);
}

SEC("uprobe")
int pyft_site(struct pt_regs *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	u8 kind = bpf_get_attach_cookie(ctx) & 0xff;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tgid = pid_tgid >> 32;

	pyft_count(PYFT_C_HITS);
	if (!current_in_target_set(task)) {
		pyft_count(PYFT_C_NOT_TARGETED);
		return 0;
	}
	PyPidData *pid_data = bpf_map_lookup_elem(&pystacks_pid_config, &tgid);
	if (!pid_data) {
		pyft_count(PYFT_C_NO_CONFIG);
		return 0;
	}

	u64 now = bpf_ktime_get_boot_ns();
	void *tstate = get_thread_state(pid_data, NULL);

	if (!tstate) {
		pyft_count(PYFT_C_NO_TSTATE);
		return 0;
	}
	void *frame = get_frame_ptr(tstate, &pid_data->offsets, false, NULL);

	if (!frame) {
		pyft_count(PYFT_C_NO_FRAME);
		return 0;
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

	void *rb = pyft_ring();

	if (!rb) {
		pyft_missed();
		return 0;
	}
	struct pyft_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
	if (!e) {
		pyft_missed();
		return 0;
	}
	pyft_task_info(&e->task, task);
	e->ts = now;
	e->frame = (u64)frame;
	e->symbol_id = symbol_id;
	e->first_line = first_line;
	e->kind = kind;
	e->pad[0] = e->pad[1] = e->pad[2] = 0;
	bpf_ringbuf_submit(e, pyft_ring_flags(rb));
	pyft_count(PYFT_C_EVENTS);
	if (kind == PYFT_ENTER || kind == PYFT_SYNC)
		pyft_count(PYFT_C_BEGUN);
	return 0;
}

/* An exec ends every frame of the process, with no event of its own. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(pyft_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (!current_in_target_set(task))
		return 0;

	void *rb = pyft_ring();

	if (!rb)
		return 0;
	struct pyft_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
	if (!e) {
		pyft_missed();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	pyft_task_info(&e->task, task);
	e->ts = bpf_ktime_get_boot_ns();
	e->kind = PYFT_EXEC;
	bpf_ringbuf_submit(e, pyft_ring_flags(rb));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
