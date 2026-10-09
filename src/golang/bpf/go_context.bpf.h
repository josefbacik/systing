/* SPDX-License-Identifier: GPL-2.0 */
/*
 * go_context.bpf.h - the BPF side of --include-go-context: for a CPU sample
 * of a Go program, the goroutine that was running and the profiler labels
 * it had (runtime/pprof.Do, SetGoroutineLabels).
 *
 * HOW IT WORKS. User space (src/golang/context/) reads each Go program's
 * executable and writes ONE recipe per process into go_context_recipes, keyed
 * by tgid: where the runtime keeps the running goroutine's g (a distance from
 * the thread pointer, read from the program's own code) and the layout of the
 * fields read in it, from the generated bindings of its Go version. For a
 * sample of the CURRENT thread the helper below then reads three words: g
 * from the thread pointer, and in g its id (goid) and its labels (a
 * *labelMap, nil without labels). The goroutine id is the sample's.
 *
 * Labels are a set of key/value strings the goroutine carries until it sets
 * others. A set travels to user space once per process: when a thread's
 * (goroutine, labels) pair is not the one it had at its last sample, the set
 * is copied, at most GO_CONTEXT_LABELS labels, keys and values cut at
 * GO_CONTEXT_KEY_MAX and GO_CONTEXT_VALUE_MAX bytes, into a record whose id
 * is a hash of what it holds. The sample carries that id. The id is of the
 * contents, not of the address: Go frees a set when no goroutine has it and
 * reuses its memory for the next, and a request's labels come and go that
 * way. A record whose id the process has sent already is discarded.
 *
 * WHAT IT NEVER DOES. As task_context_reader.bpf.h, whose checks and helpers
 * it uses: it reads only the current task's memory, with
 * bpf_probe_read_user() (which never faults a page in), at addresses inside
 * the user range; it never reads a task that is not current, a kernel or
 * io worker thread, an exiting thread or a vfork child; nothing in the
 * tracer's confidentiality mode; and a record leaves only whole, every byte
 * of it written. A process with no recipe costs one map lookup a sample.
 *
 * With the feature off (go_context_config.enabled == 0, the default) user
 * space creates none of the maps below and loads none of the programs, and
 * the call site is dead code the verifier prunes.
 */
#ifndef __GO_CONTEXT_BPF_H
#define __GO_CONTEXT_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* The thread pointer, the user-range test and the task flags. */
#include "task_context_reader.bpf.h"

#define GO_CONTEXT_LABELS 8
#define GO_CONTEXT_KEY_MAX 64
#define GO_CONTEXT_VALUE_MAX 128

const volatile struct go_context_config {
	u32 enabled; /* --include-go-context */
	u32 restricted; /* the tracer's confidentiality mode: read nothing */
	u32 labels_per_cpu_per_sec; /* label records one CPU may send a second */
	u32 execs_per_cpu_per_sec; /* exec notices one CPU may send a second */
} go_context_config = { 0 };

/* Why a call gave no goroutine, or what it did. A closed set, in the order
 * src/golang/context/mod.rs prints it. */
enum go_context_reason {
	GO_CONTEXT_R_SAME_LABELS = 0, /* goroutine read; its labels as last time */
	GO_CONTEXT_R_NO_LABELS, /* goroutine read; it has none */
	GO_CONTEXT_R_NEW_LABELS, /* labels copied and sent */
	GO_CONTEXT_R_LABELS_SENT_BEFORE, /* labels copied; the process had sent them */
	GO_CONTEXT_R_RESTRICTED,
	GO_CONTEXT_R_NO_USER_CONTEXT, /* not current, no user code, vfork child */
	GO_CONTEXT_R_TP_IMPLAUSIBLE, /* thread pointer or g out of the user range */
	GO_CONTEXT_R_G_READ_FAILED, /* g, or the words in it */
	GO_CONTEXT_R_SYSTEM_STACK, /* g0 or a signal stack: no goroutine */
	GO_CONTEXT_R_LABELS_READ_FAILED,
	GO_CONTEXT_R_LABELS_CUT, /* more labels, or longer ones, than a record holds */
	GO_CONTEXT_R_RATE_LIMITED, /* goroutine kept, labels not sent */
	GO_CONTEXT_R_RING_FULL, /* goroutine kept, labels not sent */
	GO_CONTEXT_R_SENT_FULL, /* the sent-sets table is full: may send again */
	GO_CONTEXT_R_EXEC_NOTICE_DROPPED,
	GO_CONTEXT_R_MAX,
};

/* One process's recipe, as user space found it (src/golang/context/recipe.rs). */
struct go_context_recipe {
	s64 g_tls_offset; /* &g's thread-local word - thread pointer */
	u64 goid; /* offsets in runtime.g */
	u64 labels;
	u64 label_map_list; /* offset of the []label in a labelMap */
	u64 label_size; /* one label: two strings */
	u64 label_key;
	u64 label_value;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct go_context_recipe);
	__uint(max_entries, 4096);
} go_context_recipes SEC(".maps");

/* tid -> what its last sample read, so that a thread that stays on one
 * goroutine with one label set copies the set once. Preallocated, never LRU:
 * the kind every program that records a sample may write (see
 * task_context_last_id). */
struct go_context_last {
	u64 goid;
	u64 labels; /* the labelMap's address */
	u64 labels_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct go_context_last);
	__uint(max_entries, 16384);
} go_context_last SEC(".maps");

/* The label sets each process has sent, by (tgid, image, id). When it is
 * full a set may be sent again; user space keeps one copy. */
struct go_context_sent_key {
	u32 tgid;
	u32 image;
	u64 id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct go_context_sent_key);
	__type(value, u8);
	__uint(max_entries, 65536);
} go_context_sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, GO_CONTEXT_R_MAX);
} go_context_stats SEC(".maps");

/* Per-CPU one-second budgets: slot 0 label records, slot 1 exec notices. */
struct go_context_budget {
	u64 window_start_ns;
	u64 used;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct go_context_budget);
	__uint(max_entries, 2);
} go_context_budgets SEC(".maps");

#define GO_CONTEXT_BUDGET_LABELS 0
#define GO_CONTEXT_BUDGET_EXECS 1

struct go_context_label {
	u16 key_len; /* bytes copied */
	u16 value_len;
	u32 reserved;
	char key[GO_CONTEXT_KEY_MAX];
	char value[GO_CONTEXT_VALUE_MAX];
};

/* A label set. Every byte is written before submit (the labels part is
 * cleared first) and the struct has no padding, so no byte of an earlier
 * record can ride out in it. */
struct go_context_labels_event {
	u64 ts;
	u32 tgid;
	u32 tid;
	u64 id;
	u32 image; /* low 32 bits of the mm's address, as task_context's */
	u32 count; /* labels in the record */
	struct go_context_label labels[GO_CONTEXT_LABELS];
};

_Static_assert(sizeof(struct go_context_label) == 8 + GO_CONTEXT_KEY_MAX + GO_CONTEXT_VALUE_MAX,
	       "go_context_label must have no padding");
_Static_assert(sizeof(struct go_context_labels_event) ==
		       32 + GO_CONTEXT_LABELS * sizeof(struct go_context_label),
	       "go_context_labels_event must have no padding");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} go_context_labels SEC(".maps");

/* "This process has a new image: look at it again." */
struct go_context_exec_event {
	u32 pid;
	u32 reserved;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} go_context_execs SEC(".maps");

static __always_inline void go_context_count(u32 reason)
{
	u32 key = reason;
	u64 *value = bpf_map_lookup_elem(&go_context_stats, &key);

	if (value)
		*value += 1;
}

/* One unit of this CPU's budget `which` for the current second, or false. */
static __always_inline bool go_context_take(u32 which, u64 now, u32 limit)
{
	u32 key = which;
	struct go_context_budget *b = bpf_map_lookup_elem(&go_context_budgets, &key);

	if (!b)
		return false;
	if (now - b->window_start_ns >= 1000000000ULL) {
		b->window_start_ns = now;
		b->used = 0;
	}
	if (b->used >= limit)
		return false;
	b->used += 1;
	return true;
}

/* One 8-byte word of the current task at `addr`; non-zero on failure. */
static __always_inline long go_context_word(u64 *dst, u64 addr)
{
	if (!task_context_user_range_ok(addr, sizeof(*dst)))
		return -1;
	return bpf_probe_read_user(dst, sizeof(*dst), (const void *)addr);
}

/*
 * Copy the label set at `map` (a labelMap) into `rec` and give it its id: a
 * hash of every byte of the labels part, which is cleared first, so the same
 * set gives the same id. False when it cannot be read.
 */
static __always_inline bool
go_context_copy_labels(const struct go_context_recipe *recipe, u64 map,
		       struct go_context_labels_event *rec)
{
	u64 list = 0, len = 0, hash = 0xcbf29ce484222325ULL;
	bool cut = false;
	u32 i;

	/* Cleared a word at a time, through a volatile pointer so that the
	 * compiler does not make it a memset, which BPF has none of at this
	 * size. */
	for (i = 0; i < sizeof(rec->labels) / 8; i++)
		((volatile u64 *)rec->labels)[i] = 0;
	if (go_context_word(&list, map + recipe->label_map_list) ||
	    go_context_word(&len, map + recipe->label_map_list + 8))
		return false;
	if (len > GO_CONTEXT_LABELS) {
		cut = true;
		len = GO_CONTEXT_LABELS;
	}
	rec->count = len;
	for (i = 0; i < GO_CONTEXT_LABELS; i++) {
		struct go_context_label *l = &rec->labels[i];
		u64 at = list + i * recipe->label_size;
		u64 key = 0, key_len = 0, value = 0, value_len = 0;
		u32 kn, vn;

		if (i >= len)
			break;
		if (go_context_word(&key, at + recipe->label_key) ||
		    go_context_word(&key_len, at + recipe->label_key + 8) ||
		    go_context_word(&value, at + recipe->label_value) ||
		    go_context_word(&value_len, at + recipe->label_value + 8))
			return false;
		if (key_len > GO_CONTEXT_KEY_MAX || value_len > GO_CONTEXT_VALUE_MAX)
			cut = true;
		kn = key_len > GO_CONTEXT_KEY_MAX ? GO_CONTEXT_KEY_MAX : key_len;
		vn = value_len > GO_CONTEXT_VALUE_MAX ? GO_CONTEXT_VALUE_MAX : value_len;
		/* The bounds again, past the compiler, for the verifier. */
		barrier_var(kn);
		barrier_var(vn);
		if (kn > GO_CONTEXT_KEY_MAX || vn > GO_CONTEXT_VALUE_MAX)
			return false;
		if (!task_context_user_range_ok(key, kn) ||
		    !task_context_user_range_ok(value, vn))
			return false;
		l->key_len = kn;
		l->value_len = vn;
		if (bpf_probe_read_user(l->key, kn, (const void *)key) ||
		    bpf_probe_read_user(l->value, vn, (const void *)value))
			return false;
	}
	if (cut)
		go_context_count(GO_CONTEXT_R_LABELS_CUT);

	/* FNV-1a over the labels part, a word at a time. */
	for (i = 0; i < sizeof(rec->labels) / 8; i++) {
		hash ^= ((u64 *)rec->labels)[i];
		hash *= 0x100000001b3ULL;
	}
	hash ^= rec->count;
	hash *= 0x100000001b3ULL;
	rec->id = hash ? hash : 1;
	return true;
}

/*
 * The goroutine the CURRENT thread was running at this sample, or 0 for none;
 * *labels_id gets the id of its label set, or 0 for none. `task` must be the
 * current task. Never inlined, as task_context_read_current() is not: its
 * frame stays off the emit path's.
 */
static __noinline u64 go_context_read_current(struct task_struct *task, u64 *labels_id)
{
	const struct go_context_recipe *recipe;
	struct go_context_labels_event *rec;
	struct go_context_last *last, now_last = {};
	struct go_context_sent_key sent = {};
	u64 tp, g = 0, goid = 0, labels = 0, now;
	u32 tgid = task->tgid;
	u32 tid = task->pid;
	u8 one = 1;

	*labels_id = 0;
	if (go_context_config.restricted) {
		go_context_count(GO_CONTEXT_R_RESTRICTED);
		return 0;
	}
#if !defined(__x86_64__)
	return 0;
#endif
	recipe = bpf_map_lookup_elem(&go_context_recipes, &tgid);
	if (!recipe)
		return 0;
	if ((u32)bpf_get_current_pid_tgid() != tid ||
	    (task->flags & TASK_CONTEXT_PF_NO_USER_CODE) ||
	    BPF_CORE_READ(task, vfork_done)) {
		go_context_count(GO_CONTEXT_R_NO_USER_CONTEXT);
		return 0;
	}

	tp = task_context_thread_pointer(task);
	if (!task_context_user_range_ok(tp, 0)) {
		go_context_count(GO_CONTEXT_R_TP_IMPLAUSIBLE);
		return 0;
	}
	if (go_context_word(&g, tp + (u64)recipe->g_tls_offset)) {
		go_context_count(GO_CONTEXT_R_G_READ_FAILED);
		return 0;
	}
	if (!task_context_user_range_ok(g, 0)) {
		go_context_count(g ? GO_CONTEXT_R_TP_IMPLAUSIBLE : GO_CONTEXT_R_SYSTEM_STACK);
		return 0;
	}
	if (go_context_word(&goid, g + recipe->goid) ||
	    go_context_word(&labels, g + recipe->labels)) {
		go_context_count(GO_CONTEXT_R_G_READ_FAILED);
		return 0;
	}
	/* g0 (the scheduler's and the system stack's) has id 0. */
	if (!goid) {
		go_context_count(GO_CONTEXT_R_SYSTEM_STACK);
		return 0;
	}
	if (!labels) {
		go_context_count(GO_CONTEXT_R_NO_LABELS);
		return goid;
	}

	last = bpf_map_lookup_elem(&go_context_last, &tid);
	if (last && last->goid == goid && last->labels == labels && last->labels_id) {
		go_context_count(GO_CONTEXT_R_SAME_LABELS);
		*labels_id = last->labels_id;
		return goid;
	}

	now = bpf_ktime_get_boot_ns();
	if (!go_context_take(GO_CONTEXT_BUDGET_LABELS, now,
			     go_context_config.labels_per_cpu_per_sec)) {
		go_context_count(GO_CONTEXT_R_RATE_LIMITED);
		return goid;
	}
	rec = bpf_ringbuf_reserve(&go_context_labels, sizeof(*rec), 0);
	if (!rec) {
		go_context_count(GO_CONTEXT_R_RING_FULL);
		return goid;
	}
	if (!go_context_copy_labels(recipe, labels, rec)) {
		bpf_ringbuf_discard(rec, 0);
		go_context_count(GO_CONTEXT_R_LABELS_READ_FAILED);
		return goid;
	}
	rec->ts = now;
	rec->tgid = tgid;
	rec->tid = tid;
	rec->image = (u32)(unsigned long)BPF_CORE_READ(task, mm);

	now_last.goid = goid;
	now_last.labels = labels;
	now_last.labels_id = rec->id;
	*labels_id = rec->id;
	sent.tgid = tgid;
	sent.image = rec->image;
	sent.id = rec->id;
	if (bpf_map_lookup_elem(&go_context_sent, &sent)) {
		bpf_ringbuf_discard(rec, 0);
		go_context_count(GO_CONTEXT_R_LABELS_SENT_BEFORE);
	} else {
		bpf_ringbuf_submit(rec, 0);
		go_context_count(GO_CONTEXT_R_NEW_LABELS);
		if (bpf_map_update_elem(&go_context_sent, &sent, &one, BPF_NOEXIST))
			go_context_count(GO_CONTEXT_R_SENT_FULL);
	}
	bpf_map_update_elem(&go_context_last, &tid, &now_last, BPF_ANY);
	return goid;
}

/*
 * A recipe does not outlive its image: exec drops it and asks user space to
 * look at the new image (only for a process the capture targets, within a
 * per-CPU budget: user space opens its executable); the last thread's exit
 * drops it (see task_context_exit for why the thread's own entry goes
 * first). A forked child gets none: a Go program forks only to exec. Loaded
 * only with the feature, and they do nothing in the confidentiality mode.
 */
static __always_inline bool go_context_active(void)
{
	return go_context_config.enabled && !go_context_config.restricted;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(go_context_exec, struct task_struct *task, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct go_context_exec_event *e;
	u32 tgid = task->tgid, tid = task->pid, old_tid = old_pid;

	if (!go_context_active())
		return 0;
	bpf_map_delete_elem(&go_context_recipes, &tgid);
	bpf_map_delete_elem(&go_context_last, &tid);
	if (old_tid != tid)
		bpf_map_delete_elem(&go_context_last, &old_tid);

	if (!task_in_target_set(task))
		return 0;
	if (!go_context_take(GO_CONTEXT_BUDGET_EXECS, bpf_ktime_get_boot_ns(),
			     go_context_config.execs_per_cpu_per_sec)) {
		go_context_count(GO_CONTEXT_R_EXEC_NOTICE_DROPPED);
		return 0;
	}
	e = bpf_ringbuf_reserve(&go_context_execs, sizeof(*e), 0);
	if (!e) {
		go_context_count(GO_CONTEXT_R_EXEC_NOTICE_DROPPED);
		return 0;
	}
	e->pid = tgid;
	e->reserved = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(go_context_exit, struct task_struct *task)
{
	u32 tgid = task->tgid, tid = task->pid;

	if (!go_context_active())
		return 0;
	bpf_map_delete_elem(&go_context_last, &tid);
	if (BPF_CORE_READ(task, signal, live.counter) == 0)
		bpf_map_delete_elem(&go_context_recipes, &tgid);
	return 0;
}

#endif /* __GO_CONTEXT_BPF_H */
