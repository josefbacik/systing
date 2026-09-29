/*
 * systing-heap hooks: the "python" backtrace. A sampled allocation's stack is
 * jemalloc's own native backtrace followed by the Python frames of the thread
 * that allocated, so systing-heap can show each Python function, with its
 * file and line, among the native frames. No perf trampolines, no libunwind.
 *
 * It runs inside malloc, in a process that is not ours, on threads that
 * mostly do not hold the GIL. The rules that follow from that:
 *
 *   - A thread walks only its own frames. CPython links a frame into a
 *     thread's chain once it is initialized and unlinks it before tearing it
 *     down, and a thread that has released the GIL leaves its chain as it
 *     was, so at a call boundary (malloc is one) the chain is whole.
 *   - No pointer that came from Python is dereferenced. Everything Python
 *     owns is read with process_vm_readv on ourselves (or /proc/self/mem
 *     where seccomp refuses that): the kernel copies, and a bad address is an
 *     error, not a fault. A refused read ends the walk; the native stack is
 *     recorded either way.
 *   - Nothing of Python's is called but two getters that only read a
 *     thread-local, and the finalizing flag. The GIL is never taken, no
 *     reference count is touched, nothing is allocated.
 *   - Every loop and length is bounded, and what is read is checked for what
 *     it should be (a code object's type, a str's, a bytes') before it is
 *     used, so mapped garbage gives a short or unnamed stack.
 *
 * jemalloc keeps a stack as a list of addresses, so a Python frame is stored
 * as one 64-bit slot no real address can equal (SHH_PY_TAG in its top 16
 * bits, which no user-space address has):
 *
 *     tag:16 | code id:24 | instruction index + 1:24
 *
 * The code id names a code object in the code map, a file written beside the
 * dumps with one line per code object the first time a walk meets it: its
 * qualified name, file, first line and line table, as raw bytes. systing-heap
 * decodes them. Id 0 marks an interpreter entry frame (one per C call into
 * the bytecode loop), which is what lets systing-heap put each run of Python
 * frames where its native loop frame is.
 *
 * A dump says which code map is its own: the process holds a mapping named
 * systing-pycode-<token>, the dump carries the process's maps, and the map
 * file is pycode-<pid>-<token>.map. A process that got a recycled pid cannot
 * name another's frames.
 *
 * A forked child keeps the ids it was forked with: jemalloc keeps the stacks
 * sampled before the fork, and the child's dumps hold them. Its own map, under
 * a token of its own, begins with the lines its parent had written by then,
 * and its ids go on from the parent's.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "py_offsets.h"
#include "systing_heap_hooks.h"
#include "systing_heap_hooks_python.h"

/* A slot is 64 bits in an array of addresses. */
_Static_assert(sizeof(void *) == sizeof(uint64_t), "the python backtrace needs 64-bit addresses");

#define SHH_PY_TAG ((uint64_t)0x5059 << 48)
#define SHH_PY_ID_SHIFT 24
#define SHH_PY_FIELD_MAX 0xffffffu
/* A frame whose code object could not be recorded. */
#define SHH_PY_ID_UNKNOWN SHH_PY_FIELD_MAX

/* Python's share of a stack, entry frames included; the innermost are kept.
 * jemalloc 5.3 holds 128 addresses in all. */
#define MAX_SLOTS 64
/* Frames visited in one walk, whatever they turn out to be. */
#define MAX_STEPS 1024
#define FRAME_BUF 128
#define CODE_BUF 256
#define MAX_NAME_CHARS 1024
#define MAX_FILE_CHARS 4096
#define MAX_LINETABLE 65536
/* The most a process writes to its code map: systing-heap reads no map
 * larger than 256 MiB, and one that grows without end (a program that keeps
 * making code) names nothing once it is past that. */
#define MAX_MAP_BYTES (128u << 20)
/* Code objects recorded per process; a walk past it stores unknown ids. */
#define TABLE_SLOTS (1u << 17)
#define TABLE_FULL (TABLE_SLOTS / 4 * 3)
#define MAX_PROBES 64

/* _PyInterpreterFrame.owner of a generator's or coroutine's frame. */
#define OWNED_BY_GENERATOR 1
/* _PyInterpreterFrame.owner from which a frame is the interpreter's own:
 * FRAME_OWNED_BY_CSTACK in 3.12 and 3.13, and FRAME_OWNED_BY_INTERPRETER (3)
 * and FRAME_OWNED_BY_CSTACK (4) in 3.14. */
#define FIRST_NON_PYTHON_OWNER 3
/* 3.14 keeps a frame's code as a tagged reference: the low bits are flags. */
#define STACKREF_TAG_MASK ((uintptr_t)3)

/* PyASCIIObject.state: interned:2, kind:3, compact:1, ascii:1, the same in
 * every GIL build this supports (systing's pyobject.rs reads it the same). */
#define STATE_KIND(s) (((s) >> 2) & 7)
#define STATE_COMPACT(s) (((s) >> 5) & 1)
#define STATE_ASCII(s) (((s) >> 6) & 1)

enum { READ_PVR = 1, READ_MEM = 2 };

struct entry {
	uintptr_t code; /* 0: empty */
	/* What the code object held when it was recorded: another code object
	 * at the same address later differs here and gets an id of its own. */
	uintptr_t qualname, filename, linetable;
	int32_t firstlineno;
	uint32_t id;
};

typedef void *(*getter_fn)(void);
typedef int (*flag_fn)(void);

static const struct shh_py_offsets *off;
static unsigned frame_len, code_len;
static getter_fn attached_p, gilstate_p;
static flag_fn finalizing_p;
static uintptr_t code_type, str_type, bytes_type;
static shh_backtrace_fn native_p;
/* This library's own hook, to drop its frame from the native stack. */
static uintptr_t self_start, self_end;

static int read_mode;
/* /proc/self/mem, and which file that is: the program may close descriptors
 * it did not open, and the number then names a file of its own. */
static int mem_fd = -1;
static dev_t mem_dev;
static ino_t mem_ino;

static _Atomic int enabled;
static _Atomic int active;

/* Guards the table, the code map and the buffers below; held by the fork
 * handlers across a fork, so the child's copies are whole. */
static pthread_mutex_t py_lock = PTHREAD_MUTEX_INITIALIZER;
static struct entry *table;
static unsigned table_used;
static uint32_t next_id;
static pid_t table_pid;
/* The page whose name carries the token into the process's maps. */
static void *marker;
/* The code map: made when the process installs the backtrace, and in a
 * forked child when it first has a line to write (most children exec). It is
 * opened for each line and closed again: a descriptor kept open is one the
 * program may close and reuse, and the next line would go to its file. */
static int map_made;
static int map_failed;
static size_t map_bytes;
/* Which file the map is, and how the last line left it: it is opened by its
 * path for each line, and what is at the path by then must be the file that
 * was made, as it was left. The number of a file that is gone is given to
 * the next one made, so the number alone does not say so; a file's size and
 * the time of its last change do, and nobody sets that time. */
static dev_t map_dev;
static ino_t map_ino;
static off_t map_size;
static struct timespec map_changed;
static char map_dir[3072];
static char map_path[sizeof(map_dir) + 64];
static char map_head[128];
static char token[17];
/* In a forked child: the map its first lines are copied from, past that
 * map's own header, and how many bytes of it were written by the fork. */
static char inherit_path[sizeof(map_path)];
static size_t inherit_skip;
static size_t inherit_bytes;
static dev_t inherit_dev;
static ino_t inherit_ino;
static int py_minor;
/* One code-map line, and what it is built from: static, because a walk runs
 * on whatever stack the allocating thread has left. */
static unsigned char data_buf[MAX_LINETABLE > MAX_FILE_CHARS * 4 ? MAX_LINETABLE : MAX_FILE_CHARS * 4];
static char rec_buf[64 + 2 * (MAX_NAME_CHARS * 4 + MAX_FILE_CHARS * 4 + MAX_LINETABLE) + 16];

/* ---- protected reads ---------------------------------------------------- */

/* Whether `p` can be the address of `len` bytes of an object at all: cheap,
 * and the kernel decides the rest. */
static inline int plausible(uintptr_t p, size_t len)
{
	return p >= 0x10000 && !(p & 7) && !((p + len) >> 56);
}

static int rd(void *dst, uintptr_t src, size_t len, pid_t pid)
{
	if (!plausible(src, len))
		return -1;
	if (read_mode == READ_MEM)
		return pread(mem_fd, dst, len, (off_t)src) == (ssize_t)len ? 0 : -1;
	struct iovec l = {dst, len}, r = {(void *)src, len};
	return process_vm_readv(pid, &l, 1, &r, 1, 0) == (ssize_t)len ? 0 : -1;
}

/*
 * Two reads in one call where the kernel can: bit 0 set when the first was
 * read, bit 1 when the second was. A walk needs a frame's code object and
 * the frame before it at the same moment, so this halves its system calls.
 */
static int rd2(void *dst1, uintptr_t src1, size_t len1, void *dst2,
	       uintptr_t src2, size_t len2, pid_t pid)
{
	int want2 = src2 != 0 && plausible(src2, len2);
	if (read_mode == READ_PVR && want2 && plausible(src1, len1)) {
		struct iovec l[2] = {{dst1, len1}, {dst2, len2}};
		struct iovec r[2] = {{(void *)src1, len1}, {(void *)src2, len2}};
		ssize_t got = process_vm_readv(pid, l, 2, r, 2, 0);
		if (got == (ssize_t)(len1 + len2))
			return 3;
		/* A transfer stops where it first cannot read: with all of
		 * the first read, it is the second that is bad. */
		if (got >= (ssize_t)len1)
			return 1;
		/* The first is bad; the second was never tried. */
		return rd(dst2, src2, len2, pid) == 0 ? 2 : 0;
	}
	int ok = rd(dst1, src1, len1, pid) == 0 ? 1 : 0;
	if (want2 && rd(dst2, src2, len2, pid) == 0)
		ok |= 2;
	return ok;
}

/* Close our descriptor on /proc/self/mem, if the number still names it: the
 * program may have closed it and opened a file of its own there. */
static void close_mem(void)
{
	struct stat st;
	if (mem_fd >= 0 && fstat(mem_fd, &st) == 0 && st.st_dev == mem_dev &&
	    st.st_ino == mem_ino)
		close(mem_fd);
	mem_fd = -1;
}

static int open_mem(void)
{
	struct stat st;
	close_mem();
	mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
	if (mem_fd < 0 || fstat(mem_fd, &st) != 0)
		return -1;
	mem_dev = st.st_dev;
	mem_ino = st.st_ino;
	return 0;
}

/* Whether reads can be made: with /proc/self/mem, that the descriptor is
 * still that file, opening it again if the program closed ours. */
static int can_read(void)
{
	struct stat st;
	if (read_mode != READ_MEM)
		return 1;
	if (fstat(mem_fd, &st) == 0 && st.st_dev == mem_dev && st.st_ino == mem_ino)
		return 1;
	return open_mem() == 0;
}

static inline uintptr_t ptr_at(const unsigned char *buf, int o)
{
	uintptr_t v;
	memcpy(&v, buf + o, sizeof(v));
	return v;
}

/* ---- the code map ------------------------------------------------------- */

static const char hexdigits[] = "0123456789abcdef";

static size_t put_hex(char *out, const unsigned char *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		out[2 * i] = hexdigits[p[i] >> 4];
		out[2 * i + 1] = hexdigits[p[i] & 15];
	}
	return 2 * n;
}

/* Digits are written by hand on the paths that run inside malloc: printf
 * may allocate. */
static size_t put_uint(char *out, uint64_t v, unsigned base)
{
	char tmp[24];
	size_t n = 0;
	do {
		tmp[n++] = hexdigits[v % base];
		v /= base;
	} while (v);
	for (size_t i = 0; i < n; i++)
		out[i] = tmp[n - 1 - i];
	return n;
}

static size_t put_int(char *out, int64_t v)
{
	if (v >= 0)
		return put_uint(out, (uint64_t)v, 10);
	out[0] = '-';
	return 1 + put_uint(out + 1, (uint64_t)(-(v + 1)) + 1, 10);
}

/* "<kind>:<hex>" for the str at `s`, its characters as stored (kind 1, 2 or
 * 4 bytes each); "0:" for anything that is not a str to be read whole. */
static size_t put_str(char *out, uintptr_t s, long max_chars, pid_t pid)
{
	unsigned char head[64];
	size_t o = 0;
	/* The part every str has: a short one ends before the rest would. */
	if (rd(head, s, (size_t)off->str_ascii_size, pid) == 0 &&
	    ptr_at(head, off->ob_type) == str_type) {
		uint32_t state;
		memcpy(&state, head + off->str_state, sizeof(state));
		long chars = (long)ptr_at(head, off->str_length);
		unsigned kind = STATE_KIND(state);
		if (STATE_COMPACT(state) && chars >= 0 && chars <= max_chars &&
		    (kind == 1 || kind == 2 || kind == 4)) {
			size_t bytes = (size_t)chars * kind;
			uintptr_t text = s + (STATE_ASCII(state)
						      ? (uintptr_t)off->str_ascii_size
						      : (uintptr_t)off->str_compact_size);
			if (bytes == 0 || rd(data_buf, text, bytes, pid) == 0) {
				out[o++] = (char)('0' + kind);
				out[o++] = ':';
				return o + put_hex(out + o, data_buf, bytes);
			}
		}
	}
	out[o++] = '0';
	out[o++] = ':';
	return o;
}

/* The hex of the bytes object at `b`, "-" for none that can be read whole. */
static size_t put_bytes(char *out, uintptr_t b, pid_t pid)
{
	unsigned char head[64];
	if (rd(head, b, (size_t)off->bytes_data, pid) == 0 &&
	    ptr_at(head, off->ob_type) == bytes_type) {
		long n = (long)ptr_at(head, off->bytes_size);
		if (n > 0 && n <= MAX_LINETABLE &&
		    rd(data_buf, b + (uintptr_t)off->bytes_data, (size_t)n, pid) == 0)
			return put_hex(out, data_buf, (size_t)n);
	}
	out[0] = '-';
	return 1;
}

/* One code-map line for the code object whose header is `code`:
 * "<id> <first line> <kind>:<qualname> <kind>:<file> <line table>\n". */
static size_t put_record(char *out, uint32_t id, const unsigned char *code,
			 pid_t pid)
{
	int32_t first;
	memcpy(&first, code + off->code_firstlineno, sizeof(first));
	size_t o = put_uint(out, id, 16);
	out[o++] = ' ';
	o += put_int(out + o, first);
	out[o++] = ' ';
	o += put_str(out + o, ptr_at(code, off->code_qualname), MAX_NAME_CHARS, pid);
	out[o++] = ' ';
	o += put_str(out + o, ptr_at(code, off->code_filename), MAX_FILE_CHARS, pid);
	out[o++] = ' ';
	o += put_bytes(out + o, ptr_at(code, off->code_linetable), pid);
	out[o++] = '\n';
	return o;
}

static int write_all(int fd, const char *p, size_t n)
{
	while (n) {
		ssize_t w = write(fd, p, n);
		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0)
			return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

/*
 * The lines a forked child's ids were recorded with, from the map of the
 * process it was forked from into its own. What cannot be copied is left
 * out: those ids then name nothing, which is what an id without a line does.
 */
static void copy_inherited(int fd)
{
	struct stat st;
	int from = open(inherit_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (from < 0)
		return;
	/* A regular file with the parent's number, holding at least what the
	 * parent had written: the parent may have written more since. Its
	 * lines are taken as they are. Whoever can write this folder can write
	 * any map in it, this process's own included, and the dumps. */
	if (fstat(from, &st) != 0 || !S_ISREG(st.st_mode) || st.st_dev != inherit_dev ||
	    st.st_ino != inherit_ino ||
	    st.st_size < (off_t)(inherit_skip + inherit_bytes)) {
		close(from);
		return;
	}
	off_t at = (off_t)inherit_skip;
	size_t left = inherit_bytes;
	while (left) {
		size_t want = left < sizeof(data_buf) ? left : sizeof(data_buf);
		ssize_t got = pread(from, data_buf, want, at);
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0 || write_all(fd, (const char *)data_buf, (size_t)got) != 0)
			break;
		at += got;
		left -= (size_t)got;
		map_bytes += (size_t)got;
	}
	close(from);
}

/* Add `n` bytes to the code map, making it (with its header, and in a forked
 * child the lines it inherited) the first time. A map that cannot be written
 * names nothing more.
 *
 * This runs inside malloc, and the folder may be one others can write: the
 * open never waits (a FIFO put at the path would hold it for a reader), and
 * what is written to is a regular file, the one that was made. */
static int append_map(const char *p, size_t n)
{
	if (map_failed || map_bytes + n > MAX_MAP_BYTES)
		return -1;
	struct stat st;
	int flags = O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
	int fd = open(map_path, map_made ? flags : flags | O_CREAT | O_EXCL, 0644);
	int ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
	if (ok && map_made)
		ok = st.st_dev == map_dev && st.st_ino == map_ino &&
		     st.st_size == map_size &&
		     st.st_ctim.tv_sec == map_changed.tv_sec &&
		     st.st_ctim.tv_nsec == map_changed.tv_nsec;
	ok = ok && (map_made || write_all(fd, map_head, strlen(map_head)) == 0);
	if (ok && !map_made && inherit_bytes)
		copy_inherited(fd);
	ok = ok && (n == 0 || write_all(fd, p, n) == 0);
	/* As this line leaves it, for the next. */
	ok = ok && fstat(fd, &st) == 0;
	if (ok) {
		map_dev = st.st_dev;
		map_ino = st.st_ino;
		map_size = st.st_size;
		map_changed = st.st_ctim;
	}
	if (fd >= 0)
		close(fd);
	map_made = 1;
	map_failed = !ok;
	map_bytes += n;
	return ok ? 0 : -1;
}

/* The id of the code object at `co`, recording it the first time. */
static uint32_t intern(uintptr_t co, const unsigned char *code, pid_t pid)
{
	uintptr_t qualname = ptr_at(code, off->code_qualname);
	uintptr_t filename = ptr_at(code, off->code_filename);
	uintptr_t linetable = ptr_at(code, off->code_linetable);
	int32_t first;
	memcpy(&first, code + off->code_firstlineno, sizeof(first));

	uint32_t id = SHH_PY_ID_UNKNOWN;
	pthread_mutex_lock(&py_lock);
	if (!table || pid != table_pid)
		goto out;
	/* Objects are 16-byte aligned: the low bits say nothing. */
	uint64_t h = (uint64_t)(co >> 4) * 0x9e3779b97f4a7c15ull;
	struct entry *e = NULL;
	for (unsigned i = 0; i < MAX_PROBES; i++) {
		struct entry *c = &table[((h >> 40) + i) & (TABLE_SLOTS - 1)];
		if (c->code == co) {
			if (c->qualname == qualname && c->filename == filename &&
			    c->linetable == linetable && c->firstlineno == first) {
				id = c->id;
				goto out;
			}
			e = c; /* the address has another code object now */
			break;
		}
		if (!c->code) {
			if (table_used < TABLE_FULL) {
				e = c;
				table_used++;
			}
			break;
		}
	}
	if (!e || next_id >= SHH_PY_ID_UNKNOWN)
		goto out;
	size_t n = put_record(rec_buf, next_id, code, pid);
	if (append_map(rec_buf, n) != 0) {
		if (e->code != co)
			table_used--;
		goto out;
	}
	id = next_id++;
	*e = (struct entry){co, qualname, filename, linetable, first, id};
out:
	pthread_mutex_unlock(&py_lock);
	return id;
}

/* ---- the walk ----------------------------------------------------------- */

struct seen {
	uintptr_t code; /* 0: an entry frame */
	uint32_t index; /* instruction index + 1; 0: before the first */
};

static inline uint32_t index_of(uintptr_t instr, uintptr_t co)
{
	intptr_t lasti = (intptr_t)(instr - (co + (uintptr_t)off->code_adaptive));
	/* Not started yet, or not an address in this code object at all. */
	if (lasti < 0)
		return 0;
	uintptr_t units = (uintptr_t)lasti / 2 + 1;
	return units > SHH_PY_FIELD_MAX ? 0 : (uint32_t)units;
}

/*
 * Whether a frame has reached its code's first traceable instruction. One
 * that has not is still being set up, or is the interpreter's stand-in around
 * a call (the frame that calls __init__ for a class, from 3.13): Python
 * itself leaves such frames out of every stack it shows
 * (_PyFrame_IsIncomplete), and so does this. A generator's frame is always
 * whole.
 */
static inline int started(const unsigned char *frame, const unsigned char *code,
			  uintptr_t co)
{
	int32_t first;
	if (frame[off->frame_owner] == OWNED_BY_GENERATOR)
		return 1;
	memcpy(&first, code + off->code_firsttraceable, sizeof(first));
	if (first < 0)
		return 1;
	return ptr_at(frame, off->frame_instr) >=
	       co + (uintptr_t)off->code_adaptive + 2 * (uintptr_t)first;
}

/*
 * The calling thread's frames, innermost first: `emit` is called for each
 * with the frame's code header (NULL for an entry frame) until it returns 0.
 * Returns how many were emitted.
 */
static unsigned walk(unsigned max, pid_t pid,
		     int (*emit)(void *ctx, const struct seen *,
				 const unsigned char *code),
		     void *ctx)
{
	/* A thread Python has never seen has no state, and nothing of
	 * Python's is touched for it. */
	uintptr_t ts = (uintptr_t)gilstate_p();
	if (!ts)
		return 0;
	uintptr_t attached = (uintptr_t)attached_p();
	if (attached)
		ts = attached;

	uintptr_t f = 0;
	if (rd(&f, ts + (uintptr_t)off->ts_frame, sizeof(f), pid) != 0)
		return 0;
	if (off->cframe_current_frame != SHH_PY_NO_OFFSET &&
	    rd(&f, f + (uintptr_t)off->cframe_current_frame, sizeof(f), pid) != 0)
		return 0;

	unsigned char bufs[2][FRAME_BUF], code[CODE_BUF];
	int cur = 0, have = 0;
	unsigned n = 0;
	for (unsigned steps = 0; f && n < max && steps < MAX_STEPS; steps++) {
		unsigned char *frame = bufs[cur];
		if (!have && rd(frame, f, frame_len, pid) != 0)
			break;
		have = 0;
		uintptr_t previous = ptr_at(frame, off->frame_previous);
		struct seen s = {0, 0};
		if (frame[off->frame_owner] >= FIRST_NON_PYTHON_OWNER) {
			if (!emit(ctx, &s, NULL))
				break;
			n++;
			f = previous;
			continue;
		}
		uintptr_t co = ptr_at(frame, off->frame_code) & ~STACKREF_TAG_MASK;
		int got = rd2(code, co, code_len, bufs[!cur], previous, frame_len, pid);
		if ((got & 1) && ptr_at(code, off->ob_type) == code_type &&
		    started(frame, code, co)) {
			s.code = co;
			s.index = index_of(ptr_at(frame, off->frame_instr), co);
			if (!emit(ctx, &s, code))
				break;
			n++;
		}
		if (got & 2) {
			cur = !cur;
			have = 1;
		}
		f = previous;
	}
	return n;
}

/* Whether a walk may run now; a walk that may is counted until walk_end(). */
static int walk_begin(void)
{
	if (!atomic_load(&enabled) || shh_forking_here())
		return 0;
	atomic_fetch_add(&active, 1);
	/* stop() clears `enabled` and then waits for `active`. */
	if (!atomic_load(&enabled) || (finalizing_p && finalizing_p()) || !can_read()) {
		atomic_fetch_sub(&active, 1);
		return 0;
	}
	return 1;
}

static void walk_end(void)
{
	atomic_fetch_sub(&active, 1);
}

struct slots {
	uint64_t slot[MAX_SLOTS]; /* innermost first */
	unsigned n;
	pid_t pid;
};

static int emit_slot(void *ctx, const struct seen *s, const unsigned char *code)
{
	struct slots *out = ctx;
	uint64_t id = code ? intern(s->code, code, out->pid) : 0;
	out->slot[out->n++] = SHH_PY_TAG | id << SHH_PY_ID_SHIFT | (code ? s->index : 0);
	return out->n < MAX_SLOTS;
}

void systing_heap_hooks_python_backtrace(void **vec, unsigned *len,
					 unsigned max_len)
{
	/* The native stack as jemalloc asks for it: its own backtraces are
	 * written for the whole array (one ignores a smaller length, and a
	 * debug build asserts it was given none), so nothing of ours is in
	 * the array while one runs. */
	*len = 0;
	native_p(vec, len, max_len);
	unsigned n = *len > max_len ? max_len : *len;

	/* Drop this function's frame, so the stack starts where jemalloc's
	 * own does. It is among the first few, wherever the unwinder starts. */
	for (unsigned i = 0; i < n && i < 4; i++) {
		uintptr_t pc = (uintptr_t)vec[i];
		if (pc >= self_start && pc < self_end) {
			memmove(vec + i, vec + i + 1, (n - i - 1) * sizeof(*vec));
			n--;
			break;
		}
	}
	*len = n;
	if (max_len < 2 * MAX_SLOTS || !walk_begin())
		return;

	/* The Python frames follow the native ones, which give up their
	 * outermost frames where the two do not fit. */
	struct slots py;
	py.n = 0;
	py.pid = getpid();
	/* A forked child's map is made with its first walk, not with the first
	 * function that is new to it: a dump of its own may hold nothing but
	 * stacks sampled before the fork. */
	if (!map_made) {
		pthread_mutex_lock(&py_lock);
		if (!map_made && table_pid == py.pid)
			append_map(NULL, 0);
		pthread_mutex_unlock(&py_lock);
	}
	walk(MAX_SLOTS, py.pid, emit_slot, &py);
	walk_end();
	if (n > max_len - py.n)
		n = max_len - py.n;
	memcpy(vec + n, py.slot, py.n * sizeof(py.slot[0]));
	*len = n + py.n;
}

/* ---- starting, stopping, forking ---------------------------------------- */

static void make_token(void)
{
	uint64_t r = 0;
	if (getrandom(&r, sizeof(r), GRND_NONBLOCK) != (ssize_t)sizeof(r)) {
		struct timespec t;
		clock_gettime(CLOCK_REALTIME, &t);
		r = ((uint64_t)t.tv_sec << 30 ^ (uint64_t)t.tv_nsec) *
			    0x9e3779b97f4a7c15ull ^
		    (uint64_t)getpid() << 17;
	}
	for (int i = 0; i < 16; i++)
		token[i] = hexdigits[(r >> (60 - 4 * i)) & 15];
	token[16] = 0;
}

/*
 * A code map of this process's own, named by a new token; its file is made
 * with its first line. It also runs in a forked child, which keeps the table
 * and the ids it was forked with.
 */
static int name_map(void)
{
	char name[64];
	long page = sysconf(_SC_PAGESIZE);
	if (marker) {
		munmap(marker, (size_t)page);
		marker = NULL;
	}
	map_made = 0;
	map_failed = 0;
	map_bytes = 0;
	table_pid = getpid();
	make_token();

	/* The mapping's name is how a dump, which carries the process's
	 * maps, says which code map is its own. */
	snprintf(name, sizeof(name), "systing-pycode-%s", token);
	int fd = memfd_create(name, MFD_CLOEXEC);
	if (fd < 0)
		return SHH_ERR_PY_MAP;
	void *p = MAP_FAILED;
	if (ftruncate(fd, page) == 0)
		p = mmap(NULL, (size_t)page, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED)
		return SHH_ERR_PY_MAP;
	marker = p;

	snprintf(map_path, sizeof(map_path), "%s/pycode-%d-%s.map", map_dir,
		 (int)table_pid, token);
	snprintf(map_head, sizeof(map_head),
		 "# systing-pycode 1 token=%s pid=%d python=3.%d\n", token,
		 (int)table_pid, py_minor);
	return SHH_OK;
}

/* An empty table and a code map, its file made now: a folder that cannot be
 * written is known at install. */
static int start_map(void)
{
	if (table)
		munmap(table, TABLE_SLOTS * sizeof(*table));
	table = mmap(NULL, TABLE_SLOTS * sizeof(*table), PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (table == MAP_FAILED) {
		table = NULL;
		return SHH_ERR_PY_MAP;
	}
	table_used = 0;
	next_id = 1;
	inherit_bytes = 0;
	int rc = name_map();
	if (rc == SHH_OK && append_map(NULL, 0) != 0)
		rc = SHH_ERR_PY_MAP;
	return rc;
}

/* A way to read our own memory that fails on a bad address, proved on a
 * good one and on a bad one. */
static int find_read_path(void)
{
	static const uint64_t probe = 0x73797374696e6721ull;
	/* An address with nothing mapped at it: a page just unmapped. */
	void *hole = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (hole == MAP_FAILED)
		return SHH_ERR_PY_READ;
	munmap(hole, 4096);
	for (int mode = READ_PVR; mode <= READ_MEM; mode++) {
		if (mode == READ_MEM && open_mem() != 0)
			continue;
		read_mode = mode;
		uint64_t got = 0;
		if (rd(&got, (uintptr_t)&probe, sizeof(got), getpid()) == 0 &&
		    got == probe &&
		    rd(&got, (uintptr_t)hole, sizeof(got), getpid()) != 0)
			return SHH_OK;
	}
	read_mode = 0;
	close_mem();
	return SHH_ERR_PY_READ;
}

static unsigned span(unsigned have, int offset, unsigned size)
{
	unsigned end = (unsigned)offset + size;
	return end > have ? end : have;
}

int shh_python_prepare(shh_mallctl_fn mallctl, shh_backtrace_fn native)
{
	if (atomic_load(&enabled))
		return SHH_OK;

	const unsigned long *version = dlsym(RTLD_DEFAULT, "Py_Version");
	gilstate_p = (getter_fn)dlsym(RTLD_DEFAULT, "PyGILState_GetThisThreadState");
	/* The same function: 3.13 gave it its public name. */
	attached_p = (getter_fn)dlsym(RTLD_DEFAULT, "PyThreadState_GetUnchecked");
	if (!attached_p)
		attached_p = (getter_fn)dlsym(RTLD_DEFAULT, "_PyThreadState_UncheckedGet");
	finalizing_p = (flag_fn)dlsym(RTLD_DEFAULT, "Py_IsFinalizing");
	if (!finalizing_p)
		finalizing_p = (flag_fn)dlsym(RTLD_DEFAULT, "_Py_IsFinalizing");
	code_type = (uintptr_t)dlsym(RTLD_DEFAULT, "PyCode_Type");
	str_type = (uintptr_t)dlsym(RTLD_DEFAULT, "PyUnicode_Type");
	bytes_type = (uintptr_t)dlsym(RTLD_DEFAULT, "PyBytes_Type");
	if (!version || !gilstate_p || !attached_p || !code_type || !str_type ||
	    !bytes_type)
		return SHH_ERR_NO_PYTHON;

	const struct shh_py_offsets *found = NULL;
	py_minor = (int)((*version >> 16) & 0xff);
	if (*version >> 24 == 3)
		for (size_t i = 0; i < sizeof(shh_py_offsets) / sizeof(shh_py_offsets[0]); i++)
			if (shh_py_offsets[i].minor == py_minor)
				found = &shh_py_offsets[i];
	if (!found)
		return SHH_ERR_PY_VERSION;
	off = found;
	frame_len = span(span(span(span(0, off->frame_code, 8), off->frame_previous, 8),
			      off->frame_instr, 8),
			 off->frame_owner, 1);
	frame_len = (frame_len + 7) & ~7u;
	code_len = span(span(span(span(span(span(0, off->ob_type, 8), off->code_firstlineno, 4),
				       off->code_filename, 8),
				  off->code_qualname, 8),
			     off->code_linetable, 8),
			off->code_firsttraceable, 4);
	code_len = (code_len + 7) & ~7u;
	if (frame_len > FRAME_BUF || code_len > CODE_BUF ||
	    off->str_compact_size > 64 || off->bytes_data > 64)
		return SHH_ERR_PY_VERSION;

	int rc = find_read_path();
	if (rc != SHH_OK)
		return rc;

	/* The code map goes beside the dumps, so it travels with them. */
	const char *prefix = NULL;
	size_t prefix_len = sizeof(prefix);
	if (mallctl("opt.prof_prefix", &prefix, &prefix_len, NULL, 0) != 0 || !prefix)
		prefix = "";
	const char *slash = strrchr(prefix, '/');
	size_t dir_len = slash ? (size_t)(slash - prefix) : 0;
	if (dir_len >= sizeof(map_dir)) {
		close_mem();
		return SHH_ERR_PY_MAP;
	}
	if (slash == prefix)
		strcpy(map_dir, "/");
	else if (dir_len)
		memcpy(map_dir, prefix, dir_len), map_dir[dir_len] = 0;
	else
		strcpy(map_dir, ".");

#ifdef __GLIBC__
	/* This function's extent, from the dynamic symbol table. Without it
	 * (another libc) its frame stays in the stacks. */
	Dl_info info;
	const ElfW(Sym) *sym = NULL;
	if (dladdr1((void *)systing_heap_hooks_python_backtrace, &info, (void **)&sym,
		    RTLD_DL_SYMENT) &&
	    sym && sym->st_size) {
		self_start = (uintptr_t)info.dli_saddr;
		self_end = self_start + sym->st_size;
	}
#endif

	pthread_mutex_lock(&py_lock);
	rc = start_map();
	pthread_mutex_unlock(&py_lock);
	if (rc != SHH_OK) {
		close_mem();
		return rc;
	}
	native_p = native;
	atomic_store(&enabled, 1);
	return SHH_OK;
}

void systing_heap_hooks_python_stop(void)
{
	atomic_store(&enabled, 0);
	/* A walk is microseconds; one that is stuck is not waited out. */
	for (int i = 0; i < 100000 && atomic_load(&active); i++)
		sched_yield();
	/* Nothing reads any more: the process's memory is not left open. Not
	 * under a walk that is still running, which reads through it: closed
	 * there, the number could come to name a file of the program's before
	 * the walk's next read. A forked child closes it in any case. */
	if (!atomic_load(&active))
		close_mem();
}

void shh_python_before_fork(void)
{
	pthread_mutex_lock(&py_lock);
}

void shh_python_after_fork_parent(void)
{
	pthread_mutex_unlock(&py_lock);
}

void shh_python_after_fork_child(void)
{
	/* The child's only thread is this one. */
	pthread_mutex_init(&py_lock, NULL);
	atomic_store(&active, 0);
	/* /proc/self/mem, opened in the parent, is the parent's memory: the
	 * child does not keep it, whatever it goes on to do or become, and
	 * whether or not the backtrace is in use. */
	close_mem();
	if (!atomic_load(&enabled))
		return;
	/* The stacks sampled so far are the child's too, under the ids they
	 * were recorded with: it keeps the table, and its map will begin with
	 * the lines written by now. A parent that never made a map of its own
	 * passes on what it inherited. */
	if (map_made) {
		memcpy(inherit_path, map_path, sizeof(inherit_path));
		inherit_skip = strlen(map_head);
		inherit_bytes = map_bytes;
		inherit_dev = map_dev;
		inherit_ino = map_ino;
	}
	/* The map is the child's own, under its own token: another child of
	 * this parent may get this one's pid later. */
	if (name_map() != SHH_OK || find_read_path() != SHH_OK) {
		atomic_store(&enabled, 0);
		close_mem();
	}
}

/* ---- the self-test ------------------------------------------------------ */

/*
 * What a walk of the calling thread finds, as text: "entry" for an entry
 * frame, "<code address> <instruction index + 1> <code-map line>" for a
 * Python frame, innermost first. The caller compares it with what Python
 * itself says its stack is before the hook is installed.
 */

struct check {
	char *buf;
	size_t cap, len;
	pid_t pid;
};

static int emit_check(void *ctx, const struct seen *s, const unsigned char *code)
{
	struct check *out = ctx;
	char head[64];
	size_t h, n = 0;
	if (code) {
		h = (size_t)sprintf(head, "%lx %u ", (unsigned long)s->code, s->index);
		n = put_record(rec_buf, 0, code, out->pid);
	} else {
		h = (size_t)sprintf(head, "entry\n");
	}
	if (out->cap - out->len < h + n + 1)
		return 0;
	memcpy(out->buf + out->len, head, h);
	memcpy(out->buf + out->len + h, rec_buf, n);
	out->len += h + n;
	return 1;
}

int systing_heap_hooks_python_check(char *buf, size_t cap)
{
	if (!atomic_load(&enabled))
		return -SHH_ERR_NO_PYTHON;
	if (!walk_begin())
		return -SHH_ERR_NO_PYTHON;
	struct check out = {buf, cap, 0, getpid()};
	pthread_mutex_lock(&py_lock);
	unsigned n = walk(MAX_STEPS, out.pid, emit_check, &out);
	pthread_mutex_unlock(&py_lock);
	walk_end();
	if (out.len < cap)
		buf[out.len] = 0;
	return (int)n;
}

const char *systing_heap_hooks_python_map(void)
{
	return atomic_load(&enabled) ? map_path : "";
}
