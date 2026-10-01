//! What a backtrace may not do. It runs inside malloc, on top of whatever
//! called malloc, in the middle of that caller's work, and the dynamic loader is
//! not made to be entered again. A backtrace finds out whether the loader called
//! malloc before it calls anything (`hooks/backtrace/caller.c`).
//!
//! Every thread has a table of its thread-local blocks, with room for 14 more
//! libraries than there were when it was made. Once more than that have been
//! loaded, each thread grows its own with realloc(), the next time it reads a
//! thread-local variable through `__tls_get_addr()`. If that call is sampled and
//! the backtrace reads such a variable, its own or one of a library it calls, the
//! loader starts the same update again and reallocates the same table. The outer
//! realloc() then frees a block that has been freed: from there on the allocator
//! can give the same memory out twice. "libunwind" did this through libunwind's
//! variables, and "python" through the interpreter's, where libpython is a shared
//! library.
//!
//! `hooks/README.md` has the whole account, and who else has met it.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::{Duration, Instant};

use common::HOOKS;

/// Enough libraries for a table to grow several times, the first of which, for
/// the thread a program starts with, is not by realloc().
const LIBRARIES: usize = 64;

/// What the shim ends the process with when it sees a table reallocated inside
/// its own reallocation.
const CAUGHT: i32 = 42;

const THREAD_LOCAL_C: &str = r#"
static __thread long v = 1;
long touch(void) { return ++v; }
"#;

// Goes in front of jemalloc. What it keeps for each thread it reaches without
// the loader, as a library a program starts with can. SHIM_FRAMES puts that many
// more frames between malloc's caller and jemalloc, as a chain of wrappers around
// the allocator would. SHIM_FAR puts one there that is larger than what the look at
// the stack covers.
const SHIM_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#define PER_THREAD static __thread __attribute__((tls_model("initial-exec")))
static void *(*next)(void *, size_t);
static int frames, far;
PER_THREAD int depth;
PER_THREAD void *outer;
__attribute__((noinline)) static void *through(int more, void *p, size_t n)
{
    void *r = more ? through(more - 1, p, n) : next(p, n);
    __asm__ volatile("" ::: "memory"); /* so that the call is not the last thing done */
    return r;
}
__attribute__((noinline)) static void *from_afar(void *p, size_t n)
{
    volatile char frame[8192];
    for (size_t i = 0; i < sizeof frame; i++)
        frame[i] = 0;
    void *r = next(p, n);
    __asm__ volatile("" ::: "memory");
    return r;
}
__attribute__((constructor)) static void start(void)
{
    const char *more = getenv("SHIM_FRAMES");
    frames = more ? atoi(more) : 0;
    far = getenv("SHIM_FAR") != NULL;
    next = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
}
void *realloc(void *p, size_t n)
{
    if (!next)
        start();
    if (depth > 0 && p && p == outer) {
        static const char said[] = "realloc() of a block from inside realloc() of it\n";
        if (write(2, said, sizeof said - 1) < 0) {}
        _exit(42);
    }
    if (depth == 0)
        outer = p;
    depth++;
    void *r = far ? from_afar(p, n) : through(frames, p, n);
    depth--;
    return r;
}
"#;

// A backtrace that breaks the rule in the smallest way there is.
const BREAKS_THE_RULE_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
typedef void (*backtrace_fn)(void **, unsigned *, unsigned);
static __thread volatile unsigned long calls;
static backtrace_fn jemallocs_own;
static void counts_its_calls(void **vec, unsigned *len, unsigned max_len)
{
    calls++;
    jemallocs_own(vec, len, max_len);
}
int systing_heap_hooks_install(const char *backtrace)
{
    (void)backtrace;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    backtrace_fn mine = counts_its_calls;
    size_t len = sizeof(jemallocs_own);
    return mallctl("experimental.hooks.prof_backtrace", &jemallocs_own, &len, &mine, sizeof(mine));
}
"#;

// Loads the libraries one after another and touches each one's variable, as a
// program that imports extension modules does.
const LOADS_LIBRARIES_C: &str = r#"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    if (argc != 5)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    int rc = ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))(argv[2]);
    if (rc != 0) {
        fprintf(stderr, "install: %d\n", rc);
        return 2;
    }
    // Sampling, if it was off, is on from here.
    bool on = true;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    if (mallctl("prof.active", NULL, NULL, &on, sizeof on) != 0)
        return 2;
    for (int i = 0; i < atoi(argv[4]); i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/thread_local_%d.so", argv[3], i);
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!lib) {
            fprintf(stderr, "%s\n", dlerror());
            return 2;
        }
        ((long (*)(void))dlsym(lib, "touch"))();
    }
    return 0;
}
"#;

// What a service with many threads does when it imports something late: some of
// the libraries are loaded, threads are started and wait, the rest are loaded,
// and every thread then reads a thread-local variable it has read before.
// Sampling, if it was off, is on from just before they do.
const LOADS_LIBRARIES_LATE_C: &str = r#"
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define THREADS 32
static long (*touch)(void);
static atomic_int started, go;
static void *thread(void *arg)
{
    (void)arg;
    touch();
    started++;
    while (!go)
        usleep(1000);
    touch();
    return NULL;
}
static int load(const char *dir, int from, int to)
{
    for (int i = from; i < to; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/thread_local_%d.so", dir, i);
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!lib)
            return -1;
        if (!touch)
            touch = (long (*)(void))dlsym(lib, "touch");
    }
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 5)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks || ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))(argv[2]) != 0)
        return 2;
    // The libunwind a test asked for is the one in use.
    const char *libunwind = getenv("SYSTING_HEAP_HOOKS_LIBUNWIND");
    if (libunwind && !strcmp(argv[2], "libunwind") && !dlopen(libunwind, RTLD_NOW | RTLD_NOLOAD))
        return 3;
    int libraries = atoi(argv[4]);
    if (load(argv[3], 0, libraries / 2) != 0)
        return 2;
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++)
        if (pthread_create(&threads[i], NULL, thread, NULL) != 0)
            return 2;
    while (started < THREADS)
        usleep(1000);
    if (load(argv[3], libraries / 2, libraries) != 0)
        return 2;
    bool on = true;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    if (mallctl("prof.active", NULL, NULL, &on, sizeof on) != 0)
        return 2;
    go = 1;
    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);
    return 0;
}
"#;

// What libunwind is to the hooks, as far as thread-local variables go: two words
// of them, read at every unw_backtrace().
const READS_ITS_CACHE_C: &str = r#"
static __thread void *volatile cache;
static __thread volatile long destroyed;
int unw_backtrace(void **vec, int max)
{
    if (destroyed || max < 2)
        return 0;
    cache = vec;
    vec[0] = vec[1] = (void *)unw_backtrace;
    return 2;
}
"#;

// Goes in front of libc: the walk through the libraries that was asked for stays
// where it is, with the loader's lock held, until another thread has forked or
// has had 300 ms to.
const HOLDS_THE_WALK_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdatomic.h>
#include <unistd.h>
typedef int (*callback)(struct dl_phdr_info *, size_t, void *);
static atomic_int walks_to_go, held, forked;
struct inner {
    callback call;
    void *data;
    int hold;
};
static int slowly(struct dl_phdr_info *info, size_t size, void *data)
{
    struct inner *inner = data;
    if (inner->hold) {
        inner->hold = 0;
        held = 1;
        for (int ms = 0; ms < 300 && !forked; ms++)
            usleep(1000);
    }
    return inner->call(info, size, inner->data);
}
int dl_iterate_phdr(callback call, void *data)
{
    int (*next)(callback, void *) = dlsym(RTLD_NEXT, "dl_iterate_phdr");
    struct inner inner = {call, data, walks_to_go > 0 && --walks_to_go == 0};
    return next(slowly, &inner);
}
void hold_walk(int which) { walks_to_go = which; }
int walk_is_held(void) { return held; }
void has_forked(void) { forked = 1; }
"#;

// Installs "libunwind" while another thread forks in the middle of the walk
// through the libraries that argv[2] numbers. The child then does what any
// program does sooner or later.
const FORKS_DURING_INSTALL_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
void hold_walk(int);
int walk_is_held(void);
void has_forked(void);
static int nothing(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)info, (void)size, (void)data;
    return 1;
}
static void *forks(void *arg)
{
    (void)arg;
    for (int ms = 0; !walk_is_held(); ms++) {
        if (ms > 5000)
            return (void *)6;
        usleep(1000);
    }
    pid_t child = fork();
    if (child == 0) {
        alarm(3);
        dl_iterate_phdr(nothing, NULL);
        _exit(0);
    }
    has_forked();
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child)
        return (void *)7;
    return (void *)(long)(WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 5);
}
int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    pthread_t thread;
    if (!hooks || pthread_create(&thread, NULL, forks, NULL) != 0)
        return 2;
    hold_walk(atoi(argv[2]));
    if (((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))("libunwind") != 0)
        return 2;
    void *said;
    pthread_join(thread, &said);
    return (int)(long)said;
}
"#;

// A libunwind that does no harm, and whose every stack has the loader next to
// jemalloc: __tls_get_addr(), or with ELSEWHERE some other part of it, as under a
// library's constructor.
const SHOWS_THE_LOADER_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
static char *in_the_loader;
__attribute__((constructor)) static void start(void)
{
    in_the_loader = (char *)dlsym(RTLD_DEFAULT, "__tls_get_addr") + 16;
    if (getenv("ELSEWHERE"))
        in_the_loader -= 4096;
}
int unw_backtrace(void **vec, int max)
{
    if (max < 3)
        return 0;
    vec[0] = vec[1] = (void *)unw_backtrace;
    vec[2] = in_the_loader;
    return 3;
}
"#;

// Allocates on a thread whose stack the loader has never run on, and says how
// many misses were counted.
const ALLOCATES_ON_A_NEW_THREAD_C: &str = r#"
#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
static void *allocates(void *arg)
{
    (void)arg;
    for (int i = 0; i < 10; i++) {
        void *volatile kept = malloc(100); /* or the compiler drops the pair */
        free(kept);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks || ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))("libunwind") != 0)
        return 2;
    unsigned long (*missed)(void) = (unsigned long (*)(void))dlsym(hooks, "systing_heap_hooks_missed");
    if (missed() != 0)
        return 3;
    bool on = true;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    pthread_t thread;
    if (mallctl("prof.active", NULL, NULL, &on, sizeof on) != 0 ||
        pthread_create(&thread, NULL, allocates, NULL) != 0)
        return 2;
    pthread_join(thread, NULL);
    on = false;
    mallctl("prof.active", NULL, NULL, &on, sizeof on);
    printf("%lu\n", missed());
    return 0;
}
"#;

// The look at the stack, given a stack made up for it. It follows an #include of
// caller.c.
const LOOKS_AT_C: &str = r#"
#include <string.h>
static uintptr_t stack[8];
static ssize_t made_up(void *dst, uintptr_t src, size_t len)
{
    (void)src;
    memset(dst, 0, len);
    memcpy(dst, stack, sizeof stack);
    return (ssize_t)len;
}
static int seen(uintptr_t word)
{
    stack[3] = word;
    return shh_loader_called_malloc(stack, made_up);
}
int main(void)
{
    // What a child has that another thread forked half way through
    // shh_find_loader(): it is found again.
    loader_start = loader_size = 1;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    if (shh_find_loader(&lock) != SHH_OK)
        return 2;
    uintptr_t in_the_loader = loader_start + 16;
    if (seen(0) || seen(loader_start - 8) || seen(loader_start + loader_size))
        return 3;
    if (!seen(in_the_loader))
        return 4;
    // Signed: any of the bits above those of an address.
    for (int bit = 63; ((uintptr_t)1 << bit) > loader_start + loader_size; bit--)
        if (!seen(in_the_loader | (uintptr_t)1 << bit))
            return 5;
    return seen(in_the_loader | ~loader_bits) ? 0 : 6;
}
"#;

const LOADS_LIBRARIES_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], strict=True)
for i in range(int(sys.argv[3])):
    ctypes.CDLL(f"{sys.argv[2]}/thread_local_{i}.so").touch()
try:
    os.unlink(f"/tmp/perf-{os.getpid()}.map")
except OSError:
    pass
"#;

// Loads the libraries from some Python functions deep, and keeps them. Sampling is
// off until the backtrace is installed, so that every stack is one it made.
const LOADS_LIBRARIES_DEEP_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], trampolines=sys.argv[1] == "libunwind", strict=True)
ctypes.CDLL(None).mallctl(b"prof.active", None, None, ctypes.byref(ctypes.c_bool(True)), 1)
kept = []
def deep(n):
    if n:
        return deep(n - 1)
    for i in range(int(sys.argv[3])):
        kept.append(ctypes.CDLL(f"{sys.argv[2]}/thread_local_{i}.so"))
deep(int(sys.argv[4]))
try:
    os.unlink(f"/tmp/perf-{os.getpid()}.map")
except OSError:
    pass
"#;

// What a JIT does when it has made code: hands libgcc the unwind tables for it,
// one small table for each piece. libgcc allocates as it files them.
const REGISTERS_TABLES_C: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
void __register_frame(void *);
static unsigned char *tables_for(uintptr_t pc, uintptr_t size)
{
    unsigned char *tables = calloc(1, 64), *p = tables;
    /* A CIE: length 12, id 0, version 1, no augmentation, code alignment 1,
     * data alignment -8, return address register 16, padding. */
    static const unsigned char cie[] = {12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0x78, 16, 0, 0, 0};
    memcpy(p, cie, sizeof cie);
    p += sizeof cie;
    /* An FDE: length 20, how far back its CIE is, where the code is, its size.
     * The zero word that follows ends the list. */
    uint32_t length = 20, back = (uint32_t)(p + 4 - tables);
    memcpy(p, &length, 4);
    memcpy(p + 4, &back, 4);
    memcpy(p + 8, &pc, 8);
    memcpy(p + 16, &size, 8);
    return tables;
}
void register_tables(void)
{
    for (uintptr_t i = 0; i < 2000; i++)
        __register_frame(tables_for(0x100000000000 + i * 4096, 4096));
}
"#;

const REGISTERS_TABLES_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], strict=True)
ctypes.CDLL(sys.argv[2]).register_tables()
try:
    os.unlink(f"/tmp/perf-{os.getpid()}.map")
except OSError:
    pass
"#;

// A sandbox that refuses a process the reading of memory by the kernel, its own
// included. Ends with what install() returned.
const REFUSED_C: &str = r#"
#include <dlfcn.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
int main(int argc, char **argv)
{
    if (argc != 4)
        return 100;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks)
        return 100;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_process_vm_readv, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof filter / sizeof filter[0], filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
        return 101;
    int rc = ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))("libunwind");
    if (rc != 0)
        return rc;
    bool on = true;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    if (mallctl("prof.active", NULL, NULL, &on, sizeof on) != 0)
        return 100;
    for (int i = 0; i < atoi(argv[3]); i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/thread_local_%d.so", argv[2], i);
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!lib)
            return 100;
        ((long (*)(void))dlsym(lib, "touch"))();
    }
    return 0;
}
"#;

// Sampling is off until here, so that the first allocation sampled is this one:
// libunwind's first check of an address is the one that changes errno.
const ERRNO_C: &str = r#"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
int mallctl(const char *, void *, size_t *, void *, size_t);
int errno_after_malloc(void)
{
    bool on = true;
    mallctl("prof.active", NULL, NULL, &on, sizeof on);
    errno = 4242;
    void *volatile p = malloc(1 << 16);
    int after = errno;
    free(p);
    return after;
}
"#;

// Under trampolines, which have no unwind tables: past them libunwind checks
// each address before it reads it, through a pipe that is empty the first time.
const ERRNO_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], trampolines=True, strict=True)
lib = ctypes.CDLL(sys.argv[2])
def inner():
    return lib.errno_after_malloc()
def outer():
    return inner()
changed = {e for e in (outer() for _ in range(100)) if e != 4242}
os.unlink(f"/tmp/perf-{os.getpid()}.map")
sys.exit(f"errno after malloc: {changed}" if changed else 0)
"#;

// A program that has Python in it, from a shared libpython it loads itself.
// glibc 2.40 and later answer a read made from inside malloc for the libraries a
// program starts with, and would stand in for the check in "python" if libpython
// were one of them.
const PYTHON_C: &str = r#"
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    void *python = dlopen(LIBPYTHON, RTLD_NOW | RTLD_GLOBAL);
    if (!python) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    return ((int (*)(int, char **))dlsym(python, "Py_BytesMain"))(argc, argv);
}
"#;

fn cc(dir: &Path, name: &str, source: &str, shared: bool) -> PathBuf {
    cc_with(dir, name, source, shared, false)
}

fn cc_with(dir: &Path, name: &str, source: &str, shared: bool, descriptors: bool) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let out = dir.join(if shared {
        format!("{name}.so")
    } else {
        name.to_string()
    });
    let mut cmd = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    cmd.args(["-O2", "-o"]).arg(&out).arg(&src);
    // The way to a thread-local variable is said, whatever the compiler's default
    // is: always through `__tls_get_addr()`, or by a TLS descriptor, which goes
    // there only where the thread has no block for the library yet.
    if cfg!(target_arch = "x86_64") {
        cmd.arg(if descriptors {
            "-mtls-dialect=gnu2"
        } else {
            "-mtls-dialect=gnu"
        });
    } else if cfg!(target_arch = "aarch64") {
        cmd.arg(if descriptors {
            "-mtls-dialect=desc"
        } else {
            "-mtls-dialect=trad"
        });
    }
    if shared {
        cmd.args(["-fPIC", "-shared"]);
    }
    let built = cmd.args(["-ldl", "-lpthread", "-lgcc_s"]).output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    out
}

struct Env {
    jemalloc: PathBuf,
    dir: tempfile::TempDir,
    shim: PathBuf,
}

fn setup() -> Option<Env> {
    let Some(jemalloc) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return None;
    };
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
        return None;
    }
    // One library under many names is as many libraries to the loader.
    let one = cc(dir.path(), "thread_local", THREAD_LOCAL_C, true);
    for i in 0..LIBRARIES {
        std::fs::copy(&one, dir.path().join(format!("thread_local_{i}.so"))).unwrap();
    }
    let shim = cc(dir.path(), "shim", SHIM_C, true);
    Some(Env {
        jemalloc,
        dir,
        shim,
    })
}

/// Run `cmd` under the shim and jemalloc with every allocation sampled, so
/// that the table's reallocation is. A dump is written as the program ends.
fn sampled(env: &Env, cmd: &mut Command) -> Output {
    sampled_with(env, cmd, "")
}

/// The same, with more for jemalloc's configuration.
fn sampled_with(env: &Env, cmd: &mut Command, conf: &str) -> Output {
    // What a test put between the shim and jemalloc stays there.
    if !cmd.get_envs().any(|(name, _)| name == "LD_PRELOAD") {
        cmd.env(
            "LD_PRELOAD",
            format!("{} {}", env.shim.display(), env.jemalloc.display()),
        );
    }
    cmd.env(
        "MALLOC_CONF",
        format!(
            "prof:true,lg_prof_sample:0,prof_final:true,prof_prefix:{}/jeprof{conf}",
            env.dir.path().display()
        ),
    )
    .output()
    .unwrap()
}

/// Whether `cmd`, run the same way, ends within 20 seconds, and how.
fn ends(env: &Env, cmd: &mut Command) -> Option<ExitStatus> {
    let mut child = cmd
        .env("LD_PRELOAD", &env.jemalloc)
        .env("MALLOC_CONF", "prof:true,lg_prof_sample:0")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn native(env: &Env, hooks: &Path, backtrace: &str) -> Output {
    native_with(env, hooks, backtrace, "")
}

fn native_with(env: &Env, hooks: &Path, backtrace: &str, conf: &str) -> Output {
    let program = env.dir.path().join("loads_libraries");
    if !program.exists() {
        cc(env.dir.path(), "loads_libraries", LOADS_LIBRARIES_C, false);
    }
    sampled_with(
        env,
        Command::new(program)
            .arg(hooks)
            .arg(backtrace)
            .arg(env.dir.path())
            .arg(LIBRARIES.to_string()),
        conf,
    )
}

/// Whether these tests can tell here: a backtrace that breaks the rule is
/// caught. Where it is not, the C library has changed and the tests below
/// would pass whatever the backtraces did.
fn the_trap_works(env: &Env) -> bool {
    let bad = cc(env.dir.path(), "breaks_the_rule", BREAKS_THE_RULE_C, true);
    let out = native(env, &bad, "");
    if out.status.code() == Some(CAUGHT) {
        return true;
    }
    common::skip(&format!(
        "a backtrace that reads a __thread variable is not caught here ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    ));
    false
}

#[test]
fn no_backtrace_of_a_native_program_enters_the_loader() {
    let Some(env) = setup() else { return };
    if !the_trap_works(&env) {
        return;
    }
    let hooks = env.dir.path().join("libsysting_heap_hooks.so");
    for backtrace in ["default", "libunwind"] {
        let out = native(&env, &hooks, backtrace);
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Every thread has a table of its own to grow, so a program is exposed once for
/// each thread it has when it loads libraries late.
#[test]
fn nor_in_any_thread_of_one_that_loads_libraries_late() {
    let Some(env) = setup() else { return };
    let dir = env.dir.path();
    let program = cc(dir, "loads_libraries_late", LOADS_LIBRARIES_LATE_C, false);
    let run = |hooks: &Path, backtrace: &str| {
        sampled(
            &env,
            Command::new(&program)
                .arg(hooks)
                .arg(backtrace)
                .arg(dir)
                .arg(LIBRARIES.to_string()),
        )
    };
    let bad = cc(dir, "breaks_the_rule", BREAKS_THE_RULE_C, true);
    let out = run(&bad, "");
    if out.status.code() != Some(CAUGHT) {
        common::skip(&format!(
            "a backtrace that reads a __thread variable is not caught here ({})",
            out.status
        ));
        return;
    }
    for backtrace in ["default", "libunwind"] {
        let out = run(&dir.join("libsysting_heap_hooks.so"), backtrace);
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A libunwind built to reach its variables by TLS descriptors, as one is on
/// arm64 unless it was told otherwise, asks the loader too: the first time a thread reads them, where they
/// were given no place in the thread's static block. So it is a thread's first
/// sample that counts, and sampling is off until the tables are about to grow.
#[test]
fn nor_by_a_tls_descriptor_at_a_threads_first_sample() {
    let Some(env) = setup() else { return };
    let dir = env.dir.path();
    let program = cc(dir, "loads_libraries_late", LOADS_LIBRARIES_LATE_C, false);
    let libunwind = cc_with(dir, "reads_its_cache", READS_ITS_CACHE_C, true, true);
    let run = |hooks: &Path, backtrace: &str| {
        sampled_with(
            &env,
            Command::new(&program)
                .arg(hooks)
                .arg(backtrace)
                .arg(dir)
                .arg(LIBRARIES.to_string())
                .env("SYSTING_HEAP_HOOKS_LIBUNWIND", &libunwind)
                // No place in the static block for a library loaded late, as
                // when others have used up what there is.
                .env("GLIBC_TUNABLES", "glibc.rtld.optional_static_tls=0"),
            ",prof_active:false",
        )
    };
    let bad = cc_with(dir, "breaks_the_rule", BREAKS_THE_RULE_C, true, true);
    let out = run(&bad, "");
    if out.status.code() != Some(CAUGHT) {
        common::skip(&format!(
            "a backtrace that reads a __thread variable by a descriptor is not caught here ({})",
            out.status
        ));
        return;
    }
    let out = run(&dir.join("libsysting_heap_hooks.so"), "libunwind");
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The stacks of a dump, innermost frame first, each frame as the file it is in.
fn stacks_by_file(dump: &Path) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(dump).unwrap();
    let (stacks, maps) = text.split_once("MAPPED_LIBRARIES:").unwrap();
    let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
    let maps: Vec<(u64, u64, &str)> = maps
        .lines()
        .filter_map(|l| {
            let (range, rest) = l.split_once(' ')?;
            let (start, end) = range.split_once('-')?;
            let file = rest.rsplit('/').next()?;
            Some((hex(start), hex(end), file))
        })
        .collect();
    stacks
        .lines()
        .filter_map(|l| l.strip_prefix("@ "))
        .map(|l| {
            l.split_whitespace()
                .map(|pc| {
                    let pc = hex(pc);
                    maps.iter()
                        .find(|(start, end, _)| (*start..*end).contains(&pc))
                        .map_or("?", |m| m.2)
                        .to_string()
                })
                .collect()
        })
        .collect()
}

/// What the loader allocates is still recorded, thread-local blocks among it, with
/// a stack that starts where jemalloc's own does: nothing of the hook's is in it.
#[test]
fn what_the_loader_allocates_has_a_stack() {
    // Elsewhere libunwind is not driven a frame at a time, and there is none.
    if !cfg!(target_arch = "x86_64") {
        return;
    }
    let Some(env) = setup() else { return };
    let hooks = env.dir.path().join("libsysting_heap_hooks.so");
    // Every stack in the dump is one the backtrace made.
    let out = native_with(&env, &hooks, "libunwind", ",prof_active:false");
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let dump = std::fs::read_dir(env.dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "heap"))
        .expect("jemalloc wrote no dump");
    let mut of_the_loader = 0;
    for stack in stacks_by_file(&dump) {
        let Some(loader) = stack.iter().position(|f| f.starts_with("ld-")) else {
            continue;
        };
        of_the_loader += 1;
        assert!(
            !stack[..loader]
                .iter()
                .any(|f| f.starts_with("libsysting") || f.starts_with("libunwind")),
            "{stack:#?}"
        );
    }
    assert!(of_the_loader > 0, "no allocation of the loader's is live");
}

/// What a backtrace does where the loader called malloc gives up nothing that
/// matters: the look at the stack takes many an allocation for the loader's that
/// is not. The Python functions are there, as trampolines under "libunwind" and as
/// slots under "python", neither of which is an address in a file.
#[test]
fn and_its_python_frames_too() {
    // jemalloc keeps 128 frames of a stack. Under trampolines a Python call takes
    // up to five of them (3.14), and the loader and ctypes some twenty.
    const DEEP: usize = 12;
    let Some((python, _)) = common::python() else {
        common::skip("needs Python 3.12+");
        return;
    };
    for backtrace in ["python", "libunwind"] {
        // Elsewhere libunwind is not driven a frame at a time, and there is no
        // stack.
        if backtrace == "libunwind" && !cfg!(target_arch = "x86_64") {
            continue;
        }
        let Some(env) = setup() else { return };
        let dir = env.dir.path();
        let app = dir.join("loads_libraries_deep.py");
        std::fs::write(&app, LOADS_LIBRARIES_DEEP_PY).unwrap();
        let mut child = Command::new(&python);
        child
            .arg(&app)
            .arg(backtrace)
            .arg(dir)
            .arg(LIBRARIES.to_string())
            .arg(DEEP.to_string())
            .env(
                "SYSTING_HEAP_HOOKS_LIB",
                dir.join("libsysting_heap_hooks.so"),
            )
            .env("PYTHONPATH", HOOKS);
        let out = sampled_with(&env, &mut child, ",prof_active:false");
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let dump = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "heap"))
            .expect("jemalloc wrote no dump");
        let mut of_the_loader = 0;
        for stack in stacks_by_file(&dump) {
            if !stack.iter().any(|f| f.starts_with("ld-")) {
                continue;
            }
            of_the_loader += 1;
            let in_no_file = stack.iter().filter(|f| !f.contains('.')).count();
            assert!(
                in_no_file >= DEEP,
                "{backtrace}: {in_no_file} Python frames: {stack:#?}"
            );
        }
        assert!(
            of_the_loader > 0,
            "{backtrace}: no allocation of the loader's is live"
        );
    }
}

/// Run the Python program with `python` under `backtrace`, with malloc's caller
/// further up the stack than is looked at if `far`.
fn python_program_under(env: &Env, python: &Path, backtrace: &str, far: bool) -> Output {
    let app = env.dir.path().join("loads_libraries.py");
    std::fs::write(&app, LOADS_LIBRARIES_PY).unwrap();
    let mut child = Command::new(python);
    child
        .arg(&app)
        .arg(backtrace)
        .arg(env.dir.path())
        .arg(LIBRARIES.to_string())
        .env(
            "SYSTING_HEAP_HOOKS_LIB",
            env.dir.path().join("libsysting_heap_hooks.so"),
        )
        .env("PYTHONPATH", HOOKS);
    if far {
        child.env("SHIM_FAR", "1");
    }
    sampled(env, &mut child)
}

/// Run the Python program with `python` under each backtrace it can have.
fn python_program(env: &Env, python: &Path) {
    for backtrace in ["default", "python", "libunwind"] {
        let out = python_program_under(env, python, backtrace, false);
        assert!(
            out.status.success(),
            "{} with {backtrace}: {}: {}",
            python.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn no_backtrace_of_a_python_program_enters_the_loader() {
    let Some(env) = setup() else { return };
    let pythons = common::pythons();
    if pythons.is_empty() {
        common::skip("needs Python 3.12+");
        return;
    }
    if !the_trap_works(&env) {
        return;
    }
    for (python, _) in pythons {
        python_program(&env, Path::new(&python));
    }
}

/// The shared libpython of `python`, if it has one that reads its thread-local
/// variables through the loader. Some are built so as not to
/// (`-ftls-model=initial-exec`), and a `python3` that has the interpreter
/// linked in does not either.
fn libpython_that_asks_the_loader(python: &str) -> Option<PathBuf> {
    let out = Command::new(python)
        .args([
            "-c",
            "import sysconfig as s; print(s.get_config_var('LIBDIR'), s.get_config_var('INSTSONAME'), sep='/')",
        ])
        .output()
        .ok()?;
    let lib = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    if lib.extension().is_some_and(|e| e == "a") || !lib.exists() {
        return None;
    }
    // The relocations that leave finding a variable to the loader. An import
    // of `__tls_get_addr` would not tell: TLS descriptors need none.
    let relocations = Command::new("readelf").arg("-rW").arg(&lib).output().ok()?;
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    (relocations.contains("DTPMOD") || relocations.contains("TLSDESC")).then_some(lib)
}

/// The interpreter's own thread state is a thread-local variable, and the
/// "python" backtrace asks the interpreter for it.
#[test]
fn nor_where_the_interpreters_own_variables_are_read_through_it() {
    let Some(env) = setup() else { return };
    let Some(python) = python_that_asks_the_loader(&env) else {
        return;
    };
    python_program(&env, &python);
}

/// The look covers 4 KiB. "python" has the native stack before it asks the
/// interpreter for anything, and sees the loader there too.
#[test]
fn python_sees_the_loader_where_the_look_falls_short() {
    let Some(env) = setup() else { return };
    let Some(python) = python_that_asks_the_loader(&env) else {
        return;
    };
    // It does fall short: "libunwind", which has nothing else to go by, is caught.
    let out = python_program_under(&env, &python, "libunwind", true);
    if out.status.code() != Some(CAUGHT) {
        common::skip(&format!(
            "the loader is seen from further off than expected ({})",
            out.status
        ));
        return;
    }
    let out = python_program_under(&env, &python, "python", true);
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What "libunwind" cannot see in time it sees afterwards, in the stack it made.
/// That is counted, and said once.
#[test]
fn a_miss_is_counted_and_said_once() {
    let Some(env) = setup() else { return };
    let dir = env.dir.path();
    let program = cc(
        dir,
        "allocates_on_a_new_thread",
        ALLOCATES_ON_A_NEW_THREAD_C,
        false,
    );
    let run = |libunwind: Option<&Path>, elsewhere: bool| {
        let mut cmd = Command::new(&program);
        cmd.arg(dir.join("libsysting_heap_hooks.so"));
        if let Some(libunwind) = libunwind {
            cmd.env("SYSTING_HEAP_HOOKS_LIBUNWIND", libunwind);
        }
        if elsewhere {
            cmd.env("ELSEWHERE", "1");
        }
        let out = sampled_with(&env, &mut cmd, ",prof_active:false");
        assert!(out.status.success(), "{}", out.status);
        (
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u64>()
                .unwrap(),
            String::from_utf8_lossy(&out.stderr)
                .matches("did not see it")
                .count(),
        )
    };
    assert_eq!(run(None, false), (0, 0));
    let libunwind = cc(dir, "shows_the_loader", SHOWS_THE_LOADER_C, true);
    let (missed, said) = run(Some(&libunwind), false);
    assert!(missed >= 10, "{missed}");
    assert_eq!(said, 1);
    // The loader calls a library's constructors, and is in the middle of nothing
    // when one of them allocates. Some have frames larger than is looked at.
    assert_eq!(run(Some(&libunwind), true), (0, 0));
}

/// A program that runs the interpreter out of a shared libpython that asks the
/// loader for its variables, where there is one and these tests can tell.
fn python_that_asks_the_loader(env: &Env) -> Option<PathBuf> {
    let Some(lib) = common::pythons()
        .iter()
        .find_map(|(python, _)| libpython_that_asks_the_loader(python))
    else {
        common::skip(
            "needs a shared libpython that asks the loader for its variables (Ubuntu: libpython3.12t64)",
        );
        return None;
    };
    if !the_trap_works(env) {
        return None;
    }
    let src = env.dir.path().join("python.c");
    std::fs::write(&src, PYTHON_C).unwrap();
    let python = env.dir.path().join("python");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .arg(format!("-DLIBPYTHON=\"{}\"", lib.display()))
        .arg("-o")
        .arg(&python)
        .arg(&src)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    Some(python)
}

/// A miss costs the heap and a false alarm some of one sample's detail, so the
/// loader is looked for well past where it is.
#[test]
fn the_loader_is_seen_behind_a_chain_of_wrappers() {
    let Some(env) = setup() else { return };
    if !the_trap_works(&env) {
        return;
    }
    let dir = env.dir.path();
    let mut child = Command::new(dir.join("loads_libraries"));
    child
        .arg(dir.join("libsysting_heap_hooks.so"))
        .arg("libunwind")
        .arg(dir)
        .arg(LIBRARIES.to_string())
        .env("SHIM_FRAMES", "20");
    let out = sampled(&env, &mut child);
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Started as `ld.so program`, a program has no interpreter for the kernel to
/// tell it the address of, and the loader is found the other way.
#[test]
fn the_loader_is_found_where_it_was_run_as_the_program() {
    let Some(env) = setup() else { return };
    if !the_trap_works(&env) {
        return;
    }
    let dir = env.dir.path();
    let program = dir.join("loads_libraries");
    let Some(loader) = Command::new("readelf")
        .arg("-lW")
        .arg(&program)
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let (_, rest) = text.split_once("Requesting program interpreter: ")?;
            Some(rest.split(']').next()?.to_string())
        })
    else {
        common::skip("needs readelf");
        return;
    };
    let mut child = Command::new(loader);
    child
        .arg(&program)
        .arg(dir.join("libsysting_heap_hooks.so"))
        .arg("libunwind")
        .arg(dir)
        .arg(LIBRARIES.to_string());
    let out = sampled(&env, &mut child);
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// libgcc allocates while it holds the locks its own unwinder takes, and its
/// unwinder, started from inside that malloc(), waits for them for good. That is
/// how jemalloc's own backtrace hangs, and "python", which calls it. "libunwind"
/// has no need of libgcc, whoever called malloc.
#[test]
fn libunwind_does_not_wait_for_libgcc() {
    let Some(env) = setup() else { return };
    let Some((python, _)) = common::python() else {
        common::skip("needs Python 3.12+");
        return;
    };
    let dir = env.dir.path();
    let lib = cc(dir, "registers_tables", REGISTERS_TABLES_C, true);
    let app = dir.join("registers_tables.py");
    std::fs::write(&app, REGISTERS_TABLES_PY).unwrap();
    let mut child = Command::new(&python);
    child
        .arg(&app)
        .arg("libunwind")
        .arg(&lib)
        .env(
            "SYSTING_HEAP_HOOKS_LIB",
            dir.join("libsysting_heap_hooks.so"),
        )
        .env("PYTHONPATH", HOOKS);
    match ends(&env, &mut child) {
        Some(status) => assert!(status.success(), "{status}"),
        None => panic!("waits for a lock its own thread holds"),
    }
}

/// install() walks through the libraries, with a lock of the loader's held that
/// fork() does not make anew in the child. A child forked by another thread in the
/// middle of that would wait for the lock for good, the next time it loaded a
/// library. So a fork waits for the walk.
#[test]
fn a_fork_waits_for_installs_walks_through_the_libraries() {
    let Some(env) = setup() else { return };
    let dir = env.dir.path();
    let holds = cc(dir, "holds_the_walk", HOLDS_THE_WALK_C, true);
    let src = dir.join("forks_during_install.c");
    std::fs::write(&src, FORKS_DURING_INSTALL_C).unwrap();
    let program = dir.join("forks_during_install");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O2", "-o"])
        .arg(&program)
        .arg(&src)
        .arg(&holds)
        .args(["-ldl", "-lpthread"])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    // Where the loader's code is, and how many thread-local variables libunwind
    // has, which is asked where it can be driven a frame at a time.
    let walks = if cfg!(target_arch = "x86_64") { 2 } else { 1 };
    for walk in 1..=walks {
        let status = ends(
            &env,
            Command::new(&program)
                .arg(dir.join("libsysting_heap_hooks.so"))
                .arg(walk.to_string())
                .env("LD_LIBRARY_PATH", dir),
        )
        .expect("the program did not end");
        assert!(status.success(), "walk {walk}: {status}");
    }
}

/// On arm64 a saved return address may be signed, in the bits above those of an
/// address. It is the loader's all the same.
#[test]
fn the_loader_is_seen_in_a_signed_return_address() {
    let dir = tempfile::tempdir().unwrap();
    let source = format!("#include \"{HOOKS}/backtrace/caller.c\"\n{LOOKS_AT_C}");
    let out = Command::new(cc(dir.path(), "looks_at", &source, false))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", out.status);
}

/// Where the stack cannot be read, every allocation is taken for the loader's.
/// "libunwind" goes on, a frame at a time, where it can. Where it cannot, it would
/// have no stack at all, and is not installed.
#[test]
fn a_backtrace_that_cannot_read_the_stack_takes_the_loader_to_have_called() {
    let Some(env) = setup() else { return };
    let dir = env.dir.path();
    let program = cc(dir, "refused", REFUSED_C, false);
    let run = |libunwind: Option<&Path>| {
        let mut cmd = Command::new(&program);
        cmd.arg(dir.join("libsysting_heap_hooks.so"))
            .arg(dir)
            .arg(LIBRARIES.to_string());
        if let Some(libunwind) = libunwind {
            cmd.env("SYSTING_HEAP_HOOKS_LIBUNWIND", libunwind);
        }
        // Every stack in the dump is one the backtrace made.
        sampled_with(&env, &mut cmd, ",prof_active:false").status
    };
    // SHH_ERR_STACK_READ
    let refused = Some(14);
    let status = run(None);
    if status.code() == Some(101) {
        common::skip("needs seccomp filters");
        return;
    }
    if cfg!(target_arch = "x86_64") {
        assert!(status.success(), "{status}");
        let dump = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "heap"))
            .expect("jemalloc wrote no dump");
        let whole = stacks_by_file(&dump)
            .iter()
            .filter(|stack| stack.iter().any(|f| f == "refused"))
            .count();
        assert!(whole > 0, "no stack reaches the program");
    } else {
        assert_eq!(status.code(), refused, "{status}");
    }
    // One with nothing to be driven a frame at a time by.
    let libunwind = cc(dir, "reads_its_cache", READS_ITS_CACHE_C, true);
    assert_eq!(run(Some(&libunwind)).code(), refused);
}

/// A malloc that succeeds is expected to leave errno alone.
#[test]
fn a_sampled_malloc_leaves_errno_as_it_was() {
    let Some(env) = setup() else { return };
    let Some((python, _)) = common::python() else {
        common::skip("needs Python 3.12+");
        return;
    };
    let lib = cc(env.dir.path(), "errno_after_malloc", ERRNO_C, true);
    let app = env.dir.path().join("errno.py");
    std::fs::write(&app, ERRNO_PY).unwrap();
    for backtrace in ["default", "python", "libunwind"] {
        let mut child = Command::new(&python);
        child
            .arg(&app)
            .arg(backtrace)
            .arg(&lib)
            .env(
                "SYSTING_HEAP_HOOKS_LIB",
                env.dir.path().join("libsysting_heap_hooks.so"),
            )
            .env("PYTHONPATH", HOOKS);
        let out = sampled_with(&env, &mut child, ",prof_active:false");
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The two ways into the loader that can be seen in the file: a thread-local
/// variable of the library's own, and a function left to be bound at its first
/// call.
#[test]
fn the_libraries_leave_the_loader_nothing_to_do_later() {
    let dir = tempfile::tempdir().unwrap();
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
        return;
    }
    for lib in ["libsysting_heap_hooks.so", "libsysting_heap_responder.so"] {
        let Ok(out) = Command::new("readelf")
            .args(["-ldW", "--dyn-syms"])
            .arg(dir.path().join(lib))
            .output()
        else {
            common::skip("needs readelf");
            return;
        };
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !text
                .lines()
                .any(|l| l.split_whitespace().next() == Some("TLS")),
            "{lib} has thread-local variables:\n{text}"
        );
        assert!(
            !text.contains("__tls_get_addr"),
            "{lib} calls __tls_get_addr:\n{text}"
        );
        assert!(
            text.contains("BIND_NOW") || text.contains(" NOW"),
            "{lib} is not bound when it is loaded:\n{text}"
        );
    }
}
