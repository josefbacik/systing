/*
 * EXPERIMENTAL: what is asked and answered here may change.
 *
 * systing-heap hooks: the responder. One thread that answers requests for a
 * heap dump on a Unix socket, so that a dump can be asked for from outside
 * the process (systing-heap --pid PID --ask) at any moment, and the dump is
 * not written to disk: jemalloc writes it into an anonymous file, and the
 * answer carries that file's descriptor.
 *
 * The socket is a file in the process's own filesystem,
 * <dir>/.systing-heap.<pid>, the pid being the process's own view of it. A
 * tool outside a container reaches it through /proc/<pid>/root.
 *
 * A request is one line, and so is the answer:
 *
 *   -> "systing-heap 1 dump\n"
 *   <- "ok 1 heap=<bytes> map=<0|1> active=<0|1>\n"
 *                                        with the descriptors, in one message:
 *                                        the dump, then the Python code map
 *                                        when the process writes one. active
 *                                        is jemalloc's "prof.active": 0 where
 *                                        sampling is paused, and the dump
 *                                        holds what was sampled before
 *   <- "error <why>\n"
 *
 * What the thread may and may not do:
 *
 * - It answers the process's own user and root, and no one else: the socket
 *   is made for its owner alone, and the peer's credentials are checked.
 * - The socket is known by what it is, not by its number alone: a program
 *   that closes descriptors it did not open may give the number to a socket
 *   of its own, and the thread then ends instead of answering there.
 * - It runs nothing of the program's and takes none of its own locks; of
 *   this library's it takes the "python" backtrace's while a forked child's
 *   code map is made. Every signal is blocked on it, so no handler of the
 *   program's runs there.
 * - It is an ordinary thread outside malloc: jemalloc's "prof.dump" is called
 *   as any thread of the program may call it.
 * - A peer that says nothing, or reads nothing, is given up after
 *   IO_TIMEOUT_S seconds; requests are answered one at a time.
 * - A forked child has no such thread and listens nowhere until it asks to,
 *   or unless the environment said that the processes this one forks listen
 *   as well.
 *
 * A program that is not changed at all listens when the library is loaded
 * into it with SYSTING_HEAP_HOOKS_LISTEN set in its environment: to 1, or to
 * fork for the processes it forks to listen as well. The socket is where
 * systing_heap_hooks_listen(NULL) puts it. SYSTING_HEAP_HOOKS_LISTEN_ONLY
 * names the one program that is to: the others that inherit the environment
 * then do nothing.
 *
 * This file and common.c are all the responder is: the library that is only
 * those two, libsysting_heap_responder.so, has nothing in it of Python or
 * of the backtraces.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <stdbool.h>

#include "../common/common.h"
#include "../systing_heap_hooks.h"

#define REQUEST "systing-heap 1 dump\n"
#define IO_TIMEOUT_S 5
#define DEFAULT_DIR "/tmp"

/* listen() runs from any thread; this guards the statics below. */
static pthread_mutex_t listen_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t at_exit_once = PTHREAD_ONCE_INIT;
static shh_mallctl_fn mallctl_p;
static int listen_fd = -1;
/* What listen_fd is: the number can come to name something else. */
static dev_t listen_dev;
static ino_t listen_ino;
/* The process that listens: a forked child must not take the socket of the
 * process it was forked from away as it exits. */
static pid_t listen_pid;
static char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
/* Whether a process this one forks listens as this one does, and where. */
static int listen_in_children;
static char listen_dir[sizeof(socket_path)];

static void say(int c, const char *line, const int *fds, int nfds)
{
	struct iovec iov = {(void *)line, strlen(line)};
	union {
		char buf[CMSG_SPACE(2 * sizeof(int))];
		struct cmsghdr align;
	} control;
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
	if (nfds > 0) {
		memset(&control, 0, sizeof(control));
		msg.msg_control = control.buf;
		msg.msg_controllen = CMSG_SPACE((size_t)nfds * sizeof(int));
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN((size_t)nfds * sizeof(int));
		memcpy(CMSG_DATA(cmsg), fds, (size_t)nfds * sizeof(int));
	}
	/* The line is short of any socket buffer: it goes whole or not at all. */
	while (sendmsg(c, &msg, MSG_NOSIGNAL) < 0 && errno == EINTR)
		;
}

/* Whether the peer is this process's user, or root. */
static int peer_may_ask(int c)
{
	struct ucred peer;
	socklen_t len = sizeof(peer);
	if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &peer, &len) != 0 ||
	    len != sizeof(peer))
		return 0;
	return peer.uid == 0 || peer.uid == geteuid();
}

/* The request, read to its newline: whether it is the one this answers. */
static int asked_for_a_dump(int c)
{
	char line[sizeof(REQUEST)];
	size_t have = 0;
	while (have < sizeof(REQUEST) - 1) {
		ssize_t n = read(c, line + have, sizeof(REQUEST) - 1 - have);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		have += (size_t)n;
		if (memchr(line, '\n', have))
			break;
	}
	return have == sizeof(REQUEST) - 1 &&
	       memcmp(line, REQUEST, sizeof(REQUEST) - 1) == 0;
}

/*
 * jemalloc's dump, in an anonymous file that can no longer change. jemalloc
 * writes a dump to a path only, so it is given the file's name under
 * /proc/self/fd. Returns the descriptor, or -1 with `why` set.
 */
static int dump(const char **why)
{
	int fd = memfd_create("systing-heap-dump", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0) {
		*why = "memfd_create failed";
		return -1;
	}
	char path[64];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	const char *name = path;
	if (mallctl_p("prof.dump", NULL, NULL, &name, sizeof(name)) != 0) {
		*why = "jemalloc's prof.dump failed";
		close(fd);
		return -1;
	}
	/* Best effort: a kernel that refuses leaves a file only this process
	 * can write, and it writes no more to it. */
	fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	return fd;
}

/* The code map the "python" backtrace writes, open for reading; -1 when
 * there is none, as in a library without that backtrace. It is the file at
 * the map's path now, if a regular one: what it holds is read by the tool as
 * any file of the process's is. */
static int code_map(void)
{
	const char *path = shh_code_map();
	if (!path || !path[0])
		return -1;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return -1;
	}
	return fd;
}

static void answer(int c)
{
	struct timeval patience = {IO_TIMEOUT_S, 0};
	setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience));
	setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &patience, sizeof(patience));

	if (!peer_may_ask(c)) {
		say(c, "error only the process's own user, or root, may ask\n", NULL, 0);
		return;
	}
	if (!asked_for_a_dump(c)) {
		say(c, "error expected \"systing-heap 1 dump\"\n", NULL, 0);
		return;
	}
	const char *why = "";
	int fds[2];
	fds[0] = dump(&why);
	if (fds[0] < 0) {
		char line[96];
		snprintf(line, sizeof(line), "error %s\n", why);
		say(c, line, NULL, 0);
		return;
	}
	struct stat st;
	long long size = fstat(fds[0], &st) == 0 ? (long long)st.st_size : 0;
	fds[1] = code_map();
	/* A dump of a process whose sampling is paused looks like any other. */
	bool active = true;
	size_t active_len = sizeof(active);
	if (mallctl_p("prof.active", &active, &active_len, NULL, 0) != 0)
		active = true;
	char line[96];
	snprintf(line, sizeof(line), "ok 1 heap=%lld map=%d active=%d\n", size,
		 fds[1] >= 0, (int)active);
	say(c, line, fds, fds[1] >= 0 ? 2 : 1);
	close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
}

/* Whether `fd` is still the socket that was made to listen. */
static int is_the_socket(int fd)
{
	struct stat st;
	return fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode) &&
	       st.st_dev == listen_dev && st.st_ino == listen_ino;
}

/* The thread is ending: the process listens no more, and may ask to again.
 * The descriptor is closed only if it is still the socket. */
static void stop_listening(int fd)
{
	pthread_mutex_lock(&listen_lock);
	if (listen_fd == fd && listen_pid == getpid()) {
		if (is_the_socket(fd)) {
			if (socket_path[0])
				unlink(socket_path);
			close(fd);
		}
		listen_fd = -1;
		socket_path[0] = '\0';
	}
	pthread_mutex_unlock(&listen_lock);
}

static void *respond(void *arg)
{
	int fd = (int)(long)arg;
	pthread_setname_np(pthread_self(), "heap-responder");
	for (;;) {
		int c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
		/* Whatever came of it, it was asked of this number: if the
		 * number has come to name something else, what was taken from
		 * it is the program's, and is let go without a word. */
		if (!is_the_socket(fd)) {
			if (c >= 0)
				close(c);
			break;
		}
		if (c < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			/* Out of descriptors or memory: the program may free
			 * some. Anything else, and no one can be answered. */
			if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
			    errno == ENOMEM) {
				sleep(1);
				continue;
			}
			break;
		}
		answer(c);
		close(c);
	}
	stop_listening(fd);
	return NULL;
}

static void forget_the_socket(void)
{
	/* At exit nothing is waited for: a lock that is held stays held. */
	if (pthread_mutex_trylock(&listen_lock) != 0)
		return;
	if (listen_fd >= 0 && listen_pid == getpid() && socket_path[0])
		unlink(socket_path);
	pthread_mutex_unlock(&listen_lock);
}

static void register_at_exit(void)
{
	atexit(forget_the_socket);
}

static int listen_locked(const char *dir);

/* Why the process does not listen, in one line on standard error, where
 * there is no caller to tell: what the environment asked for, and what a
 * forked child was to do. Built here and written in one call. */
static void complain(const char *how, int rc)
{
	char line[256];
	int n = snprintf(line, sizeof(line),
			 "systing_heap_hooks: SYSTING_HEAP_HOOKS_LISTEN=%.16s (pid %ld): %s\n",
			 how, (long)getpid(), systing_heap_hooks_strerror(rc));
	if (n > 0) {
		size_t len = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
		ssize_t written = write(STDERR_FILENO, line, len);
		(void)written;
	}
}

/*
 * Held from before the socket is made until it is on record, and across
 * every fork: a child is not forked with a socket that is listened on and
 * that nothing names, which it could not let go of. Nothing is done under
 * it but system calls: it is taken before a fork, when other locks are held
 * by whoever forks.
 */
static pthread_mutex_t making_lock = PTHREAD_MUTEX_INITIALIZER;

static void before_fork(void)
{
	pthread_mutex_lock(&making_lock);
}

static void after_fork_in_parent(void)
{
	pthread_mutex_unlock(&making_lock);
}

static void after_fork_in_child(void)
{
	/* The thread is not in the child, and the socket is the parent's: the
	 * child lets go of its copy, and listens once it asks to. */
	pthread_mutex_init(&listen_lock, NULL);
	pthread_mutex_init(&making_lock, NULL);
	int listened = listen_fd >= 0;
	if (listened && is_the_socket(listen_fd))
		close(listen_fd);
	listen_fd = -1;
	socket_path[0] = '\0';
	/* Asked for in the environment: the child has a socket and a thread
	 * of its own before fork() returns in it. */
	if (listened && listen_in_children) {
		int rc = listen_locked(listen_dir);
		if (rc != SHH_OK)
			complain("fork", rc);
	}
}

static const struct shh_fork_part fork_part = {before_fork, after_fork_in_parent,
					       after_fork_in_child};

/* Whether something answers at `addr`. It is asked without waiting: a
 * socket whose queue is full is one that someone listens on, and whoever
 * made it must not be able to hold the program that asks. */
static int someone_listens(const struct sockaddr_un *addr)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return 1;
	int rc = connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
	int refused = rc != 0 && errno == ECONNREFUSED;
	close(fd);
	return !refused;
}

static int bind_and_listen(const struct sockaddr_un *addr)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	/* The mode the socket's file is made with: its owner's alone, where
	 * the program's umask would have let others in. */
	if (fchmod(fd, 0600) != 0)
		goto fail;
	if (bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) != 0) {
		/* A socket a process that is gone left behind, with this
		 * one's pid, is taken over; one that answers is not. */
		if (errno != EADDRINUSE || someone_listens(addr))
			goto fail;
		if (unlink(addr->sun_path) != 0 ||
		    bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) != 0)
			goto fail;
	}
	if (listen(fd, 4) != 0) {
		unlink(addr->sun_path);
		goto fail;
	}
	return fd;
fail:
	close(fd);
	return -1;
}

/* Whether jemalloc is here and profiles: SHH_OK, or why not. */
static int profiles_locked(void)
{
	if (!mallctl_p)
		mallctl_p = shh_find_mallctl();
	if (!mallctl_p)
		return SHH_ERR_NO_JEMALLOC;
	bool prof = false;
	size_t prof_len = sizeof(prof);
	if (mallctl_p("opt.prof", &prof, &prof_len, NULL, 0) != 0 || !prof)
		return SHH_ERR_PROF_OFF;
	return SHH_OK;
}

static int listen_locked(const char *dir)
{
	if (listen_fd >= 0)
		return SHH_OK;

	int profiles = profiles_locked();
	if (profiles != SHH_OK)
		return profiles;

	if (!dir)
		dir = secure_getenv("SYSTING_HEAP_HOOKS_SOCKET_DIR");
	if (!dir || !dir[0])
		dir = DEFAULT_DIR;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	int n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.systing-heap.%ld",
			 dir, (long)getpid());
	if (n < 0 || (size_t)n >= sizeof(addr.sun_path))
		return SHH_ERR_SOCKET_PATH;

	if (dir != listen_dir)
		snprintf(listen_dir, sizeof(listen_dir), "%s", dir);

	/* No fork between the socket's making and its being on record. */
	pthread_mutex_lock(&making_lock);
	int fd = bind_and_listen(&addr);
	struct stat st;
	if (fd >= 0 && fstat(fd, &st) != 0) {
		unlink(addr.sun_path);
		close(fd);
		fd = -1;
	}
	if (fd < 0) {
		pthread_mutex_unlock(&making_lock);
		return SHH_ERR_SOCKET;
	}
	/* Known from here on, before there is a thread: a child forked by
	 * another thread from now on lets go of it like any other. */
	listen_dev = st.st_dev;
	listen_ino = st.st_ino;
	listen_pid = getpid();
	memcpy(socket_path, addr.sun_path, sizeof(socket_path));
	listen_fd = fd;
	pthread_mutex_unlock(&making_lock);

	/* The thread starts with every signal blocked, as the thread that
	 * makes it has them for that moment. */
	sigset_t all, before;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &before);
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_t thread;
	int rc = pthread_create(&thread, &attr, respond, (void *)(long)fd);
	pthread_attr_destroy(&attr);
	pthread_sigmask(SIG_SETMASK, &before, NULL);
	if (rc != 0) {
		listen_fd = -1;
		socket_path[0] = '\0';
		unlink(addr.sun_path);
		close(fd);
		return SHH_ERR_SOCKET;
	}
	return SHH_OK;
}

int systing_heap_hooks_listen(const char *dir)
{
	/* jemalloc is called before this library takes its part in fork():
	 * jemalloc takes its own part when it is first called, and whoever
	 * took part first is first in a forked child. There the child's
	 * handler of this library may start a thread, and jemalloc's locks
	 * are its own again by then. */
	pthread_mutex_lock(&listen_lock);
	int profiles = profiles_locked();
	pthread_mutex_unlock(&listen_lock);
	shh_at_fork(&fork_part);
	if (profiles != SHH_OK)
		return profiles;
	pthread_once(&at_exit_once, register_at_exit);
	pthread_mutex_lock(&listen_lock);
	int rc = listen_locked(dir);
	pthread_mutex_unlock(&listen_lock);
	return rc;
}

const char *systing_heap_hooks_socket(void)
{
	/* The path is written once for a process, before listen_fd says so. */
	pthread_mutex_lock(&listen_lock);
	const char *path = listen_fd >= 0 ? socket_path : "";
	pthread_mutex_unlock(&listen_lock);
	return path;
}

/* Whether this program is the one named `only`: the last part of what
 * /proc/self/exe names, which for a Python service is the interpreter. */
static bool this_program_is(const char *only)
{
	char exe[4096];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return false;
	exe[n] = '\0';
	const char *slash = strrchr(exe, '/');
	return strcmp(slash ? slash + 1 : exe, only) == 0;
}

/* What the environment asks for, when the library is loaded. There is no
 * caller to tell what came of it, so a request that fails is said once, on
 * standard error. */
__attribute__((constructor)) static void listen_as_the_environment_says(void)
{
	const char *how = secure_getenv("SYSTING_HEAP_HOOKS_LISTEN");
	if (!how || !how[0] || strcmp(how, "0") == 0)
		return;
	/* The environment is inherited by every program the service starts.
	 * One that is not the program named does nothing and says nothing: it
	 * has no thread that it did not start, which some programs cannot
	 * have (one that makes a user namespace is refused with any). */
	const char *only = secure_getenv("SYSTING_HEAP_HOOKS_LISTEN_ONLY");
	if (only && only[0] && !this_program_is(only))
		return;
	bool children = strcmp(how, "fork") == 0;
	int rc = SHH_ERR_LISTEN_HOW;
	if (children || strcmp(how, "1") == 0)
		rc = systing_heap_hooks_listen(NULL);
	if (rc == SHH_OK) {
		pthread_mutex_lock(&listen_lock);
		listen_in_children = children;
		pthread_mutex_unlock(&listen_lock);
		return;
	}
	complain(how, rc);
}
