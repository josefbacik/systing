/*
 * EXPERIMENTAL: what is asked and answered here may change.
 *
 * systing-heap hooks: the responder. One thread that answers requests for a
 * heap dump on a Unix socket, so that a dump can be asked for from outside
 * the process (systing-heap --pid PID --ask) at any moment, and nothing is
 * written to disk: jemalloc writes the dump into an anonymous file, and the
 * answer carries that file's descriptor.
 *
 * The socket is a file in the process's own filesystem,
 * <dir>/.systing-heap.<pid>, the pid being the process's own view of it. A
 * tool outside a container reaches it through /proc/<pid>/root.
 *
 * A request is one line, and so is the answer:
 *
 *   -> "systing-heap 1 dump\n"
 *   <- "ok 1 heap=<bytes> map=<0|1>\n"   with the descriptors, in one message:
 *                                        the dump, then the Python code map
 *                                        when the process writes one
 *   <- "error <why>\n"
 *
 * What the thread may and may not do:
 *
 * - It answers the process's own user and root, and no one else: the socket
 *   is made for its owner alone, and the peer's credentials are checked.
 * - The socket is known by what it is, not by its number alone: a program
 *   that closes descriptors it did not open may give the number to a socket
 *   of its own, and the thread then ends instead of answering there.
 * - It runs nothing of the program's and takes none of its locks. Every
 *   signal is blocked on it, so no handler of the program's runs there.
 * - It is an ordinary thread outside malloc: jemalloc's "prof.dump" is called
 *   as any thread of the program may call it.
 * - A peer that says nothing, or reads nothing, is given up after
 *   IO_TIMEOUT_S seconds; requests are answered one at a time.
 * - A forked child has no such thread and listens nowhere until it asks to.
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

#include "systing_heap_hooks.h"
#include "systing_heap_hooks_listen.h"

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
 * there is none. It is the file at the map's path now, if a regular one:
 * what it holds is read by the tool as any file of the process's is. */
static int code_map(void)
{
	shh_python_make_map();
	const char *path = systing_heap_hooks_python_map();
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
	char line[96];
	snprintf(line, sizeof(line), "ok 1 heap=%lld map=%d\n", size, fds[1] >= 0);
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

void shh_listen_after_fork_child(void)
{
	/* The thread is not in the child, and the socket is the parent's: the
	 * child lets go of its copy, and listens once it asks to. */
	pthread_mutex_init(&listen_lock, NULL);
	if (listen_fd >= 0 && is_the_socket(listen_fd))
		close(listen_fd);
	listen_fd = -1;
	socket_path[0] = '\0';
}

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

static int listen_locked(const char *dir)
{
	if (listen_fd >= 0)
		return SHH_OK;

	if (!mallctl_p)
		mallctl_p = shh_find_mallctl();
	if (!mallctl_p)
		return SHH_ERR_NO_JEMALLOC;
	bool prof = false;
	size_t prof_len = sizeof(prof);
	if (mallctl_p("opt.prof", &prof, &prof_len, NULL, 0) != 0 || !prof)
		return SHH_ERR_PROF_OFF;

	if (!dir)
		dir = secure_getenv("SYSTING_HEAP_HOOKS_SOCKET_DIR");
	if (!dir || !dir[0])
		dir = DEFAULT_DIR;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	int n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/.systing-heap.%ld",
			 dir, (long)getpid());
	if (n < 0 || (size_t)n >= sizeof(addr.sun_path))
		return SHH_ERR_SOCKET_PATH;

	int fd = bind_and_listen(&addr);
	if (fd < 0)
		return SHH_ERR_SOCKET;
	struct stat st;
	if (fstat(fd, &st) != 0) {
		unlink(addr.sun_path);
		close(fd);
		return SHH_ERR_SOCKET;
	}
	/* Known from here on, before there is a thread: a child forked by
	 * another thread meanwhile lets go of it like any other. */
	listen_dev = st.st_dev;
	listen_ino = st.st_ino;
	listen_pid = getpid();
	memcpy(socket_path, addr.sun_path, sizeof(socket_path));
	listen_fd = fd;

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
	shh_register_fork_handlers();
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
