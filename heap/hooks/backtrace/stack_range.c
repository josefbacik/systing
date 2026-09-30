/*
 * systing-heap hooks: the mapping an address is in, read from /proc/self/maps
 * without allocating, for the "frame-pointer" backtrace (frame_pointer.c).
 *
 * This file is jemalloc's, from the frame-pointer unwinder it had between
 * September 2024 and July 2026: src/prof_stack_range.c at commit
 * afeda129b00ca57624be06902a5e5752a7517c65 of
 * https://github.com/jemalloc/jemalloc, the last one that has it. How it reads
 * and parses is unchanged. What is changed:
 *
 *   - jemalloc's wrappers for open, read and close (malloc_open, malloc_read_fd
 *     and malloc_close, of malloc_io.h and malloc_io.c) are written out here,
 *     as they are in a jemalloc built for Linux: system calls made directly.
 *     The C library's own open(), read() and close() are places a thread can
 *     be cancelled at, which must not happen inside malloc. The call to open
 *     is openat, which every machine has, where jemalloc prefers open.
 *   - The file is opened O_CLOEXEC: another thread may fork and exec while it
 *     is open.
 *   - The path is /proc/self/maps and not /proc/<pid>/task/<tid>/maps. Only
 *     addresses are read, which are the same in both, and the path needs no
 *     formatting.
 *   - What is left of the buffer is moved to its start with memmove() and not
 *     memcpy(): after a short read the two can overlap.
 *   - Names, and the layout of the text, are this library's.
 *
 * It is used under jemalloc's license:
 *
 * Copyright (C) 2002-present Jason Evans <jasone@canonware.com>.
 * All rights reserved.
 * Copyright (C) 2007-2012 Mozilla Foundation.  All rights reserved.
 * Copyright (C) 2009-present Facebook, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice(s),
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice(s),
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "frame_pointer.h"

static int open_maps(void)
{
	return (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps",
			    O_RDONLY | O_CLOEXEC);
}

static ssize_t read_fd(int fd, void *buf, size_t count)
{
	size_t bytes_read = 0;
	do {
		ssize_t result = (ssize_t)syscall(SYS_read, fd,
						  (char *)buf + bytes_read,
						  count - bytes_read);
		if (result < 0) {
			if (errno == EINTR)
				continue;
			return result;
		} else if (result == 0) {
			break;
		}
		bytes_read += (size_t)result;
	} while (bytes_read < count);
	return (ssize_t)bytes_read;
}

/*
 * Converts a string representing a hexadecimal number to an unsigned long long
 * integer. Functionally equivalent to strtoull() (for base 16) but faster for
 * that case.
 *
 * `endptr`, which can be NULL, is set to the character in `nptr` where parsing
 * stopped.
 */
static inline unsigned long long strtoull_hex(const char *nptr, char **endptr)
{
	unsigned long long val = 0;
	int ii = 0;
	for (; ii < 16; ++ii) {
		char c = nptr[ii];
		if (c >= '0' && c <= '9') {
			val = (val << 4) + (unsigned long long)(c - '0');
		} else if (c >= 'a' && c <= 'f') {
			val = (val << 4) + (unsigned long long)(c - 'a' + 10);
		} else {
			break;
		}
	}
	if (endptr)
		*endptr = (char *)(nptr + ii);
	return val;
}

int shh_mapping_containing(uintptr_t addr, uintptr_t *mm_start, uintptr_t *mm_end)
{
	int ret = ENOENT; /* not found */
	*mm_start = *mm_end = 0;

	/*
	 * Each line of /proc/<pid>/maps is:
	 * <start>-<end> <perms> <offset> <dev> <inode> <pathname>
	 *
	 * The fields we care about are always within the first 34 characters so
	 * as long as `buf` contains the start of a mapping line it can always be
	 * parsed.
	 */
	static const int kMappingFieldsWidth = 34;

	int fd = -1;
	char buf[4096];
	ssize_t remaining = 0; /* actual number of bytes read to buf */
	char *line = NULL;

	while (1) {
		if (fd < 0) {
			/* case 0: initial open of maps file */
			fd = open_maps();
			if (fd < 0)
				return errno;

			remaining = read_fd(fd, buf, sizeof(buf));
			if (remaining < 0) {
				ret = errno;
				break;
			} else if (remaining == 0) {
				break;
			}
			line = buf;
		} else if (line == NULL) {
			/* case 1: no newline found in buf */
			remaining = read_fd(fd, buf, sizeof(buf));
			if (remaining < 0) {
				ret = errno;
				break;
			} else if (remaining == 0) {
				break;
			}
			line = memchr(buf, '\n', (size_t)remaining);
			if (line != NULL) {
				line++; /* advance to character after newline */
				remaining -= (line - buf);
			}
		} else if (remaining < kMappingFieldsWidth) {
			/*
			 * case 2: found newline but insufficient characters
			 * remaining in buf
			 */
			/* copy remaining characters to start of buf */
			memmove(buf, line, (size_t)remaining);
			line = buf;

			ssize_t count = read_fd(fd, buf + remaining,
						sizeof(buf) - (size_t)remaining);
			if (count < 0) {
				ret = errno;
				break;
			} else if (count == 0) {
				break;
			}

			remaining += count; /* actual number of bytes read to buf */
		} else {
			/* case 3: found newline and sufficient characters to parse */

			/* parse <start>-<end> */
			char *tmp = line;
			uintptr_t start_addr = (uintptr_t)strtoull_hex(tmp, &tmp);
			if (addr >= start_addr) {
				tmp++; /* advance to character after '-' */
				uintptr_t end_addr =
					(uintptr_t)strtoull_hex(tmp, NULL);
				if (addr < end_addr) {
					*mm_start = start_addr;
					*mm_end = end_addr;
					ret = 0;
					break;
				}
			}

			/* Advance to character after next newline in the current buf. */
			char *prev_line = line;
			line = memchr(line, '\n', (size_t)remaining);
			if (line != NULL) {
				line++; /* advance to character after newline */
				remaining -= (line - prev_line);
			}
		}
	}

	syscall(SYS_close, fd);
	return ret;
}
