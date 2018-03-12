/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

// The utilities used
#if defined(HAVE_POSIX_FALLOCATE) && !defined(__sun) && !defined(__sun__)
#define _XOPEN_SOURCE 600
#endif
#if !defined(_GNU_SOURCE) && defined(HAVE_LINUX_FALLOC_H)
#define _GNU_SOURCE
#endif
#include <utime.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/types.h>
#include <sys/uio.h>
#endif
#if defined(HAVE_SENDFILE) && (defined(__linux__) || (defined(__sun) && defined(__SVR4)))
#include <sys/sendfile.h>
#endif

#if defined(__APPLE__) && defined(__MACH__) && !defined(__DARWIN__)
#define DARWIN 1
#endif

#if defined(DARWIN) || defined(HAVE_LINUX_FALLOC_H) || defined(HAVE_POSIX_FALLOCATE)
#include <fcntl.h>
#endif

#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif

#include <sys/mman.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>

#include <pthread.h>

#include "dl_broker_segment.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_utils.h"

static int dl_alloc_big_file(int, long int, long int);
#ifdef HAVE_POSIX_FALLOCATE
static int dl_call_posix_fallocate(int, Sint64, Sint64);
#endif

// Adopted from http://www.doc.ic.ac.uk/~rn710/Installs/otp_src_17.0/erts/emulator/drivers/unix/unix_efile.c
//
static int
dl_alloc_big_file(int fd, long int offset, long int length)
{
#if defined HAVE_FALLOCATE
	/* Linux specific, more efficient than posix_fallocate. */
	int ret;

	do {
		ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, (off_t) offset,
		    (off_t) length);
	} while (ret != 0 && errno == EINTR);

#if defined HAVE_POSIX_FALLOCATE
	/* Fallback to posix_fallocate if available. */
	if (ret != 0) {
        	ret = dl_call_posix_fallocate(fd, offset, length);
    	}
#endif

	return check_error(ret, errInfo);
#elif defined F_PREALLOCATE
	/* Mac OS X specific, equivalent to posix_fallocate. */
	int ret;
	fstore_t fs;

	memset(&fs, 0, sizeof(fs));
	fs.fst_flags = F_ALLOCATECONTIG;
	fs.fst_posmode = F_VOLPOSMODE;
	fs.fst_offset = (off_t) offset;
	fs.fst_length = (off_t) length;

	dl_debug(PRIO_LOW, "Preallocating the file for mac ... ");
	ret = fcntl(fd, F_PREALLOCATE, &fs);
	printf("%d\n", ret);

	if (-1 == ret) {
		dl_debug(PRIO_NORMAL, "Failed to preallocate... Trying to allocate all...\n");
		fs.fst_flags = F_ALLOCATEALL;
		ret = fcntl(fd, F_PREALLOCATE, &fs);
		dl_debug(PRIO_NORMAL, "Returncode: %d\n", ret);

#if defined HAVE_POSIX_FALLOCATE
		/* Fallback to posix_fallocate if available. */
		if (-1 == ret) {
			ret = dl_call_posix_fallocate(fd, offset, length);
		}
#endif
	}

	return ret < 0 ? 0 : 1;
#elif defined HAVE_POSIX_FALLOCATE
	/* Other Unixes, use posix_fallocate if available. */
	return dl_call_posix_fallocate(fd, offset, length) < 0 ? 0 : 1;
#else
	return -1;
#endif
}

#ifdef HAVE_POSIX_FALLOCATE
static int
dl_call_posix_fallocate(int fd, Sint64 offset, Sint64 length)
{
	int ret;

	/*
	* On Linux and Solaris for example, posix_fallocate() returns
	* a positive error number on error and it does not set errno.
	* On FreeBSD however (9.0 at least), it returns -1 on error
	* and it sets errno.
	*/
	do {
		ret = posix_fallocate(fd, (off_t) offset, (off_t) length);
		if (ret > 0) {
			errno = ret;
			ret = -1;
		}
	} while (ret != 0 && errno == EINTR);

	return ret;
}
#endif /* HAVE_POSIX_FALLOCATE */

struct dl_segment *
dl_segment_new_default(struct sbuf *partition_name)
{
	return dl_segment_new(0, 1024*1024, partition_name);
}

struct dl_segment *
dl_segment_new_default_sized(long int base_offset,
    struct sbuf *partition_name)
{
	return dl_segment_new(base_offset, 1024*1024, partition_name);
}

//Method used to create the segment with its log and index files
struct dl_segment * dl_segment_new(long int base_offset,
    long int length, struct sbuf *partition_name)
{
	struct dl_segment *seg;
	int log_file, index_file;
	struct sbuf *log_name, *idx_name;

	log_name = sbuf_new_auto();
	sbuf_printf(log_name, "%s/%.*ld.log",
	    sbuf_data(partition_name), 20, base_offset);
	log_file = open(sbuf_data(log_name), O_RDWR | O_APPEND | O_CREAT, 0666);
	dl_alloc_big_file(log_file, 0, length);
	sbuf_delete(log_name);

	idx_name = sbuf_new_auto();
	sbuf_printf(idx_name, "%s/%.*ld.index",
	    sbuf_data(partition_name), 20, base_offset);
	index_file = open(sbuf_data(idx_name), O_RDWR | O_APPEND | O_CREAT, 0666);
	dl_alloc_big_file(index_file, 0,  length);
	sbuf_delete(idx_name);

	/* Memory map the index file to perform efficient fecthing;
	 * binary search based on requested offset.
	 */
	mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, index_file, 0);

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
// TODO
	seg->_log = log_file;
	seg->_index = index_file;
	seg->offset = base_offset;
	seg->base_offset = base_offset;
	seg->segment_size = length;
	if (pthread_mutex_init(&seg->mtx, NULL) != 0){
		dl_debug(PRIO_HIGH, "Segment mutex init failed\n");
	}

	return seg;
}

//Method invoked when a new message gets recieved into a segment
int
dl_segment_insert_message(struct dl_segment *as, char *message, int32_t message_size)
{
	off_t index_position, log_position;
	uint32_t offset, relative_offset;
	struct iovec index_bufs[2], log_bufs[2];

	DLOGTR1(PRIO_HIGH, "Inserting into the log: '%s'\n", message);

	dl_segment_lock(as);
	
	/* Update the index file. */
	relative_offset = htobe32((uint32_t) as->offset - as->base_offset);
	index_bufs[0].iov_base = &relative_offset;
	index_bufs[0].iov_len = sizeof(uint32_t);

	log_position = htobe32(lseek(as->_log, 0, SEEK_END));
	index_bufs[1].iov_base = &log_position;
	index_bufs[1].iov_len = sizeof(uint32_t);

	writev(as->_index, index_bufs, 2);	

	/* Update the log file. */
	offset = htobe32(as->offset); 
	log_bufs[0].iov_base = &offset;
	log_bufs[0].iov_len = sizeof(uint32_t);

	log_bufs[1].iov_base = message;
	log_bufs[1].iov_len = message_size;

	writev(as->_log, log_bufs, 2);	

	/* Update the offset. */
	as->offset++;

	dl_segment_unlock(as);

	return 0;
}

/*
int
dl_segment_get_message_by_offset(struct dl_segment *as, int offset, void *saveto)
{
	char buf[bytes_per_index_entry];
	char *bp = buf;
	char log_size_field[log_size_entry];
	int ret, log_offset, msg_size;

	lseek(as->_index, offset*bytes_per_index_entry, SEEK_SET);

	ret = read(as->_index, buf, bytes_per_index_entry);
	if (ret > 0) {
		log_offset = atoi(bp+index_size_entry);
		dl_debug(PRIO_LOW,
		    "For requested offset %d log offset is %d\n", offset,
		    log_offset);

		lseek(as->_log, log_offset, SEEK_SET);

		log_size_field[log_size_entry] = '\0';

		ret = read(as->_log, log_size_field, log_size_entry);
		if (ret > 0) {
			msg_size = atoi(log_size_field);

			ret = read(as->_log, saveto, msg_size);
			return msg_size;
		}
		return ret;
	} else {
		dl_debug(PRIO_HIGH, "For offset %d no message found.\n",
		    offset);
	}
	return 0;
}
*/

void
dl_segment_close(struct dl_segment *seg)
{
	// kqueue event on close to fsync the files
	close(seg->_log);
	close(seg->_index);
}

void
dl_segment_lock(struct dl_segment *seg)
{
	pthread_mutex_lock(&seg->mtx);
}

void
dl_segment_unlock(struct dl_segment *seg)
{
	pthread_mutex_unlock(&seg->mtx);
}
