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

#ifndef _KERNEL
// TODO what is all this mess
#include <utime.h>
#endif

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


#include <sys/types.h>
//#include <sys/mman.h>
#include <sys/uio.h>

#ifdef _KERNEL
#include <sys/capsicum.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_utils.h"

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

void
dl_segment_delete(struct dl_segment *self)
{
#ifdef _KERNEL
	//mtx_destroy(&seg->mtx);
#else
	pthread_mutex_destroy(&self->mtx);
#endif
	dlog_free(self);
}

//Method used to create the segment with its log and index files
//#ifdef _KERNEL
struct dl_segment * dl_segment_new(long int base_offset,
    long int length, struct sbuf *partition_name)
{
	struct dl_segment *seg;
	struct sbuf *log_name, *idx_name;
	int log_file, index_file;

	log_name = sbuf_new_auto();
	sbuf_printf(log_name, "%s/%.*ld.log",
	    sbuf_data(partition_name), 20, base_offset);
	sbuf_finish(log_name);
#ifdef _KERNEL
	log_file = 0;
#else
	log_file = open(sbuf_data(log_name), O_RDWR | O_APPEND | O_CREAT, 0666);
	dl_alloc_big_file(log_file, 0, length);
#endif
	sbuf_delete(log_name);

	idx_name = sbuf_new_auto();
	sbuf_printf(idx_name, "%s/%.*ld.index",
	    sbuf_data(partition_name), 20, base_offset);
	sbuf_finish(idx_name);
#ifdef _KERNEL
	index_file = 0;
#else
	index_file = open(sbuf_data(idx_name), O_RDWR | O_APPEND | O_CREAT,
	    0666);
	dl_alloc_big_file(index_file, 0,  length);
#endif
	sbuf_delete(idx_name);

	/* Memory map the index file to perform efficient fecthing;
	 * binary search based on requested offset.
	 */
#ifdef _KERNEL
#else
	//mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, index_file, 0);
#endif

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
#ifdef _KERNEL
#else
#endif
// TODO
#ifdef _KERNEL
#else
	seg->_log = log_file;
	seg->_index = index_file;
#endif
	seg->offset = base_offset;
	seg->base_offset = base_offset;
	seg->segment_size = length;
	seg->last_sync_pos = 0;
#ifdef _KERNEL
#else
	if (pthread_mutex_init(&seg->mtx, NULL) != 0){
		dl_debug(PRIO_HIGH, "Segment mutex init failed\n");
	}
#endif

	return seg;
}
//#endif
int
dl_segment_new_from_desc(struct dl_segment **self,
    struct dl_segment_desc *seg_desc)
{
	struct dl_segment *seg;

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
#ifdef _KERNEL
	struct thread *td = curthread;
	cap_rights_t rights;
	struct file *fp;

	seg->ucred = td->td_ucred;
	fget_write(td, seg_desc->dlsd_log, cap_rights_init(&rights, CAP_WRITE),
	    &fp); 
	seg->_log = fp->f_vnode;
	fget_write(td, seg_desc->dlsd_index,
	    cap_rights_init(&rights, CAP_WRITE), &fp);
	seg->_index = fp->f_vnode;
#else
	seg->_log = seg_desc->dlsd_log;
	seg->_index = seg_desc->dlsd_index;
#endif
	seg->offset = seg_desc->dlsd_base_offset;
	seg->base_offset = seg_desc->dlsd_base_offset;
	seg->segment_size = seg_desc->dlsd_seg_size;
	seg->last_sync_pos = 0;
#ifdef _KERNEL
	//mtx_init(&seg->mtx);
#else
	if (pthread_mutex_init(&seg->mtx, NULL) != 0){
		dl_debug(PRIO_HIGH, "Segment mutex init failed\n");
	}
#endif
	*self = seg;
	return 0;
}

//Method invoked when a new message gets recieved into a segment
int
dl_segment_insert_message(struct dl_segment *self, unsigned char *message,
    int32_t message_size)
{
#ifdef _KERNEL
	struct mount *mp;
	struct thread *td = curthread;
	struct uio u;
#endif
	struct iovec index_bufs[2], log_bufs[2]; //log_bufs[3];
	off_t log_position;
	uint32_t offset, relative_offset;

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));

	DLOGTR1(PRIO_HIGH, "Inserting (%d bytes) into the log\n", message_size);

	dl_segment_lock(self);
	
	/* Update the index file. */
	relative_offset = (uint32_t) self->offset - self->base_offset;
	DLOGTR1(PRIO_HIGH, "relative_offset : '%d'\n", relative_offset);
	index_bufs[0].iov_base = &relative_offset;
	index_bufs[0].iov_len = sizeof(uint32_t);

#ifdef _KERNEL
	//log_position = vn_seek(self->_log, 0, 2, td);
	log_position = 0;
#else
	log_position = lseek(self->_log, 0, SEEK_END);
#endif
	DLOGTR1(PRIO_HIGH, "log_position : '%ld'\n",log_position);
	index_bufs[1].iov_base = &log_position;
	index_bufs[1].iov_len = sizeof(uint32_t);

#ifdef _KERNEL
	bzero(&u, sizeof(struct uio));
	u.uio_iov = index_bufs;
	u.uio_iovcnt = 2;
	u.uio_offset = -1;
        u.uio_resid = index_bufs[0].iov_len + index_bufs[1].iov_len;
        u.uio_segflg = UIO_USERSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	VREF(self->_index);
	crhold(self->ucred);
	vn_start_write(self->_index, &mp, V_WAIT);
	vn_lock(self->_index, LK_EXCLUSIVE | LK_RETRY);
	VOP_WRITE(self->_index, &u, IO_UNIT | IO_APPEND, self->ucred);
	VOP_UNLOCK(self->_index, 0);
	vn_finished_write(mp);
	crfree(self->ucred);
#else
	writev(self->_index, index_bufs, 2);	
#endif

	/* Update the log file. */
	offset = htobe32(self->offset); 
	log_bufs[0].iov_base = &offset;
	log_bufs[0].iov_len = sizeof(uint32_t);
	
	//log_bufs[1].iov_base = &timestamp;
	//log_bufs[1].iov_len = sizeof(uint32_t);

	log_bufs[1].iov_base = message;
	log_bufs[1].iov_len = message_size;

#ifdef _KERNEL
	bzero(&u, sizeof(struct uio));
	u.uio_iov = log_bufs;
	u.uio_iovcnt = 2;
	u.uio_offset = -1;
        u.uio_resid = log_bufs[0].iov_len + log_bufs[1].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	VREF(self->_log);
	crhold(self->ucred);
	vn_start_write(self->_log, &mp, V_WAIT);
	vn_lock(self->_log, LK_EXCLUSIVE | LK_RETRY);
	VOP_WRITE(self->_log, &u, IO_UNIT | IO_APPEND, self->ucred);
	VOP_UNLOCK(self->_log, 0);
	vn_finished_write(mp);
	crfree(self->ucred);
#else
	writev(self->_log, log_bufs, 2);	
#endif

	/* Update the offset. */
	self->offset++;

	dl_segment_unlock(self);
	return 0;
}

int
dl_segment_get_message_by_offset(struct dl_segment *as, int offset,
    struct dl_bbuf **msg_buf)
{
	struct dl_bbuf *idx_buf, *t;
	int32_t roffset, poffset, tmp_buf[2], cid, size;
	int ret;

#ifdef _KERNEL
	ret = - 1;
#else
	lseek(as->_index, offset * 2 * sizeof(int32_t), SEEK_SET);
	ret = read(as->_index, tmp_buf, sizeof(tmp_buf));
#endif
	if (ret > 0) {
		dl_bbuf_new(&idx_buf, (unsigned char *) tmp_buf,
		    sizeof(tmp_buf), DL_BBUF_BIGENDIAN);

		dl_bbuf_get_int32(idx_buf, &roffset);
		dl_bbuf_get_int32(idx_buf, &poffset);

		DLOGTR2(PRIO_LOW,
		    "Relative log offset %d indexs to physical log offset %d\n",
		    roffset, poffset);
		// TODO: buf needs to be allocated
		//dl_bbuf_delete(idx_buf);

#ifdef _KERNEL
#else
		lseek(as->_log, poffset, SEEK_SET);
		read(as->_log, tmp_buf, sizeof(tmp_buf));
#endif
		dl_bbuf_new(&t, (unsigned char *) tmp_buf,
		    sizeof(tmp_buf), DL_BBUF_BIGENDIAN);
		dl_bbuf_get_int32(t, &cid);
		dl_bbuf_get_int32(t, &size);
		// TODO: buf needs to be allocated
		//dl_bbuf_delete(idx_buf);

		DLOGTR1(PRIO_LOW, "Message set size = %d\n", size);
		

		unsigned char *msg_tmp =
		    dlog_alloc(size * sizeof(unsigned char) + sizeof(int32_t));
#ifdef _KERNEL
#else
		lseek(as->_log, poffset+sizeof(int32_t), SEEK_SET);
		ret = read(as->_log, msg_tmp, size + sizeof(int32_t));
#endif
		dl_bbuf_new(msg_buf, NULL, size + sizeof(int32_t), DL_BBUF_BIGENDIAN);
		dl_bbuf_bcat(*msg_buf, msg_tmp, size + sizeof(int32_t));
		return 0;
	} else {
#ifdef _KERNEL
		DLOGTR1(PRIO_HIGH, "For offset %d no message found\n", offset);
#else
		DLOGTR3(PRIO_HIGH, "For offset %d no message found %d (%d).\n",
		    offset, ret, errno);
#endif
		return -1;
	}
	return 0;
}

void
dl_segment_close(struct dl_segment *seg)
{
#ifdef _KERNEL
#else
	// kqueue event on close to fsync the files
	close(seg->_log);
	close(seg->_index);
#endif
}

void
dl_segment_lock(struct dl_segment *seg)
{
#ifdef _KERNEL
#else
	pthread_mutex_lock(&seg->mtx);
#endif
}

void
dl_segment_unlock(struct dl_segment *seg)
{
#ifdef _KERNEL
#else
	pthread_mutex_unlock(&seg->mtx);
#endif
}
