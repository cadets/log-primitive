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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>

#include "dl_assert.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_utils.h"

struct dl_index {
	struct dl_segment *dli_seg;
	int dli_fd;
};

struct dl_index_record {
	uint32_t dlir_offset;
	uint32_t dlir_poffset;
};

static inline void 
dl_index_check_integrity(struct dl_index const * const self)
{

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	DL_ASSERT(self->dli_seg != NULL, ("Index segment cannot be NULL."));
}

int
dl_index_new(struct dl_index **self, struct dl_segment *seg,
    struct sbuf *part_name)
{
	struct dl_index *idx;
	struct sbuf *idx_name;
	int fd;

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	DL_ASSERT(seg != NULL, ("Index segment cannot be NULL."));
	
	idx = (struct dl_index *) dlog_alloc(sizeof(struct dl_index));
	if (idx == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed instantiating dl_index.\n");
		return -1;
	}

	idx->dli_seg = seg;

	idx_name = sbuf_new_auto();
	sbuf_printf(idx_name, "%s/%.*ld.index",
	    sbuf_data(part_name), 20, dl_segment_get_base_offset(seg));
	sbuf_finish(idx_name);
	fd = open(sbuf_data(idx_name), O_RDWR | O_APPEND | O_CREAT, 0666);

	/* Memory map the index file to perform efficient fecthing;
	 * binary search based on requested offset.
	 */
#ifdef _KERNEL
#else
	//mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, index_file, 0);
#endif

	//if (fd)
	//dl_alloc_big_file(idx->dli_fd, 0,  length);
	sbuf_delete(idx_name);
	idx->dli_fd = fd;

	*self = idx;
	dl_index_check_integrity(*self);
	return 0;
}

void
dl_index_delete(struct dl_index *self)
{

	dl_index_check_integrity(self);
	dlog_free(self);
}

void
dl_index_update(struct dl_index *self)
{
	struct iovec index_bufs[2];
	uint32_t o, s, t, x, last_sync;
	off_t log_end;
	int rc;
	
	dl_index_check_integrity(self);
	
	/* Create the index. */
	log_end = lseek(dl_segment_get_log(self->dli_seg), 0, SEEK_END);

	lseek(self->dli_fd, 0, SEEK_END);
	last_sync = dl_segment_get_last_sync_pos(self->dli_seg);
	while (last_sync < log_end) {
		//DLOGTR2(PRIO_NORMAL, "last_sync = %zu log end =%zu\n", last_sync, log_end);
		lseek(dl_segment_get_log(self->dli_seg), last_sync, SEEK_SET);

		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(uint32_t);

		index_bufs[1].iov_base = &s;
		index_bufs[1].iov_len = sizeof(uint32_t);

		rc = readv(dl_segment_get_log(self->dli_seg), index_bufs, 2);	
		//DLOGTR2(PRIO_NORMAL, "o = %zu s =%zu\n",
		//    be32toh(o), be32toh(s));

		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(uint32_t);

		t = htobe32(last_sync);
		index_bufs[1].iov_base = &t;
		index_bufs[1].iov_len = sizeof(uint32_t);

		writev(self->dli_fd, index_bufs, 2);	
		
		last_sync += 2 * sizeof(uint32_t);
		last_sync += be32toh(s);
	}

	fsync(self->dli_fd);
	dl_segment_set_last_sync_pos(self->dli_seg, log_end);
}


off_t
dl_index_lookup(struct dl_index *self, int offset)
{
	struct dl_index_record record;
	struct dl_bbuf *idx_buf, *t;
	int32_t roffset, poffset;
	int ret;
	
	dl_index_check_integrity(self);

	// TODO: Error checking on the lseek
	lseek(self->dli_fd, offset * sizeof(struct dl_index_record), SEEK_SET);

	ret = read(self->dli_fd, &record, sizeof(record));
	if (ret > 0) {
		dl_bbuf_new(&idx_buf, (unsigned char *) &record,
		    sizeof(record), DL_BBUF_BIGENDIAN);

		dl_bbuf_get_int32(idx_buf, &roffset);
		DL_ASSERT(offset == roffset,
		    ("Request offset doesn't match that it index."));
		dl_bbuf_get_int32(idx_buf, &poffset);
		dl_bbuf_delete(idx_buf);

		return poffset;
	}
	return -1;
}