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

#include "dl_assert.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_utils.h"

struct dl_index {
	struct dl_segment *dli_seg;
};

static inline void 
dl_index_check_integrity(struct dl_index const * const self)
{

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	DL_ASSERT(self->dli_seg != NULL, ("Index segment cannot be NULL."));
}

int
dl_index_new(struct dl_index **self, struct dl_segment *seg)
{
	struct dl_index *idx;

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	DL_ASSERT(seg != NULL, ("Index segment cannot be NULL."));
	
	idx = (struct dl_index *) dlog_alloc(sizeof(struct dl_index));
	if (idx == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed instantiating dl_index.\n");
		return -1;
	}

	idx->dli_seg = seg;

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
	uint32_t o, s, t, x, tmp;
	off_t log_end;
	int rc;
	
	dl_index_check_integrity(self);
	
	/* Create the index. */
	log_end = lseek(self->dli_seg->_log, 0, SEEK_END);

	lseek(self->dli_seg->_index, 0, SEEK_END);
	tmp = self->dli_seg->last_sync_pos;
	while (tmp < log_end) {
		DLOGTR2(PRIO_NORMAL, "tmp = %zu log end =%zu\n", tmp, log_end);
		lseek(self->dli_seg->_log, tmp, SEEK_SET);

		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(uint32_t);

		index_bufs[1].iov_base = &s;
		index_bufs[1].iov_len = sizeof(uint32_t);

		rc = readv(self->dli_seg->_log, index_bufs, 2);	
		DLOGTR2(PRIO_NORMAL, "o = %zu s =%zu\n",
		    be32toh(o), be32toh(s));

		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(uint32_t);

		t = htobe32(tmp);
		index_bufs[1].iov_base = &t;
		index_bufs[1].iov_len = sizeof(uint32_t);

		writev(self->dli_seg->_index, index_bufs, 2);	
		
		tmp += 2 * sizeof(uint32_t);
		tmp += be32toh(s);
	}
	self->dli_seg->last_sync_pos = log_end;
}
