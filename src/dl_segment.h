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

#ifndef _DL_SEGMENT_H
#define _DL_SEGMENT_H

#include <sys/types.h>
#include <sys/queue.h>

SLIST_HEAD(dl_segments, segment);

struct segment {
	SLIST_ENTRY(segment) dls_entries;
	pthread_mutex_t mtx; /* Lock for segemnt whilst updating its log/index. */
	int _log; /* Segement's log file descriptor. */
	int _index; /* Segment's index file descriptor. */
	u_int64_t base_offset; /* Start offset of the log. */
	u_int32_t segment_size;
	u_int64_t offset; /* Current position in the log. TODO remove */
};

extern struct segment * dl_make_default_sized_segment(long int, const char *);
extern struct segment * dl_make_initial_default_sized_segment(const char *);
extern struct segment * dl_make_segment(long int, long int, const char *);
extern void dl_close_segment(struct segment *);
extern int dl_insert_message(struct segment *, char *, int);
extern int dl_get_message_by_offset(struct segment *, int, void *);
extern void dl_lock_seg(struct segment *);
extern void dl_unlock_seg(struct segment *);

#endif
