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

#ifndef _DL_LIST_OFFSET_REQUEST_H
#define _DL_LIST_OFFSET_REQUEST_H

#include <sys/queue.h>
#include <sys/types.h>
#ifdef _KERNEL
#include <sys/sbuf.h>
#else
#include <sys/sbuf.h>
#include <stdint.h>
#endif

#include "dl_bbuf.h"

struct dl_request;

SLIST_HEAD(dl_list_offset_request_topics, dl_list_offset_request_topic);

struct dl_list_offset_request_partition {
	int32_t dlorp_partition;
	int64_t dlorp_time;
};

struct dl_list_offset_request_topic {
	SLIST_ENTRY(dl_list_offset_request_topic) dlort_entries;
	struct sbuf *dlort_topic_name;
	int32_t dlort_npartitions;
	struct dl_list_offset_request_partition dlort_partitions[1];
};

struct dl_list_offset_request {
	struct dl_list_offset_request_topics dlor_topics;
	int32_t dlor_ntopics;
	int32_t dlor_replica_id;
};

extern struct dl_request * dl_list_offset_request_new(int32_t, struct sbuf *,
    struct sbuf *, int64_t);
extern void dl_list_offset_request_delete(struct dl_request *);

extern int dl_list_offset_request_decode(struct dl_list_offset_request **, 
    struct dl_bbuf *);
extern int dl_list_offset_request_encode(struct dl_list_offset_request *,
    struct dl_bbuf *);

#endif
