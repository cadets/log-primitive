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

#ifndef _DL_FETCH_RESPONSE_H
#define _DL_FETCH_RESPONSE_H

#include <sys/types.h>
#include <sys/queue.h>
#ifdef KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#endif

#include "dl_bbuf.h"
#include "dl_message_set.h"

SLIST_HEAD(dl_fetch_response_topics, dl_fetch_response_topic);
SLIST_HEAD(dl_fetch_response_partitions, dl_fetch_response_partition);

struct dl_fetch_response_partition {
	SLIST_ENTRY(dl_fetch_response_partition) dlfrp_entries;
	struct dl_message_set *dlfrp_message_set;
	int64_t dlfrpr_high_watermark;
	int32_t dlfrpr_partition;
	int16_t dlfrpr_error_code;
};

struct dl_fetch_response_topic {
	struct dl_fetch_response_partitions dlfrt_partitions;
	SLIST_ENTRY(dl_fetch_response_topic) dlfrt_entries;
	struct sbuf *dlfrt_topic_name;
	int32_t dlfrt_npartitions;
};	

struct dl_fetch_response {
	struct dl_fetch_response_topics dlfr_topics;
	int32_t dlfr_ntopics;
	int32_t dlfr_throttle_time;
};

extern struct dl_response * dl_fetch_response_decode(char *);
extern int dl_fetch_response_encode(struct dl_fetch_response *,
    struct dl_bbuf *);

#endif
