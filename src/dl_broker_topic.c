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

#include <sys/queue.h>

#ifdef KERNEL
#include <sys/hash.h>
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#endif

#include <stddef.h>

#include "dl_memory.h"
#include "dl_broker_topic.h"
#include "dl_utils.h"

void *
dl_topic_hashinit(int elements, unsigned long *hashmask)
{
	long hashsize;
	LIST_HEAD(dl_broker_topics, dl_broker_topic) *hashtbl;
	int i;

	DL_ASSERT(elements > 0, ("Elements in hash table must be > 0."));

	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	hashtbl = dlog_alloc((unsigned long) hashsize * sizeof(*hashtbl));
	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize -1;
	}

	return hashtbl;
}

struct dl_broker_topic *
dl_topic_new(struct sbuf *topic_name)
{
	struct dl_partition *partition;
	struct dl_broker_topic *topic;
	struct sbuf *tname;
		
	topic = (struct dl_broker_topic *) dlog_alloc(
	    sizeof(struct dl_broker_topic));
#ifdef KERNEL
	DL_ASSERT(partition != NULL, ("Failed allocating topic."));
	{
#else
	if (topic != NULL) {
#endif
		tname = sbuf_new_auto();
		sbuf_cpy(tname, topic_name);

		SLIST_INIT(&topic->dlt_partitions);
		topic->dlbt_topic_name = topic_name;

		if (dl_partition_new(&partition, topic_name) == 0) {

			topic->dlt_offset = 0;
			SLIST_INSERT_HEAD(&topic->dlt_partitions, partition,
			    dlp_entries);

		} else {
			DLOGTR0(PRIO_HIGH,
			    "Error instantiating default partition\n");
			dlog_free(topic);
			topic = NULL;
		}
	}
	return topic;
}
