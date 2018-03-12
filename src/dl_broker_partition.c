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

#include <stddef.h>

#include "dl_assert.h"
#include "dl_broker_partition.h"
#include "dl_memory.h"
#include "dl_utils.h"

int
dl_partition_new(struct dl_partition **self, struct sbuf *topic_name)
{
	struct dl_partition *partition;
	struct dl_segement *segment;

	DL_ASSERT(topic_name != NULL, ("Topic name cannot be NULL."));

	partition = (struct dl_partition *) dlog_alloc(
	    sizeof(struct dl_partition));
#ifdef KERNEL
	DL_ASSERT(partition != NULL, ("Failed allocating partition."));
	{
#else
	if (partition != NULL) {
#endif
		SLIST_INIT(&partition->dlp_segments);

		/* Create the specified partition;
		 * deleting if already present. */
		sbuf_printf(topic_name, "-%d", DL_DEFAULT_PARTITION);
		DLOGTR1(PRIO_HIGH, "t/p = %s\n", sbuf_data(topic_name));

		dl_del_folder(sbuf_data(topic_name));
		dl_make_folder(sbuf_data(topic_name));

		partition->dlp_active_segment =
		    dl_segment_new_default(topic_name);
// TODO error check
		SLIST_INSERT_HEAD(&partition->dlp_segments,
		    partition->dlp_active_segment, dls_entries);

		*self = partition;
		return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed allocating partition.\n");
	return -1;
}
