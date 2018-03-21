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
#include <sys/event.h>
#include <sys/time.h>

#ifdef __KERNEL
#else
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#endif

#include "dl_assert.h"
#include "dl_broker_partition.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_utils.h"


#ifdef __KERNEL
#else
static const off_t DL_FSYNC_DEFAULT_CHARS = 1000;

static dl_event_handler_handle dl_partition_get_kq(void *);
static void dl_partition_handle_kq(void *);

static dl_event_handler_handle
dl_partition_get_kq(void* instance)
{
	const struct dl_partition *partition = instance;
	return partition->_klog;
}

static void
dl_partition_handle_kq(void *instance)
{
	struct dl_partition * const partition = instance;
	struct dl_segment *segment = partition->dlp_active_segment;
	struct kevent event;
	off_t log_position;
	int rc;

	rc = kevent(partition->_klog, 0, 0, &event, 1, 0);
	if (rc == -1)
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.", rc, errno);
	else {
		dl_segment_lock(segment);
		log_position = lseek(segment->_log, 0, SEEK_END);
		DLOGTR2(PRIO_LOW, "log_position = %d, last_sync_pos = %d\n",
		    log_position, segment->last_sync_pos);
		if (log_position - segment->last_sync_pos > DL_FSYNC_DEFAULT_CHARS) {

			DLOGTR0(PRIO_NORMAL, "Syncing the index and log...\n");

			fsync(segment->_log);
			fsync(segment->_index);
			segment->last_sync_pos = log_position;
		}
		dl_segment_unlock(segment);
	}
}
#endif

int
dl_partition_new(struct dl_partition **self, struct sbuf *topic_name)
{
	struct dl_partition *partition;
#ifndef _KERNEL
	struct dl_segement *segment;
	struct kevent event;
#endif
	struct sbuf *partition_name;

	DL_ASSERT(topic_name != NULL, ("Topic name cannot be NULL."));

	partition = (struct dl_partition *) dlog_alloc(
	    sizeof(struct dl_partition));
#ifdef _KERNEL
	DL_ASSERT(partition != NULL, ("Failed allocating partition."));
	{
#else
	if (partition != NULL) {
#endif
		SLIST_INIT(&partition->dlp_segments);

		/* Create the specified partition; deleting if already present. */
		partition_name = sbuf_new_auto();
		sbuf_printf(partition_name, "%s-%d", sbuf_data(topic_name),
		    DL_DEFAULT_PARTITION);

		dl_del_folder(partition_name);
		dl_make_folder(partition_name);

		partition->dlp_active_segment =
		    dl_segment_new_default(partition_name);
#ifdef _KERNEL
		DL_ASSERT(partition->dlp_active_segment != NULL,
		    ("Failed allocating partition segment."));
		{
#else
		if (partition->dlp_active_segment != NULL) {
#endif
			SLIST_INSERT_HEAD(&partition->dlp_segments,
			    partition->dlp_active_segment, dls_entries);

			/* Register kqueue event to monitor writes on the partition's
			* active segment. fsync is called on the segment when writes
			* exceed a per-topic configured limit.
			*/
			//topic_partition = SLIST_FIRST(&topic->dlt_partitions);
			//active_segment = topic_partition->dlp_active_segment; 

#ifdef __KERNEL
#else
			partition->_klog = kqueue();
// TODO error handling
			EV_SET(&event, partition->dlp_active_segment->_log,
			    EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0, NULL);
			kevent(partition->_klog, &event, 1, NULL, 0, NULL); 
// TODO error handling
			partition->event_handler.dleh_instance = partition;
			partition->event_handler.dleh_get_handle = dl_partition_get_kq;
			partition->event_handler.dleh_handle_event = dl_partition_handle_kq;

			/* Register the topic's active partition with the poll reactor. */
			dl_poll_reactor_register(&partition->event_handler);
// TODO error handling
#endif

			*self = partition;
			return 0;
		}

		dlog_free(partition);
	}

	DLOGTR0(PRIO_HIGH, "Failed allocating partition.\n");
	return -1;
}
