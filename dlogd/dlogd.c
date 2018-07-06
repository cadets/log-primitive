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

#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/event.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "dlog.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_response.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const DLOG = "/dev/dlog";

static int stop  = 0;

unsigned long topic_hashmask2;
LIST_HEAD(dld_parts, dld_part) *topic_hashmap2;

static void dlogd_stop(int);

static void
dlogd_stop(int sig)
{
	stop = 1;
}

	int
main(void)
{
	struct dl_client_config_desc *conf;
	struct dl_topic_desc *tp_desc;
	nvlist_t *props;
	size_t packed_len;
	int dlog, rc;
	struct dl_topic *t;
	struct sbuf *tname;

	DLOGTR0(PRIO_LOW, "Dlog daemon starting...\n");

	signal(SIGINT, dlogd_stop);

	/* Create the hashmap to store the names of the topics managed by the
	 * broker and their segments.
	 */
	topic_hashmap2 = dl_topic_hashmap_new(10, &topic_hashmask2);

	/* Preallocate an initial segement file for the topic and add to the
	 * hashmap.
	 */
	tname = sbuf_new_auto();
	sbuf_cpy(tname, "cadets-trace");
	sbuf_finish(tname);
	dl_topic_new(&t, tname);
	sbuf_delete(tname);

	dlog = open(DLOG, O_RDWR);
	DLOGTR2(PRIO_LOW, "%s %d...\n", DLOG, dlog);

	dl_topic_as_desc(t, &tp_desc);	
	rc = ioctl(dlog, DLOGIOC_ADDTOPICPART, &tp_desc);	
	DLOGTR3(PRIO_LOW, "%s %d (%d)...\n", DLOG, rc, errno);

	while (stop == 0) {

		dl_poll_reactor_handle_events();
	}

	/* Delete the topic hashmap */
	dl_topic_hashmap_delete(topic_hashmap2);

	/* Free the topic. */
	dl_topic_delete(t);

	/* Close the distibuted log. */	
	DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	close(dlog);

	DLOGTR0(PRIO_LOW, "Dlog daemon stopped.\n");

	return 0;
}
