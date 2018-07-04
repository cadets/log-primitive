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
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/hash.h>
#include <sys/nv.h>
#include <sys/conf.h>
#include <fs/devfs/devfs_int.h>

#include <dtrace.h>
#include <dtrace_impl.h>

#include "dl_assert.h"
#include "dlog_client.h"
#include "dl_utils.h"

MALLOC_DECLARE(M_DLKON);
MALLOC_DEFINE(M_DLKON, "dlkon", "DLog konsumer memory");

static void konsumer_open(void *, struct dtrace_state *);
static void konsumer_close(void *, struct dtrace_state *);
static int konsumer_event_handler(struct module *, int, void *);
static void konsumer_on_response(struct dl_response const * const);
static void konsumer_thread(void *);

static char const * const KONSUMER_NAME = "dl_konsumer";

static moduledata_t konsumer_conf = {
	KONSUMER_NAME,
	konsumer_event_handler,
	NULL
};

struct konsumer {
	LIST_ENTRY(konsumer) konsumer_entries;
	struct cv konsumer_cv;
	struct mtx konsumer_mtx;
	struct proc *konsumer_pid;
	dtrace_state_t *konsumer_state;
	struct dlog_handle *konsumer_dlog_handle;
	int konsumer_exit;
};

static const int KON_NHASH_BUCKETS = 16;

static dtrace_kops_t kops = {
	.dtkops_open = konsumer_open,
	.dtkops_close = konsumer_close,
};
static dtrace_konsumer_id_t kid;

static LIST_HEAD(konsumers, konsumer) *konsumer_hashtbl = NULL;
static u_long konsumer_hashmask;

static void
konsumer_on_response(struct dl_response const * const response)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_topic *produce_topic;
	int part;

	DLOGTR1(PRIO_LOW, "Response correlation id = %d\n",
	    response->dlrs_correlation_id);
	DLOGTR1(PRIO_LOW, "Response api key= %d\n", response->dlrs_api_key);

	switch (response->dlrs_api_key) {
	case DL_PRODUCE_API_KEY:
		produce_response = response->dlrs_produce_response;

		DLOGTR1(PRIO_LOW, "ntopics= %d\n",
		     produce_response->dlpr_ntopics);

		SLIST_FOREACH(produce_topic,&produce_response->dlpr_topics,
		    dlprt_entries) {

			DLOGTR1(PRIO_LOW, "Topic: %s\n",
			    sbuf_data(produce_topic->dlprt_topic_name));

			for (part = 0; part < produce_topic->dlprt_npartitions;
			    part++) {

				DLOGTR1(PRIO_LOW, "Partition: %d\n",
				    produce_topic->dlprt_partitions[part].dlprp_partition);

				DLOGTR1(PRIO_LOW, "ErrorCode: %d\n",
				    produce_topic->dlprt_partitions[part].dlprp_error_code);

				DLOGTR1(PRIO_LOW, "Base offset: %ld\n",
				    produce_topic->dlprt_partitions[part].dlprp_offset);
			};
		};
		break;
	default:
		DLOGTR1(PRIO_HIGH, "Unexcepted Response %d\n",
		    response->dlrs_api_key);
		break;
	}
}

static int
konsumer_event_handler(struct module *module, int event, void *arg)
{
	struct konsumer *k, *k_tmp;
	int e = 0, i;

	switch(event) {
	case MOD_LOAD:
		DLOGTR0(PRIO_LOW, "Loading Konsumer kernel module\n");

		/* Initialise the hash table of konsumer instances. */
		konsumer_hashtbl = hashinit(KON_NHASH_BUCKETS, M_DLKON,
		    &konsumer_hashmask);

		/* Register the konsumer with DTrace. After successfully
		 * registering the konsumer with be informed of lifecycle
		 * events (open/close) that result from DTrace consumers.
		 */ 
		dtrace_konsumer_register(KONSUMER_NAME, &kops, NULL, &kid);
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading Konsumer kernel module\n");
		
		/* Unregister and stop any konsumer threads. */ 
		for (i = 0; i < KON_NHASH_BUCKETS; i++) {	
			LIST_FOREACH_SAFE(k, &konsumer_hashtbl[i],
			    konsumer_entries, k_tmp) {
				DLOGTR1(PRIO_HIGH,
				    "Stopping konsumer thread %p..\n", k);
				/* Signal konsumer and wait for completion. */
				mtx_lock(&k->konsumer_mtx);
				k->konsumer_exit = 1;
				cv_broadcast(&k->konsumer_cv);
				mtx_unlock(&k->konsumer_mtx);
				tsleep(k->konsumer_pid, 0,
				    "waiting for konsumer process",
				    10 * hz / 9);

				/* Remove the konsumer and destroy. */
				DLOGTR0(PRIO_LOW,
				    "Konsumer thread stoppped successfully\n");
				LIST_REMOVE(k, konsumer_entries);
				mtx_destroy(&k->konsumer_mtx);
				cv_destroy(&k->konsumer_cv);
				free(k, M_DLKON);
			}
		}
		
		hashdestroy(konsumer_hashtbl, M_DLKON, konsumer_hashmask);
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static void
konsumer_thread(void *arg)
{
	struct dlog_handle *handle;
	struct konsumer *k = (struct konsumer *)arg;
	dtrace_icookie_t cookie;
	uint64_t offset = 0, xamot_offset = 0;

	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL\n"));
	
	DLOGTR0(PRIO_HIGH, "Konsumer thread starting...\n");
	
	handle = k->konsumer_dlog_handle;

	/* Configure the default values for the client_id, topic and
	 * hostname.
	 */
	for (;;) {
		mtx_lock(&k->konsumer_mtx);
		cv_timedwait(&k->konsumer_cv, &k->konsumer_mtx, 10 * hz / 9);
		if (k->konsumer_exit)  {
			mtx_unlock(&k->konsumer_mtx);
	 		DLOGTR0(PRIO_HIGH, "Stopping konsumer thread..\n");
			break;
		}
		cookie = dtrace_interrupt_disable();
		DL_ASSERT(k->konsumer_state->dts_buffer != NULL,
		    ("DTrace buffer invalid whilst konsumer state is open."));
		if (k->konsumer_exit)  {
			mtx_unlock(&k->konsumer_mtx);
	 		DLOGTR0(PRIO_HIGH, "Stopping konsumer thread..\n");
			break;
		}
		offset = k->konsumer_state->dts_buffer->dtb_offset;
		xamot_offset = k->konsumer_state->dts_buffer->dtb_xamot_offset;
		dtrace_interrupt_enable(cookie);
		mtx_unlock(&k->konsumer_mtx);

		DLOGTR1(PRIO_HIGH, "Buffer dtb_offset = %lu\n", offset);
		DLOGTR1(PRIO_HIGH, "Buffer dtb_xamot_offset = %lu\n",
		    xamot_offset);

		/* TODO: Handle the buffer wrapping and find EPIDNONE */
		uint64_t size = 0;
		while (k->konsumer_state->dts_buffer->dtb_tomax[0] != 0) {
		    size++;
		}

		DLOGTR1(PRIO_HIGH, "Buffer dtb_size = %lu\n", size);
		if (dlog_produce(handle, "record", strlen("record"),
		    &k->konsumer_state->dts_buffer->dtb_tomax[0],
		    size) == 0) {
			DLOGTR0(PRIO_LOW,
			    "Successfully produced message to DLog\n");

			/* Consumed value from the DTrace ring buffer, adjust
			 * the ring buffer accordingly.
			 */
			cookie = dtrace_interrupt_disable();
			k->konsumer_state->dts_buffer->dtb_xamot_offset =
			    offset;
			dtrace_interrupt_enable(cookie);
		}
	}

	DLOGTR0(PRIO_HIGH, "Konsumer thread exited successfully.\n");
	kproc_exit(0);
}

static void
konsumer_open(void *arg, struct dtrace_state *state)
{
	struct cdev_privdata *p;
	struct dlog_handle *handle;
	struct file *fp;
	struct filedesc *fdp = curproc->p_fd;
	dtrace_konsumer_t *konsumer = (dtrace_konsumer_t *)arg;
	dtrace_konsumer_id_t id = (dtrace_konsumer_id_t)konsumer;
	struct konsumer *k;
	uint32_t hash;

	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL\n"));
	DL_ASSERT(konsumer != NULL,
	    ("DTrace konsumer instance cannot be NULL\n"));

	DLOGTR3(PRIO_HIGH, "konsumer_open called by dtrace: %s %lu %p\n",
	    konsumer->dtk_name, id, state);

	/* Convert the DLog file descriptor into a struct dlog_handle * */
	FILEDESC_SLOCK(fdp);
	fp = fget_locked(fdp, 3); // TODO: 3 is fd from dtrace options
	// TODO: what to do if rendezvous fails
	FILEDESC_SUNLOCK(fdp);
	p = fp->f_cdevpriv;
	// TODO: what to do if rendezvous fails
	handle = (struct dlog_handle *) p->cdpd_data;
	// TODO: what to do if rendezvous fails
	
	k = (struct konsumer *) malloc(sizeof(struct konsumer), M_DLKON,
	    M_NOWAIT);
	DL_ASSERT(k != NULL, ("Failed to allocate konsumer instance."));

	bzero(k, sizeof(struct konsumer));
	mtx_init(&k->konsumer_mtx, "konsumer mtx", "konsumer", MTX_DEF);
	cv_init(&k->konsumer_cv, "konsumer cv");
	k->konsumer_state = state;
	k->konsumer_exit = 0;
	k->konsumer_pid = NULL;
	k->konsumer_dlog_handle = handle;

	hash = murmur3_32_hash(&state, sizeof(struct dtrace_state *), 0) &
	    konsumer_hashmask;
	LIST_INSERT_HEAD(&konsumer_hashtbl[hash], k, konsumer_entries);

	kproc_kthread_add(konsumer_thread, k, &k->konsumer_pid, NULL, 0, 0,
	    NULL, NULL);
}

static void
konsumer_close(void *arg, struct dtrace_state *state)
{
	struct konsumer *k, *k_tmp;
	uint32_t hash;

	DLOGTR1(PRIO_HIGH, "konsumer_close called by dtrace %p\n", state);

	hash = murmur3_32_hash(&state, sizeof(struct dtrace_state *), 0) &
	    konsumer_hashmask;
	LIST_FOREACH_SAFE(k, &konsumer_hashtbl[hash], konsumer_entries, k_tmp) {
		if (state == k->konsumer_state) {

			mtx_lock(&k->konsumer_mtx);
			k->konsumer_exit = 1;
			cv_broadcast(&k->konsumer_cv);
			mtx_unlock(&k->konsumer_mtx);
			tsleep(k->konsumer_pid, 0,
			     "waiting for konsumer thread", hz);
			DLOGTR0(PRIO_LOW,
			     "Konsumer thread stoppped successfully\n");

			LIST_REMOVE(k, konsumer_entries);
			mtx_destroy(&k->konsumer_mtx);
			cv_destroy(&k->konsumer_cv);
			free(k, M_DLKON);
		}
	}
}

DECLARE_MODULE(konsumer, konsumer_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(konsumer, 1);
MODULE_DEPEND(konsumer, dlog, 1, 1, 1);
MODULE_DEPEND(konsumer, dtrace, 1, 1, 1);
