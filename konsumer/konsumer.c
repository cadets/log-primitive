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
#include <machine/atomic.h>
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
#include "dl_protocol.h"
#include "dl_utils.h"

MALLOC_DECLARE(M_DLKON);
MALLOC_DEFINE(M_DLKON, "dlkon", "DLog konsumer memory");

static int konsumer_event_handler(struct module *, int, void *);
static void konsumer_thread(void *);

static void konsumer_buffer_switch(dtrace_state_t *, struct dlog_handle *);
static void konsumer_buffer_switch_locked(dtrace_state_t *,
    struct dlog_handle *);
static void konsumer_persist_trace(dtrace_state_t *, struct dlog_handle *,
    dtrace_bufdesc_t *);

static void konsumer_open(void *, struct dtrace_state *);
static void konsumer_close(void *, struct dtrace_state *);

static char const * const KONSUMER_NAME = "dlog_konsumer";

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
	struct dlog_handle *konsumer_dlog_handle;
	dtrace_state_t *konsumer_state;
	int konsumer_exit;
};

extern kmutex_t dtrace_lock;

static const int KON_NHASH_BUCKETS = 16;

static dtrace_kops_t kops = {
	.dtkops_open = konsumer_open,
	.dtkops_close = konsumer_close,
};
static dtrace_konsumer_id_t kid;

static LIST_HEAD(konsumers, konsumer) *konsumer_hashtbl = NULL;
static u_long konsumer_hashmask;

static inline void
konsumer_assert_integrity(const char *func, struct konsumer *self)
{

	DL_ASSERT(self != NULL, ("%s konsumer instance is NULL", func)); 
	DL_ASSERT(self->konsumer_dlog_handle != NULL,
	    ("%s konsumer instance Dlog handle field is NULL", func)); 
	DL_ASSERT(self->konsumer_state != NULL,
	    ("%s konsumer instance DTrace state field is NULL", func)); 
	DL_ASSERT(self->konsumer_pid != NULL,
	    ("%s konsumer instance proc is field NULL", func)); 
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
		if (dtrace_konsumer_register(KONSUMER_NAME, &kops, NULL,
		    &kid) == 0) {

			DLOGTR0(PRIO_NORMAL,
			    "Successfully registered konsumer with DTrace\n");
		} else {

			DLOGTR0(PRIO_HIGH,
			    "Failed to register konsumer with DTrace\n");
			e = -1;
		}
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading Konsumer kernel module\n");
		
		/* Unregister and stop any konsumer threads. */ 
		for (i = 0; i < KON_NHASH_BUCKETS; i++) {	
			LIST_FOREACH_SAFE(k, &konsumer_hashtbl[i],
			    konsumer_entries, k_tmp) {

				DLOGTR1(PRIO_LOW,
				    "Stopping konsumer thread %p..\n", k);
				/* Signal konsumer and wait for completion. */
				mtx_lock(&k->konsumer_mtx);
				k->konsumer_exit = 1;
				mtx_unlock(&k->konsumer_mtx);
				cv_broadcast(&k->konsumer_cv);
				tsleep(k->konsumer_pid, 0,
				    "waiting for konsumer process", 0);

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
	
		/* Unregister the Konsumer with DTrace. */	
		dtrace_konsumer_unregister(&kid);
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static void
konsumer_buffer_switch_locked(dtrace_state_t *state, struct dlog_handle *handle)
{
	caddr_t cached;
	dtrace_bufdesc_t desc;
	dtrace_buffer_t *buf;

	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL\n"));
	DL_ASSERT(handle != NULL, ("DLog handle cannot be NULL\n"));
	DL_ASSERT(MUTEX_HELD(&dtrace_lock),
	    ("dtrace_lock should be held in dtrace_state_stop"));

	/* Switch and process the trace buffers for each CPU. */
	for (int cpu = 0; cpu < mp_ncpus; cpu++) {

		buf = &state->dts_buffer[cpu];
		DL_ASSERT(
		    (buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL)) == 0,
		    ("DTrace ring/fill buffer policy is not supported"));

		if (buf->dtb_tomax == NULL)
			break;

		cached = buf->dtb_tomax;
		DL_ASSERT(!(buf->drb & DTRACEBUF_NOSWITCH),
		    ("DTrace buffer no switch flag set."));

		dtrace_xcall(cpu, (dtrace_xcall_t) dtrace_buffer_switch, buf);

		state->dts_errors += buf->dtb_xamot_errors;

		if (buf->dtb_tomax == cached)
			break;

		desc.dtbd_data = buf->dtb_xamot;
		desc.dtbd_size = buf->dtb_xamot_offset;
		desc.dtbd_drops = buf->dtb_xamot_drops;
		desc.dtbd_errors = buf->dtb_xamot_errors;
		desc.dtbd_oldest = 0;
		desc.dtbd_timestamp = buf->dtb_switched;

		if (desc.dtbd_size != 0)
			konsumer_persist_trace(state, handle, &desc);
	}
}

static void
konsumer_thread(void *arg)
{
	struct konsumer *k = (struct konsumer *) arg;
	struct timespec curtime;

	konsumer_assert_integrity(__func__, k);
	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL\n"));
	
	for (;;) {

		mtx_lock(&k->konsumer_mtx);
		cv_timedwait(&k->konsumer_cv, &k->konsumer_mtx, 10 * hz / 9);
		if (k->konsumer_exit)  {

			mtx_unlock(&k->konsumer_mtx);
	 		DLOGTR0(PRIO_LOW, "Stopping konsumer thread..\n");
			break;
		}
		mtx_unlock(&k->konsumer_mtx);

		/* Mimic the userpsace status ioctl. */
		nanouptime(&curtime);
		k->konsumer_state->dts_laststatus =
		    curtime.tv_sec * 1000000000UL + curtime.tv_nsec;

		/* Switch the buffer and write the contents to DLog. */ 
		konsumer_buffer_switch_locked(k->konsumer_state,
		    k->konsumer_dlog_handle);
	}

	/* Switch the buffer and write the contetnts to DLog before exiting.
	 * This ensure that the userspace DTrace process recieves an
	 * empty buffer on termination.
	 */ 
	konsumer_buffer_switch_locked(k->konsumer_state,
	     k->konsumer_dlog_handle);

	DLOGTR0(PRIO_NORMAL, "Konsumer thread exited successfully.\n");
	kthread_exit();
}

static void
konsumer_persist_trace(dtrace_state_t *state, struct dlog_handle *hdl,
    dtrace_bufdesc_t *desc)
{
	dtrace_epid_t epid;
	size_t msg_start = 0, msg_size = 0, size = 0;
	
	DL_ASSERT(desc->dtbd_data != NULL,
	    ("konsumer_persist_trace called with NULL buffer."));
	DL_ASSERT(desc->dtbd_size != 0,
	    ("konsumer_persist_trace called with empty buffer."));

	while (desc->dtbd_size != 0 && size < desc->dtbd_size) {

		epid = (dtrace_epid_t) desc->dtbd_data[size];
		if (epid == DTRACE_EPIDNONE) {

			DLOGTR0(PRIO_LOW, "End of DTrace buffer\n");
			break;
		}

		if (dtrace_epid2size(state, epid) == 0) {

			DLOGTR1(PRIO_HIGH,
			    "Error payload size is 0 for epid = %u\n", epid);
			break;
		}
		size += dtrace_epid2size(state, epid);

		if (msg_size + dtrace_epid2size(state, epid) > DL_MTU) {
			if (dlog_produce_no_key(hdl, 
			    &desc->dtbd_data[msg_start], msg_size) != 0) {

				DLOGTR0(PRIO_HIGH,
				    "Error producing message to DLog\n");
			}

			msg_start += msg_size;
			msg_size = 0;
		} else {

			msg_size += dtrace_epid2size(state, epid);
			if (msg_size == desc->dtbd_size) {
				if (dlog_produce_no_key(hdl, 
				    &desc->dtbd_data[msg_start],
				    msg_size) != 0) {

					DLOGTR0(PRIO_HIGH,
					    "Error producing message to "
					    "DLog\n");
				}

				msg_start += msg_size;
				msg_size = 0;
			}
		}
	}
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
	int rc;
	
	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL\n"));
	DL_ASSERT(konsumer != NULL,
	    ("DTrace konsumer instance cannot be NULL\n"));

	DLOGTR3(PRIO_LOW, "konsumer_open called by dtrace: %s %lu %p\n",
	    konsumer->dtk_name, id, state);

	/* Confirm that the DTrace buffer policy is "switch". */
	if (state->dts_options[DTRACEOPT_BUFPOLICY] !=
	    DTRACEOPT_BUFPOLICY_SWITCH) {
	
		DLOGTR1(PRIO_HIGH,
		    "Rendezvous with DLog state failed (%p)\n", state);
		return;
	}

	/* Convert the DLog file descriptor into a struct dlog_handle * */
	FILEDESC_SLOCK(fdp);
	fp = fget_locked(fdp, state->dts_options[DTRACEOPT_KONSUMERARG]);
	if (fp == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Rendezvous with DLog state failed (%p)\n", state);
		FILEDESC_SUNLOCK(fdp);
		return;
	}
	FILEDESC_SUNLOCK(fdp);

	p = fp->f_cdevpriv;
	if (p == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Rendezvous with DLog state failed (%p)\n", state);
		return;
	}

	handle = (struct dlog_handle *)p->cdpd_data;
	if (handle == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Rendezvous with DLog state failed (%p)\n", state);
		return;
	}
	
	k = (struct konsumer *) malloc(sizeof(struct konsumer), M_DLKON,
	    M_NOWAIT);
	DL_ASSERT(k != NULL, ("Failed to allocate new konsumer instance."));

	bzero(k, sizeof(struct konsumer));
	mtx_init(&k->konsumer_mtx, "konsumer mtx", KONSUMER_NAME, MTX_DEF);
	cv_init(&k->konsumer_cv, "konsumer cv");
	k->konsumer_state = state;
	k->konsumer_exit = 0;
	k->konsumer_dlog_handle = handle;
	rc = kproc_kthread_add(konsumer_thread, k, &k->konsumer_pid, NULL, 0, 0,
	    NULL, NULL);
	DL_ASSERT(rc == 0, ("Konsumer open kproc_kthread_add failed \n", rc));
	
	konsumer_assert_integrity(__func__, k);

	/* Added the new konsumer instance into the hashmap, index by the
	 * dtrace_state pointer.
	 */
	hash = murmur3_32_hash(&state, sizeof(struct dtrace_state *), 0) &
	    konsumer_hashmask;
	LIST_INSERT_HEAD(&konsumer_hashtbl[hash], k, konsumer_entries);
}

static void
konsumer_close(void *arg, struct dtrace_state *state)
{
	dtrace_konsumer_t *konsumer = (dtrace_konsumer_t *)arg;
	dtrace_konsumer_id_t id = (dtrace_konsumer_id_t)konsumer;
	struct konsumer *k, *k_tmp;
	uint32_t hash;
	
	DL_ASSERT(state != NULL, ("DTrace state cannot be NULL"));
	DL_ASSERT(MUTEX_HELD(&dtrace_lock),
	    ("dtrace_lock should be held in dtrace_state_stop()"));

	DLOGTR3(PRIO_LOW, "konsumer_close called by dtrace: %s %lu %p\n",
	    konsumer->dtk_name, id, state);

	/* Lookup the Konsumer instance based on the Dtrace state passed into
	 * konsumer_close.
	 */
	hash = murmur3_32_hash(&state, sizeof(struct dtrace_state *), 0) &
	    konsumer_hashmask;
	LIST_FOREACH_SAFE(k, &konsumer_hashtbl[hash], konsumer_entries, k_tmp) {
	
		konsumer_assert_integrity(__func__, k);
		if (state == k->konsumer_state) {

			/* Stop the konsumer thread and wait until it has
			 * persisted all oustanding DTrace records to DLog.
			 */
			mtx_lock(&k->konsumer_mtx);
			k->konsumer_exit = 1;
			mtx_unlock(&k->konsumer_mtx);
			cv_broadcast(&k->konsumer_cv);
			tsleep(k->konsumer_pid, 0,
			     "waiting for konsumer thread", 0);

			/* Remove the konsumer instance from the hash map
			 * and destroy it.
			 */
			DLOGTR0(PRIO_NORMAL,
			     "Konsumer thread stoppped successfully\n");
			LIST_REMOVE(k, konsumer_entries);
			mtx_destroy(&k->konsumer_mtx);
			cv_destroy(&k->konsumer_cv);
			free(k, M_DLKON);
			break;
		}
	}

	DL_ASSERT(0, ("konsumer_close called with invalid DTrace state."));
}

DECLARE_MODULE(konsumer, konsumer_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(konsumer, 1);
MODULE_DEPEND(konsumer, dlog, 1, 1, 1);
MODULE_DEPEND(konsumer, dtrace, 1, 1, 1);
