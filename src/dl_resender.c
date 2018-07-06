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
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/nv.h>

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kthread.h>
#else
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#endif

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_request_queue.h"
#include "dl_resender.h"
#include "dl_transport.h"
#include "dl_utils.h"
	
RB_HEAD(dlr_unackd_requests, dl_request_element);

struct dl_resender {
	struct dlr_unackd_requests dlr_unackd;
#ifdef _KERNEL
	//pthread_t dlr_tid;
	struct mtx dlr_unackd_mtx;
	struct cv dlr_unackd_cond;
#else
	pthread_t dlr_tid;
	pthread_mutex_t dlr_unackd_mtx;
	pthread_cond_t dlr_unackd_cond;
#endif
	struct dlog_handle *dlr_handle;
};

struct dl_resender_argument {
	struct dl_resender *dlra_resender;
};

static int dl_request_element_cmp(struct dl_request_element *,
    struct dl_request_element *);
static void * dl_resender_thread(void *);

RB_PROTOTYPE(dlr_unackd_requests, dl_request_element, dlrq_linkage,
    dl_request_element_cmp);
RB_GENERATE(dlr_unackd_requests, dl_request_element, dlrq_linkage,
    dl_request_element_cmp);

static char *DL_RESENDER_TYPE = "dlog";
static char *test = "resender";

static int
dl_request_element_cmp(struct dl_request_element *el1,
    struct dl_request_element *el2)
{
	return el2->dlrq_correlation_id - el1->dlrq_correlation_id;
}

static void *
dl_resender_thread(void *vargp)
{
	struct dl_resender *resender;
	struct dl_resender_argument *ra =
	    (struct dl_resender_argument *) vargp;
	struct dl_request_element *request, *request_temp;
	nvlist_t *props;
	time_t now;
#ifndef _KERNEL
	int old_cancel_state;
#endif
	int resend_timeout, resend_period;
	bool to_resend;

	DL_ASSERT(vargp != NULL, "Resender thread arguments cannot be NULL");

	DLOGTR0(PRIO_LOW, "Resender thread started\n");

	/* Take a copy of the resender thread arguments before freeing. */
	resender = ra->dlra_resender;
	dlog_free(vargp);
	
	props = NULL; //resender->dlr_handle->dlh_config->dlcc_props;

	if (!nvlist_exists_bool(props, DL_CONF_TORESEND)) {
		to_resend = nvlist_get_number(props, DL_CONF_TORESEND);
	} else {
		to_resend = DL_DEFAULT_TORESEND;
	}

	if (!nvlist_exists_string(props, DL_CONF_RESENDTIMEOUT)) {
		resend_timeout = nvlist_get_number(props,
		    DL_CONF_RESENDTIMEOUT);
	} else {
		resend_timeout = DL_DEFAULT_RESENDTIMEOUT;
	}

	if (!nvlist_exists_string(props, DL_CONF_RESENDPERIOD)) {
		resend_period = nvlist_get_number(props, DL_CONF_RESENDPERIOD);
	} else {
		resend_period = DL_DEFAULT_RESENDPERIOD;
	}

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
#ifdef _KERNEL
	// TODO
#else
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);
#endif

	for (;;) {
		// TODO: should probably check that this is empty
#ifdef _KERNEL
#else
		pthread_testcancel();
#endif

#ifdef _KERNEL
		mtx_lock(&resender->dlr_unackd_mtx);
#else
		pthread_mutex_lock(&resender->dlr_unackd_mtx);
#endif
		RB_FOREACH_SAFE(request, dlr_unackd_requests,
		    &resender->dlr_unackd, request_temp) {
			if (to_resend) {
#ifdef _KERNEL
				now = 0; // TODO
#else
				now = time(NULL);
#endif
				DLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
				    "Resend when the difference is %d. "
				    "Current: %lu\n",
				    request->dlrq_last_sent, now,
				    resend_timeout, 
				    now - request->dlrq_last_sent);

				if ((now - request->dlrq_last_sent) >
				    resend_timeout) {
#ifdef _KERNEL
#else
					request->dlrq_last_sent = time(NULL);
#endif

					RB_REMOVE(dlr_unackd_requests,
					    &resender->dlr_unackd, request);

					/* Resend the request. */
					//dl_request_q_enqueue(resender->dlr_handle->dlh_request_q,
					  //  request);
					
					DLOGTR0(PRIO_LOW, "Resending request.\n");
				}
			}
		}
#ifdef _KERNEL
		mtx_unlock(&resender->dlr_unackd_mtx);
#else
		pthread_mutex_unlock(&resender->dlr_unackd_mtx);
#endif

		DLOGTR1(PRIO_LOW,
		    "Resender thread is going to sleep for %d seconds\n",
		    resend_period);

#ifdef _KERNEL
#else
		sleep(resend_period);
#endif
	}
#ifdef _KERNEL
	kproc_exit(0);
#else
	pthread_exit(NULL);
#endif
}

struct dl_resender *
dl_resender_new(struct dlog_handle *handle)
{
	struct dl_resender *resender;

	resender = (struct dl_resender *) dlog_alloc(
	    sizeof(struct dl_resender));
#ifdef _KERNEL
	DL_ASSERT(resender != NULL, ("Failed allocating resender."));	
	{
#else
	if (resender != NULL) {
#endif
		bzero(resender, sizeof(struct dl_resender));

		/* Initialise a red/black tree used to index the unacknowledge
		 * responses.
		 */
		RB_INIT(&resender->dlr_unackd);
#ifdef _KERNEL
		mtx_init(&resender->dlr_unackd_mtx, test, DL_RESENDER_TYPE,
		    MTX_DEF);
		cv_init(&resender->dlr_unackd_cond, DL_RESENDER_TYPE);
#else
		pthread_mutex_init(&resender->dlr_unackd_mtx, NULL);
		pthread_cond_init(&resender->dlr_unackd_cond, NULL);
#endif
		resender->dlr_handle = handle;
	}

	return resender;
}	

void
dl_resender_delete(struct dl_resender *self)
{

	DL_ASSERT(self != NULL, ("Resender instance cannot be NULL."));

#ifdef _KERNEL
	mtx_assert(&self->dlr_unackd_mtx, MA_NOTOWNED);
	mtx_destroy(&self->dlr_unackd_mtx);
	cv_destroy(&self->dlr_unackd_cond);
#else
	pthread_mutex_destroy(&self->dlr_unackd_mtx);
	pthread_cond_destroy(&self->dlr_unackd_cond);
#endif
	dlog_free(self);
}

int
dl_resender_start(struct dl_resender *resender)
{
	struct dl_resender_argument *resender_arg;

	DL_ASSERT(resender != NULL, "Resender instance cannot be NULL");

	resender_arg = (struct dl_resender_argument *) dlog_alloc(
	    sizeof(struct dl_resender_argument));
#ifdef _KERNEL
	DL_ASSERT(resender_arg != NULL, ("Failed allocating resender arguments."));
	resender_arg->dlra_resender = resender;
	// TODO
	return 0;
#else
	if (resender_arg != NULL) {
		resender_arg->dlra_resender = resender;
		return pthread_create(&resender->dlr_tid, NULL, dl_resender_thread,
	    resender_arg);
	}
	DLOGTR0(PRIO_HIGH, "Failed allocating resender arguments.\n");
	return -1;
#endif
}

/* Cancel the resender thread */
int
dl_resender_stop(struct dl_resender *resender)
{
#ifdef _KERNEL
	// TODO
	//return kthread_suspend(handle->dlh_response_tid, 2 * (10 * hz / 9));
	return 0;
#else
	return pthread_cancel(resender->dlr_tid);
#endif
}

int
dl_resender_unackd_request(struct dl_resender *resender,
    struct dl_request_element *request)
{

#ifdef _KERNEL
	mtx_lock(&resender->dlr_unackd_mtx);
#else
	pthread_mutex_lock(&resender->dlr_unackd_mtx);
#endif
	RB_INSERT(dlr_unackd_requests, &resender->dlr_unackd, request);
#ifdef _KERNEL
	mtx_unlock(&resender->dlr_unackd_mtx);
#else
	pthread_mutex_unlock(&resender->dlr_unackd_mtx);
#endif

	return 0;
}

struct dl_request_element *
dl_resender_ackd_request(struct dl_resender *resender, int correlation_id)
{
	struct dl_request_element find, *request = NULL;

	/* Lookup the unacknowledged Request message based
	 * on the CorrelationId returned in the response.
 	 */
	find.dlrq_correlation_id = correlation_id;

#ifdef _KERNEL
	mtx_lock(&resender->dlr_unackd_mtx);
#else
	pthread_mutex_lock(&resender->dlr_unackd_mtx);
#endif
	request = RB_FIND(dlr_unackd_requests,
	    &resender->dlr_unackd, &find);
	if (request != NULL) {
		DLOGTR1(PRIO_LOW, "Found unacknowledged request id: %d\n",
		    request->dlrq_correlation_id);

		/* Remove the unacknowledged request and return it
		 * to the caller for processing.
		 */
		request = RB_REMOVE(dlr_unackd_requests,
		    &resender->dlr_unackd, request);
	}
#ifdef _KERNEL
	mtx_unlock(&resender->dlr_unackd_mtx);
#else
	pthread_mutex_unlock(&resender->dlr_unackd_mtx);
#endif

	return request;
}
