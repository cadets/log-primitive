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
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_request_queue.h"
#include "dl_resender.h"
#include "dl_transport.h"
#include "dl_utils.h"
#include "dlog_client_impl.h"
	
RB_HEAD(dlr_unackd_requests, dl_request_element);

struct dl_resender {
	struct dlr_unackd_requests dlr_unackd;
	pthread_t dlr_tid;
	pthread_mutex_t dlr_unackd_mtx;
	pthread_cond_t dlr_unackd_cond;
	struct dlog_handle *dlr_handle;
	int dlr_sleep_ms;
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
	time_t now;
	int old_cancel_state;

	DL_ASSERT(vargp != NULL, "Resender thread arguments cannot be NULL");

	DLOGTR0(PRIO_LOW, "Resender thread started\n");

	/* Take a copy of the resender thread arguments before freeing. */
	resender = ra->dlra_resender;
	dlog_free(vargp);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {
		// TODO: should probably check that this is empty
		pthread_testcancel();

		pthread_mutex_lock(&resender->dlr_unackd_mtx);
		RB_FOREACH_SAFE(request, dlr_unackd_requests,
		    &resender->dlr_unackd, request_temp) {
			if (resender->dlr_handle->dlh_config->to_resend) {
				now = time(NULL);
				DLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
				    "Resend when the difference is %lu. "
				    "Current: %lu\n",
				    request->dlrq_last_sent, now,
				    resender->dlr_handle->dlh_config->resend_timeout, 
				    request->dlrq_last_sent);

				if ((now - request->dlrq_last_sent) >
				    resender->dlr_handle->dlh_config->resend_timeout) {
					request->dlrq_last_sent = time(NULL);

					RB_REMOVE(dlr_unackd_requests,
					    &resender->dlr_unackd, request);

					dlog_free(request);
					DLOGTR0(PRIO_LOW, "Done.\n");
				}
			}
		}
		pthread_mutex_unlock(&resender->dlr_unackd_mtx);

		DLOGTR1(PRIO_LOW,
		    "Resender thread is going to sleep for %d seconds\n",
		    resender->dlr_sleep_ms);

		sleep(resender->dlr_sleep_ms);
	}
	pthread_exit(NULL);
}

struct dl_resender *
dl_resender_new(struct dlog_handle *handle)
{
	struct dl_resender *resender;

	resender = (struct dl_resender *) dlog_alloc(
	    sizeof(struct dl_resender));

	/* Initialise a red/black tree used to index the unacknowledge
	 * responses.
	 */
	RB_INIT(&resender->dlr_unackd);
	pthread_mutex_init(&resender->dlr_unackd_mtx, NULL);
	pthread_cond_init(&resender->dlr_unackd_cond, NULL);
	resender->dlr_sleep_ms = handle->dlh_config->resender_thread_sleep_length;

	return resender;
}	
int
dl_resender_fini()
{
	return 0;
}

int
dl_resender_start(struct dl_resender *resender)
{
	struct dl_resender_argument *resender_arg;
	int ret;

	DL_ASSERT(resender != NULL, "Resender instance cannot be NULL");

	resender_arg = (struct dl_resender_argument *) dlog_alloc(
	    sizeof(struct dl_resender_argument));
	resender_arg->dlra_resender = resender;

	return pthread_create(&resender->dlr_tid, NULL, dl_resender_thread,
	    resender_arg);
}

/* Cancel the resender thread */
int
dl_resender_stop(struct dl_resender *resender)
{

	return pthread_cancel(resender->dlr_tid);
}

int
dl_resender_unackd_request(struct dl_resender *resender,
    struct dl_request_element *request)
{
	pthread_mutex_lock(&resender->dlr_unackd_mtx);
	RB_INSERT(dlr_unackd_requests, &resender->dlr_unackd, request);
	pthread_mutex_unlock(&resender->dlr_unackd_mtx);

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

	pthread_mutex_lock(&resender->dlr_unackd_mtx);
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
	pthread_mutex_unlock(&resender->dlr_unackd_mtx);

	return request;
}
