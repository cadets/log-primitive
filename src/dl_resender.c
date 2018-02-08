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

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif
#include <errno.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_request_queue.h"
#include "dl_resender.h"
#include "dl_transport.h"
#include "dl_utils.h"

struct dl_resender_argument {
	struct dl_client_configuration *dlra_config;
	pthread_t *dlra_tid;
	int dlra_index;
};

static struct dl_resender_argument resender_arg;
static pthread_t resender;

RB_HEAD(dl_unackd_requests, dl_request_element) unackd_requests;
static pthread_mutex_t unackd_requests_mtx;
static pthread_cond_t unackd_requests_cond;

static int
dl_request_element_cmp(struct dl_request_element *el1,
    struct dl_request_element *el2)
{
	return el2->dlrq_correlation_id -
	    el1->dlrq_correlation_id;
}

RB_PROTOTYPE(dl_unackd_requests, dl_request_element, dlrq_linkage,
    dl_request_element_cmp);
RB_GENERATE(dl_unackd_requests, dl_request_element, dlrq_linkage,
    dl_request_element_cmp);

static void * dl_resender_thread(void *);
static void dl_start_resender(struct dl_client_configuration *);

static void *
dl_resender_thread(void *vargp)
{
	struct dl_resender_argument *ra = (struct dl_reader_argument *) vargp;
	struct dl_request_element *request, *request_temp;
	time_t now;
	int old_cancel_state;

	DL_ASSERT(vargp != NULL, "Resender thread arguments cannot be NULL");

	DISTLOGTR0(PRIO_LOW, "Resender thread started\n");

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {
		// TODO: should probably check that this is empty
		pthread_testcancel();

		pthread_mutex_lock(&unackd_requests_mtx);
		RB_FOREACH_SAFE(request, dl_unackd_requests, &unackd_requests,
		    request_temp) {
			if (request->dlrq_should_resend) {
				now = time(NULL);
				DISTLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
				    "Resend when the difference is %lu. "
				    "Current: %lu\n",
				    request->dlrq_last_sent, now,
				    request->dlrq_resend_timeout,
				    request->dlrq_last_sent);

				if ((now - request->dlrq_last_sent) >
				    request->dlrq_resend_timeout) {
					request->dlrq_last_sent = time(NULL);

					RB_REMOVE(dl_unackd_requests,
					    &unackd_requests, request);

					dlog_free(request);
					DISTLOGTR0(PRIO_LOW, "Done.\n");
				}
			}
		}
		pthread_mutex_unlock(&unackd_requests_mtx);

		DISTLOGTR1(PRIO_LOW,
		    "Resender thread is going to sleep for %d seconds\n",
		    ra->dlra_config->resender_thread_sleep_length);

		// TODO: sleep_length is a slight odd name
		// and it is in seconds
		sleep(ra->dlra_config->resender_thread_sleep_length);
	}
	return NULL;
}

int
dl_resender_init(struct dl_client_configuration *cc)
{
	/* Initialise a red/black tree used to index the unacknowledge
	 * responses.
	 */
	RB_INIT(&unackd_requests);
	pthread_mutex_init(&unackd_requests_mtx, NULL);

	return 0;
}	
int
dl_resender_fini()
{
}

int
dl_resender_start(struct dl_client_configuration *cc)
{
	int ret;

	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	ret = pthread_create(&resender, NULL, dl_resender_thread,
	    &resender_arg);
	if (ret == 0) {
		resender_arg.dlra_tid = &resender;
		resender_arg.dlra_index = 0;
		resender_arg.dlra_config = cc;
	} 
}

/* Cancel the resender thread */
int
dl_resender_stop()
{

	return pthread_cancel(resender);
}

int
dl_resender_unackd_request(struct dl_request_element *request)
{
	pthread_mutex_lock(&unackd_requests_mtx);
	RB_INSERT(dl_unackd_requests, &unackd_requests, request);
	pthread_mutex_unlock(&unackd_requests_mtx);
}

struct dl_request_element *
dl_resender_ackd_request(int correlation_id)
{
	struct dl_request_element find, *request = NULL;

	/* Lookup the unacknowledged Request message based
	 * on the CorrelationId returned in the response.
 	 */
	find.dlrq_correlation_id = correlation_id;

	pthread_mutex_lock(&unackd_requests_mtx);
	request = RB_FIND(dl_unackd_requests, &unackd_requests, &find);
	if (request != NULL) {
		DISTLOGTR1(PRIO_NORMAL,
			"Found unacknowledged request id: %d\n",
			request->dlrq_correlation_id);

		/* Remove the unacknowledged request and return it
		 * to the caller for processing.
		 */
		request = RB_REMOVE(dl_unackd_requests,
			&unackd_requests, request);
	}
	pthread_mutex_unlock(&unackd_requests_mtx);

	return request;
}
