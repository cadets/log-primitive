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
#include <sys/time.h>
#include <sys/tree.h>
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif
#include <errno.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_notifier.h"
#include "dl_request_queue.h"
#include "dl_resender.h"
#include "dl_response.h"
#include "dl_utils.h"

struct dl_response_element {
	struct dl_response rsp_msg;
	LIST_ENTRY(dl_response_element) entries;
};

static void * dl_notifier_thread(void *);
static int dl_notify_response(struct notify_queue_element *,
    struct dl_notifier_argument *);

static void *
dl_notifier_thread(void *vargp)
{
	struct dl_notifier_argument *na =
	    (struct dl_notifier_argument *) vargp;
	struct notify_queue local_notify_queue;
	struct notify_queue_element *notify, *notify_temp;
	int old_cancel_state;
	struct timespec ts;
	struct timeval now;

	DL_ASSERT(vargp != NULL,
	    "Request notifier thread argument cannot be NULL");	

	DLOGTR1(PRIO_LOW, "%s: Notifier thread started...\n",
	    na->dlna_config->client_id);
	
	/* Initialize a local queue, used to enqueue requests from the
	 * notify queue prior to processing.
	 */
	STAILQ_INIT(&local_notify_queue);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {
		/* Copy elements from the notifier queue,
		 * to a thread local queue prior to processing.
		 */
		pthread_mutex_lock(na->notify_queue_mtx);		
		while (STAILQ_EMPTY(na->notify_queue) != 0 ) {
			/* There are no elements in the notifier's
			 * queue check whether the thread has been
			 * canceled.
			 */
			pthread_testcancel();

			/* Wait for elements to be added to the
			 * notifier's queue, whilst also periodically checking
			 * the thread's cancellation state.
			 */
			gettimeofday(&now, NULL);
			ts.tv_sec = now.tv_sec + 2;
			ts.tv_nsec = 0;
			pthread_cond_timedwait(na->notify_queue_cond,
			    na->notify_queue_mtx, &ts);
		}

		while ((notify = STAILQ_FIRST(na->notify_queue))) {
			STAILQ_REMOVE_HEAD(na->notify_queue, entries);
			STAILQ_INSERT_TAIL(&local_notify_queue, notify,
			    entries);
		}
		pthread_mutex_unlock(na->notify_queue_mtx);		

		/* Process the elements in the thread local queue,
		 * notifying the lients for each response.
		 */
		STAILQ_FOREACH_SAFE(notify, &local_notify_queue, entries,
		    notify_temp) {
			if (dl_notify_response(notify, na) != 0) {
				DLOGTR0(PRIO_HIGH,
				    "Failed notifying client\n");

			}

			STAILQ_REMOVE_HEAD(&local_notify_queue, entries);
		}
	}
	return NULL;
}

// TODO: Introduce sensible error handling
static int 
dl_notify_response(struct notify_queue_element *notify,
    struct dl_notifier_argument *na)
{
	struct dl_request_element *request;	
	struct dl_response_element *response;
	struct dl_response *res_m;
	char *pbuf = notify->pbuf;

	DL_ASSERT(notify != NULL, "Notifier element cannot be NULL");
	DL_ASSERT(na != NULL, "Notifier thread argument cannot be NULL");

	response = (struct dl_response_element *) dlog_alloc(
	    sizeof(struct dl_response_element));
	if (NULL != response) {
		/* Deserialise the response message. */
		res_m = &response->rsp_msg;
		if (dl_decode_response(res_m, pbuf) == 0) {
				
			DLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_size);
			DLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_correlation_id);

			/* Acknowledge the request message based
			 * on the CorrelationId returned in the response.
			 */
			request = dl_resender_ackd_request(
			    res_m->dlrs_correlation_id);
			if (NULL != request) {

				// TODO: Add error checking
				switch (request->dlrq_api_key) {
				case DL_PRODUCE_REQUEST:
					res_m->dlrs_message.dlrs_produce_response =
					    dl_produce_response_decode(
						pbuf+2*sizeof(int32_t)); // TODO: remove hack
					break;
				case DL_FETCH_REQUEST:
					res_m->dlrs_message.dlrs_fetch_response =
					    dl_decode_fetch_response(
					    pbuf+2*sizeof(int32_t)); // TODO: remove hack
					break;
				case DL_OFFSET_REQUEST:
					res_m->dlrs_message.dlrs_offset_response =
					    dl_list_offset_response_decode(
					    pbuf+2*sizeof(int32_t)); // TODO: remove hack
					break;
				default:
					// TODO: invalid
					break;
				}
					
				// TODO: don't don't invoke client callbacks
				// if the decoding of the response failed!

				/* Invoke the client callbacks. */
				if (na->dlna_on_ack != NULL)
					na->dlna_on_ack(res_m->dlrs_correlation_id);

				if (na->dlna_on_response != NULL)
					na->dlna_on_response(
					    request->dlrq_api_key, res_m);
			
				// TOOD: who is responsible for freeing the 
				// memory?	
				dlog_free(response);
			} else {
				DLOGTR1(PRIO_HIGH,
				    "Couldn't find the unacknowledged request "
				    "id: %d\n", res_m->dlrs_correlation_id);
				dlog_free(response);
			}
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Cant borrow a response element\n");
	}

	return 0;
}

struct dl_notifier *
dl_notifier_new(struct dl_client_configuration const *cc)
{
	struct dl_notifier *notifier;
	
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	notifier = (struct dl_notifier *) dlog_alloc(
	    sizeof(struct dl_notifier));

	notifier->dln_arg.dlna_on_ack = cc->dlcc_on_ack;
	notifier->dln_arg.dlna_on_response = cc->dlcc_on_response;
	notifier->dln_arg.dlna_config = cc;
	notifier->dln_arg.notify_queue = &notifier->notify_queue;
	notifier->dln_arg.notify_queue_mtx = &notifier->notify_queue_mtx;
	notifier->dln_arg.notify_queue_cond = &notifier->notify_queue_cond;
	
	/* Initialise the notify queue. Responses to be notified back to
	 * the client are enqueued onto this queue.
	 */
	STAILQ_INIT(&notifier->notify_queue);
	pthread_mutex_init(&notifier->notify_queue_mtx, NULL);
	pthread_cond_init(&notifier->notify_queue_cond, NULL);

	return notifier;
}	

void
dl_notifier_fini(struct dl_notifier *notifier)
{
	DL_ASSERT(notifier != NULL,
	    "Notifier instance configuration cannot be NULL");

	// TODO
	//STAILQ_INIT(&notifier->notify_queue);
	//pthread_mutex_init(&notifier->notify_queue_mtx, NULL);
	//pthread_cond_init(&notifier->notify_queue_cond, NULL);

	/* Free the notifier instance's memory. */	
	dlog_free(notifier);
}

int
dl_notifier_start(struct dl_notifier *notifier)
{
	int ret;

	DL_ASSERT(notifier != NULL,
	    "Notifier instance configuration cannot be NULL");

	return pthread_create(&notifier->dln_tid, NULL, dl_notifier_thread,
	    &notifier->dln_arg);
}

/* Cancel the notifier thread */
int
dl_notifier_stop(struct dl_notifier *notifier)
{

	return pthread_cancel(notifier->dln_tid);
}

void
dl_notifier_response(struct dl_notifier *notifier,
    struct notify_queue_element *el)
{
	DL_ASSERT(notifier != NULL,
	    "Notifier instance configuration cannot be NULL");

	pthread_mutex_lock(&notifier->notify_queue_mtx);
	STAILQ_INSERT_TAIL(&notifier->notify_queue, el, entries);
	pthread_cond_signal(&notifier->notify_queue_cond);
	pthread_mutex_unlock(&notifier->notify_queue_mtx);
}
