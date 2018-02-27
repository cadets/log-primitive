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

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef _KERNEL
#else
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#endif

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_notifier.h"
#include "dl_resender.h"
#include "dl_response.h"
#include "dl_utils.h"

struct dl_notifier_argument {
	struct dl_notifier *dlna_notifier;
};

struct dl_notifier {
	pthread_t dln_tid;
	dl_response_function dln_on_response;
	char const *dln_client_id;
	struct notify_queue dln_q;
	pthread_mutex_t dln_q_mtx;
	pthread_cond_t dln_q_cond;
};

static void * dl_notifier_thread(void *);
static struct dl_response * dl_notify_get_response(
    struct notify_queue_element *);

static void *
dl_notifier_thread(void *vargp)
{
	struct dl_notifier_argument *na =
	    (struct dl_notifier_argument *) vargp;
	struct dl_notifier *notifier;
	struct notify_queue local_dln_q;
	struct notify_queue_element *notify, *notify_temp;
	struct dl_response *response;
	int old_cancel_state;
	struct timespec ts;
	struct timeval now;

	DL_ASSERT(vargp != NULL,
	    "Request notifier thread argument cannot be NULL");	

	/* Take a copy of the thread's arguments then free the memory used
	 * to pass arguments into the thread.
	 */
	notifier = na->dlna_notifier;
	dlog_free(na);

	DLOGTR1(PRIO_LOW, "%s: Notifier thread started...\n",
	    notifier->dln_client_id);
	
	/* Initialize a local queue, used to enqueue requests from the
	 * notify queue prior to processing.
	 */
	STAILQ_INIT(&local_dln_q);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {
		/* Copy elements from the notifier queue,
		 * to a thread local queue prior to processing.
		 */
		pthread_mutex_lock(&notifier->dln_q_mtx);		
		while (STAILQ_EMPTY(&notifier->dln_q) != 0 ) {
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
			pthread_cond_timedwait(&notifier->dln_q_cond,
			    &notifier->dln_q_mtx, &ts);
		}

		/* Copy elements onto the local queue for processing. */
		while ((notify = STAILQ_FIRST(&notifier->dln_q))) {
			STAILQ_REMOVE_HEAD(&notifier->dln_q, entries);
			STAILQ_INSERT_TAIL(&local_dln_q, notify,
			    entries);
		}
		pthread_mutex_unlock(&notifier->dln_q_mtx);		

		/* Process the elements in the thread local queue,
		 * notifying the lients for each response.
		 */
		STAILQ_FOREACH_SAFE(notify, &local_dln_q, entries,
		    notify_temp) {
			response = dl_notify_get_response(notify);
			if (response != NULL) {

				/* Invoke the client callback. */
				if (notifier->dln_on_response != NULL)
					notifier->dln_on_response(response);

				dlog_free(response);

			} else {			
				DLOGTR0(PRIO_HIGH,
				    "Failed notifying client\n");
			
			}
			STAILQ_REMOVE_HEAD(&local_dln_q, entries);
			dlog_free(notify);
		}
	}
	pthread_exit(NULL);
}

static struct dl_response * 
dl_notify_get_response(struct notify_queue_element *notify)
{
	struct dl_request_element *request;	
	struct dl_response *response = NULL;
	struct dl_response_header *header;
	char *pbuf = notify->pbuf, *mpbuf;

	DL_ASSERT(notify != NULL, "Notifier element cannot be NULL");

	/* Deserialise the response header. */
	header = dl_response_header_decode(pbuf, &mpbuf);
#ifdef _KERNEL
	DL_ASSERT(response != NULL, ("Failed decoding response header.\n"));
	{
#else 
	if (header != NULL) {
#endif
		DLOGTR1(PRIO_LOW, "Got response id = : %d\n",
			header->dlrsh_correlation_id);

		/* Acknowledge the request message based
		 * on the CorrelationId returned in the response.
		 */
		request = dl_resender_ackd_request(
		    header->dlrsh_correlation_id);
		if (request != NULL) {
			switch (request->dlrq_api_key) {
			case DL_PRODUCE_API_KEY:
				response = dl_produce_response_decode(mpbuf);
				break;
			case DL_FETCH_API_KEY:
				response = dl_fetch_response_decode(mpbuf);
				break;
			case DL_OFFSET_API_KEY:
				response = dl_list_offset_response_decode(
				    mpbuf);
				break;
			default:
				DLOGTR1(PRIO_HIGH,
				    "Request ApiKey is invalid (%d)\n",
				    request->dlrq_api_key);
				break;
			}
			
			/* The request has been acknowleded and can now be
			 * freed.
			 */
			dlog_free(request);
		} else {
			DLOGTR1(PRIO_HIGH,
			    "Couldn't find the unack'd request id: %d\n",
			    header->dlrsh_correlation_id);
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Cant allocate a response element\n");
	}
	return response;
}

struct dl_notifier *
dl_notifier_new(struct dl_client_configuration const *cc)
{
	struct dl_notifier *notifier;
	
	DL_ASSERT(cc != NULL, ("Client configuration cannot be NULL"));

	notifier = (struct dl_notifier *) dlog_alloc(
	    sizeof(struct dl_notifier));
#ifdef _KERNEL
	DL_ASSERT(notifier != NULL, ("Allocation of Client notifier failed"));
#else
	if (notifier != NULL) {
		notifier->dln_on_response = cc->dlcc_on_response;
		notifier->dln_client_id = cc->client_id;

		/* Initialise the notify queue. Responses to be notified back
		 * to the client are enqueued onto this queue.
		 */
		STAILQ_INIT(&notifier->dln_q);
		if (pthread_mutex_init(&notifier->dln_q_mtx, NULL) == 0) {
		    if (pthread_cond_init(&notifier->dln_q_cond, NULL) == 0) {

			} else {
				DLOGTR0(PRIO_HIGH, "Failed initializing "
				    "notifier cond var.\n");

				/* Cleanup */
				pthread_mutex_destroy(
				    &notifier->dln_q_mtx);
				dlog_free(notifier);
				notifier = NULL;
			}
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Failed initializing norifier mtx.\n");

			/* Cleanup */
			dlog_free(notifier);
			notifier = NULL;
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Failed allocating client notifier.\n");
	}
#endif
	return notifier;
}	

void
dl_notifier_fini(struct dl_notifier *notifier)
{
	int rc;

	DL_ASSERT(notifier != NULL,
	    "Notifier instance configuration cannot be NULL");

	rc = pthread_cancel(notifier->dln_tid);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH,
		    "Error cancelling notifier thread (%d)\n", rc);
	DL_ASSERT(STAILQ_EMPTY(&notifier->dln_q) == 0,
	    ("Notifier queue has unprocessed elements.\n"));

	/* Destroy the notifier's mutex and condition variable. */
	rc = pthread_mutex_destroy(&notifier->dln_q_mtx);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH,
		    "Error destroying notifier mutex (%d)\n", rc);

	rc = pthread_cond_destroy(&notifier->dln_q_cond);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH,
		    "Error destroying notifier cond var (%d)\n", rc);

	/* Free the notifier instance's memory. */	
	dlog_free(notifier);
}

int
dl_notifier_start(struct dl_notifier *notifier)
{
	struct dl_notifier_argument *args;
	int rc = -1;

	DL_ASSERT(notifier != NULL, ("Notifier instance cannot be NULL"));

	args = (struct dl_notifier_argument *) dlog_alloc(
	    sizeof(struct dl_notifier_argument));
#ifdef _KERNEL
	DL_ASSERT(args != NULL, ("Failed allocating notifier arguments.\n"));
	{
#else
	if (args != NULL) {
#endif
		args->dlna_notifier = notifier;
	
		rc = pthread_create(&notifier->dln_tid, NULL,
		    dl_notifier_thread, args);
		if (rc != 0)
			dlog_free(args);
	}
	return rc;
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
	DL_ASSERT(notifier != NULL, "Notifier instance cannot be NULL");
	DL_ASSERT(el != NULL, "Notify element cannot be NULL");

	pthread_mutex_lock(&notifier->dln_q_mtx);
	STAILQ_INSERT_TAIL(&notifier->dln_q, el, entries);
	pthread_cond_signal(&notifier->dln_q_cond);
	pthread_mutex_unlock(&notifier->dln_q_mtx);
}
