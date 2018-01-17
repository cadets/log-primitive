/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * Copyright (c) 2017 (Graeme Jenkinson)
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
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif

#include "distlog_client.h"
#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_resender.h"
#include "dl_request.h"
#include "dl_transport.h"
#include "dl_utils.h"

// TODO: I don't think FreeBSD defines this
// if not should it be 63 or 255?
#define HOST_NAME_MAX 255
	
STAILQ_HEAD(notify_queue, notify_queue_element);
STAILQ_HEAD(dl_request_queue, dl_request_element);

struct dl_notifier_argument {
	dl_ack_function dlna_on_ack;
	dl_response_function dlna_on_response;
	struct dl_client_configuration *dlna_config;
	pthread_t *dlna_tid;
	int dlna_index;
	struct notify_queue notify_queue;
	pthread_mutex_t notify_queue_mtx;
	pthread_cond_t notify_queue_cond;
};

struct dl_reader_argument {
	struct dl_client_configuration *dlra_config;
	pthread_t *dlra_tid;
	int dlra_index;
	int dlra_portnumber;
	char dlra_hostname[HOST_NAME_MAX];
	struct dl_request_queue *request_queue;
	pthread_mutex_t *dl_request_queue_mtx;
	pthread_cond_t *dl_request_queue_cond;
	struct notify_queue *notify_queue;
	pthread_mutex_t *notify_queue_mtx;
	pthread_cond_t *notify_queue_cond;
};

static int const NUM_NOTIFIERS = 5;
static int const NUM_READERS   = 1;
static int const REQUESTS_PER_NOTIFIER = 10;
/* Maximum number of outstanding un-acked messages */
//static int const NODE_POOL_SIZE = 128; 

struct notify_queue_element {
	char pbuf[MTU];
	STAILQ_ENTRY(notify_queue_element) entries;
};

struct dl_response_element {
	struct dl_response rsp_msg;
	LIST_ENTRY(dl_response_element) entries;
};

static int num_readers;

struct distlog_handle {
	struct dl_notifier_argument *nas;
	pthread_t *notifiers;
	struct dl_reader_argument *ras;
	pthread_t *readers;
	struct dl_request_queue request_queue;
	pthread_mutex_t dl_request_queue_mtx;
	pthread_cond_t dl_request_queue_cond;
	struct notify_queue notify_queue;
	pthread_mutex_t notify_queue_mtx;
	pthread_cond_t notify_queue_cond;
	struct dl_correlation_id *correlation_id;
};

static struct distlog_handle handle;

static int dl_allocate_client_datastructures(struct dl_client_configuration *);
static int dl_enqueue_request(struct dl_request_element *);
static int dl_free_client_datastructures();
static int dl_notify_response(struct notify_queue_element *,
    struct dl_notifier_argument *);
static void dl_process_request(const struct dl_transport *,
    struct dl_request_element *);
static void * dl_reader_thread(void *);
static void * dl_request_notifier_thread(void *);
static void dl_start_notifiers(struct distlog_handle *,
    struct dl_client_configuration *);
static void dl_start_reader_threads(struct distlog_handle *,
    struct dl_client_configuration *, int, char *, int);

static void *
dl_reader_thread(void *vargp)
{
	struct dl_reader_argument *ra = (struct dl_reader_argument *) vargp;
	struct dl_request_queue local_request_queue;
	struct dl_request_element *request, *request_temp;
	struct dl_transport transport;
	struct timespec ts;
	struct timeval now;
	int rv, msg_size, old_cancel_state;
	
	DL_ASSERT(vargp != NULL, "Reader thread arguments cannot be NULL");
	
	DISTLOGTR1(PRIO_LOW, "Reader thread %d started...\n", ra->dlra_index);
	
	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	transport.dlt_sock = -1;
	for (;;) {
		if (transport.dlt_sock < 0) {
			DISTLOGTR2(PRIO_NORMAL, "Connecting to '%s:%d'\n",
			    ra->dlra_hostname, ra->dlra_portnumber);

			dl_transport_connect(&transport,
			    ra->dlra_hostname, ra->dlra_portnumber);
			if (transport.dlt_sock < 0) {
				DISTLOGTR0(PRIO_NORMAL,
				    "Error connecting...\n");

				// TODO: Timer event for retries
				sleep(ra->dlra_config->reconn_timeout);
				continue;
			}
		}

		rv = dl_transport_poll(&transport,
		    ra->dlra_config->poll_timeout);
		DISTLOGTR1(PRIO_NORMAL, "Reader thread polling ... %d\n", rv);
		if (rv == -1) {
			DISTLOGTR0(PRIO_HIGH, "Poll error...");
			continue;
		}
		if (rv) {
       			struct notify_queue_element *temp_el =
			    (struct notify_queue_element *) distlog_alloc(
				sizeof(struct notify_queue_element));
			msg_size = dl_transport_read_msg(&transport,
			    temp_el->pbuf);
			if (msg_size > 0) {
				DISTLOGTR1(PRIO_LOW, "Reader thread read %d "
				    "bytes\n", msg_size);

				pthread_mutex_lock(ra->notify_queue_mtx);
				STAILQ_INSERT_TAIL(ra->notify_queue,
				    temp_el, entries);
				pthread_cond_signal(ra->notify_queue_cond);
				pthread_mutex_unlock(ra->notify_queue_mtx);
			} else {
				transport.dlt_sock = -1;
			}
		}

		pthread_mutex_lock(ra->dl_request_queue_mtx);		
		while (STAILQ_EMPTY(ra->request_queue) != 0 ) {
			/* There are no elements in the reader's
			 * queue check whether the thread has been
			 * canceled.
			 */
			pthread_testcancel();
			
			/* Wait for elements to be added to the
			 * reader's queue, whilst also periodically checking
			 * the thread's cancellation state.
			 */
			gettimeofday(&now, NULL);
			ts.tv_sec = now.tv_sec + 2;
			ts.tv_nsec = 0;
			pthread_cond_timedwait(ra->dl_request_queue_cond,
			    &ra->dl_request_queue_mtx, &ts);
		}

		while (STAILQ_EMPTY(ra->request_queue) == 0 ) {
			request = STAILQ_FIRST(ra->request_queue);
			STAILQ_REMOVE_HEAD(ra->request_queue, entries);

			STAILQ_INSERT_TAIL(&local_request_queue,
				request, entries);
		}
		pthread_mutex_unlock(ra->dl_request_queue_mtx);

		STAILQ_FOREACH_SAFE(request, &local_request_queue, entries,
		    request_temp) {
			STAILQ_REMOVE_HEAD(&local_request_queue, entries);
			dl_process_request(&transport, request);
			// TODO: proper errro handling is necessary
			//DISTLOGTR0(PRIO_NORMAL, "socket send error\n");
		}
	}
	return NULL;
}

static void
dl_process_request(const struct dl_transport *transport,
    struct dl_request_element *request)
{
	struct dl_request *request_msg = &request->dlrq_msg;
	ssize_t nbytes;

	DL_ASSERT(transport != NULL, "Transport cannot be NULL");
	DL_ASSERT(request != NULL, "Request cannot be NULL");

	DISTLOGTR1(PRIO_LOW, "Dequeued request with address %p\n",
	    request);
	DISTLOGTR1(PRIO_LOW, "Dequeued request with address %p\n",
	    request_msg);
	DISTLOGTR1(PRIO_LOW, "request_msg->CorrelationId %d\n",
	    request_msg->dlrqm_correlation_id);

	nbytes = dl_transport_send_request(transport, request_msg);
	if (nbytes != -1) {
		DISTLOGTR1(PRIO_LOW, "Request last_sent = %d\n",
			request->should_resend);

		if (request_msg->dlrqm_api_key == DL_PRODUCE_REQUEST &&
		    !request_msg->dlrqm_message.dlrqmt_produce_request.dlpr_required_acks) {
			/* The request does not require an acknowledgment;
			 * as we have finished processing the request free it.
			 */
			 distlog_free(request);
		} else {
			/* The request must be acknowledged, store
			 * the request until an acknowledgment is
			 * received from the broker.
			 */

			/* Successfuly send the request,
			 * record the last send time.
			 */	
			request->last_sent = time(NULL);
				
			DISTLOGTR1(PRIO_NORMAL,
			    "Inserting into the tree with key %d\n",
			    request_msg->dlrqm_correlation_id);

			// TODO: Add error handling
			dl_resender_unackd_request(request);
			DISTLOGTR1(PRIO_NORMAL, "Processed request %d\n",
			    request_msg->dlrqm_correlation_id);
		}
	} else {
		// TODO: proper errro handling is necessary
		DISTLOGTR0(PRIO_NORMAL, "socket send error\n");
	}
}

static void *
dl_request_notifier_thread(void *vargp)
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

	DISTLOGTR1(PRIO_LOW, "Notifier thread %d started...\n",
	    na->dlna_index);
	
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
		pthread_mutex_lock(&na->notify_queue_mtx);		
		while (STAILQ_EMPTY(&na->notify_queue) != 0 ) {
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
			pthread_cond_timedwait(&na->notify_queue_cond,
			    &na->notify_queue_mtx, &ts);
		}

		while ((notify = STAILQ_FIRST(&na->notify_queue))) {
			STAILQ_REMOVE_HEAD(&na->notify_queue, entries);
			STAILQ_INSERT_TAIL(&local_notify_queue, notify,
			    entries);
		}
		pthread_mutex_unlock(&na->notify_queue_mtx);		

		/* Process the elements in the thread local queue,
		 * notifying the lients for each response.
		 */
		STAILQ_FOREACH_SAFE(notify, &local_notify_queue, entries,
		    notify_temp) {
			if (dl_notify_response(notify, na) != 0) {
				DISTLOGTR0(PRIO_HIGH,
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
	struct dl_request *req_m;
	struct dl_response *res_m;
	char *pbuf = notify->pbuf;

	DL_ASSERT(notify != NULL, "Notifier element cannot be NULL");
	DL_ASSERT(na != NULL, "Notifier thread argument cannot be NULL");

	response = (struct dl_response_element *) distlog_alloc(
	    sizeof(struct dl_response_element));
	if (NULL != response) {
		/* Deserialise the response message. */
		res_m = &response->rsp_msg;
		if (dl_decode_response(res_m, pbuf) == 0) {
				
			DISTLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_size);
			DISTLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_correlation_id);

			/* Acknowledge the request message based
			 * on the CorrelationId returned in the response.
			 */
			request = dl_resender_ackd_request(
			    res_m->dlrs_correlation_id);
			if (NULL != request) {
				req_m = &request->dlrq_msg;

				// TODO: Add error checking
				switch (req_m->dlrqm_api_key) {
				case DL_PRODUCE_REQUEST:
					dl_decode_produce_response(
					    &res_m->dlrs_message.dlrs_produce_response,
					    pbuf+2*sizeof(int32_t)); // TODO: remove hack
					break;
				case DL_FETCH_REQUEST:
					dl_decode_fetch_response(
					    &res_m->dlrs_message.dlrs_fetch_response,
					    pbuf+2*sizeof(int32_t)); // TODO: remove hack
					break;
				case DL_OFFSET_REQUEST:
					dl_decode_offset_response(
					    &res_m->dlrs_message.dlrs_offset_response,
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
					na->dlna_on_response(req_m, res_m);
			
				// TOOD: who is responsible for freeing the 
				// memory?	
				distlog_free(response);
			} else {
				DISTLOGTR1(PRIO_HIGH,
				    "Couldn't find the unacknowledged request "
				    "id: %d\n", res_m->dlrs_correlation_id);
				distlog_free(response);
			}
		}
	} else {
		DISTLOGTR0(PRIO_HIGH, "Cant borrow a response element\n");
	}

	return 0;
}

static void
dl_start_notifiers(struct distlog_handle *handle,
    struct dl_client_configuration *cc)
{
	int notifier;

	for (notifier = 0; notifier < NUM_NOTIFIERS; notifier++) {

		handle->nas[notifier].dlna_index = notifier;
		handle->nas[notifier].dlna_tid = NULL;
		handle->nas[notifier].dlna_config = cc;
		handle->nas[notifier].dlna_on_ack = cc->dlcc_on_ack;
		handle->nas[notifier].dlna_on_response = cc->dlcc_on_response;
		handle->nas[notifier].notify_queue = handle->notify_queue;
		handle->nas[notifier].notify_queue_mtx =
		    handle->notify_queue_mtx;
		handle->nas[notifier].notify_queue_cond =
		    handle->notify_queue_cond;

		if (0 == pthread_create(&handle->notifiers[notifier], NULL,
		    dl_request_notifier_thread, &handle->nas[notifier])) {

			handle->nas[notifier].dlna_tid =
			    &handle->notifiers[notifier];
		}
	}
}

static int
dl_allocate_client_datastructures(struct dl_client_configuration *cc)
{
	int processor;

	/* Allocate memory for the notifier threads. These threads
	 * asynchronously report ack's requests back to the client.
	 */
	handle.nas = (struct dl_notifier_argument *) distlog_alloc(
		sizeof(struct dl_notifier_argument) * NUM_NOTIFIERS);

	handle.notifiers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_NOTIFIERS);

	/* Allocate memory for the reader threads. These threads read response
	 * from the distributed log broker. 
	 */
	handle.readers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_READERS);

	handle.ras = (struct dl_reader_argument *) distlog_alloc(
		sizeof(struct dl_reader_argument) * NUM_READERS);
	
	/* Initialise the notify queue. Responses to be notified back to
	 * the client are enqueued onto this queue.
	 */
	STAILQ_INIT(&handle.notify_queue);
	pthread_mutex_init(&handle.notify_queue_mtx, NULL);
	pthread_cond_init(&handle.notify_queue_cond, NULL);

	/* Initialise the response queue (on which client requests are
	 * enqueued).
	 */
	STAILQ_INIT(&handle.request_queue);
	pthread_mutex_init(&handle.dl_request_queue_mtx, NULL);
	pthread_cond_init(&handle.dl_request_queue_cond, NULL);

	/* Initialise (preallocate) a pool of requests.
	 * TODO: Change this to work like the kaudit_queue.
	 */
	/*STAILQ_INIT(&handle.request_pool);

	for (processor = 0; processor < MAX_NUM_REQUESTS_PER_PROCESSOR;
	    processor++) {
		struct dl_request_element * list_entry =
		    distlog_alloc(sizeof(struct dl_request_element));
		STAILQ_INSERT_HEAD(&handle.request_pool, list_entry, entries);
	}
	
	pthread_mutex_init(&handle.request_pool_mtx, NULL);
	*/

	/* Instantiate a correlation id. */
	handle.correlation_id = dl_correlation_id_new();

	return 1;
}

static int 
dl_enqueue_request(struct dl_request_element *request)
{
	pthread_mutex_lock(&handle.dl_request_queue_mtx);
	STAILQ_INSERT_TAIL(&handle.request_queue, request, entries);
	pthread_cond_signal(&handle.dl_request_queue_cond);
	pthread_mutex_unlock(&handle.dl_request_queue_mtx);

	return 0;
}

static int
dl_free_client_datastructures()
{
	/* Free the memory associated with the reader threads */
	distlog_free(handle.readers);
	distlog_free(handle.ras);

	/* Free the memory associated with the notifier threads */
	distlog_free(handle.notifiers);
	distlog_free(handle.nas);

	/* Free the correlation id. */	
	dl_correlation_id_fini(handle.correlation_id);
}

static void
dl_start_reader_threads(struct distlog_handle *handle,
    struct dl_client_configuration *cc, int num, char * hostname, int port)
{
	int reader;

	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");

	num_readers = MIN(NUM_READERS, num);

	for (reader = 0; reader < num_readers; reader++) {

		handle->ras[reader].dlra_index = reader;
		handle->ras[reader].dlra_tid = NULL;
		handle->ras[reader].dlra_config = cc;
		// TODO: In-kernel strlcpy
		strlcpy(handle->ras[reader].dlra_hostname, hostname,
			HOST_NAME_MAX);
		handle->ras[reader].dlra_portnumber = port;
		handle->ras[reader].request_queue = &handle->request_queue;
		handle->ras[reader].dl_request_queue_mtx =
		    &handle->dl_request_queue_mtx;
		handle->ras[reader].dl_request_queue_cond =
		    &handle->dl_request_queue_cond;
		handle->ras[reader].notify_queue = &handle->notify_queue;
		handle->ras[reader].notify_queue_mtx =
		    &handle->notify_queue_mtx;
		handle->ras[reader].notify_queue_cond =
		    &handle->notify_queue_cond;

		if (0 == pthread_create(&handle->readers[reader], NULL,
		    dl_reader_thread, &handle->ras[reader])) {

			handle->ras[reader].dlra_tid =
			    &handle->readers[reader];
		}
	}
}

int
distlog_client_fini()
{
	int notifier, reader, rc, cancelled_threads;

	/* Cancel the reader threads */
	cancelled_threads = 0;
	for (reader = 0; reader < num_readers; reader++) {
		rc = pthread_cancel(handle.readers[reader]);
		if (rc != ESRCH)
			cancelled_threads++;
	}

	DISTLOGTR2(PRIO_HIGH, "Cancelled %d/%d reader threads\n",
	    cancelled_threads, num_readers);

	/* Cancel the notifier threads */
	cancelled_threads = 0;
	for (notifier = 0; notifier < NUM_NOTIFIERS; notifier++) {
		rc = pthread_cancel(handle.notifiers[notifier]);
		if (rc != ESRCH)
			cancelled_threads++;
	}

	DISTLOGTR2(PRIO_NORMAL, "Cancelled %d/%d notifier threads\n",
	    cancelled_threads, NUM_NOTIFIERS);

	/* Cancel the resender thread */
	dl_resender_stop();
	if (rc != ESRCH)
		DISTLOGTR0(PRIO_NORMAL, "Cancelled resender thread\n");
	else
		DISTLOGTR0(PRIO_HIGH, "Failed cancelling resender thread\n");

	/* Free all memory allocated by the client */
	dl_free_client_datastructures();

	return 0;
}

// Need to split into init and open
struct distlog_handle *
distlog_client_open(char const * const hostname,
    const int portnumber, struct dl_client_configuration const * const cc)
{
	int ret;
	
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	DISTLOGTR0(PRIO_NORMAL, "Initialising the distlog client...\n");

	ret  = dl_allocate_client_datastructures(cc);
	if (ret > 0) {
		DISTLOGTR0(PRIO_NORMAL, "Finished allocation...\n");

		dl_start_notifiers(&handle, cc);
		dl_start_reader_threads(&handle, cc, 1, hostname, portnumber);

		dl_resender_init(cc);
		dl_resender_start(cc);
		return &handle;
	}
	return NULL;
}

int
distlog_client_init(char const * const hostname,
    const int portnumber, struct dl_client_configuration const * const cc)
{
	int ret;
	
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	DISTLOGTR0(PRIO_NORMAL, "Initialising the distlog client...\n");

	ret  = dl_allocate_client_datastructures(cc);
	if (ret > 0) {
		DISTLOGTR0(PRIO_NORMAL, "Finished allocation...\n");

		dl_start_notifiers(&handle, cc);
		dl_start_reader_threads(&handle, cc, 1, hostname, portnumber);

		dl_resender_init(cc);
		dl_resender_start(cc);
		return 0;
	}
	return 1;
}

int
distlog_client_close(struct distlog_handle *handle)
{
	return 0;
}

int
distlog_send(struct distlog_handle *handle, int server_id, char *client_id,
    bool should_resend, int resend_timeout, ...)
//    int resend_timeout, char *topic, int num_msgs, ...)
{
	struct dl_buffer *buffer;
	struct dl_request_element *request;
	int result = 0;
	int octets_to_send;
	va_list ap;

	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	va_start(ap, resend_timeout);

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
	 * and responses and specifying policy for resending requests.
	 */
	request = (struct dl_request_element *) distlog_alloc(
	    sizeof(struct dl_request_element));
	if (request) {
		/* Construct the request */
		request->should_resend = should_resend;
		request->resend_timeout = resend_timeout;

		DISTLOGTR1(PRIO_LOW, "Request should_resend = %d\n",
		    request->should_resend);
		if (should_resend) {
			DISTLOGTR1(PRIO_LOW, "Request resend_timeout = %d\n",
			    request->resend_timeout);
		}

		DISTLOGTR1(PRIO_LOW, "Building request message "
		    "(correlation_id = %d)\n",
		    dl_correlation_id_val(handle->correlation_id));

		/* Instantiate a new produce request */
		dl_produce_request_new(&request->dlrq_msg,
		    	dl_correlation_id_val(handle->correlation_id),
			client_id, ap);
	
		DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

		/* Enqueue the request for processing */
		if (0 == dl_enqueue_request(request)) {
			
			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DISTLOGTR0(PRIO_HIGH, "Error enquing request\n");
		}
	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
		
	va_end(ap);

	return result;
}

int
distlog_recv(struct distlog_handle *handle, int server_id, char *client_id,
    bool should_resend, int resend_timeout, ...)
{
	struct dl_buffer *buffer;
	struct dl_request_element *request;
	int result = 0;
	int octets_to_send;
	va_list ap;

	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	va_start(ap, resend_timeout);

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
	 * and responses and specifying policy for resending requests.
	 */
	request = (struct dl_request_element *) distlog_alloc(
	    sizeof(struct dl_request_element));
	if (NULL != request) {
		/* Construct the request */
		request->should_resend = should_resend;
		request->resend_timeout = resend_timeout;

		DISTLOGTR1(PRIO_LOW, "Request should_resend = %d\n",
		    request->should_resend);
		if (should_resend) {
			DISTLOGTR1(PRIO_LOW, "Request resenid_timeout = %d\n",
			    request->resend_timeout);
		}

		DISTLOGTR1(PRIO_LOW, "Building request message "
		    "(correlation_id = %d)\n",
		    dl_correlation_id_val(handle->correlation_id));

		dl_fetch_request_new(&request->dlrq_msg,
		    dl_correlation_id_val(handle->correlation_id), client_id, ap);

		/* Enqueue the request for processing */
		if (0 == dl_enqueue_request(request)) {
			
			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DISTLOGTR0(PRIO_HIGH, "Error enquing request\n");
		}
	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
		
	va_end(ap);

	return result;
}

int
distlog_offset(struct distlog_handle *handle, int server_id, char *client_id,
    bool should_resend, int resend_timeout)
{
	int result = 0;
	struct dl_request_element * request;

	// TODO: In fact I think that the protocol allows this!
	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
	 * and responses and specifying policy for resending requests.
	 */
	request = (struct dl_request_element *) distlog_alloc(
	    sizeof(struct dl_request_element));
	if (request) {
		/* Construct the request */
		request->should_resend = should_resend;
		request->resend_timeout = resend_timeout;

		DISTLOGTR1(PRIO_LOW, "Request should_resend = %d\n",
		    request->should_resend);
		if (should_resend) {
			DISTLOGTR1(PRIO_LOW, "Request resenid_timeout = %d\n",
			    request->resend_timeout);
		}

		DISTLOGTR1(PRIO_LOW, "Building request message "
		    "(correlation_id = %d)\n",
		    dl_correlation_id_val(handle->correlation_id));

		// TODO: Temporarily send an OffsetRequest
		// need a constructor for this
		request->dlrq_msg.dlrqm_api_key = DL_OFFSET_REQUEST;
		request->dlrq_msg.dlrqm_api_version = 1;
		request->dlrq_msg.dlrqm_correlation_id =
			dl_correlation_id_val(handle->correlation_id);
		strcpy(&request->dlrq_msg.dlrqm_client_id, "consumer");
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_replica_id = -1;
		strcpy(&request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_topic_name,
		    "cadets-trace");
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_partition = 0;
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_time = -2;

		DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

		/* Enqueue the request for processing */
		if (0 == dl_enqueue_request(request)) {
			
			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DISTLOGTR0(PRIO_HIGH, "Error enquing request\n");
		}
	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
	
	return result;
}
