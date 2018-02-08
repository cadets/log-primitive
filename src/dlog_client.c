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

#include <stddef.h>

#ifdef _APPLE
#include <kern/clock.h>
#else
#include <sys/time.h>
#endif

#include <sys/param.h>
#include <sys/queue.h>
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif

#include "dlog_client.h"
#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_notifier.h"
#include "dl_resender.h"
#include "dl_request.h"
#include "dl_request_queue.h"
#include "dl_transport.h"
#include "dl_utils.h"

// TODO: I don't think FreeBSD defines this
// if not should it be 63 or 255?
#define HOST_NAME_MAX 255
	
struct dl_reader_argument {
	struct dl_client_configuration *dlra_config;
	int dlra_portnumber;
	char dlra_hostname[HOST_NAME_MAX];
	struct dl_request_queue *request_queue;
	pthread_mutex_t *dl_request_queue_mtx;
	pthread_cond_t *dl_request_queue_cond;
	struct dl_notifier *notifier;
};

struct dlog_handle {
	struct dl_client_configuration *dlh_config;
	struct dl_notifier *dlh_notifier;
	struct dl_reader_argument ra;
	pthread_t reader;
	struct dl_request_queue request_queue;
	pthread_mutex_t dl_request_queue_mtx;
	pthread_cond_t dl_request_queue_cond;
	struct dl_correlation_id *correlation_id;
};

static int dl_enqueue_request(struct dlog_handle *, struct dl_buffer*,
    int32_t, int32_t, int16_t);
static void dl_process_request(const struct dl_transport *,
    struct dl_request_element *);
static void * dl_reader_thread(void *);
static void dl_start_reader_thread(struct dlog_handle *,
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
	
	DISTLOGTR1(PRIO_LOW, "%s: Reader thread started...\n",
	    ra->dlra_config->client_id);
	
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

				sleep(ra->dlra_config->reconn_timeout);
				continue;
			} else {
				DISTLOGTR2(PRIO_LOW, "Connected to %s:%d\n",
				    ra->dlra_hostname, ra->dlra_portnumber);
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
			    (struct notify_queue_element *) dlog_alloc(
				sizeof(struct notify_queue_element));
			msg_size = dl_transport_read_msg(&transport,
			    temp_el->pbuf);
			if (msg_size > 0) {
				DISTLOGTR1(PRIO_LOW, "Reader thread read %d "
				    "bytes\n", msg_size);

				dl_notifier_response(ra->notifier, temp_el);
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
			// TODO: In-kernel timing
			gettimeofday(&now, NULL);
			ts.tv_sec = now.tv_sec + 2;
			ts.tv_nsec = 0;
			pthread_cond_timedwait(ra->dl_request_queue_cond,
			    ra->dl_request_queue_mtx, &ts);
		}

		while (STAILQ_EMPTY(ra->request_queue) == 0 ) {
			request = STAILQ_FIRST(ra->request_queue);
			STAILQ_REMOVE_HEAD(ra->request_queue, dlrq_entries);

			STAILQ_INSERT_TAIL(&local_request_queue,
				request, dlrq_entries);
		}
		pthread_mutex_unlock(ra->dl_request_queue_mtx);

		STAILQ_FOREACH_SAFE(request, &local_request_queue, dlrq_entries,
		    request_temp) {
			STAILQ_REMOVE_HEAD(&local_request_queue, dlrq_entries);
			dl_process_request(&transport, request);
			// TODO: proper errro handling is necessary
		}
	}
	return NULL;
}

static void
dl_process_request(const struct dl_transport *transport,
    struct dl_request_element *request)
{
	ssize_t nbytes;
#ifdef __APPLE__
	int32_t secs, msecs;
#else
	struct timeval tv;
#endif

	DL_ASSERT(transport != NULL, "Transport cannot be NULL");
	DL_ASSERT(request != NULL, "Request cannot be NULL");

	DISTLOGTR1(PRIO_LOW, "Dequeued request (id = %d)\n",
	    request->dlrq_correlation_id);

	nbytes = dl_transport_send_request(transport,
	    request->dlrq_buffer, request->dlrq_buffer_len);
	if (nbytes != -1) {
		DISTLOGTR1(PRIO_LOW, "Successfully sent request (id = %d)\n",
		    request->dlrq_correlation_id);

		if (request->dlrq_api_key == DL_PRODUCE_REQUEST &&
		    request->dlrq_required_acks == 0) {
			/* The request does not require an acknowledgment;
			 * as we have finished processing the request free it.
			 */
			 dlog_free(request);
		} else {
			/* The request must be acknowledged, store
			 * the request until an acknowledgment is
			 * received from the broker.
			 */

			/* Successfuly send the request,
			 * record the last send time.
			 */
#ifdef _KERNEL
#ifdef __APPLE__
			clock_get_calendar_microtime(&secs, &msecs);
			request->dlrq_last_sent = (secs * 1000) + msecs;
#else
			getmicrottime(&tv);
			request->dlrq_last_sent =
			    (tv.tv_sec *1000) + (tv.tv_usec/1000);
#endif
#else
			request->dlrq_last_sent = time(NULL);
#endif

			DISTLOGTR1(PRIO_NORMAL,
			    "Inserting into the tree with key %d\n",
			    request->dlrq_correlation_id);

			// TODO: Add error handling
			dl_resender_unackd_request(request);
			DISTLOGTR1(PRIO_NORMAL, "Processed request %d\n",
			    request->dlrq_correlation_id);
		}
	} else {
		// TODO: proper errro handling is necessary
		DISTLOGTR0(PRIO_NORMAL, "socket send error\n");
	}
}

static int 
dl_enqueue_request(struct dlog_handle *handle, struct dl_buffer *buffer,
    int32_t buffer_len, int32_t correlation_id, int16_t api_key)
{
	struct dl_request_element *request;

	DISTLOGTR0(PRIO_LOW, "Building request message..\n ");

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
	 * and responses and specifying policy for resending requests.
	 */
	request = (struct dl_request_element *) dlog_alloc(
	    sizeof(struct dl_request_element));
	if (request) {
		/* Construct the request */
		request->dlrq_buffer = buffer;
		request->dlrq_buffer_len = buffer_len;
		request->dlrq_should_resend = handle->dlh_config->to_resend;
		request->dlrq_resend_timeout =
		    handle->dlh_config->resend_timeout;
		request->dlrq_correlation_id = correlation_id;
		request->dlrq_api_key = api_key;
		request->dlrq_required_acks = 1; // message->dlrqm_message.dlrqmt_produce_request->dlrqm_required_acks;

		DISTLOGTR1(PRIO_LOW, "Request should_resend = %d\n",
		    request->dlrq_should_resend);
		if (request->dlrq_should_resend) {
			DISTLOGTR1(PRIO_LOW, "Request resend_timeout = %d\n",
			    request->dlrq_resend_timeout);
		}
		
		pthread_mutex_lock(&handle->dl_request_queue_mtx);
		STAILQ_INSERT_TAIL(&handle->request_queue, request,
		    dlrq_entries);
		pthread_cond_signal(&handle->dl_request_queue_cond);
		pthread_mutex_unlock(&handle->dl_request_queue_mtx);
		
		DISTLOGTR0(PRIO_LOW, "Enqueued request message..\n ");
		return 0;
	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		return -1;
	}
}

static void
dl_start_reader_thread(struct dlog_handle *handle,
    struct dl_client_configuration *cc, int num, char * hostname, int port)
{
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");

	handle->ra.dlra_config = cc;
	// TODO: In-kernel strlcpy
	strlcpy(handle->ra.dlra_hostname, hostname,
		HOST_NAME_MAX);
	handle->ra.dlra_portnumber = port;
	handle->ra.request_queue = &handle->request_queue;
	handle->ra.dl_request_queue_mtx =
		&handle->dl_request_queue_mtx;
	handle->ra.dl_request_queue_cond =
		&handle->dl_request_queue_cond;
	handle->ra.notifier = handle->dlh_notifier;

	if (0 == pthread_create(&handle->reader, NULL,
		dl_reader_thread, &handle->ra)) {

	}
}

struct dlog_handle *
dlog_client_open(char const * const hostname,
    const int portnumber, struct dl_client_configuration const * const cc)
{
	struct dlog_handle *handle;
	int ret;
	
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");
	
	handle = (struct dlog_handle *) dlog_alloc(
	    sizeof(struct dlog_handle));
	
	/* Store the client configuration. */
	handle->dlh_config = cc;

	/* Instatiate the client notifier. */
	handle->dlh_notifier = dl_notifier_new(cc);
	DL_ASSERT(handle->dlh_notifier != NULL,
	    "Failed instatiating new notifier\n");
	
	/* Instatiate the client resender. */
	dl_resender_init(cc);

	/* Initialise the response queue (on which client requests are
	 * enqueued).
	 */
	STAILQ_INIT(&handle->request_queue);
	pthread_mutex_init(&handle->dl_request_queue_mtx, NULL);
	pthread_cond_init(&handle->dl_request_queue_cond, NULL);

	/* Instantiate a correlation id. */
	handle->correlation_id = dl_correlation_id_new();
	DL_ASSERT(handle->correlation_id != NULL,
	    "Failed instatiating new correlation_id\n");

	DISTLOGTR0(PRIO_NORMAL, "Initialising the dlog client...\n");

	/* Start the client threads. */
	dl_notifier_start(handle->dlh_notifier, cc);
	dl_resender_start(cc);
	dl_start_reader_thread(handle, cc, 1, hostname, portnumber);

	return handle;
}

int
dlog_client_close(struct dlog_handle *handle)
{
	int rc;

	/* Cancel the reader threads */
	rc = pthread_cancel(handle->reader);
	if (rc != 0)
		DISTLOGTR1(PRIO_HIGH, "Error stopping reader %d\n", rc);
	
	/* Cancel the notifier */
	rc = dl_notifier_stop(handle->dlh_notifier);
	if (rc != 0)
		DISTLOGTR1(PRIO_HIGH, "Error stopping notifier %d\n", rc);
	
	/* Free the memory associated with the notifier */
	dl_notifier_fini(handle->dlh_notifier);

	/* Cancel the resender */
	rc = dl_resender_stop();
	if (rc != 0)
		DISTLOGTR1(PRIO_HIGH, "Failed stopping the resender %d\n", rc);

	/* Free the correlation id. */	
	dl_correlation_id_fini(handle->correlation_id);

	return 0;
}

int
dlog_fetch(struct dlog_handle *handle, char *topic_name, int32_t min_bytes,
    int32_t max_wait_time, int64_t fetch_offset, int32_t max_bytes)
{
	struct dl_buffer *buffer;
	struct dl_request *message;
	int result = 0;
	int32_t buffer_len;

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	message = dl_fetch_request_new(
	    dl_correlation_id_val(handle->correlation_id),
	    handle->dlh_config->client_id, topic_name, min_bytes,
	    max_wait_time, fetch_offset, max_bytes);
	
	DISTLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);

	/* Allocate and initialise a buffer to encode the request. */
	buffer = (struct dl_buffer *) dlog_alloc(
		sizeof(struct dl_buffer_hdr) + (sizeof(char) * MTU));
	DL_ASSERT(buffer != NULL, "Buffer to encode request cannot be NULL");
	buffer->dlb_hdr.dlbh_data = buffer->dlb_databuf;
	buffer->dlb_hdr.dlbh_len = MTU;
	
	DISTLOGTR0(PRIO_LOW, "Encoded request message\n");
	/* Encode the request the request. */	
	buffer_len = dl_request_encode(message, buffer);

	// mesasge xtor

	DISTLOGTR0(PRIO_LOW, "Encoded request message\n");

	/* Enqueue the request for processing */
	if (dl_enqueue_request(handle, buffer, buffer_len,
	    message->dlrqm_correlation_id, message->dlrqm_api_key) == 0) {
		
		/* Increment the monotonic correlation id. */
		dl_correlation_id_inc(handle->correlation_id);
	} else {
		DISTLOGTR0(PRIO_HIGH, "Error enqueing request\n");
	}

	return result;
}

int
dlog_list_offset(struct dlog_handle *handle, char *topic, int64_t time)
{
	struct dl_buffer *buffer;
	struct dl_request *message;
	int result = 0;
	int32_t buffer_len;

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Instantiate a new ListOffsetRequest. */
	message = dl_list_offset_request_new(
	    dl_correlation_id_val(handle->correlation_id), 
	    handle->dlh_config->client_id, topic, time);
	
	DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

	/* Allocate and initialise a buffer to encode the request. */
	buffer = (struct dl_buffer *) dlog_alloc(
		sizeof(struct dl_buffer_hdr) + (sizeof(char) * MTU));
	DL_ASSERT(buffer != NULL, "Buffer to encode request cannot be NULL");
	buffer->dlb_hdr.dlbh_data = buffer->dlb_databuf;
	buffer->dlb_hdr.dlbh_len = MTU;
	
	/* Encode the request the request. */	
	buffer_len = dl_request_encode(message, buffer);
	
	// mesasge xtor

	DISTLOGTR0(PRIO_LOW, "Encoded request message\n");

	/* Enqueue the request for processing */
	if (dl_enqueue_request(handle, buffer, buffer_len,
	    message->dlrqm_correlation_id, message->dlrqm_api_key) == 0) {
		
		DISTLOGTR0(PRIO_HIGH, "Enqued request\n");

		/* Increment the monotonic correlation id. */
		dl_correlation_id_inc(handle->correlation_id);
	} else {
		DISTLOGTR0(PRIO_HIGH, "Error enqueing request\n");
	}
	

	return result;
}

int
dlog_produce(struct dlog_handle *handle, char *topic, char *key, int key_len,
    char *value, int value_len)
{
	struct dl_buffer *buffer;
	struct dl_request *message;
	int result = 0;
	int32_t buffer_len;

	/* Instantiate a new ProduceRequest */
	message = dl_produce_request_new(
	    dl_correlation_id_val(handle->correlation_id),
	    handle->dlh_config->client_id, topic,
	    key, key_len, value, value_len);

	DISTLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);

	/* Allocate and initialise a buffer to encode the request. */
	buffer = (struct dl_buffer *) dlog_alloc(
		sizeof(struct dl_buffer_hdr) + (sizeof(char) * MTU));
	DL_ASSERT(buffer != NULL, "Buffer to encode request cannot be NULL");
	buffer->dlb_hdr.dlbh_data = buffer->dlb_databuf;
	buffer->dlb_hdr.dlbh_len = MTU;

	/* Encode the request the request. */	
	buffer_len = dl_request_encode(message, buffer);
	
	// mesasge xtor
	
	DISTLOGTR0(PRIO_LOW, "Encoded request message\n");

	/* Enqueue the request for processing */
	if (dl_enqueue_request(handle, buffer, buffer_len,
	    message->dlrqm_correlation_id, message->dlrqm_api_key) == 0) {
		
		/* Increment the monotonic correlation id. */
		dl_correlation_id_inc(handle->correlation_id);
	} else {
		DISTLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		result = -1;
	}
	
	return result;
}


