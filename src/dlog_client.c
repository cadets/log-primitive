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

#ifdef _APPLE
#include <kern/clock.h>
#else
#include <sys/time.h>
#endif
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#endif

#include <stddef.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_broker_client.h"
#include "dl_broker_topic.h"
#include "dl_correlation_id.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_resender.h"
#include "dl_request.h"
#include "dl_response.h"
#include "dl_request_queue.h"
#include "dl_transport.h"
#include "dl_utils.h"
#include "dlog_broker.h"
#include "dlog_client.h"
#include "dlog_client_impl.h"

// TODO: I don't think FreeBSD defines this
// if not should it be 63 or 255?
#define HOST_NAME_MAX 255

static void * dl_request_thread(void *);
static void * dl_response_thread(void *);
static void dl_start_response_thread(struct dlog_handle *,
    struct dl_client_configuration const *, struct dl_transport *);

//dlog_client_init(()
//pthread_t dlh_reader;
//static struct dl_correlation_id *correlation_id;
//correlation_id = dl_correlation_id_new();

static dl_event_handler_handle
dlog_client_get_handle(void *instance)
{
	const struct dlog_handle *handle = instance;
	return handle->dlh_transport->dlt_sock;
}

static void
dlog_client_handle_read_event(void *instance)
{
	const struct dlog_handle *handle = instance;
	struct dl_request_element *request;	
	struct dl_response *response = NULL;
	struct dl_response_header *header;
	struct dl_bbuf *buffer;
	int msg_size;

	DLOGTR0(PRIO_LOW, "dlog_client_handle_read_event\n");

	if (dl_transport_read_msg(handle->dlh_transport, &buffer) == 0) {

		char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_len(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<0x%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		/* Flip the buffer as we are now reading values from it. */
		dl_bbuf_flip(buffer);

		/* Deserialise the response header. */
		if (dl_response_header_decode(&header, buffer) == 0) {

			DLOGTR1(PRIO_LOW, "Got response id = : %d\n",
			    header->dlrsh_correlation_id);

			/* Acknowledge the request message based
			 * on the CorrelationId returned in the response.
			 */
			request = dl_resender_ackd_request(
			    handle->dlh_resender,
			    header->dlrsh_correlation_id);
			if (request != NULL) {
				switch (request->dlrq_api_key) {
				case DL_PRODUCE_API_KEY:
					dl_produce_response_decode(&response,
					    buffer);
					break;
				case DL_FETCH_API_KEY:
					response = dl_fetch_response_decode(
					    buffer);
					break;
				case DL_OFFSET_API_KEY:
					response =
					    dl_list_offset_response_decode(
						buffer);
					break;
				default:
					DLOGTR1(PRIO_HIGH,
					    "Request ApiKey is invalid (%d)\n",
					    request->dlrq_api_key);
					break;
				}
				
				/* The request has been acknowleded and can
				* now be freed.
				*/
				dlog_free(request);

				/* Invoke the client callback. */
				if (response != NULL &&
				    handle->dlh_config->dlcc_on_response != NULL) {
					//handle->dlh_config->dlcc_on_response(
			    		//header->dlrsh_correlation_id);
					//response);
					handle->dlh_config->dlcc_on_response(response);

					dlog_free(response);
				}
			} else {
				DLOGTR1(PRIO_HIGH,
				    "Couldn't find the unack'd request id: "
				    "%d\n", header->dlrsh_correlation_id);
			}
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Error decoding response header.\n");
		}

		// TODO: Free the dl_bbuf instance
	} else {
		/* Server disconnected. */
		dl_poll_reactor_unregister(&handle->dlh_event_handler);

		/* Reconnect and register */
		// TODO: What about the request?
	}
}

static void *
dl_request_thread(void *vargp)
{
	struct dlog_handle *handle = (struct dl_request_argument *) vargp;
	struct dl_request_queue local_request_queue;
	struct dl_request_element *request, *request_temp;
	struct dl_transport *transport;
	struct timespec ts;
	struct timeval now;
	int rv, msg_size, old_cancel_state, port;
	ssize_t nbytes;
#ifdef __APPLE__
	int32_t secs, msecs;
#else
	struct timeval tv;
#endif

	DL_ASSERT(vargp != NULL, "Request thread arguments cannot be NULL");
	
	DLOGTR0(PRIO_LOW, "Request thread started...\n");

	/* Copy the thread arguements and free the memory. */
	transport = handle->dlh_transport;

	/* Defer cancellation of the thread until the cancellation point 
	 * This ensures that thread isn't cancelled until outstanding requests
	 * have been processed.
	 */	
#ifdef _KERNEL
#else
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);
#endif

	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	for (;;) {
		dl_request_q_dequeue(handle->dlh_request_q, &local_request_queue);

		STAILQ_FOREACH_SAFE(request, &local_request_queue, dlrq_entries,
		    request_temp) {
			STAILQ_REMOVE_HEAD(&local_request_queue, dlrq_entries);

			DLOGTR1(PRIO_LOW, "Dequeued request (id = %d)\n",
			request->dlrq_correlation_id);

			nbytes = dl_transport_send_request(transport,
			    request->dlrq_buffer);
			if (nbytes != -1) {
				DLOGTR1(PRIO_LOW,
				    "Successfully sent request (id = %d)\n",
				    request->dlrq_correlation_id);

				/* The request must be acknowledged, store
				 * the request until an acknowledgment is
				 * received from the broker.
				 */

				/* Successfuly send the request,
				 * record the last send time.
				 */
#ifdef _KERNEL
#ifdef __APPLE__
				clock_get_calendar_microtime(&secs,
					&msecs);
				request->dlrq_last_sent =
					(secs * 1000) + msecs;
#else
				getmicrottime(&tv);
				request->dlrq_last_sent =
					(tv.tv_sec *1000) +
					(tv.tv_usec/1000);
#endif
#else
				request->dlrq_last_sent = time(NULL);
#endif

				DLOGTR1(PRIO_LOW,
				"Inserting into the tree with key %d\n",
				request->dlrq_correlation_id);

				// TODO: Add error handling
				dl_resender_unackd_request(
					handle->dlh_resender, request);
				DLOGTR1(PRIO_NORMAL,
					"Processed request %d\n",
				request->dlrq_correlation_id);
			} else {
				// TODO: proper errro handling is necessary
				DLOGTR0(PRIO_NORMAL, "socket send error\n");
				//singal cond var and break ?
			}
		}
	}
#ifdef _KERNEL
	kproc_exit(0);
#else
	pthread_exit(NULL);
#endif
}

static void *
dl_response_thread(void *vargp)
{

	DLOGTR0(PRIO_LOW, "Response thread started...\n");

	for (;;) {
		dl_poll_reactor_handle_events();
	}
#ifdef _KERNEL
	kproc_exit(0);
#else
	pthread_exit(NULL);
#endif
}

static void
dl_start_response_thread(struct dlog_handle *handle,
    struct dl_client_configuration const *cc, struct dl_transport *transport)
{
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

#ifdef _KERNEL
	kproc_kthread_add(dl_response_thread, NULL, dlog_client_proc, &handle->dlh_reader, 0, 0, NULL);
#else
	pthread_create(&handle->dlh_reader, NULL, dl_response_thread, NULL);
#endif
}

struct dlog_handle *
dlog_client_open(struct sbuf *hostname,
    const int portnumber, struct dl_client_configuration const * const cc)
{
	struct dlog_handle *handle;
	int ret;
	
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");
	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");
	
	handle = (struct dlog_handle *) dlog_alloc(sizeof(struct dlog_handle));
#ifdef _KERNEL
	DL_ASSERT(handle != NULL, ("Failed allocating DLog client handle."));
	{
#else
	if (handle != NULL) {
#endif	
		/* Store the client configuration. */
		handle->dlh_config = cc;

		/* Instatiate the client resender. */
		handle->dlh_resender = dl_resender_new(handle);

		/* Initialise the response queue (on which client requests are
		* enqueued).
		*/
		dl_request_q_new(&handle->dlh_request_q);

		/* Instantiate a correlation id. */
		handle->correlation_id = dl_correlation_id_new();
		DL_ASSERT(handle->correlation_id != NULL,
		"Failed instatiating new correlation_id\n");

		DLOGTR0(PRIO_NORMAL, "Initialising the dlog client...\n");

		/* Start the client threads. */
		dl_resender_start(handle->dlh_resender);
			
		struct dl_transport *transport =
		    (struct dl_transport *) dlog_alloc(sizeof(struct dl_transport));
		dl_transport_connect(transport, sbuf_data(hostname), portnumber);

		handle->dlh_transport = transport;
		handle->dlh_event_handler.dleh_instance = handle;
		handle->dlh_event_handler.dleh_get_handle = dlog_client_get_handle;
		handle->dlh_event_handler.dleh_handle_event = dlog_client_handle_read_event;

#ifdef _KERNEL
		kproc_kthread_add(request_thread, NULL, dlog_client_proc,
		    &handle->dlh_request_tid, 0, 0, NULL);
#else
		pthread_t request_thread;
		if (0 == pthread_create(&request_thread, NULL,
			dl_request_thread, handle)) {

		}
#endif

		// TODO: temp
		struct broker_configuration *bc = (struct broker_configuration *)
		dlog_alloc(sizeof(struct broker_configuration));
		bc->fsync_thread_sleep_length = 10;

		dlog_broker_init("cadets-trace", bc);

		dl_poll_reactor_register(&handle->dlh_event_handler);
		dl_start_response_thread(handle, cc, transport);
	}
	return handle;
}

int
dlog_client_close(struct dlog_handle *handle)
{
	int rc;

	/* Cancel the reader threads */
#ifdef _KERNEL
#else
	rc = pthread_cancel(handle->dlh_reader);
#endif
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error stopping reader %d\n", rc);
	
	/* Cancel the resender */
	rc = dl_resender_stop(handle->dlh_resender);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Failed stopping the resender %d\n", rc);

	/* Free the correlation id. */	
	dl_correlation_id_fini(handle->correlation_id);

	return 0;
}

int
dlog_fetch(struct dlog_handle *handle, struct sbuf *topic_name,
    int32_t min_bytes, int32_t max_wait_time, int64_t fetch_offset,
    int32_t max_bytes)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	int result = 0;

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	message = dl_fetch_request_new(
	    dl_correlation_id_val(handle->correlation_id),
	    handle->dlh_config->dlcc_client_id,
	    topic_name, min_bytes,
	    max_wait_time, fetch_offset, max_bytes);
	
	DLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		// TODO: mesasge xtor
		// dl_fetch_request_delete(message);

		/* Enqueue the request for processing */
		if (dl_request_q_enqueue_new(handle->dlh_request_q, buffer,
		    message->dlrqm_correlation_id,
		    message->dlrqm_api_key) == 0) {
			
			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Error encoding FetchRequest\n");
		result = -1;
	}
	return result;
}

int
dlog_list_offset(struct dlog_handle *handle, struct sbuf *topic_name,
    int64_t time)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	int result = 0;

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Instantiate a new ListOffsetRequest. */
	message = dl_list_offset_request_new(
	    dl_correlation_id_val(handle->correlation_id), 
	    handle->dlh_config->dlcc_client_id,
	    topic_name, time);
	
	DLOGTR0(PRIO_LOW, "Constructed request message\n");

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		// TODO: mesasge xtor
		// dl_list_offset_request_delete(message);

		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		/* Enqueue the request for processing */
		if (dl_request_q_enqueue_new(handle->dlh_request_q, buffer,
		    message->dlrqm_correlation_id,
		    message->dlrqm_api_key) == 0) {
			
			DLOGTR0(PRIO_LOW, "Enqued request\n");

			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		}
	} else {
		DLOGTR0(PRIO_HIGH, "Error encoding ListOffsetRequest\n");
		result = -1;
	}
	return result;
}

int
dlog_produce(struct dlog_handle *handle, struct sbuf *topic_name,
    char *key, int key_len, char *value, int value_len)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	struct dl_message_set *message_set;
	int result = 0;

	/* Instantiate a new MessageSet. */
	message_set = dl_message_set_new(key, key_len, value, value_len);

	/* Instantiate a new ProduceRequest */
	if (dl_produce_request_new(&message,
	    dl_correlation_id_val(handle->correlation_id),
	    handle->dlh_config->dlcc_client_id,
	    topic_name, message_set) != 0)
		return -1;

	DLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);
		
	dlog_broker_handle(message);

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {
		
		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		/* Enqueue the request for processing */
		if (dl_request_q_enqueue_new(handle->dlh_request_q, buffer,
		    message->dlrqm_correlation_id,
		    message->dlrqm_api_key) == 0) {
			
			DLOGTR0(PRIO_LOW, "Enqued request\n");

			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(handle->correlation_id);
		} else {
			DLOGTR0(PRIO_HIGH, "Error enqueing request\n");
		}

		dl_produce_request_delete(message);
		//dl_bbuf_delete(buffer);

		return 0;
	} 

	DLOGTR0(PRIO_HIGH, "Error encoding ProduceRequest\n");
	return -1;
}
