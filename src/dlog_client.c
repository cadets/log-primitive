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
#include <sys/nv.h>

#ifdef _KERNEL
#include <sys/kthread.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/socketvar.h>
#include <sys/poll.h>
#include <sys/proc.h>
#else
#include <sys/sbuf.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#endif

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

#ifdef _KERNEL
static void dl_request_thread(void *);
static void dl_response_thread(void *);
#else
static void * dl_request_thread(void *);
static void * dl_response_thread(void *);
#endif
static int dl_start_response_thread(struct dlog_handle *);
static int dl_stop_response_thread(struct dlog_handle *);
static int dl_start_request_thread(struct dlog_handle *);
static int dl_stop_request_thread(struct dlog_handle *);

#ifdef _KERNEL
extern struct proc *dlog_client_proc;
#endif

/*
static dl_event_handler_handle
dlog_client_get_handle(void *instance)
{
	const struct dlog_handle *handle = instance;
	return handle->dlh_transport->dlt_sock;
}
*/

static void
dlog_client_handle_read_event(void *instance)
{
	const struct dlog_handle *handle = instance;
	struct dl_request_element *request;	
	struct dl_response *response = NULL;
	struct dl_response_header *header;
	struct dl_bbuf *buffer;

	DLOGTR0(PRIO_LOW, "dlog_client_handle_read_event\n");

	if (dl_transport_read_msg(handle->dlh_transport, &buffer) == 0) {

		unsigned char *bufval = dl_bbuf_data(buffer);
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
					dl_fetch_response_decode(&response,
					    buffer);
					break;
				case DL_OFFSET_API_KEY:
					dl_list_offset_response_decode(
					    &response, buffer);
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
					handle->dlh_config->dlcc_on_response(
					    response);
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
		//dl_poll_reactor_unregister(&handle->dlh_event_handler);

		/* Reconnect and register */
		// TODO: What about the request?
	}
}

#ifdef _KERNEL
static void
#else
static void *
#endif
dl_request_thread(void *vargp)
{
	struct dlog_handle *handle = (struct dlog_handle *) vargp;
	struct dl_request_queue local_request_queue;
	struct dl_request_element *request, *request_temp;
	struct dl_transport *transport;
#ifndef _KERNEL
	struct timespec ts;
	struct timeval now;
	int rv, msg_size, old_cancel_state, port;
#endif
	ssize_t nbytes;
#ifdef __APPLE__
	int32_t secs, msecs;
#else
	struct timeval tv;
#endif

	DL_ASSERT(vargp != NULL, "Request thread arguments cannot be NULL");
	
	DLOGTR0(PRIO_LOW, "Request thread started...\n");

	/* Copy the thread arguments and free the memory. */
	transport = handle->dlh_transport;

	/* Defer cancellation of the thread until the cancellation point 
	 * This ensures that thread isn't cancelled until outstanding requests
	 * have been processed.
	 */	
#ifndef _KERNEL
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);
#endif

	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	for (;;) {
		DLOGTR0(PRIO_LOW, "Dequeuing requests...\n");
/*
#ifdef _KERNEL
		mtx_assert(&handle->dl_request_mtx, MA_UNOWNED);
		mtx_lock(&handle->dl_request_mtx);
		if (handle->dl_client_exit) { // && dl_request_q_is_empty();
			mtx_unlock(&handle->dl_request_mtx);
			break;
		}
		mtx_unlock(&handle->dl_request_mtx);
#else
		pthread_testcancel();
#endif
*/
		if (dl_request_q_dequeue(handle->dlh_request_q,
			&local_request_queue) == 0) {
			STAILQ_FOREACH_SAFE(request, &local_request_queue,
			    dlrq_entries, request_temp) {
				STAILQ_REMOVE_HEAD(&local_request_queue,
				    dlrq_entries);

				DLOGTR1(PRIO_LOW,
				    "Dequeued request (id = %d)\n",
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
					getmicrotime(&tv);
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
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Checking request thread supsend...");
#ifdef _KERNEL
			mtx_lock(&handle->dl_client_exit_mtx);
			if (handle->dl_client_exit) {
				mtx_unlock(&handle->dl_client_exit_mtx);
				break;
			}
			mtx_unlock(&handle->dl_client_exit_mtx);
#else
			// TODO
#endif
		}
}

	DLOGTR0(PRIO_LOW, "Request thread stopped.\n");
#ifdef _KERNEL
	kproc_exit(0);
#else
	pthread_exit(NULL);
#endif
}

#ifdef _KERNEL
static void
#else
static void *
#endif
dl_response_thread(void *vargp)
{
	struct dlog_handle *handle = (struct dlog_handle *) vargp;
	struct timeval tv;

	DL_ASSERT(vargp != NULL, "Request thread arguments cannot be NULL");

	DLOGTR0(PRIO_LOW, "Response thread started...\n");
	
	/* Configure the response thread polling interval. */	
/*	
	if (!nvlist_exists_string(props, DL_CONF_RESPONSE_POLL)) {
		portnumber = DL_DEFAULT_RESPONSE_POLL
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}
*/
	tv.tv_sec = 1;

	for (;;) {
#ifdef _KERNEL
		if (selsocket(handle->dlh_transport->dlt_sock, POLLIN, &tv,
		    curthread) == 0) {

			dlog_client_handle_read_event(handle);
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Checking response thread supsend...");
			mtx_lock(&handle->dl_client_exit_mtx);
			if (handle->dl_client_exit) {
				mtx_unlock(&handle->dl_client_exit_mtx);
				break;
			}
			mtx_unlock(&handle->dl_client_exit_mtx);
		}
#endif
		//dl_poll_reactor_handle_events();
		//dlog_client_handle_read_event(handle);
	}

	DLOGTR0(PRIO_LOW, "Response thread stopped.\n");
#ifdef _KERNEL
	kproc_exit(0);
#else
	pthread_exit(NULL);
#endif
}

static int 
dl_start_response_thread(struct dlog_handle *handle)
{

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

#ifdef _KERNEL
	return kproc_kthread_add(dl_response_thread, handle, &dlog_client_proc,
	    &handle->dlh_response_tid, 0, 0, NULL, NULL);
#else
	return pthread_create(&handle->dlh_response_tid, NULL,
	    dl_response_thread, handle);
#endif
}

static int 
dl_stop_response_thread(struct dlog_handle *handle)
{

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	/* Wait for the twice the response thread polling interval. */	
/*	
	if (!nvlist_exists_string(props, DL_CONF_RESPONSE_POLL)) {
		portnumber = DL_DEFAULT_RESPONSE_POLL
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}
	*/
	
#ifdef _KERNEL
	int timeo =  2 * (10 * hz / 9);

	mtx_lock(&handle->dl_client_exit_mtx);
	handle->dl_client_exit = 1;
	mtx_unlock(&handle->dl_client_exit_mtx);
	tsleep(handle->dlh_response_tid, 0, "waiting for response thread",
	    timeo);
	return 0;
#else
	return pthread_cancel(handle->dlh_response_tid);
#endif
}

static int 
dl_start_request_thread(struct dlog_handle *handle)
{

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

#ifdef _KERNEL
	return kproc_kthread_add(dl_request_thread, handle, &dlog_client_proc,
	    &handle->dlh_request_tid, 0, 0, NULL, NULL);
#else
	return pthread_create(&handle->dlh_request_tid, NULL,
	    dl_request_thread, handle);
#endif
}

static int 
dl_stop_request_thread(struct dlog_handle *handle)
{

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	/* Wait for the twice the response thread polling interval. */	
/*	
	if (!nvlist_exists_string(props, DL_CONF_RESPONSE_POLL)) {
		portnumber = DL_DEFAULT_RESPONSE_POLL
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}
	*/
#ifdef _KERNEL
	int timeo =  2 * (10 * hz / 9);

	mtx_lock(&handle->dl_client_exit_mtx);
	handle->dl_client_exit = 1;
	mtx_unlock(&handle->dl_client_exit_mtx);
	tsleep(handle->dlh_response_tid, 0, "waiting for response thread",
	    timeo);
	DLOGTR0(PRIO_LOW, "Response thread stopped.\n");
	return 0;
#else
	return pthread_cancel(handle->dlh_request_tid);
#endif
}

struct dlog_handle *
dlog_client_open(struct dl_client_config const * const config)
{
	struct dlog_handle *handle;
	nvlist_t *props = config->dlcc_props;
	char *hostname;
	int rc;
	unsigned short portnumber;

	DL_ASSERT(config != NULL, "Client configuration cannot be NULL");
	
	DLOGTR0(PRIO_NORMAL, "Opening the Dlog client...\n");

	if (!nvlist_exists_string(props, DL_CONF_BROKER)) {
		hostname = DL_DEFAULT_BROKER;
	} else {
		hostname = nvlist_get_string(props, DL_CONF_BROKER);
	}

	if (!nvlist_exists_string(props, DL_CONF_BROKER_PORT)) {
		portnumber = DL_DEFAULT_BROKER_PORT;
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}

	handle = (struct dlog_handle *) dlog_alloc(sizeof(struct dlog_handle));
#ifdef _KERNEL
	DL_ASSERT(handle != NULL, ("Failed allocating DLog client handle."));
#else
	if (handle == NULL) {
		// TODO
	}
#endif	
	bzero(handle, sizeof(struct dlog_handle));

	/* Store the client configuration. */
	handle->dlh_config = config;

	/* Instatiate the client resender. */
	handle->dlh_resender = dl_resender_new(handle);
	//dl_resender_start(handle->dlh_resender);

	/* Initialise the response queue (on which client requests are
	 * enqueued).
	 */
	dl_request_q_new(&handle->dlh_request_q);

	/* Instantiate a correlation id. */
	dl_correlation_id_new(&handle->correlation_id);
	DL_ASSERT(handle->correlation_id != NULL,
	"Failed instatiating new correlation_id\n");

	struct dl_transport *transport =
	    (struct dl_transport *) dlog_alloc(
	    sizeof(struct dl_transport));
	dl_transport_connect(transport, hostname, portnumber);

	handle->dlh_transport = transport;

	// TODO: this looks like it can be removed
	//handle->dlh_event_handler.dleh_instance = handle;
	//handle->dlh_event_handler.dleh_get_handle = dlog_client_get_handle;
	//handle->dlh_event_handler.dleh_handle_event = dlog_client_handle_read_event;

	rc = dl_start_response_thread(handle);
#ifdef _KERNEL
	mtx_init(&handle->dl_client_exit_mtx, "response", "dlog client", MTX_DEF);
#else
#endif
	// TODO error handling

	rc = dl_start_request_thread(handle);
	// TODO error handling

	// TODO: temp
	//struct broker_configuration *bc = (struct broker_configuration *)
	//dlog_alloc(sizeof(struct broker_configuration));
	// bc->fsync_thread_sleep_length = 10;

	//dlog_broker_init("cadets-trace", bc);

	//dl_poll_reactor_register(&handle->dlh_event_handler);
	return handle;
}

int
dlog_client_close(struct dlog_handle *handle)
{
	int rc;

	DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	/* Cancel the request thread. */
	DLOGTR0(PRIO_LOW, "Cancelling request thread\n");
	rc = dl_stop_request_thread(handle);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error stopping request thread %d\n", rc);

	/* Cancel the response thread. */
	DLOGTR0(PRIO_LOW, "Cancelling response thread\n");
	rc = dl_stop_response_thread(handle);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error stopping response thread %d\n", rc);
		
	/* Delete the request_q. */
	DLOGTR0(PRIO_LOW, "Deleting request q\n");
	dl_request_q_delete(handle->dlh_request_q);
	
	/* Cancel the resender */
	DLOGTR0(PRIO_LOW, "TODO\n");
	rc = dl_resender_stop(handle->dlh_resender);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Failed stopping the resender %d\n", rc);

	dl_resender_delete(handle->dlh_resender);

	/* Free the correlation id. */	
	dl_correlation_id_delete(handle->correlation_id);
	
	/* Free all the memory associated with the transport - TODO fix. */
	// TODO  Needs to be closed 
	dlog_free(handle->dlh_transport);

	/* Free all the memory associated with the client handle. */
	dlog_free(handle);	

	// TODO: what about the client configuration

	DLOGTR0(PRIO_LOW, "DLog client finished\n");

	return 0;
}

int
dlog_fetch(struct dlog_handle *handle, struct sbuf *topic_name,
    int32_t min_bytes, int32_t max_wait_time, int64_t fetch_offset,
    int32_t max_bytes)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	nvlist_t *props = handle->dlh_config->dlcc_props;
	struct sbuf *client_id;
	int result = 0;

	client_id = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		sbuf_cpy(client_id, DL_DEFAULT_CLIENTID);
	} else {
		sbuf_cpy(client_id, nvlist_get_string(props, DL_CONF_CLIENTID));
	}
	sbuf_finish(client_id);

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Instantiate a new FetchRequest */
	if (dl_fetch_request_new(&message,
	    dl_correlation_id_val(handle->correlation_id),
	    client_id, topic_name, min_bytes,
	    max_wait_time, fetch_offset, max_bytes) != 0)
		return -1;
	
	DLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		unsigned char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

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

	// TODO: mesasge xtor
	// dl_request_delete(message);

	return result;
}

int
dlog_list_offset(struct dlog_handle *handle, struct sbuf *topic_name,
    int64_t time)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	nvlist_t *props = handle->dlh_config->dlcc_props;
	struct sbuf *client_id;
	int result = 0;

	client_id = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		sbuf_cpy(client_id, DL_DEFAULT_CLIENTID);
	} else {
		sbuf_cpy(client_id, nvlist_get_string(props, DL_CONF_CLIENTID));
	}
	sbuf_finish(client_id);

	DLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    dl_correlation_id_val(handle->correlation_id));

	/* Instantiate a new ListOffsetRequest. */
	if (dl_list_offset_request_new(&message,
	    dl_correlation_id_val(handle->correlation_id), 
	    client_id, topic_name, time) != 0)
		return -1;
	
	DLOGTR0(PRIO_LOW, "Constructed request message\n");

	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {

		unsigned char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

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

	// TODO: mesasge xtor
	// dl_request_delete(message);

	return result;
}

int
dlog_produce(struct dlog_handle *handle, unsigned char *key, int key_len,
    unsigned char *value, int value_len)
{
	struct dl_bbuf *buffer;
	struct dl_request *message;
	struct dl_message_set *message_set;
	nvlist_t *props = handle->dlh_config->dlcc_props;
	struct sbuf *client_id, *topic_name;

	topic_name = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_TOPIC)) {
		sbuf_cpy(topic_name, DL_DEFAULT_TOPIC);
	} else {
		sbuf_cpy(topic_name, nvlist_get_string(props, DL_CONF_TOPIC));
	}
	sbuf_finish(topic_name);

	client_id = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		sbuf_cpy(client_id, DL_DEFAULT_CLIENTID);
	} else {
		sbuf_cpy(client_id, nvlist_get_string(props, DL_CONF_CLIENTID));
	}
	sbuf_finish(client_id);

	/* Instantiate a new MessageSet. */
	if (dl_message_set_new(&message_set, key, key_len, value, value_len
	    != 0))
		return -1;

	/* Instantiate a new ProduceRequest */
	if (dl_produce_request_new(&message,
	    dl_correlation_id_val(handle->correlation_id),
	    client_id, 2000, 1, topic_name, message_set) != 0)
		return -1;

	DLOGTR1(PRIO_LOW, "Constructed request (id = %d)\n",
	    message->dlrqm_correlation_id);
		
	/* Encode the request. */	
	if (dl_request_encode(message, &buffer) == 0) {
		
		DLOGTR0(PRIO_LOW, "Encoded request message\n");

		unsigned char *bufval = dl_bbuf_data(buffer);
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

		dl_request_delete(message);

		return 0;
	} else {
		DLOGTR0(PRIO_HIGH, "Error encoding ProduceRequest\n");
	}	

	dl_request_delete(message);

	return -1;
}
