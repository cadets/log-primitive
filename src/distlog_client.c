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
#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/tree.h>
#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdbool.h>
#endif

#include "distlog_client.h"
#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_protocol_parser.h"
#include "dl_protocol_encoder.h"
#include "dl_utils.h"

// TODO: I don't think FreeBSD defines this
// if not should it be 63 or 255?
#define HOST_NAME_MAX 255

struct dl_notifier_argument {
	dl_ack_function dlna_on_ack;
	dl_response_function dlna_on_response;
	struct dl_client_configuration *dlna_config;
	pthread_t *dlna_tid;
	int dlna_index;
};

struct dl_reader_argument {
	struct dl_client_configuration *dlra_config;
	pthread_t *dlra_tid;
	int dlra_index;
	int dlra_portnumber;
	char dlra_hostname[HOST_NAME_MAX];
};

static int const NUM_NOTIFIERS = 5;
static int const NUM_READERS   = 1;
static int const REQUESTS_PER_NOTIFIER = 10;
/* Maximum number of outstanding un-acked messages */
static int const NODE_POOL_SIZE = 128; 

struct notify_queue_element {
	char pbuf[MTU];
	STAILQ_ENTRY(notify_queue_element) entries;
};
STAILQ_HEAD(notify_queue, notify_queue_element);
static struct notify_queue notify_queue;
static pthread_mutex_t notify_queue_mtx;
static pthread_cond_t notify_queue_cond;

// Array containing arguments to the reader threads
static struct dl_reader_argument *ras;
static pthread_t *notifiers;

// Array containing arguments to the notifier threads
static struct dl_notifier_argument *nas;
static pthread_t *readers;

static struct dl_reader_argument resender_arg;
static pthread_t resender;

static int num_readers;

struct dl_request_element {
	struct dl_request dlrq_msg;
	time_t last_sent;
	time_t resend_timeout;
	bool should_resend;
	STAILQ_ENTRY(dl_request_element) entries;
	RB_ENTRY(dl_request_element)linkage;
};
static STAILQ_HEAD(dl_request_pool, dl_request_element) request_pool;
static pthread_mutex_t request_pool_mtx;

STAILQ_HEAD(dl_request_queue, dl_request_element);
static struct dl_request_queue request_queue;
static pthread_mutex_t dl_request_queue_mtx;
static pthread_cond_t dl_request_queue_cond;

STAILQ_HEAD(dl_unackd_request_queue, dl_request_element);
static struct dl_unackd_request_queue unackd_request_queue;
static pthread_mutex_t unackd_request_queue_mtx;
static pthread_cond_t unackd_request_queue_cond;

RB_HEAD(dl_unackd_requests, dl_request_element) unackd_requests;
static pthread_mutex_t unackd_requests_mtx;
static pthread_cond_t unackd_requests_cond;

static int
dl_request_element_cmp(struct dl_request_element *el1,
    struct dl_request_element *el2)
{
	return el2->dlrq_msg.dlrqm_correlation_id -
	    el1->dlrq_msg.dlrqm_correlation_id;
}

RB_PROTOTYPE(dl_unackd_requests, dl_request_element, linkage,
    dl_request_element_cmp);
RB_GENERATE(dl_unackd_requests, dl_request_element, linkage,
    dl_request_element_cmp);

struct dl_response_element {
	struct dl_response rsp_msg;
	LIST_ENTRY(dl_response_element) entries;
};
static LIST_HEAD(response_pool, dl_response_element) response_pool;
static pthread_mutex_t response_pool_mtx;

static int dl_allocate_client_datastructures(struct dl_client_configuration *);
static int dl_free_client_datastructures();
static int dl_connect_to_server(const char *, const int);
static int dl_notify_response(struct notify_queue_element *,
    struct dl_notifier_argument *);
static void dl_process_request(const int, struct dl_request_element *);
static void * dl_reader_thread(void *);
static void * dl_request_notifier_thread(void *);
static void * dl_resender_thread(void *);
static void dl_start_notifiers(struct dl_client_configuration *);
static void dl_start_reader_threads(struct dl_client_configuration *, int,
    char *, int);
static void dl_start_resender(struct dl_client_configuration *);

static dl_correlation_id correlation_id = 0;

static int
dl_connect_to_server(const char *hostname, const int portnumber)
{
	struct sockaddr_in dest;
	int sockfd;

 	// socreate(int dom, struct socket **aso, int	type, int proto,
     	// struct	ucred *cred, struct thread *td);
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;

	// socreate(int dom, struct socket **aso, int	type, int proto,
	// 	 struct	ucred *cred, struct thread *td);
	if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0)
		return -3;

	return sockfd;
}

static void *
dl_resender_thread(void *vargp)
{
	struct dl_reader_argument *ra = (struct dl_reader_argument *) vargp;
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
			if (request->should_resend) {
				now = time(NULL);
				DISTLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
				    "Resend when the difference is %lu. "
				    "Current: %lu\n",
				    request->last_sent, now,
				    request->resend_timeout,
				    request->last_sent);

				if ((now - request->last_sent) >
				    request->resend_timeout) {
					request->last_sent = time(NULL);

					RB_REMOVE(dl_unackd_requests,
					    &unackd_requests, request);

					pthread_mutex_lock(
					    &dl_request_queue_mtx);
					STAILQ_INSERT_TAIL(&request_queue,
					    request, entries);
					pthread_cond_signal(
					    &dl_request_queue_cond);
					pthread_mutex_unlock(
					    &dl_request_queue_mtx);

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

static void *
dl_reader_thread(void *vargp)
{
	struct dl_request_queue local_request_queue;
	struct pollfd ufd;
	struct dl_reader_argument *ra = (struct dl_reader_argument *) vargp;
	struct dl_request_element *request, *request_temp;
	int server_conn = -1, rv, msg_size;
	int old_cancel_state;
	struct timespec ts;
	struct timeval now;

	DL_ASSERT(vargp != NULL, "Reader thread arguments cannot be NULL");

	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {

		if (server_conn < 0) {
			DISTLOGTR2(PRIO_NORMAL, "Connecting to '%s:%d'\n",
			    ra->dlra_hostname, ra->dlra_portnumber);
			server_conn = dl_connect_to_server(ra->dlra_hostname,
				ra->dlra_portnumber);
			if (server_conn < 0) {
				DISTLOGTR0(PRIO_NORMAL,
				    "Error connecting...\n");
				sleep(ra->dlra_config->reconn_timeout);
			}

			continue;
		}
		ufd.fd = server_conn;
		ufd.events = POLLIN;

		//rv = sopoll(struct socket *so, int events, struct ucred
		//*active_cred, structthread *td);
		rv = poll(&ufd, 1, ra->dlra_config->poll_timeout);
		DISTLOGTR1(PRIO_NORMAL, "Reader thread polling ... %d\n", rv);
		if (rv == -1) {
			DISTLOGTR0(PRIO_HIGH, "Poll error...");
			continue;
		}
		if (rv) {
       			struct notify_queue_element *temp_el =
			    (struct notify_queue_element *) distlog_alloc(
				sizeof(struct notify_queue_element));
			msg_size = read_msg(ufd.fd, temp_el->pbuf);
			if (msg_size > 0) {
				DISTLOGTR1(PRIO_LOW, "Reader thread read %d "
				    "bytes\n", msg_size);

				pthread_mutex_lock(&notify_queue_mtx);
				STAILQ_INSERT_TAIL(&notify_queue,
				    temp_el, entries);
				pthread_cond_signal(&notify_queue_cond);
				pthread_mutex_unlock(&notify_queue_mtx);
			} else {
				server_conn = -1;
			}
		}

		pthread_mutex_lock(&dl_request_queue_mtx);		
		while (STAILQ_EMPTY(&request_queue) != 0 ) {
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
			pthread_cond_timedwait(&dl_request_queue_cond,
			    &dl_request_queue_mtx, &ts);
		}

		while (STAILQ_EMPTY(&request_queue) == 0 ) {
			request = STAILQ_FIRST(&request_queue);
			STAILQ_REMOVE_HEAD(&request_queue, entries);

			STAILQ_INSERT_TAIL(&local_request_queue,
				request, entries);
		}
		pthread_mutex_unlock(&dl_request_queue_mtx);

		STAILQ_FOREACH_SAFE(request, &local_request_queue, entries,
		    request_temp) {
			STAILQ_REMOVE_HEAD(&local_request_queue, entries);
			dl_process_request(server_conn, request);
		}
	}
	return NULL;
}

static void
dl_process_request(const int server_conn, struct dl_request_element *request)
{
	char *pbuf, *request_buffer;
	struct dl_request *request_msg = &request->dlrq_msg;
	ssize_t nbytes;

	DL_ASSERT(request != NULL, "Request cannot be NULL");

	pbuf = (char *) distlog_alloc(sizeof(char) * MTU);
	request_buffer = (char *) distlog_alloc(sizeof(char) * MTU);

	DISTLOGTR1(PRIO_LOW, "Dequeued request with address %p\n",
	    request);
	DISTLOGTR1(PRIO_LOW, "Dequeued request with address %p\n",
	    request_msg);
	DISTLOGTR1(PRIO_LOW, "request_msg->CorrelationId %d\n",
	    request_msg->dlrqm_correlation_id);

	int fi = dl_encode_request(request_msg, pbuf);
	
	DISTLOGTR1(PRIO_NORMAL, "Sending: '%s'\n", pbuf);
	DISTLOGTR1(PRIO_NORMAL, "Sending: '%d bytes'\n", fi);
	DISTLOGTR1(PRIO_NORMAL, "Sending: '%s'\n", request_buffer);
	// sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	// 	 struct	mbuf *top, struct mbuf *control, int flags,
	// 	 	 struct	thread *td);
	//nbytes = send(server_conn, request_buffer, fi, 0);
	nbytes = send(server_conn, pbuf, fi, 0);
	if (nbytes != -1) {
		DISTLOGTR1(PRIO_LOW, "Request last_sent = %d\n",
			request->should_resend);

		if (request_msg->dlrqm_api_key == DL_PRODUCE_REQUEST&&
			!request_msg->dlrqm_message.dlrqmt_produce_request.dlpr_required_acks) {
			/* The request does not require an acknowledgment;
			 * as we have finished processing the request return it
			 * to the request pool.
			 */
			pthread_mutex_lock(&request_pool_mtx);
			STAILQ_INSERT_TAIL(&request_pool, request, entries);
			pthread_mutex_unlock(&request_pool_mtx);
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

			pthread_mutex_lock(&unackd_requests_mtx);
			RB_INSERT(dl_unackd_requests, &unackd_requests,
			    request);
			pthread_mutex_unlock(&unackd_requests_mtx);
			
			DISTLOGTR1(PRIO_NORMAL, "Processed request %d\n",
			    request_msg->dlrqm_correlation_id);
		}
	} else {
		// TODO: proper errro handling is necessary
		DISTLOGTR0(PRIO_NORMAL, "socket send error\n");
	}

	distlog_free(pbuf);
	distlog_free(request_buffer);
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

	DISTLOGTR1(PRIO_LOW, "Request notifier thread %d started...\n",
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
		pthread_mutex_lock(&notify_queue_mtx);		
		while (STAILQ_EMPTY(&notify_queue) != 0 ) {
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
			pthread_cond_timedwait(&notify_queue_cond,
			    &notify_queue_mtx, &ts);
		}

		while ((notify = STAILQ_FIRST(&notify_queue))) {
			STAILQ_REMOVE_HEAD(&notify_queue, entries);
			STAILQ_INSERT_TAIL(&local_notify_queue, notify,
			    entries);
		}
		pthread_mutex_unlock(&notify_queue_mtx);		

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
	struct dl_request_element find, *request;	
	struct dl_response_element *response;
	struct dl_request *req_m;
	struct dl_response *res_m;
	char *pbuf = notify->pbuf;

	DL_ASSERT(notify != NULL, "Notifier element cannot be NULL");
	DL_ASSERT(na != NULL, "Notifier thread argument cannot be NULL");

	pthread_mutex_lock(&response_pool_mtx);
	response = LIST_FIRST(&response_pool);
	LIST_REMOVE(response, entries);
	pthread_mutex_unlock(&response_pool_mtx);
	if (response) {
		/* Deserialise the response message. */
		res_m = &response->rsp_msg;
		if (dl_decode_response(res_m, pbuf) == 0) {
				
			DISTLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_size);
			DISTLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->dlrs_correlation_id);

			//DISTLOGTR2(PRIO_NORMAL,
			//    "Requester[%d] got the following message '%s'\n",
			//    na->dlna_index, pbuf);

			/* Lookup the unacknowledged Request message based
			 * on the CorrelationId returned in the response.
			 */
			find.dlrq_msg.dlrqm_correlation_id =
			    res_m->dlrs_correlation_id;

			printf("here\n");
			pthread_mutex_lock(&unackd_requests_mtx);
			request = RB_FIND(dl_unackd_requests,
			    &unackd_requests, &find);
			printf("here2 %p\n", request);
			if (request != NULL) {
				DISTLOGTR1(PRIO_NORMAL,
				    "Found unacknowledged request id: %d\n",
				    request->dlrq_msg.dlrqm_correlation_id);

				/* Remove the unacknowledged request
				 * and process the Response.
				 */
				request = RB_REMOVE(dl_unackd_requests,
				    &unackd_requests, request);
			}
			pthread_mutex_unlock(&unackd_requests_mtx);
			if (request != NULL) {
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
				
				pthread_mutex_lock(&response_pool_mtx);
				LIST_INSERT_HEAD(&response_pool,
					response, entries);
				pthread_mutex_unlock(&response_pool_mtx);
			} else {
			printf("here5\n");
				DISTLOGTR1(PRIO_HIGH,
				    "Couldn't find the unacknowledge request "
				    "id: %d\n", res_m->dlrs_correlation_id);
				pthread_mutex_lock(&response_pool_mtx);
				LIST_INSERT_HEAD(&response_pool, response, entries);
				pthread_mutex_unlock(&response_pool_mtx);
			}
		}
	} else {
		DISTLOGTR0(PRIO_HIGH, "Cant borrow a response element\n");
	}

	return 0;
}

static void
dl_start_notifiers(struct dl_client_configuration *cc)
{
	int notifier;

	for (notifier = 0; notifier < NUM_NOTIFIERS; notifier++) {
		nas[notifier].dlna_index = notifier;
		nas[notifier].dlna_tid = NULL;
		nas[notifier].dlna_config = cc;
		nas[notifier].dlna_on_ack = cc->dlcc_on_ack;
		nas[notifier].dlna_on_response = cc->dlcc_on_response;

		if (pthread_create(&notifiers[notifier], NULL,
		    dl_request_notifier_thread, &nas[notifier]) == 0){
			nas[notifier].dlna_tid = &notifiers[notifier];
		}
	}
}

static void
dl_start_resender(struct dl_client_configuration *cc)
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

static int
dl_allocate_client_datastructures(struct dl_client_configuration *cc)
{
	int processor;

	/* Allocate memory for the notifier threads. These threads
	 * asynchronously report ack's requests back to the client.
	 */
	nas = (struct dl_notifier_argument *) distlog_alloc(
		sizeof(struct dl_notifier_argument) * NUM_NOTIFIERS);

	notifiers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_NOTIFIERS);

	/* Allocate memory for the reader threads. These threads read response
	 * from the distributed log broker. 
	 */
	readers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_READERS);

	ras = (struct dl_reader_argument *) distlog_alloc(
		sizeof(struct dl_reader_argument) * NUM_READERS);

	/* Initialise the response queue (on which client requests are
	 * enqueued).
	 */
	STAILQ_INIT(&request_queue);
	pthread_mutex_init(&dl_request_queue_mtx, NULL);
	pthread_cond_init(&dl_request_queue_cond, NULL);

	/* Initialise (preallocate) a pool of requests.
	 * TODO: Change this to work like the kaudit_queue.
	 */
	STAILQ_INIT(&request_pool);

	for (processor = 0; processor < MAX_NUM_REQUESTS_PER_PROCESSOR;
	    processor++) {
		struct dl_request_element * list_entry =
		    distlog_alloc(sizeof(struct dl_request_element));
		STAILQ_INSERT_HEAD(&request_pool, list_entry, entries);
	}

	pthread_mutex_init(&request_pool_mtx, NULL);

	/* Initialise the notify queue. Responses to be notified back to
	 * the client are enqueued onto this queue.
	 * */
	STAILQ_INIT(&notify_queue);
	pthread_mutex_init(&notify_queue_mtx, NULL);
	pthread_cond_init(&notify_queue_cond, NULL);

	/* Initialise (preallocate) a pool of responses.
	 * TODO: Change this to work like the kaudit_queue.
	 */
	LIST_INIT(&response_pool);

	for (processor = 0; processor < MAX_NUM_RESPONSES_PER_PROCESSOR;
	    processor++) {
		struct dl_response_element * list_entry =
		    distlog_alloc(sizeof(struct dl_response_element));
		LIST_INSERT_HEAD(&response_pool, list_entry, entries);
	}

	pthread_mutex_init(&response_pool_mtx, NULL);

	/* Initialise a red/black tree used to index the unacknowledge
	 * responses.
	 */
	RB_INIT(&unackd_requests);
	pthread_mutex_init(&unackd_requests_mtx, NULL);
	
	STAILQ_INIT(&unackd_request_queue);
	pthread_mutex_init(&unackd_request_queue_mtx, NULL);
	pthread_cond_init(&unackd_request_queue_cond, NULL);

	return 1;
}

static int
dl_free_client_datastructures()
{
	/* Free the memory associated with the reader threads */
	distlog_free(readers);
	distlog_free(ras);

	/* Free the memory associated with the notifier threads */
	distlog_free(notifiers);
	distlog_free(nas);
}

static void
dl_start_reader_threads(struct dl_client_configuration *cc, int num,
    char * hostname, int port)
{
	int reader;

	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");
	DL_ASSERT(hostname != NULL, "Hostname cannot be NULL");

	num_readers = MIN(NUM_READERS, num);

	for (reader = 0; reader < num_readers; reader++) {
		if (0 == pthread_create(&readers[reader], NULL,
		    dl_reader_thread, &ras[reader])) {

			ras[reader].dlra_tid = &readers[reader];
			ras[reader].dlra_index = reader;
			ras[reader].dlra_config = cc;
			strlcpy(ras[reader].dlra_hostname, hostname,
			    HOST_NAME_MAX);
			ras[reader].dlra_portnumber = port;
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
		rc = pthread_cancel(readers[reader]);
		if (rc != ESRCH)
			cancelled_threads++;
	}

	DISTLOGTR2(PRIO_HIGH, "Cancelled %d/%d reader threads\n",
	    cancelled_threads, num_readers);

	/* Cancel the notifier threads */
	cancelled_threads = 0;
	for (notifier = 0; notifier < NUM_NOTIFIERS; notifier++) {
		rc = pthread_cancel(notifiers[notifier]);
		if (rc != ESRCH)
			cancelled_threads++;
	}

	DISTLOGTR2(PRIO_NORMAL, "Cancelled %d/%d notifier threads\n",
	    cancelled_threads, NUM_NOTIFIERS);

	/* Cancel the resender thread */
	rc = pthread_cancel(resender);
	if (rc != ESRCH)
		DISTLOGTR0(PRIO_NORMAL, "Cancelled resender thread\n");
	else
		DISTLOGTR0(PRIO_HIGH, "Failed cancelling resender thread\n");

	/* Free all memory allocated by the client */
	dl_free_client_datastructures();

	return 0;
}

// Need to split imto init and open
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

		dl_start_notifiers(cc);
		dl_start_reader_threads(cc, 1, hostname, portnumber);
		dl_start_resender(cc);
		return 0;
	}
	return 1;
}

int
distlog_send(int server_id, char *client_id, bool should_resend,
    int resend_timeout, ...)
{
	int result = 0;
	struct dl_request_element * request;
	va_list ap;

	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	va_start(ap, resend_timeout);

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    correlation_id);

	// TODO replace this with an allocated value

	/* Take a new request from the pool */
	pthread_mutex_lock(&request_pool_mtx);
	request = STAILQ_FIRST(&request_pool);
	STAILQ_REMOVE_HEAD(&request_pool, entries);
	pthread_mutex_unlock(&request_pool_mtx);
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
		    "(correlation_id = %d)\n", correlation_id);

		// TODO: replace this
		dl_build_produce_request(&request->dlrq_msg,
			correlation_id, client_id, ap);
		
		DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

		/* Enque the request for processing */
		pthread_mutex_lock(&dl_request_queue_mtx);
		STAILQ_INSERT_TAIL(&request_queue, request, entries);
		pthread_cond_signal(&dl_request_queue_cond);
		pthread_mutex_unlock(&dl_request_queue_mtx);
	
		DISTLOGTR0(PRIO_LOW, "User request finished\n");

	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
		
	/* Increment the monotonically increasing correlation id. */
	// TODO: this action isn't atomic
	correlation_id++;

	va_end(ap);

	return result;
}

int
distlog_recv(int server_id, char *client_id, bool should_resend,
    int resend_timeout, ...)
{
	int result = 0;
	struct dl_request_element * request;
	va_list ap;

	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	va_start(ap, resend_timeout);

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    correlation_id);

	// TODO replace this with an allocated value

	/* Take a new request from the pool */
	pthread_mutex_lock(&request_pool_mtx);
	request = STAILQ_FIRST(&request_pool);
	STAILQ_REMOVE_HEAD(&request_pool, entries);
	pthread_mutex_unlock(&request_pool_mtx);
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
		    "(correlation_id = %d)\n", correlation_id);

		dl_build_fetch_request(&request->dlrq_msg,
			correlation_id, client_id, ap);

		DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

		/* Enque the request for processing */
		pthread_mutex_lock(&dl_request_queue_mtx);
		STAILQ_INSERT_TAIL(&request_queue, request, entries);
		pthread_cond_signal(&dl_request_queue_cond);
		pthread_mutex_unlock(&dl_request_queue_mtx);
	
		DISTLOGTR0(PRIO_LOW, "User request finished\n");

	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
		
	/* Increment the monotonically increasing correlation id. */
	correlation_id++;

	va_end(ap);

	return result;
}

int
distlog_offset(int server_id, char *client_id, bool should_resend,
    int resend_timeout, ...)
{
	int result = 0;
	struct dl_request_element * request;
	va_list ap;

	// TODO: If fact I think that the protocol allows this!
	DL_ASSERT(client_id != NULL, "Client ID cannot be NULL");

	va_start(ap, resend_timeout);

	DISTLOGTR1(PRIO_LOW,
	    "User requested to send a message with correlation id = %d\n",
	    correlation_id);

	// TODO replace this with an allocated value

	/* Take a new request from the pool */
	pthread_mutex_lock(&request_pool_mtx);
	request = STAILQ_FIRST(&request_pool);
	STAILQ_REMOVE_HEAD(&request_pool, entries);
	pthread_mutex_unlock(&request_pool_mtx);
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
		    "(correlation_id = %d)\n", correlation_id);

		// TODO: Temporarily send an OffsetRequest
		// need a constructor for this
		request->dlrq_msg.dlrqm_api_key = DL_OFFSET_REQUEST;
		request->dlrq_msg.dlrqm_api_version = 1;
		request->dlrq_msg.dlrqm_correlation_id = correlation_id;
		strcpy(&request->dlrq_msg.dlrqm_client_id, "consumer");
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_replica_id = -1;
		strcpy(&request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_topic_name,
		    "cadets-trace");
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_partition = 0;
		request->dlrq_msg.dlrqm_message.dlrqmt_offset_request.dlor_time = -2;

		DISTLOGTR0(PRIO_LOW, "Constructed request message\n");

		/* Enque the request for processing */
		pthread_mutex_lock(&dl_request_queue_mtx);
		STAILQ_INSERT_TAIL(&request_queue, request, entries);
		pthread_cond_signal(&dl_request_queue_cond);
		pthread_mutex_unlock(&dl_request_queue_mtx);
	
		DISTLOGTR0(PRIO_LOW, "User request finished\n");

	} else {
        	DISTLOGTR0(PRIO_HIGH,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}
		
	/* Increment the monotonically increasing correlation id. */
	correlation_id++;

	va_end(ap);

	return result;
}
