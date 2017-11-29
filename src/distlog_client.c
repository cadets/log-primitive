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
#define MAX_SIZE_HOSTNAME 255

struct dl_notifier_argument {
	ack_function on_ack;
	struct client_configuration *config;
	pthread_t * tid;
	response_function on_response;
	int index;
};

struct dl_reader_argument {
	struct client_configuration *config;
	pthread_t *tid;
	int index;
	int portnumber;
	char hostname[MAX_SIZE_HOSTNAME];
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
	struct request_message req_msg;
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
	return el2->req_msg.correlation_id - el1->req_msg.correlation_id;
}

RB_PROTOTYPE(dl_unackd_requests, dl_request_element, linkage,
    dl_request_element_cmp);
RB_GENERATE(dl_unackd_requests, dl_request_element, linkage,
    dl_request_element_cmp);

struct dl_response_element {
	struct response_message rsp_msg;
	LIST_ENTRY(dl_response_element) entries;
};
static LIST_HEAD(response_pool, dl_response_element) response_pool;
static pthread_mutex_t response_pool_mtx;

static int dl_allocate_client_datastructures(struct client_configuration *);
static int dl_connect_to_server(const char *, const int);
static void dl_parse_response(struct request_message *,
    struct response_message *, char *);
static void dl_notify_response(struct notify_queue_element *,
    struct dl_notifier_argument *);
static void dl_process_request(const int, struct dl_request_element *);
static void * dl_reader_thread(void *);
static void * dl_request_notifier_thread(void *);
static void * dl_resender_thread(void *);
static void dl_start_notifiers(struct client_configuration *);
static void dl_start_reader_threads(struct client_configuration *, int, ...);
static void dl_start_resender(struct client_configuration *);

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

	DL_ASSERT(vargp != NULL, "Resender thread arguments cannot be NULL");

	DISTLOGTR0(PRIO_LOW, "Resender thread started\n");

	for (;;) {
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

		DISTLOGTR1(PRIO_NORMAL,
		    "Resender thread is going to sleep for %d seconds\n",
		    ra->config->resender_thread_sleep_length);
		sleep(ra->config->resender_thread_sleep_length);
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

	DL_ASSERT(vargp != NULL, "Reader thread arguments cannot be NULL");

	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	for (;;) {
		if (server_conn < 0) {
			DISTLOGTR2(PRIO_NORMAL, "No connection to server. "
			    "Attempting to connect to '%s:%d'\n",
			    ra->hostname, ra->portnumber);
			server_conn = dl_connect_to_server(ra->hostname,
				ra->portnumber);
			if (server_conn < 0) {
				DISTLOGTR0(PRIO_NORMAL, "Error connecting...\n");
			}

			sleep(ra->config->reconn_timeout);
			continue;
		}
		ufd.fd = server_conn;
		ufd.events = POLLIN;

		//rv = sopoll(struct socket *so, int events, struct ucred
		//*active_cred, structthread *td);
		rv = poll(&ufd, 1, ra->config->poll_timeout);
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
			pthread_cond_wait(&dl_request_queue_cond,
			    &dl_request_queue_mtx);
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
	struct request_message *request_msg = &request->req_msg;
	ssize_t nbytes;

	DL_ASSERT(request != NULL, "Request cannot be NULL");

	pbuf = (char *) distlog_alloc(sizeof(char) * MTU);
	request_buffer = (char *) distlog_alloc(sizeof(char) * MTU);

	DISTLOGTR1(PRIO_LOW, "Dequeued request with address %p\n",
	    request_msg);
	DISTLOGTR1(PRIO_LOW, "request_msg->CorrelationId %d\n",
	    request_msg->correlation_id);

	int req_size = dl_encode_requestmessage(request_msg, &pbuf);
	// TODO: what is this doing here
	// remove sprintf for running in kernel
	// I think it just prepends the size
	int fi = sprintf(request_buffer, "%.*d%s", OVERALL_MSG_FIELD_SIZE,
		req_size+OVERALL_MSG_FIELD_SIZE, pbuf);

	DISTLOGTR1(PRIO_NORMAL, "Sending: '%s'\n", pbuf);
	DISTLOGTR1(PRIO_NORMAL, "Sending: '%s'\n", request_buffer);
	// sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	// 	 struct	mbuf *top, struct mbuf *control, int flags,
	// 	 	 struct	thread *td);
	nbytes = send(server_conn, request_buffer, fi, 0);
	if (nbytes != -1) {
		DISTLOGTR1(PRIO_LOW, "Request last_sent = %d\n",
			request->should_resend);

		if ((request_msg->api_key == REQUEST_FETCH ||
			request_msg->api_key == REQUEST_PRODUCE) &&
			request_msg->rm.produce_request.required_acks) {
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
			    request_msg->correlation_id);

			pthread_mutex_lock(&unackd_requests_mtx);
			RB_INSERT(dl_unackd_requests, &unackd_requests,
			    request);
			pthread_mutex_unlock(&unackd_requests_mtx);
			
			DISTLOGTR1(PRIO_NORMAL, "Processed request %d\n",
			    request_msg->correlation_id);
		} else {
			/* The request does not require an acknowledgment;
			 * as we have finished processing the request return it
			 * to the request pool.
			 */
			pthread_mutex_lock(&request_pool_mtx);
			STAILQ_INSERT_TAIL(&request_pool, request, entries);
			pthread_mutex_unlock(&request_pool_mtx);
		}
	} else {
		// TODO: proper errro handling is necessary
		DISTLOGTR0(PRIO_NORMAL, "socket send error\n");
	}

	distlog_free(pbuf);
	distlog_free(request_buffer);
}

static void
dl_parse_response(struct request_message *req_m,
	struct response_message *res_m, char *pbuf)
{

	clear_responsemessage(res_m, req_m->api_key);
	dl_parse_responsemessage(res_m, pbuf,
	    match_requesttype(req_m->api_key));
}

static void *
dl_request_notifier_thread(void *vargp)
{
	struct dl_notifier_argument *na =
	    (struct dl_notifier_argument *) vargp;
	struct notify_queue local_notify_queue;
	struct notify_queue_element *notify, *notify_temp;

	DL_ASSERT(vargp != NULL,
	    "Request notifier thread argument cannot be NULL");	

	DISTLOGTR1(PRIO_LOW, "Request notifier thread %d started...\n",
	    na->index);
	
	/* Initialize a local queue, used to enqueue requests from the
	 * notify queue prior to processing.
	 */
	STAILQ_INIT(&local_notify_queue);
	
	for (;;) {
		pthread_mutex_lock(&notify_queue_mtx);		
		while (STAILQ_EMPTY(&notify_queue) != 0 ) {
			// TODO: what was the idea here
			if (pthread_cond_wait(&notify_queue_cond,
			    &notify_queue_mtx) == 0) {		
				break;
			}
		}

		while ((notify = STAILQ_FIRST(&notify_queue))) {
			STAILQ_REMOVE_HEAD(&notify_queue, entries);
			STAILQ_INSERT_TAIL(&local_notify_queue, notify,
			    entries);
		}
		pthread_mutex_unlock(&notify_queue_mtx);		

		STAILQ_FOREACH_SAFE(notify, &local_notify_queue, entries,
		    notify_temp) {
			/* Notifiy the client of the response and if
			 * successful deque the element.
			 */
			dl_notify_response(notify, na);
			// TODO: what to do about errors here?
			//
			STAILQ_REMOVE_HEAD(&local_notify_queue, entries);
		}
	}
	return NULL;
}

static void
dl_notify_response(struct notify_queue_element *notify,
    struct dl_notifier_argument *na)
{
	struct dl_request_element find, *data;	
	struct dl_response_element * test;
	struct request_message *req_m;
	struct response_message *res_m;

	DL_ASSERT(notify != NULL, "Notifier element cannot be NULL");
	DL_ASSERT(na != NULL, "Notifier thread argument cannot be NULL");

	pthread_mutex_lock(&response_pool_mtx);
	test = LIST_FIRST(&response_pool);
	LIST_REMOVE(test, entries);
	pthread_mutex_unlock(&response_pool_mtx);
	if (test) {
		char * pbuf = notify->pbuf;
		DISTLOGTR2(PRIO_NORMAL, "Requester[%d] "
			"got the following message "
			"'%s'\n", na->index, pbuf);
		correlationId_t message_corr_id =
			get_corrid(pbuf);

		find.req_msg.correlation_id = message_corr_id;	
		pthread_mutex_lock(&unackd_requests_mtx);
		data = RB_FIND(dl_unackd_requests, &unackd_requests, &find);
		pthread_mutex_unlock(&unackd_requests_mtx);

		if (data != NULL) {
			DISTLOGTR0(PRIO_NORMAL, "Found the un_acked node\n");
			DISTLOGTR2(PRIO_NORMAL, "Requested: %d Gotten: %d\n",
			    message_corr_id, data->req_msg.correlation_id);

			req_m = &data->req_msg;
			res_m = &test->rsp_msg;

			dl_parse_response(req_m, res_m, pbuf);

			na->on_ack(res_m->correlation_id);
			na->on_response(req_m, res_m);
			DISTLOGTR1(PRIO_NORMAL, "Got acknowledged: %d\n",
			    res_m->correlation_id);
			
			pthread_mutex_lock(&response_pool_mtx);
			LIST_INSERT_HEAD(&response_pool,
				test, entries);
			pthread_mutex_unlock(&response_pool_mtx);
		} else {
			DISTLOGTR0(PRIO_LOW, "Not found the un_acked node\n");
			pthread_mutex_lock(&response_pool_mtx);
			LIST_INSERT_HEAD(&response_pool, test, entries);
			pthread_mutex_unlock(&response_pool_mtx);
		}
	} else {
		DISTLOGTR0(PRIO_HIGH, "Cant borrow a response "
		    "to send stuff off\n");
	}
}

static void
dl_start_notifiers(struct client_configuration *cc)
{
	int notifier;

	for (notifier = 0; notifier < NUM_NOTIFIERS; notifier++) {
		nas[notifier].index = notifier;
		nas[notifier].tid = NULL;
		nas[notifier].config = cc;
		nas[notifier].on_ack = cc->on_ack;
		nas[notifier].on_response = cc->on_response;

		if (pthread_create(&notifiers[notifier], NULL,
		    dl_request_notifier_thread, &nas[notifier]) == 0){
			nas[notifier].tid = &notifiers[notifier];
		}
	}
}

static void
dl_start_resender(struct client_configuration *cc)
{
	int ret;

	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	ret = pthread_create(&resender, NULL, dl_resender_thread,
	    &resender_arg);
	if (ret == 0) {
		resender_arg.tid = &resender;
		resender_arg.index = 0;
		resender_arg.config = cc;
	} 
}

static int
dl_allocate_client_datastructures(struct client_configuration *cc)
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

static void
dl_start_reader_threads(struct client_configuration *cc, int num, ...)
{
	va_list argvars;
	int reader;

	DL_ASSERT(cc != NULL, "Client configuration cannot be NULL");

	num_readers = MIN(NUM_READERS, num);

	va_start(argvars, num);
	for (reader = 0; reader < num_readers; reader++) {
		if (0 == pthread_create(&readers[reader], NULL,
		    dl_reader_thread, &ras[reader])) {

			ras[reader].tid = &readers[reader];
			ras[reader].index = reader;
			ras[reader].config = cc;
			// TODO: Need to check that the max host  name len
			// isn't exceeded
			char *thost = va_arg(argvars, char *);
			memcpy(ras[reader].hostname, thost, strlen(thost));
			ras[reader].portnumber = va_arg(argvars, int);
		}
	}
	va_end(argvars);
}

int
distlog_client_init(char const * const hostname,
    const int portnumber, struct client_configuration const * const cc)
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
distlog_client_fini()
{
	/* TODO: Implement finalisation of the distlog client */
	return 0;
}

int
distlog_send_request(int server_id, enum request_type rt,
    correlationId_t correlation_id, char *client_id, bool should_resend,
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
		clear_requestmessage(&request->req_msg, rt);
		build_req(&request->req_msg, rt, correlation_id, client_id,
		    ap);
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

	va_end(ap);

	return result;
}
