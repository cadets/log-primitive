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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/tree.h>

#include "caml_client.h"
#include "caml_memory.h"
#include "circular_queue.h"
#include "protocol_parser.h"
#include "protocol_encoder.h"
#include "utils.h"

static int allocate_client_datastructures(struct client_configuration *);
static int connect_to_server(const char *, int);
static void parse_server_answer(struct RequestMessage *,
    struct ResponseMessage *, char *);
static void * reader_thread(void *);
static void * request_notifier_thread(void *);
static void * resender_thread(void *);
static void start_notifiers(struct client_configuration *);
static void start_reader_threads(struct client_configuration *, int, ...);
static void start_resender(struct client_configuration *);

#define MAX_SIZE_HOSTNAME 16

struct notifier_argument {
	ack_function on_ack;
	struct client_configuration *config;
	pthread_t * tid;
	response_function on_response;
	int index;
};

struct reader_argument {
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

static CircularQueue *request_notifiers;
static CircularQueue *send_out_queue;

// Array containing arguments to the reader threads
static struct reader_argument *ras;
static pthread_t *notifiers;

// Array containing arguments to the notifier threads
static struct notifier_argument *nas;
static pthread_t *readers;

static struct reader_argument resender_arg;
static pthread_t resender;

static int current_request_notifier = 0;

static int num_readers;

struct lentry {
	struct RequestMessage req_msg;
	unsigned long last_sent;
	unsigned long resend_timeout;
	int should_resend;
	LIST_ENTRY(lentry) entries;
};

struct listhead *headp;

LIST_HEAD(listhead, lentry) head = LIST_HEAD_INITIALIZER(head);
pthread_mutex_t mtx;

struct lentryx {
	struct ResponseMessage rsp_msg;
	LIST_ENTRY(lentryx) entries;
};

struct listheadx *headpx;

LIST_HEAD(listheadx, lentryx) headx = LIST_HEAD_INITIALIZER(headx);
pthread_mutex_t mtxx;

struct tentry {
	struct lentry *value;
	int key;
	LIST_ENTRY(tentry) entries;
	RB_ENTRY(tentry) linkage;
};

struct treehead *headpt;


LIST_HEAD(tlisthead, tentry) tlhead = LIST_HEAD_INITIALIZER(tlhead);
pthread_mutex_t tlmtx;

RB_HEAD(treehead, tentry) thead = RB_INITIALIZER(&thead);
pthread_mutex_t tmtx;
static int
tentry_cmp(struct tentry *e1, struct tentry *e2)
{
	return e2->key - e1->key;
}

RB_PROTOTYPE(treehead, tentry, linkage, tentry_cmp);
RB_GENERATE(treehead, tentry, linkage, tentry_cmp);

static int
connect_to_server(const char *hostname, int portnumber)
{
	struct sockaddr_in dest;
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;
	if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0)
		return -3;

	return sockfd;
}

static void *
resender_thread(void *vargp)
{
	struct reader_argument *ra = (struct reader_argument *) vargp;
	unsigned long now;
	int server_id_assign = 0;

	debug(PRIO_LOW, "Resender thread started\n");

	for (;;) {
		struct tentry *data;
		pthread_mutex_lock(&tmtx);
		RB_FOREACH(data, treehead, &thead) {
			if (data->value->should_resend) {
				now = time(NULL);
				debug(PRIO_LOW, "Was sent %lu now is %lu. "
				    "Resend when the difference is %lu. "
				    "Current: %lu\n",
				    data->value->last_sent, now,
				    data->value->resend_timeout,
				    data->value->last_sent);
				if((now - data->value->last_sent) >
				    data->value->resend_timeout) {
					data->value->last_sent = time(NULL);

					lock_cq(
					    &send_out_queue[server_id_assign]);
					enqueue(
					    &send_out_queue[server_id_assign],
					    data, sizeof(struct lentry *));
					ulock_cq(
					    &send_out_queue[server_id_assign]);

					server_id_assign =
					    (server_id_assign + 1) %
					    num_readers;
					debug(PRIO_LOW, "Done.\n");

				}
			}
		}
		pthread_mutex_unlock(&tmtx);

		debug(PRIO_NORMAL, "Resender thread is going to sleep for %d "
			"seconds\n", ra->config->resender_thread_sleep_length);
		sleep(ra->config->resender_thread_sleep_length);
	}
	return NULL;
}

static void *
reader_thread(void *vargp)
{
	char *pbuf = (char *) distlog_alloc(sizeof(char) * MTU);
	char *send_out_buffer;
	int server_conn = -1, rv, msg_size;
	struct reader_argument *ra = (struct reader_argument *) vargp;
	
	send_out_buffer = (char *) distlog_alloc(sizeof(char) * MTU);

	for (;;) {
		if (server_conn < 0) {
			debug(PRIO_NORMAL, "No connection to server. "
			    "Attempting to connect to '%s:%d'\n",
			    ra->hostname, ra->portnumber);
			server_conn = connect_to_server(ra->hostname,
				ra->portnumber);
			if (server_conn < 0) {
				debug(PRIO_NORMAL, "Error connecting...\n");
			}

			sleep(ra->config->reconn_timeout);
			continue;
		}
		struct pollfd ufd;
		ufd.fd = server_conn;
		ufd.events = POLLIN;

		rv = poll(&ufd, 1, ra->config->poll_timeout);
		debug(PRIO_NORMAL, "Reader thread polling ... %d\n", rv);
		if (rv == -1) {
			debug(PRIO_HIGH, "Poll error...");
			continue;
		}
		if (rv) {
			msg_size = read_msg(ufd.fd, &pbuf);
			if (msg_size > 0) {
				debug(PRIO_LOW, "Reader thread read %d "
				    "bytes\n", msg_size);
				int mnotif = (current_request_notifier + 1) %
				    NUM_NOTIFIERS;
				lock_cq(&request_notifiers[mnotif]);

				enqueue(&request_notifiers[mnotif], pbuf,
					sizeof(char) * MTU);

				current_request_notifier = mnotif;
				ulock_cq(&request_notifiers[mnotif]);
			} else {
				server_conn = -1;
			}
		}
				
		debug(PRIO_LOW, "No. messages in send_out_queue %d = %d\n",
		    ra->index, send_out_queue[ra->index].num_elems);
		while (send_out_queue[ra->index].num_elems > 0) {

			struct lentry *temp;

			lock_cq(&send_out_queue[ra->index]);
			int ind = dequeue(&send_out_queue[ra->index],
			    (void *) &temp, sizeof(struct lentry *));
			ulock_cq(&send_out_queue[ra->index]);

			if (ind != -1) {
				struct RequestMessage* mimi = &temp->req_msg;
				debug(PRIO_LOW,
				    "[%d]Dequeued request with address %p\n",
				    ind, mimi);
				debug(PRIO_LOW, "mimi->CorreltionsId %d\n",
				    mimi->CorrelationId);
				int req_size = encode_requestmessage(
					mimi, &pbuf);
				int fi = sprintf(send_out_buffer, "%.*d%s",
				    OVERALL_MSG_FIELD_SIZE,
				    req_size+OVERALL_MSG_FIELD_SIZE, pbuf);

				debug(PRIO_NORMAL, "[%d]Sending: '%s'\n",
				    ind, send_out_buffer);
				send(server_conn, send_out_buffer, fi, 0);
			}
		}
	}
	return NULL;
}

static void
parse_server_answer(struct RequestMessage* req_m,
	struct ResponseMessage* res_m, char* pbuf)
{

	clear_responsemessage(res_m, req_m->APIKey);
	parse_responsemessage(res_m, pbuf, match_requesttype(req_m->APIKey));
}

static void *
request_notifier_thread(void *vargp)
{
	struct notifier_argument *na = (struct notifier_argument *) vargp;
	char *pbuf;
	
	// TODO move this guy to the allocations
	pbuf = (char *) distlog_alloc(sizeof(char) * MTU);

	debug(PRIO_LOW, "Requester thread with id %d started...\n", na->index);

	for (;;) {
		if (request_notifiers[na->index].num_elems > 0) {
			debug(PRIO_LOW, "num_elems %d started...\n",
			    request_notifiers[na->index].num_elems);

			pthread_mutex_lock(&mtxx);
			struct lentryx * test;
			test = LIST_FIRST(&headx);
			LIST_REMOVE(test, entries);
			pthread_mutex_unlock(&mtxx);
			if (test) {

				lock_cq(&request_notifiers[na->index]);
				int ind = dequeue(
					&request_notifiers[na->index],
					(void*) pbuf, sizeof(char)*MTU);
				ulock_cq(&request_notifiers[na->index]);
				if (ind != -1) {
					debug(PRIO_NORMAL, "Requester[%d] "
						"got the following message "
						"'%s'\n", na->index, pbuf);
					correlationId_t message_corr_id =
						get_corrid(pbuf);

					struct tentry *data;	
					struct tentry find;
					find.key = message_corr_id;	
					pthread_mutex_lock(&tmtx);
					data = RB_FIND(treehead, &thead, &find);
					pthread_mutex_unlock(&tmtx);

					if (data != NULL) {
						debug(PRIO_NORMAL,
						    "Found the un_acked node\n");
						debug(PRIO_NORMAL,
						    "Requested: %d "
						    "Gotten: %d\n",
						    message_corr_id, data->key);
						struct RequestMessage *req_m =
						    &(data->value)->req_msg;
						struct ResponseMessage *res_m =
						    &test->rsp_msg;

						parse_server_answer(req_m, res_m, pbuf);

						na->on_ack(res_m->CorrelationId);
						na->on_response(req_m, res_m);
						debug(PRIO_NORMAL,
						    "Got acknowledged: %d\n",
						    res_m->CorrelationId);
						
						pthread_mutex_lock(&mtxx);
						LIST_INSERT_HEAD(&headx,
						    test, entries);
						pthread_mutex_unlock(&mtxx);
					} else {
						debug(PRIO_LOW,
						    "Not found the un_acked node\n");
						pthread_mutex_lock(&mtxx);
						LIST_INSERT_HEAD(&headx, test, entries);
						pthread_mutex_unlock(&mtxx);
					}
				} else {
					pthread_mutex_lock(&mtxx);
					LIST_INSERT_HEAD(&headx, test, entries);
					pthread_mutex_unlock(&mtxx);
				}
			} else {
				debug(PRIO_HIGH, "Cant borrow a response "
					"to send stuff off\n");
			}
		}
		sleep(na->config->request_notifier_thread_sleep_length);
	}
	return NULL;
}

static void
start_notifiers(struct client_configuration *cc)
{
	int notifiers_it;

	for (notifiers_it = 0; notifiers_it < NUM_NOTIFIERS; notifiers_it++){
		nas[notifiers_it].index = notifiers_it;
		nas[notifiers_it].tid   = NULL;
		nas[notifiers_it].config = cc;
		nas[notifiers_it].on_ack = cc->on_ack;
		nas[notifiers_it].on_response = cc->on_response;

		pthread_create(&notifiers[notifiers_it], NULL,
		    request_notifier_thread, &nas[notifiers_it]);
		nas[notifiers_it].tid = &notifiers[notifiers_it];
	}
}

static void
start_resender(struct client_configuration *cc)
{
	int ret;

	resender_arg.index = 0;
	resender_arg.tid = NULL;
	resender_arg.config = cc;
	ret = pthread_create(&resender, NULL, resender_thread, &resender_arg);
	if (ret == 0) {
		resender_arg.tid = &resender;
	}
}

static int
allocate_client_datastructures(struct client_configuration *cc)
{
	int processor_it;

	RB_INIT(&thead);
	pthread_mutex_init(&tmtx, NULL);

	// Preallocate the list
	LIST_INIT(&tlhead);

	for (processor_it = 0; processor_it < MAX_NUM_REQUESTS_PER_PROCESSOR;
	    processor_it++) {
		struct tentry * entry = distlog_alloc(sizeof(struct tentry));
		LIST_INSERT_HEAD(&tlhead, entry, entries);
	}

	pthread_mutex_init(&tlmtx, NULL);

	nas = (struct notifier_argument *) distlog_alloc(
		sizeof(struct notifier_argument) * NUM_NOTIFIERS);
	notifiers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_NOTIFIERS);

	readers = (pthread_t *) distlog_alloc(
		sizeof(pthread_t) * NUM_READERS);
	ras = (struct reader_argument *) distlog_alloc(
		sizeof(struct reader_argument) * NUM_READERS);

	request_notifiers = allocate_circ_queue_per_num_processors(
		NUM_NOTIFIERS, REQUESTS_PER_NOTIFIER, sizeof(char) * MTU);
	send_out_queue = allocate_circ_queue_per_num_processors(
	    NUM_NOTIFIERS, REQUESTS_PER_NOTIFIER,
	    sizeof(struct lentry *));

	// TODO: Allocate a list per "processor" currently this is one
	LIST_INIT(&head);

	// Preallocate the request list
	for (processor_it = 0; processor_it < MAX_NUM_REQUESTS_PER_PROCESSOR;
	    processor_it++) {
		struct lentry * list_entry =
		    distlog_alloc(sizeof(struct lentry));
		LIST_INSERT_HEAD(&head, list_entry, entries);
	}

	pthread_mutex_init(&mtx, NULL);

	// TODO: Allocate a list per "processor" currently this is one
	LIST_INIT(&headx);

	// Preallocate the response list
	for (processor_it = 0; processor_it < MAX_NUM_RESPONSES_PER_PROCESSOR;
	    processor_it++) {
		struct lentryx * list_entry =
		    distlog_alloc(sizeof(struct lentryx));
		LIST_INSERT_HEAD(&headx, list_entry, entries);
	}

	pthread_mutex_init(&mtx, NULL);

	return 1;
}

static void
start_reader_threads(struct client_configuration *cc, int num, ...)
{
	va_list argvars;

	num_readers = MIN(NUM_READERS, num);

	va_start(argvars, num);
	for (int i = 0; i < num_readers; i++) {
		ras[i].index = i;
		ras[i].tid = NULL;
		ras[i].config = cc;

		char *thost = va_arg(argvars, char*);
		memcpy(ras[i].hostname, thost, strlen(thost));
		ras[i].portnumber = va_arg(argvars, int);

		pthread_create(&readers[i], NULL, reader_thread, &ras[i]);
		ras[i].tid = &readers[i];
	}
	va_end(argvars);
}

void
client_busyloop(const char *hostname, int portnumber,
    struct client_configuration* cc)
{
	int ret;

	ret  = allocate_client_datastructures(cc);
	if (ret > 0) {
		debug(PRIO_NORMAL, "Finished allocation...\n");

		start_notifiers(cc);
		start_reader_threads(cc, 1, hostname, portnumber);
		start_resender(cc);
	}
}

int
send_request(int server_id, enum request_type rt,
    correlationId_t correlation_id, char* client_id, int should_resend,
    int resend_timeout, ...)
{
	int result = 0;
	struct lentry * request;
	va_list ap;

	va_start(ap, resend_timeout);

	debug(PRIO_LOW, "User requested to send a message "
		"with correlation id of %d\n", correlation_id);

	/* Take a new request from the pool */
	pthread_mutex_lock(&mtx);
	request = LIST_FIRST(&head);
	LIST_REMOVE(request, entries);
	pthread_mutex_unlock(&mtx);
	if (request) {
		request->should_resend = should_resend;
		request->resend_timeout = resend_timeout;
		request->last_sent = time(NULL);

		struct RequestMessage *trq = &request->req_msg;

		debug(PRIO_LOW, "Requested rm (DLL: %p) "
			"(RequestMessage: %p)\n", request, trq);

		debug(PRIO_LOW, "Building request message ",
			"(correlation_id = %d)\n", correlation_id);
		clear_requestmessage(trq, rt);
		build_req(trq, rt, correlation_id, client_id, ap);
		debug(PRIO_LOW, "Done\n");

		/* Enque the request for processing */
		lock_cq(&send_out_queue[server_id]);
		enqueue(&send_out_queue[server_id], &request,
			sizeof(struct lentry *));
		ulock_cq(&send_out_queue[server_id]);

		if (trq->APIKey == REQUEST_FETCH ||
		    (trq->APIKey == REQUEST_PRODUCE) &&
		    trq->rm.produce_request.RequiredAcks) {
			
			/* The request must be acknowledged, store
			 * the request until an acknowledgment is
			 * received from the broker.
			 */
			pthread_mutex_lock(&tlmtx);
			struct tentry * unack_request;
			unack_request = LIST_FIRST(&tlhead);
			LIST_REMOVE(unack_request, entries);
			pthread_mutex_unlock(&tlmtx);
			if (unack_request) {
				debug(PRIO_NORMAL, "Inserting into the tree "
					"with key %d\n", correlation_id);

				unack_request->key = correlation_id;
				unack_request->value = request;
				pthread_mutex_lock(&tmtx);
				RB_INSERT(treehead, &thead, unack_request);
				pthread_mutex_unlock(&tmtx);
				
				debug(PRIO_NORMAL, "Key of the request %d "
					"when the user submitted is %d\n",
					trq->CorrelationId,
					correlation_id);
				debug(PRIO_NORMAL, "Done\n");
			} else {
				/* Failed storing the unacknowledged
				 * request. Return the request
				 * object to the pool.
				 */
				pthread_mutex_lock(&mtx);
				LIST_INSERT_HEAD(&head, request, entries);
				pthread_mutex_unlock(&mtx);

				result = -1;
			}
		}
	       	else {
			/* The request does not require and acknowledgment,
			 * therefor return the request to the pool.
			 */
			pthread_mutex_lock(&mtx);
			LIST_INSERT_HEAD(&head, request, entries);
			pthread_mutex_unlock(&mtx);
		}
	} else {
        	debug(PRIO_LOW,
		    "Error borrowing the request to perform user send\n");
		result = -1;
	}

	debug(PRIO_LOW, "User request finished\n");
	va_end(ap);

	return result;
}
