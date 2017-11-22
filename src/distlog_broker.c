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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <unistd.h>

#include "distlog_broker.h"
#include "dl_common.h"
#include "dl_memory.h"
#include "message.h"
#include "dl_protocol.h"
#include "dl_protocol_encoder.h"
#include "dl_protocol_parser.h"
#include "dl_utils.h"

struct dl_processor_argument {
	int index;
	pthread_t const * tid;
	struct broker_configuration const * config;
};

static void dl_accept_loop(int, struct broker_configuration *);
static int dl_assign_to_processor(int, int);
static int dl_broker_handle(struct RequestMessage * const,
    struct ResponseMessage * const);
static void * dl_fsync_thread(void *);
static void * dl_processor_thread(void *);
static void dl_signal_handler(int);
static void dl_start_processor_threads(
    struct broker_configuration const * const);
static int dl_allocate_broker_datastructures(struct broker_configuration *);
static void dl_close_listening_socket(int);
static int dl_handle_request_produce(struct ResponseMessage *,
    struct RequestMessage *);
static int dl_handle_request_fetch(struct ResponseMessage *,
    struct RequestMessage *);
static int dl_free_datastructures();
static int dl_init_listening_socket(int);
static void dl_start_fsync_thread(struct broker_configuration *);

/* TODO: Do we want to limit connections from a pool? */
struct thread_to_proc_pool_element {
	LIST_ENTRY(thread_to_proc_pool_element) entries;
	int fd;
};
LIST_HEAD(thread_to_proc_pool, thread_to_proc_pool_element);
static struct thread_to_proc_pool thread_to_proc_pools[NUM_PROCESSORS];
static pthread_mutex_t thread_to_proc_pool_mtx[NUM_PROCESSORS];

struct request_pool_element {
	struct RequestMessage req_msg;
	LIST_ENTRY(request_pool_element) entries;
	STAILQ_ENTRY(request_pool_element) tq_entries;
	int fd;
};
LIST_HEAD(request_pool, request_pool_element);
static struct request_pool request_pools[NUM_PROCESSORS];
static pthread_mutex_t request_pool_mtx[NUM_PROCESSORS];

struct response_pool_element {
	struct ResponseMessage rsp_msg;
	LIST_ENTRY(response_pool_element) entries;
	int fd;
};
LIST_HEAD(response_pool, response_pool_element);
static struct response_pool response_pools[NUM_PROCESSORS];
static pthread_mutex_t response_pool_mtx[NUM_PROCESSORS];

LIST_HEAD(unfsynced_response, request_pool_element);
static struct unfsynced_response unfsynced_responses; 
static pthread_mutex_t unfsynced_responses_mtx;
static pthread_cond_t unfsynced_responses_cond;

static pthread_t *created_threads;
static struct dl_processor_argument *pas;

static pthread_t fsy_thread;
static struct dl_processor_argument fsy_args;

STAILQ_HEAD(request, request_pool_element);
static struct request unprocessed_requests;

static segment *ptr_seg;

static void
dl_accept_loop(int sockfd, struct broker_configuration *conf)
{
	socklen_t addrlen;
	struct sockaddr_in client_addr;
	int current_processor_id = 0;
	int clientfd, ret;
	
	addrlen = sizeof(client_addr);

	for (;;) {
		clientfd = accept(sockfd, (struct sockaddr *) &client_addr,
		    &addrlen);
		if (clientfd < 0) {
			break;
		}
		ret = dl_assign_to_processor(current_processor_id, clientfd);
		if (ret > 0) {
			debug(PRIO_NORMAL, "%s:%d connected "
			    "and assigned to processor number %d\n",
			    inet_ntoa(client_addr.sin_addr),
			    ntohs(client_addr.sin_port),
			    current_processor_id);
		    	current_processor_id =
			    (current_processor_id + 1) % NUM_PROCESSORS;
		}
	}
}

static int
dl_assign_to_processor(int processorid, int conn_fd)
{
	struct thread_to_proc_pool_element *element =
	    (struct thread_to_proc_pool_element *) distlog_alloc(
		sizeof(struct thread_to_proc_pool_element));
	if (element != NULL) {
		element->fd = conn_fd;
		pthread_mutex_lock(&thread_to_proc_pool_mtx[processorid]);
		LIST_INSERT_HEAD(&thread_to_proc_pools[processorid],
		    element, entries);
		pthread_mutex_unlock(&thread_to_proc_pool_mtx[processorid]);
		return 1;
	} else {
		return -1;
	}
}

static int
dl_broker_handle(struct RequestMessage * const request,
    struct ResponseMessage * const response)
{
	ASSERT(request != NULL);
	// TODO: In the current implementation response can be NULL, need to fix
	ASSERT(response != NULL);

	clear_responsemessage(response, request->APIKey);
	response->CorrelationId = request->CorrelationId;
	
	debug(PRIO_NORMAL, "CorrelationId: %d ClientID: %s\n",
	    request->CorrelationId, request->ClientId);
	switch(request->APIKey) {
	case REQUEST_PRODUCE:;
		debug(PRIO_NORMAL, "Got a request_process message\n");
		dl_handle_request_produce(response, request);
		break;
	case REQUEST_OFFSET_COMMIT:
		break;
	case REQUEST_OFFSET:
		break;
	case REQUEST_FETCH:
		debug(PRIO_NORMAL, "Got a request_fetch message\n");
		// TODO: handle return codes properly
		return dl_handle_request_fetch(response, request);
		break;
	case REQUEST_OFFSET_FETCH:
		break;
	case REQUEST_METADATA:
		break;
	case REQUEST_GROUP_COORDINATOR:
		break;
	}
	debug(PRIO_LOW, "Finished dl_broker_handle\n");
	return 1;

}

static int
dl_handle_request_fetch(struct ResponseMessage *res_ph,
    struct RequestMessage *req_ph)
{
	struct FetchResponse *curfres = &res_ph->rm.fetch_response;
	struct FetchRequest *curfreq = &req_ph->rm.fetch_request;

	debug(PRIO_NORMAL, "Request: %p Response: %p\n", req_ph, res_ph);

	char *current_topic_name = curfreq->TopicName.TopicName;
	int topic_name_len = strlen(current_topic_name);
	debug(PRIO_NORMAL, "The associated topic name is: %s\n",
	    current_topic_name);

	debug(PRIO_NORMAL,
	    "Fetching messages from %s starting at offset %ld\n",
	    curfreq->TopicName.TopicName, curfreq->FetchOffset);

	long handle_start = time(NULL);

	int bytes_so_far = 0;
	long current_offset = curfreq->FetchOffset;

	curfres->NUM_SFR = 0; //Currently the only supported mode
	int csfr = 0, cssfr = 0, curm = 0, first_time = 1;
	while ((time(NULL) - handle_start) < curfreq->MaxWaitTime) {
		if (first_time) {
			debug(PRIO_NORMAL, "The first time for the given configuration:\n\tcsfr: %d\n\tcssfr: %d\n\tcurm: %d\n", csfr, cssfr, curm);
			memcpy(curfres->sfr[csfr].TopicName.TopicName,
				current_topic_name, topic_name_len);
			curfres->ThrottleTime = 0; //TODO: IMPLEMENT IF NEEDED
			curfres->sfr[csfr].ssfr[cssfr].HighwayMarkOffset = 0;//TODO: implement getting the last possible offset
			curfres->sfr[csfr].ssfr[cssfr].Partition = 0;
			first_time = 0;
		}

		if(curm == MAX_SET_SIZE){
			debug(PRIO_NORMAL,
				"The current message has reached the "
				"upper boundary of %d\n", MAX_SET_SIZE);
			cssfr += 1;
			curm = 0;
			first_time = 1;
			continue;
		}

		if(cssfr == MAX_SUB_SUB_FETCH_SIZE){
			cssfr = 0;
			curm  = 0;
			csfr  += 1;
			first_time = 1;
			continue;
		}

		if(csfr == MAX_SUB_FETCH_SIZE){
			debug(PRIO_HIGH,
				"Fetch response has reached its maximum "
				"size\n");
			break;
		}
		struct message_set_element *mse =
			&curfres->sfr[csfr].ssfr[cssfr].MessageSet.Elems[curm];
		mse->message.attributes = 0;

		int msglen = get_message_by_offset(ptr_seg,
			current_offset, mse->message.value);

		if(msglen < 0){
			mse->message.attributes = msglen;
		}

		if(msglen == 0){
			debug(PRIO_NORMAL,
				"No message for a given offset(%lu) "
				"found. Stopping here meaning it is the "
				"end\n", current_offset); 
			break;
		}

		debug(PRIO_NORMAL, "Found a message %s "
			"for offset %d\n", mse->message.value,
			current_offset);
		curfres->NUM_SFR = csfr+1;
		curfres->sfr[csfr].NUM_SSFR = cssfr+1;
		curfres->sfr[csfr].ssfr[cssfr].MessageSet.NUM_ELEMS =
			curm+1;

		mse->offset = current_offset;
		mse->message.timestamp = time(NULL);
		mse->message.crc = get_crc(mse->message.value, msglen);

		bytes_so_far += msglen >= 0 ? msglen : 0;
		curm += 1;
		current_offset += 1;

		if (bytes_so_far >=curfreq->MaxBytes) {
			break;
		}
	}

	if (bytes_so_far < curfreq->MinBytes) {
		// Do not send anything
		return 0;
	}

	return 1;
}

static int
dl_handle_request_produce(struct ResponseMessage *res_ph,
    struct RequestMessage *req_ph)
{
	char * current_topic_name =
	    req_ph->rm.produce_request.spr.TopicName.TopicName;
	debug(PRIO_NORMAL,
		"Inserting messages into the topicname '%s'\n",
		current_topic_name);

	if (res_ph) {
		int topic_name_len = strlen(current_topic_name);
		debug(PRIO_NORMAL, "There is a response needed [%d]\n",
		    req_ph->CorrelationId);

		/* Get the current subproduce */
		int current_subreply =
		    res_ph->rm.produce_response.NUM_SUB;

		struct SubProduceResponse *current_spr =
		    &(res_ph->rm.produce_response.spr[current_subreply]);
		// Say that you have occupied a cell in the subproduce
		res_ph->rm.produce_response.NUM_SUB++; 
		char* ttn = current_spr->TopicName.TopicName;
		debug(PRIO_LOW, "starting copying...\n");
		memcpy(ttn, current_topic_name, topic_name_len);
		debug(PRIO_LOW, "Done...\n");
		current_spr->NUM_SUBSUB =
			req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS;

		for (int i = 0;
		    i < req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS;
		    i++) {
			struct dl_message *tmsg =
			    &req_ph->rm.produce_request.spr.sspr.mset.Elems[i].message;
			debug(PRIO_LOW, "\tMessage: '%s'\n", tmsg->value);
			int slen = strlen(tmsg->value);

			struct SubSubProduceResponse *curr_sspr =
			    &current_spr->sspr[i];
			curr_sspr->Timestamp = time(NULL);
			int curr_repl = 0;
			unsigned long mycrc = get_crc(tmsg->value, slen);

			// Checking to see if the crcs match
			if (tmsg->crc == mycrc) { 
				lock_seg(ptr_seg);
				int ret = insert_message(ptr_seg, tmsg->value, slen);
				ulock_seg(ptr_seg);
				curr_repl |= CRC_MATCH;
				if (ret > 0) {
					curr_repl |= INSERT_SUCCESS;
					curr_sspr->Offset = ret;
				} else {
					curr_repl |= INSERT_ERROR;
				}
			} else {
				curr_repl |= CRC_NOT_MATCH;
				debug(PRIO_LOW,
				    "The CRCs do not match for msg: '%s'\n",
				    tmsg->value);
			}

			curr_sspr->ErrorCode = curr_repl;
			// TODO: implement the proper partitions
			curr_sspr->Partition = 1;
		}
	} else {
		debug(PRIO_LOW, "There is no response needed\n");
		for (int i = 0;
			i < req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS;
			i++) {
			struct dl_message *tmsg =
			    &req_ph->rm.produce_request.spr.sspr.mset.Elems[i].message;
			int slen = strlen(tmsg->value);

			unsigned long mycrc = get_crc(tmsg->value, slen);

		       	// Checking to see if the crcs match
			if (tmsg->crc == mycrc) {
				lock_seg(ptr_seg);
				insert_message(ptr_seg, tmsg->value, slen);
				ulock_seg(ptr_seg);
			}
		}
	}
	return 0;
}

static int
dl_free_datastructures()
{
	int processor_it;

	/*
	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		distlog_free(
		    threadid_to_array_of_connections[processor_it].head);
	}
	distlog_free(threadid_to_array_of_connections);
	*/

	distlog_free(pas);
	distlog_free(created_threads);
	// TODO: clean the req/res
	// TODO: clean&join the threads

	return 1;
}

static int
dl_allocate_broker_datastructures(struct broker_configuration *conf)
{
	int connection_it, processor_it, request_it, response_it;

	/* TODO */
	pas = (struct dl_processor_argument *) distlog_alloc(
	    sizeof(struct dl_processor_argument) * NUM_PROCESSORS);
	created_threads = (pthread_t *) distlog_alloc(
	    sizeof(pthread_t) * NUM_PROCESSORS);
		
	/* TODO */
	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		LIST_INIT(&thread_to_proc_pools[processor_it]);
		pthread_mutex_init(&thread_to_proc_pool_mtx[processor_it],
		    NULL);
	}

	/* TODO */
	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		LIST_INIT(&request_pools[processor_it]);
		pthread_mutex_init(&request_pool_mtx[processor_it], NULL);
		
		for (request_it = 0;
		    request_it < MAX_NUM_REQUESTS_PER_PROCESSOR;
		    request_it++) {
			struct request_pool_element *element =
			    (struct request_pool_element *) distlog_alloc(
			    sizeof(struct request_pool_element));
			LIST_INSERT_HEAD(&request_pools[processor_it],
			    element, entries);
		}
	}

	/* TODO */
	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		LIST_INIT(&response_pools[processor_it]);
		pthread_mutex_init(&response_pool_mtx[processor_it], NULL);
		
		for (response_it = 0;
		    response_it < MAX_NUM_REQUESTS_PER_PROCESSOR;
		    response_it++) {
			struct response_pool_element *element =
			    (struct response_pool_element *) distlog_alloc(
			    sizeof(struct response_pool_element));
			LIST_INSERT_HEAD(&response_pools[processor_it],
			    element, entries);
		}
	}
	
	/* TODO */
	STAILQ_INIT(&unprocessed_requests);

	/* TODO */
	if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
		LIST_INIT(&response_pools[processor_it]);
		pthread_mutex_init(&unfsynced_responses_mtx, NULL);
		pthread_cond_init(&unfsynced_responses_cond, NULL);
	}

	return 0;
}

static int
dl_init_listening_socket(int portnumber)
{
	struct sockaddr_in self;
	int sockfd;

	/*---Create streaming socket---*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	/*---Initialize address/port structure---*/
	bzero(&self, sizeof(self));
	self.sin_family = AF_INET;
	self.sin_port = htons(portnumber);
	self.sin_addr.s_addr = INADDR_ANY;

	/*---Assign a port number to the socket---*/
	if (bind(sockfd, (struct sockaddr *) &self, sizeof(self)) != 0)
		return -2;

	/*---Make it a "listening socket"---*/
	if (listen(sockfd, 20) != 0)
		return -3;

	return sockfd;
}

static void *
dl_processor_thread(void *vargp)
{
	struct dl_processor_argument *pa = (struct dl_processor_argument *) vargp;
	struct thread_to_proc_pool_element *element, *temp_element;
	struct request_pool_element *temp;
	int msg_size;
	int old_cancel_state;
	int rv;
	char buffer[MTU], *pbuf = buffer;
	char send_out_buf[MTU];

	debug(PRIO_LOW, "Processor thread with id %d started...\n", pa->index);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	for (;;) {
		pthread_testcancel();

		int connections = 0;
		pthread_mutex_lock(&thread_to_proc_pool_mtx[pa->index]);
		LIST_FOREACH_SAFE(element,
		    &thread_to_proc_pools[pa->index], entries, temp_element) {
			connections++;
		}
		pthread_mutex_unlock(&thread_to_proc_pool_mtx[pa->index]);

		struct pollfd ufds[connections];
			
		int connection_it = 0;
		pthread_mutex_lock(&thread_to_proc_pool_mtx[pa->index]);
		LIST_FOREACH_SAFE(element,
		    &thread_to_proc_pools[pa->index], entries, temp_element) {
			ufds[connection_it].fd = element->fd;
			ufds[connection_it].events = POLLIN;
			connection_it++;
		}
		pthread_mutex_unlock(&thread_to_proc_pool_mtx[pa->index]);
			
		/* Poll the connections assigned to this processor */
		rv = poll(ufds, connections, 3000);
		debug(PRIO_NORMAL, "Processor thread [%d] polling... %d\n",
			pa->index, rv);
		if (rv == -1) {
			debug(PRIO_HIGH, "POLL ERROR\n");
			exit(-1);
		}

		if (rv != 0) {
			connection_it = 0;
			LIST_FOREACH_SAFE(element,
			    &thread_to_proc_pools[pa->index], entries,
			    temp_element) {
				if (ufds[connection_it].revents & POLLIN) {
					/* Get a request from the pool of objects */
					pthread_mutex_lock(&request_pool_mtx[pa->index]);
					struct request_pool_element *request;
					request = LIST_FIRST(&request_pools[pa->index]);
					LIST_REMOVE(request, entries);
					pthread_mutex_unlock(&request_pool_mtx[pa->index]);

					if (!request) {
						//TODO it is actually a very good q what to do here. Either
						//ignore, or send back a message saying there is a problem
						//For now it just ignores it as the client policy just resends it.
						//Meaning that potentially one may starve
						debug(PRIO_NORMAL, "Cant borrow any more requests.\n");
						continue;
					}

					msg_size = read_msg(
					    ufds[connection_it].fd, pbuf);
					if (msg_size > 0) {
						debug(PRIO_LOW, "Enqueuing: '%s'\n", pbuf);

						struct RequestMessage *trq =
						    &request->req_msg;

						clear_requestmessage(trq,
						    get_apikey(pbuf));
						parse_requestmessage(trq,
						    pbuf);
						request->fd = ufds[connection_it].fd;
						
						STAILQ_INSERT_TAIL(
						    &unprocessed_requests,
						    request, tq_entries);
					} else {
						//This is the disconnect. Maybe need to clean the
						//responses to this guy. Not sure how to do that
						//yet. TODO: decide
						pthread_mutex_lock(
						    &thread_to_proc_pool_mtx[pa->index]);
						LIST_REMOVE(element, entries);
						distlog_free(element);
						pthread_mutex_unlock(
						    &thread_to_proc_pool_mtx[pa->index]);

						pthread_mutex_lock(
						    &request_pool_mtx[pa->index]);
						LIST_INSERT_HEAD(
						    &request_pools[pa->index],
						    request, entries);
						pthread_mutex_unlock(
						    &request_pool_mtx[pa->index]);
					}

				}
				connection_it++;
			}
		}
	
		if (STAILQ_EMPTY(&unprocessed_requests) == 0) {
			struct request_pool_element *rq_temp;

			rq_temp = STAILQ_FIRST(&unprocessed_requests);
			STAILQ_REMOVE_HEAD(&unprocessed_requests, tq_entries);

			/* Get a response from the pool of objects */
			pthread_mutex_lock(&response_pool_mtx[pa->index]);
			struct response_pool_element *response;
			response = LIST_FIRST(&response_pools[pa->index]);
			LIST_REMOVE(response, entries);
			pthread_mutex_unlock(&response_pool_mtx[pa->index]);

			struct RequestMessage *rmsg =
				(struct RequestMessage *) &rq_temp->req_msg;
			struct RequestMessage *req_ph =
				(struct RequestMessage*) &rq_temp->req_msg;
			response->fd = rq_temp->fd;

			int sh = dl_broker_handle(req_ph, &response->rsp_msg);
			if (sh > 0) {
				debug(PRIO_NORMAL,
					"dl_broker_handle finished "
					"with code %d\n", sh);
				if(pa->config->val &
					BROKER_FSYNC_ALWAYS) {
					lock_seg(ptr_seg);
					fsync(ptr_seg->_log);
					fsync(ptr_seg->_index);
					ulock_seg(ptr_seg);

					if ((rmsg->APIKey == REQUEST_PRODUCE) &&
						(!rmsg->rm.produce_request.RequiredAcks)) {
						struct ResponseMessage* myres = &response->rsp_msg;
						int fi = wrap_with_size(&response->rsp_msg, &pbuf, send_out_buf, rmsg->APIKey);
						debug(PRIO_NORMAL, "Sending: '%s'\n", send_out_buf);
						send(temp->fd, send_out_buf, fi, 0);

						/* Return the response to the
						* object pool.
						*/
						pthread_mutex_lock(&response_pool_mtx[pa->index]);
						LIST_INSERT_HEAD(&response_pools[pa->index], response, entries);
						pthread_mutex_unlock(&response_pool_mtx[pa->index]);

						pthread_mutex_lock(&response_pool_mtx[pa->index]);
						LIST_INSERT_HEAD(&response_pools[pa->index], response, entries);
						pthread_mutex_unlock(&response_pool_mtx[pa->index]);
					}
				} else {
					if(response) {
						printf("Adding responsse to the unfsynced list\n");
						pthread_mutex_lock(&unfsynced_responses_mtx);
						LIST_INSERT_HEAD(&unfsynced_responses, response, entries);
						pthread_cond_signal(&unfsynced_responses_cond);
						pthread_mutex_unlock(&unfsynced_responses_mtx);
					} else {

						pthread_mutex_lock(&response_pool_mtx[pa->index]);
						LIST_INSERT_HEAD(&response_pools[pa->index], response, entries);
						pthread_mutex_unlock(&response_pool_mtx[pa->index]);

						debug(PRIO_NORMAL, "Returned the request object into the pool %p\n", temp);
					}

					pthread_mutex_lock(
					    &request_pool_mtx[pa->index]);
					LIST_INSERT_HEAD(
					    &request_pools[pa->index],
					    rq_temp, entries);
					pthread_mutex_unlock(
					    &request_pool_mtx[pa->index]);
				}
			} else {
				/* Failed handling request - return
				 * the response to the object pool.
				 */
				pthread_mutex_lock(
					&response_pool_mtx[pa->index]);
				LIST_INSERT_HEAD(
					&response_pools[pa->index],
					response, entries);
				pthread_mutex_unlock(
					&response_pool_mtx[pa->index]);

				pthread_mutex_lock(
				    &request_pool_mtx[pa->index]);
				LIST_INSERT_HEAD(
				    &request_pools[pa->index], response,
				    entries);
				pthread_mutex_unlock(&request_pool_mtx[pa->index]);
			}
		} else {
			sleep(pa->config->processor_thread_sleep_length);
		}
	}
	return NULL;
}

/* TODO: Fix up coarse locking and multithreading */
static void *
dl_fsync_thread(void *vargp)
{
	char *pbuf;
        char *send_out_buf;
	struct dl_processor_argument *pa = (struct dl_processor_argument *) vargp;
	struct response_pool_element *response, *response_temp;
	int old_cancel_state;

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread ins't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	pbuf = (char *) distlog_alloc(MTU * sizeof(char));
	send_out_buf = (char *) distlog_alloc(MTU * sizeof(char));
	
	debug(PRIO_LOW, "FSync thread started... %d\n", pa->index);

	for (;;) {
		pthread_mutex_lock(&unfsynced_responses_mtx);
		if (pthread_cond_wait(&unfsynced_responses_cond,
		    &unfsynced_responses_mtx) == 0) {
			/* If there are un-fsynced response, fsync the log and
			 * the disk and send the responses.
			 */
			if (LIST_EMPTY(&unfsynced_responses) == 0) {
				/* Synchronously write both the log and
				 * the index to the disk.
				 */
				lock_seg(ptr_seg);
				fsync(ptr_seg->_log);
				fsync(ptr_seg->_index);

				LIST_FOREACH_SAFE(response,
				    &unfsynced_responses, entries,
				    response_temp) {
					debug(PRIO_LOW, "Unfsynching: %d\n",
					response->rsp_msg.CorrelationId);
				
					int fi = wrap_with_size(
					    &response->rsp_msg, &pbuf,
					    send_out_buf,
					    (enum request_type) response->fd);
					debug(PRIO_NORMAL, "Sending: '%s'\n",
					    send_out_buf);
					if (send(response->fd, send_out_buf,
					    fi, 0) == 0) {

						/* Response has been ack'd,
						 * remove it from the
						 * unfsynced_responses
						 * and return to the
						 * appropriate response pool
						 */
						LIST_REMOVE(response, entries);

						/* TODO: which reponse pool did it come from?
						pthread_mutex_lock(&response_pool_mtx[pa->index]);
						LIST_INSERT_HEAD(&response_pools[pa->index], response, entries);
						pthread_mutex_unlock(&response_pool_mtx[pa->index]);
						*/
					}
				}
				ulock_seg(ptr_seg);

			}
		}
		pthread_mutex_unlock(&unfsynced_responses_mtx);
	
		/* Fsync'd all outstanding responses. Check whether the
		 * thread has been canceled.
		 */	
		pthread_testcancel();

		debug(PRIO_LOW, "Fsynch thread is going to sleep for %d "
		    "seconds\n", pa->config->fsync_thread_sleep_length);
		
		sleep(pa->config->fsync_thread_sleep_length);
	}

	distlog_free(pbuf);
	distlog_alloc(send_out_buf);

	return NULL;
}

static void
dl_start_fsync_thread(struct broker_configuration *conf)
{
	int ret;

	fsy_args.tid   = NULL;
	fsy_args.config = conf;
	fsy_args.index = 0;

	/* TODO: handle error creating thread */
	ret = pthread_create(&fsy_thread, NULL, dl_fsync_thread, &fsy_args);
	if (ret == 0) {
		fsy_args.tid = &fsy_thread;
	}
}

static void
dl_close_listening_socket(int sockfd)
{

	close(sockfd);
}

static void
dl_signal_handler(int dummy)
{
	int processor_it;

	debug(PRIO_NORMAL, "Caught SIGINT[%d]\n", dummy);

	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		pthread_cancel(created_threads[processor_it]);
	}

	for (processor_it = 0; processor_it < NUM_PROCESSORS; processor_it++) {
		pthread_join(created_threads[processor_it], NULL);
	}

	dl_free_datastructures();
	exit(0);
}

static void
dl_start_processor_threads(struct broker_configuration const * const conf)
{
	int processor;

	for (processor= 0; processor < NUM_PROCESSORS; processor++) {
		pas[processor].index = processor;
		pas[processor].tid   = NULL;
		pas[processor].config = conf;
		pthread_create(&created_threads[processor], NULL,
		    dl_processor_thread, &pas[processor]);
		pas[processor].tid = &created_threads[processor];
	}
}

void
broker_busyloop(int portnumber, const char *p_name,
    struct broker_configuration *conf)
{
	int sockfd;

	print_configuration(conf);
	dl_allocate_broker_datastructures(conf);
	dl_start_processor_threads(conf);

	// TODO: NEED TO MOVE IT SOMEWHERE
	del_folder(p_name);
	make_folder(p_name);
	ptr_seg = make_segment(0, 1024*1024, p_name);

	signal(SIGINT, dl_signal_handler);

	if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
		dl_start_fsync_thread(conf);
	}

	sockfd = dl_init_listening_socket(portnumber);
	dl_accept_loop(sockfd, conf);
}
