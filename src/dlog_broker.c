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

#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/socket.h>

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
#include <unistd.h>

#include "dlog_broker.h"

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_response.h"
#include "dl_transport.h"
#include "dl_utils.h"

/* Record statistics for the broker */
struct dl_broker_statistics {
	// TODO
};

/* Record statistics for the broker */
struct dl_processor_statistics {
	// TODO
};

struct dl_processor_argument {
	int index;
	pthread_t const *tid;
	struct broker_configuration const *config;
};

static void dl_accept_loop(int, struct broker_configuration *);
static int dl_assign_to_processor(int, int);
static struct dl_response * dl_broker_handle(struct dl_request * const);
static void * dl_fsync_thread(void *);
static void dl_processor(struct dl_processor_argument *);
static void * dl_processor_thread(void *);
static void dl_siginfo_handler(int);
static void dl_sigint_handler(int);
static void dl_start_processor_threads(
    struct broker_configuration const * const);
static int dl_allocate_broker_datastructures(struct broker_configuration *);
static void dl_close_listening_socket(int);
static struct dl_response * dl_handle_fetch_request(struct dl_request *);
static struct dl_response * dl_handle_produce_request(struct dl_request *);
static struct dl_response * dl_handle_list_offset_request(struct dl_request *);
static int dl_free_datastructures();
static int dl_init_listening_socket(int);
static int dl_start_fsync_thread(struct broker_configuration *);

struct thread_to_proc_pool_element {
	LIST_ENTRY(thread_to_proc_pool_element) entries;
	int fd;
};
LIST_HEAD(thread_to_proc_pool, thread_to_proc_pool_element);
static struct thread_to_proc_pool thread_to_proc_pools[NUM_PROCESSORS];
static pthread_mutex_t thread_to_proc_pool_mtx[NUM_PROCESSORS];

struct request_pool_element {
	struct dl_request *req_msg;
	STAILQ_ENTRY(request_pool_element) entries;
	int fd;
};
STAILQ_HEAD(request, request_pool_element);
static struct request unprocessed_requests;

struct response_pool_element {
	struct dl_response *rsp_msg;
	STAILQ_ENTRY(response_pool_element) entries;
	int fd;
};

STAILQ_HEAD(unfsynced_response, response_pool_element);
static struct unfsynced_response unfsynced_responses; 
static pthread_mutex_t unfsynced_responses_mtx;
static pthread_cond_t unfsynced_responses_cond;

static pthread_t *processor_threads;
static struct dl_processor_argument *pas;

static pthread_t fsy_thread;
static struct dl_processor_argument fsy_args;

static struct segment *ptr_seg;

static const int POLL_TIMEOUT_MS = 3000;

static void
dl_accept_loop(int sockfd, struct broker_configuration *conf)
{
	socklen_t addrlen;
	struct sockaddr_in client_addr;
	int current_processor_id = 0;
	int clientfd, ret;

	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");

	addrlen = sizeof(client_addr);

	for (;;) {
		clientfd = accept(sockfd, (struct sockaddr *) &client_addr,
		    &addrlen);
		if (clientfd < 0) {
			break;
		}
		ret = dl_assign_to_processor(current_processor_id, clientfd);
		if (ret > 0) {
			dl_debug(PRIO_NORMAL, "%s:%d connected "
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
	    (struct thread_to_proc_pool_element *) dlog_alloc(
		sizeof(struct thread_to_proc_pool_element));
	if (element != NULL) {
		element->fd = conn_fd;
		pthread_mutex_lock(&thread_to_proc_pool_mtx[processorid]);
		LIST_INSERT_HEAD(&thread_to_proc_pools[processorid],
		    element, entries);
		pthread_mutex_unlock(&thread_to_proc_pool_mtx[processorid]);

		return 0;
	} else {
		return -1;
	}
}

struct dl_response *
dl_broker_handle(struct dl_request * const request)
{
	DL_ASSERT(request != NULL, "Request message cannot be NULL");

	switch (request->dlrqm_api_key) {
	case DL_FETCH_REQUEST:
		dl_debug(PRIO_LOW, "Processing FetchRequest "
		    "(client: %s, id: %d)\n", request->dlrqm_client_id,
		    request->dlrqm_correlation_id);
		return dl_handle_fetch_request(request);
		break;
	case DL_OFFSET_REQUEST:
		dl_debug(PRIO_LOW, "Processing OffsetRequest "
		    "(client: %s, id: %d)\n", request->dlrqm_client_id,
		    request->dlrqm_correlation_id);
		return dl_handle_list_offset_request(request);
		break;
	case DL_PRODUCE_REQUEST:;
		dl_debug(PRIO_LOW, "Processing ProduceRequest "
		    "(client: %s, id: %d)\n", request->dlrqm_client_id,
		    request->dlrqm_correlation_id);
		return dl_handle_produce_request(request);
		break;
	default:
		dl_debug(PRIO_HIGH, "Unsupported Request %d\n",
		    request->dlrqm_api_key);
		return NULL;
	}
}

struct dl_response *
dl_handle_fetch_request(struct dl_request *req_msg)
{
	struct dl_fetch_request *curfreq;
	struct dl_fetch_response *curfres;
	int csfr = 0, cssfr = 0, curm = 0, first_time = 1;
	int topic_name_len;
	int bytes_so_far = 0;
	char *current_topic_name;
	
	DL_ASSERT(req_msg != NULL, "FetchRequest cannot be NULL");
/*
	dl_debug(PRIO_NORMAL, "Request: %p Response: %p\n", req_msg, rsp_msg);

	curfreq = &req_msg->dlrqm_message.dlrqmt_fetch_request;
	current_topic_name = curfreq->dlfr_topic_name;
	topic_name_len = strlen(current_topic_name);

	dl_debug(PRIO_NORMAL, "The associated topic name is: %s\n",
	    current_topic_name);

	dl_debug(PRIO_NORMAL,
	    "Fetching messages from %s starting at offset %ld\n",
	    curfreq->dlfr_topic_name, curfreq->dlfr_fetch_offset);

	long handle_start = time(NULL);

	long current_offset = curfreq->dlfr_fetch_offset;
*/
       	// TODO: Currently the only supported mode, this is nonsense
	// that again needs fixing
	/*
	curfres->dlfrs_num_responses = 0;
	while ((time(NULL) - handle_start) < curfreq->dlfr_max_wait_time) {
		if (first_time) {
			dl_debug(PRIO_NORMAL,
			    "The first time for the given configuration:\n\t"
			    "csfr: %d\n\tcssfr: %d\n\tcurm: %d\n", csfr, cssfr,
			    curm);
			memcpy(curfres->sfr[csfr].topic_name.topic_name,
				current_topic_name, topic_name_len);
			curfres->dlfrs_throttle_time = 0; //TODO: IMPLEMENT IF NEEDED
			//TODO: implement getting the last possible offset
			curfres->sfr[csfr].ssfr[cssfr].highway_mark_offset = 0;
			curfres->sfr[csfr].ssfr[cssfr].partition = 0;
			first_time = 0;
		}

		if (curm == MAX_SET_SIZE) {
			dl_debug(PRIO_NORMAL,
				"The current message has reached the "
				"upper boundary of %d\n", MAX_SET_SIZE);
			cssfr += 1;
			curm = 0;
			first_time = 1;
			continue;
		}

		if (cssfr == MAX_SUB_SUB_FETCH_SIZE){
			cssfr = 0;
			curm  = 0;
			csfr  += 1;
			first_time = 1;
			continue;
		}

		if (csfr == MAX_SUB_FETCH_SIZE) {
			dl_debug(PRIO_HIGH,
			    "Fetch response has reached its maximum size\n");
			break;
		}
		struct message_set_element *mse =
		    &curfres->sfr[csfr].ssfr[cssfr].message_set.elems[curm];
		mse->message.attributes = 0;

		int msglen = dl_get_message_by_offset(ptr_seg,
			current_offset, mse->message.value);

		if (msglen < 0){
			mse->message.attributes = msglen;
		}

		if (msglen == 0){
			dl_debug(PRIO_NORMAL,
				"No message for a given offset(%lu) "
				"found. Stopping here meaning it is the "
				"end\n", current_offset); 
			break;
		}

		dl_debug(PRIO_NORMAL, "Found a message %s "
			"for offset %d\n", mse->message.value,
			current_offset);
		curfres->num_sfr = csfr+1;
		curfres->sfr[csfr].num_ssfr = cssfr+1;
		curfres->sfr[csfr].ssfr[cssfr].message_set.num_elems =
			curm+1;

		mse->offset = current_offset;
		mse->message.timestamp = time(NULL);
		mse->message.crc = get_crc(mse->message.value, msglen);

		bytes_so_far += msglen >= 0 ? msglen : 0;
		curm += 1;
		current_offset += 1;

		if (bytes_so_far >=curfreq->dlfr_max_bytes) {
			break;
		}
	}
	*/

	if (bytes_so_far < curfreq->dlfr_min_bytes) {
		// Do not send anything
		return 0;
	}

	return 1;
}

static struct dl_response *
dl_handle_produce_request(struct dl_request *request)
{
	char *current_topic_name;

	DL_ASSERT(request != NULL, "ProduceRequest cannot be NULL");

	DLOGTR1(PRIO_NORMAL, "Inserting messages into the topicname '%s'\n",
	    current_topic_name);
		
	/*
	// TODO: this doesn't appear to handle batching correctly	
	current_topic_name =
	    dl_produce_request_get_topic_name(req_msg->dlrqm_message.dlrqmt_produce_request);
	    //req_msg->dlrqm_message.dlrqmt_produce_request.spr.topic_name.topic_name;

	if (rsp_msg) {
		int topic_name_len = strlen(current_topic_name);
		dl_debug(PRIO_NORMAL, "There is a response needed [%d]\n",
		    req_msg->dlrqm_correlation_id);
		// Get the current subproduce
		int current_subreply =
		    rsp_msg->rm.produce_response.num_sub;

		struct sub_produce_response *current_spr =
		    &(rsp_msg->rm.produce_response.spr[current_subreply]);
		// Say that you have occupied a cell in the subproduce
		rsp_msg->rm.produce_response.num_sub++; 
		char* ttn = current_spr->topic_name.topic_name;
		dl_debug(PRIO_LOW, "starting copying...\n");
		memcpy(ttn, current_topic_name, topic_name_len);
		dl_debug(PRIO_LOW, "Done...\n"
		current_spr->num_subsub =
			req_msg->rm.produce_request.spr.sspr.mset.num_elems;

		for (int i = 0;
		    i < req_msg->rm.produce_request.spr.sspr.mset.num_elems;
		    i++) {
			struct dl_message *tmsg =
			    &req_msg->rm.produce_request.spr.sspr.mset.elems[i].message;
			dl_debug(PRIO_LOW, "\tMessage: '%s'\n", tmsg->value);
			int slen = strlen(tmsg->value);

			struct sub_sub_produce_response *curr_sspr =
			    &current_spr->sspr[i];
			curr_sspr->timestamp = time(NULL);
			int curr_repl = 0;
			unsigned long mycrc = get_crc(tmsg->value, slen);

			// Checking to see if the crcs match
			if (tmsg->crc == mycrc) { 
				dl_lock_seg(ptr_seg);
				int ret = dl_insert_message(ptr_seg, tmsg->value, slen);
				dl_unlock_seg(ptr_seg);
				curr_repl |= CRC_MATCH;
				if (ret > 0) {
					curr_repl |= INSERT_SUCCESS;
					curr_sspr->offset = ret;
				} else {
					curr_repl |= INSERT_ERROR;
				}
			} else {
				curr_repl |= CRC_NOT_MATCH;
				dl_debug(PRIO_LOW,
				    "The CRCs do not match for msg: '%s'\n",
				    tmsg->value);
			}

			curr_sspr->error_code = curr_repl;
			// TODO: implement the proper partitions
			curr_sspr->partition = 1;
		}
	} else {
		// TODO: This doesn't appear sensible
		// The CRC checking needs to be done in the decoding

		dl_debug(PRIO_LOW, "There is no response needed\n");
		/*
		for (int i = 0;
			i < req_msg->rm.produce_request.spr.sspr.mset.num_elems;
			i++) {
			struct dl_message *tmsg =
			    &req_msg->rm.produce_request.spr.sspr.mset.elems[i].message;
			int slen = strlen(tmsg->value);

			unsigned long mycrc = get_crc(tmsg->value, slen);

		       	// Checking to see if the crcs match
			if (tmsg->crc == mycrc) {
				dl_lock_seg(ptr_seg);
				dl_insert_message(ptr_seg, tmsg->value, slen);
				dl_unlock_seg(ptr_seg)/make
			} else {
				// TODO: What to do if the CRCs don't match?
			}
		}
	}
	*/
	return 0;
}

// TODO: ListOffset
static struct dl_response *
dl_handle_list_offset_request(struct dl_request * request)
{
	return NULL;
}

static int
dl_free_datastructures()
{
	int processor;

	/*
	for (processor = 0; processor < NUM_PROCESSORS; processor++) {
		dlog_free(
		    threadid_to_array_of_connections[processor].head);
	}
	dlog_free(threadid_to_array_of_connections);
	*/

	dlog_free(pas);
	dlog_free(processor_threads);
	// TODO: clean the req/res
	// TODO: clean&join the threads

	return 1;
}

static int
dl_allocate_broker_datastructures(struct broker_configuration *conf)
{
	int processor;

	/* TODO */
	processor_threads = (pthread_t *) dlog_alloc(
	    sizeof(pthread_t) * NUM_PROCESSORS);
	
	pas = (struct dl_processor_argument *) dlog_alloc(
	    sizeof(struct dl_processor_argument) * NUM_PROCESSORS);
		
	/* TODO */
	for (processor = 0; processor < NUM_PROCESSORS; processor++) {
		LIST_INIT(&thread_to_proc_pools[processor]);
		pthread_mutex_init(&thread_to_proc_pool_mtx[processor], NULL);
	}

	/* Create the queue onto which unprocessed requests are enqueued
	 * prior to processing.
	 */
	STAILQ_INIT(&unprocessed_requests);

	/* If the broker isn't configured to immediately fsync log entries,
	 * create the a queue used to asynchronously fsync requests.
	 */
	if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
		STAILQ_INIT(&unfsynced_responses);
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
	struct dl_processor_argument *pa =
	    (struct dl_processor_argument *) vargp;
	int old_cancel_state;
	
	DL_ASSERT(vargp != NULL, "processor thread argument cannot be NULL");
	
	dl_debug(PRIO_LOW, "Processor thread with id %d started...\n", pa->index);

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread isn't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	dl_processor(pa);
	return NULL;
}

static void
dl_processor(struct dl_processor_argument *pa)
{
	struct dl_buffer *buffer;
	struct thread_to_proc_pool_element *element;
	struct request_pool_element *temp;
	struct dl_transport transport;
	int msg_size;
	int rv;
	char  *pbuf = buffer;
	char send_out_buf[MTU];
	struct pollfd ufds[CONNECTIONS_PER_PROCESSOR];
	int connection, max_connection;
	int32_t buffer_len;

	for (;;) {
		pthread_testcancel();

		max_connection = 0;		
		pthread_mutex_lock(&thread_to_proc_pool_mtx[pa->index]);
		LIST_FOREACH(element,
		    &thread_to_proc_pools[pa->index], entries) {
			ufds[connection].fd = element->fd;
			ufds[connection].events = POLLIN;
			max_connection++;
		}
		pthread_mutex_unlock(&thread_to_proc_pool_mtx[pa->index]);
			
		/* Poll the connections assigned to this processor */
		//dl_transport_poll
		rv = poll(ufds, connection, POLL_TIMEOUT_MS);
		dl_debug(PRIO_NORMAL, "Processor thread [%d] polling... %d\n",
			pa->index, rv);
		if (rv == 0) {
			dl_debug(PRIO_LOW, "POLL Timeout\n");
		} else if (rv == -1) {
			dl_debug(PRIO_HIGH, "POLL ERROR\n");
			// TODO: What to do here
			exit(EXIT_FAILURE);

		} else {
			for (connection = 0; connection < max_connection;
			    connection++) {
				if (ufds[connection].revents & POLLIN) {
			
					//dl_transport_read_msg	
					msg_size = read_msg(
					    ufds[connection].fd, pbuf);

					if (msg_size > 0) {
						struct request_pool_element *request = (struct request_pool_element *)
						    dlog_alloc(sizeof(struct request_pool_element));;
						if (request != NULL) {
							dl_debug(PRIO_LOW, "Enqueuing: '%s'\n", pbuf);

							// TODO: Some error
							// handling 
							request->req_msg = dl_decode_request(pbuf);
							request->fd = ufds[connection].fd;
						
							// TODO: Not MT safe	
							STAILQ_INSERT_TAIL(
							    &unprocessed_requests,
							    request, entries);
						} else {
							//TODO it is actually a very good q what to do here. Either
							//ignore, or send back a message saying there is a problem
							//For now it just ignores it as the client policy just resends it.
							//Meaning that potentially one may starve
							dl_debug(PRIO_NORMAL, "Cant borrow any more requests.\n");
							continue;
						}
					} else {
						//This is the disconnect. Maybe need to clean the
						//responses to this guy. Not sure how to do that
						//yet. TODO: decide
						pthread_mutex_lock(
						    &thread_to_proc_pool_mtx[pa->index]);
						LIST_REMOVE(element, entries);
						dlog_free(element);
						pthread_mutex_unlock(
						    &thread_to_proc_pool_mtx[pa->index]);
					}
				}
			}
		}

		// This is a completely orthoganl concern
		// The thread model here is completly silly

		if (STAILQ_EMPTY(&unprocessed_requests) == 0) {
			struct request_pool_element *rq_temp;

			rq_temp = STAILQ_FIRST(&unprocessed_requests);
			STAILQ_REMOVE_HEAD(&unprocessed_requests, entries);

			// TODO: I don't think that the unfsyncd response
			// handling makes any sense
			struct response_pool_element *response =
			    (struct response_pool_element *) dlog_alloc(sizeof(struct response_pool_element));;

			struct dl_request *rmsg = &rq_temp->req_msg;
			struct dl_request *req_msg = &rq_temp->req_msg;
			response->fd = rq_temp->fd;
			
			response->rsp_msg = dl_broker_handle(req_msg);
			if (response != NULL) {
				if (rmsg->dlrqm_api_key == DL_PRODUCE_REQUEST &&
				    (!dl_produce_request_get_required_acks(rmsg->dlrqm_message.dlrqmt_produce_request))) {

					/* Allocate and initialise a buffer to encode the request. */
					buffer = (struct dl_buffer *) dlog_alloc(
						sizeof(struct dl_buffer_hdr) + (sizeof(char) * MTU));
					DL_ASSERT(buffer != NULL, "Buffer to encode request cannot be NULL");
					buffer->dlb_hdr.dlbh_data = buffer->dlb_databuf;
					buffer->dlb_hdr.dlbh_len = MTU;

					/* Encode the request the request. */	
					buffer_len = dl_response_encode(rmsg, buffer);
					//dl_transport_send(transport, buffer, buffer_len);
					
					dl_debug(PRIO_NORMAL, "Returned the request object into the pool %p\n", temp);
				}

				if(pa->config->val & BROKER_FSYNC_ALWAYS) {
					/* TODO */
					dl_debug(PRIO_LOW, "Adding responsse to the unfsynced list\n");

					/* Fsync the segment. */
					dl_lock_seg(ptr_seg);
					fsync(ptr_seg->_log);
					fsync(ptr_seg->_index);
					dl_unlock_seg(ptr_seg);
				} else {
					/* TODO */
					dl_debug(PRIO_LOW, "Adding responsse to the unfsynced list\n");

					// TODO: this is makes no sense;
					// remove it
					//pthread_mutex_lock(&unfsynced_responses_mtx);
					//STAILQ_INSERT_TAIL(&unfsynced_responses, response, entries);
					//pthread_cond_signal(&unfsynced_responses_cond);
					//pthread_mutex_unlock(&unfsynced_responses_mtx);

					/* Finished processing the request. */
					//dlog_free(rq_temp);
				}

				/* Finished processing the request. */
				dlog_free(response);
			} else {
				/* Failed processing the request. */
				dlog_free(rq_temp);
			}
		}
		
		// TODO: totally not convinced about this	
		// isn't the poll doing?
		sleep(pa->config->processor_thread_sleep_length);
	}
}

/* TODO: Fix up coarse locking and multithreading */
static void *
dl_fsync_thread(void *vargp)
{
	char *pbuf;
        char *send_out_buf;
	struct dl_processor_argument *pa =
	    (struct dl_processor_argument *) vargp;
	struct response_pool_element *response, *response_temp;
	ssize_t rc;
	int old_cancel_state;
	struct unfsynced_response responses; 

	DL_ASSERT(vargp != NULL, "fsync thread argument cannot be NULL");

	/* Defer cancellation of the thread until the cancellation point 
	 * pthread_testcancel(). This ensures that thread ins't cancelled until
	 * outstanding requests have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	pbuf = (char *) dlog_alloc(MTU * sizeof(char));
	send_out_buf = (char *) dlog_alloc(MTU * sizeof(char));

	STAILQ_INIT(&responses);	

	dl_debug(PRIO_LOW, "FSync thread started... %d\n", pa->index);

	for (;;) {
		pthread_mutex_lock(&unfsynced_responses_mtx);
		
		/* If there are un-fsynced response, fsync the log and
		 * the disk and send the responses.
	 	 */
		while (STAILQ_EMPTY(&unfsynced_responses) != 0) {
			pthread_cond_wait(&unfsynced_responses_cond,
			    &unfsynced_responses_mtx);
		}
		
		/* Enqueue the unfsynced responses to a thread local queue.*/
		while ((response = STAILQ_FIRST(&unfsynced_responses))) {
			STAILQ_REMOVE_HEAD(&unfsynced_responses, entries);
			STAILQ_INSERT_TAIL(&responses, response, entries);
		}
		pthread_mutex_unlock(&unfsynced_responses_mtx);

		STAILQ_FOREACH_SAFE(response, &responses, entries,
		    response_temp) {
			dl_debug(PRIO_LOW, "Unfsynching: %d\n",
			    response->rsp_msg->dlrs_correlation_id);
		
			//int fi = wrap_with_size(&response->rsp_msg, pbuf,
			//    send_out_buf, (enum request_type) response->fd);
			// TODO: dl_encode_response();
			dl_debug(PRIO_NORMAL, "Sending: '%s'\n", send_out_buf);
			//rc = send(response->fd, send_out_buf, fi, 0);
			if (rc != -1) {
				/* Response has been ack'd, remove it from the
				 * unfsynced_responses and return to the
				 * appropriate response pool
				 */
				STAILQ_REMOVE_HEAD(&responses, entries);

				// TODO: Free the response
				// dlog_free(response);
			} else {
				// What if some of the sends failed?
			}
		}


		/* Synchronously write both the log and the index to the disk.
		 */
		dl_lock_seg(ptr_seg);
		fsync(ptr_seg->_log);
		fsync(ptr_seg->_index);
		dl_unlock_seg(ptr_seg);
	
		/* Fsync'd all outstanding responses. Check whether the
		 * thread has been canceled.
		 */	
		pthread_testcancel();

		dl_debug(PRIO_LOW, "Fsynch thread is going to sleep for %d "
		    "seconds\n", pa->config->fsync_thread_sleep_length);
		
		sleep(pa->config->fsync_thread_sleep_length);
	}

	dlog_free(pbuf);
	dlog_free(send_out_buf);

	return NULL;
}

static int 
dl_start_fsync_thread(struct broker_configuration *conf)
{
	/* TODO: handle error creating thread */
	fsy_args.config = conf;
	return pthread_create(&fsy_thread, NULL, dl_fsync_thread, &fsy_args);
	//if (ret == 0) {
	//	fsy_args.tid = &fsy_thread;
	//	fsy_args.index = 0;
	//}
}

// TODO: This isn't even used!
static void
dl_close_listening_socket(int sockfd)
{

	close(sockfd);
}

static void
dl_siginfo_handler(int dummy)
{
	dl_debug(PRIO_LOW, "Caught SIGIFO[%d]\n", dummy);

	/* Report the broker statistics. */
	// dl_debug(PRIO_NORMAL, );
}

static void
dl_sigint_handler(int dummy)
{
	dl_debug(PRIO_LOW, "Caught SIGINT[%d]\n", dummy);
	dlog_broker_fini();

	exit(EXIT_SUCCESS);
}

static void
dl_start_processor_threads(struct broker_configuration const * const conf)
{
	int processor;
	
	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");

	for (processor= 0; processor < NUM_PROCESSORS; processor++) {
		if (pthread_create(&processor_threads[processor], NULL,
		    dl_processor_thread, &pas[processor]) == 0) {
			pas[processor].index = processor;
			pas[processor].config = conf;
			pas[processor].tid = &processor_threads[processor];
		}
	}
}

/* TODO allow client to specify which network interface to bind to */
void
dlog_broker_init(int portnumber, const char *partition_name,
    struct broker_configuration *conf)
{
	int sockfd;

	DL_ASSERT(partition_name != NULL, "Partition name cannot be NULL");
	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");
	
	/* Install signal handler to terminate broker cleanly. */	
	signal(SIGINT, dl_sigint_handler);

	/* Install signal handler to report broker statistics. */
	signal(SIGINFO, dl_siginfo_handler);

	/* Create the specified partition; deleting if already present. */
	dl_del_folder(partition_name);
	dl_make_folder(partition_name);

	/* TODO */
	// TODO: what is the 1024*1024 default size?
	ptr_seg = dl_make_segment(0, 1024*1024, partition_name);

	/* TODO */
	print_configuration(conf);
	dl_allocate_broker_datastructures(conf);
	dl_start_processor_threads(conf);

	/* If the broker isn't configured to fsync produce requests
	 * immediately, create and start a thread to asynchronously fsync
	 * requests to disk.
	 */
	if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
		dl_start_fsync_thread(conf);
	}

	/* TODO: Seperate the initialization from the starting?
	 * Check what makes sense for running in the kernel
	 */
	//dl_transport
	sockfd = dl_init_listening_socket(portnumber);
	if (sockfd >= 0) {
		dl_accept_loop(sockfd, conf);
	}
}

void
dlog_broker_fini()
{
	int processor;

	for (processor = 0; processor < NUM_PROCESSORS; processor++) {
		pthread_cancel(processor_threads[processor]);
	}

	for (processor = 0; processor < NUM_PROCESSORS; processor++) {
		pthread_join(processor_threads[processor], NULL);
	}
	
	//if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
	//	pthread_cancel(fsy_thread);
	//}

	//dl_close_listening_socket(int sockfd)

	dl_free_datastructures();
}
