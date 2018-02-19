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

#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "dl_assert.h"
#include "dl_broker_client.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_request_or_response.h"
#include "dl_utils.h"

#define MAX_MESSAGE_SIZE 1024

static dl_event_handler_handle dl_accept_client_connection(int);
static dl_event_handler_handle dl_get_client_socket(void *instance);
static void dl_handle_read_event(void *instance);

static struct dl_response * dlog_broker_handle(struct dl_request * const);
static struct dl_response * dl_handle_fetch_request(struct dl_request *);
static struct dl_response * dl_handle_produce_request(struct dl_request *);
static struct dl_response * dl_handle_list_offset_request(struct dl_request *);

struct request_pool_element {
	struct dl_request *req_msg;
	STAILQ_ENTRY(request_pool_element) entries;
	int fd;
};
STAILQ_HEAD(request, request_pool_element);
static struct request unprocessed_requests;

/* Create the queue onto which unprocessed requests are enqueued
	* prior to processing.
	*/
//STAILQ_INIT(&unprocessed_requests);

static
dl_event_handler_handle dl_get_client_socket(void *instance)
{
	const struct dl_broker_client *client = instance;
	return client->client_socket;
}

static void
dl_handle_read_event(void *instance)
{
	const struct dl_broker_client *client = instance;
	struct dl_request_or_response *req_or_res;
	int rc;
	size_t bytes_read = 0, total = 0;
	char *buffer = (char *) dlog_alloc(1024);

	/* Read the size of the request to process. */
	rc = recv(client->client_socket, buffer,
	    sizeof(req_or_res->dlrx_size), 0);
	
	DLOGTR2(PRIO_LOW, "Read %d bytes (%p)...\n", rc, buffer);
	if (rc == 0) {
		/* Peer has closed connection */
	} else if (rc > 0) {
		req_or_res = dl_decode_request_or_response(buffer);
		if (NULL != req_or_res) {
			DLOGTR1(PRIO_LOW, "\tNumber of bytes: %d\n",
			    req_or_res->dlrx_size);

			buffer += sizeof(int32_t);

			while (total < req_or_res->dlrx_size) {
				bytes_read = recv(client->client_socket,
				    &buffer[total],
				    req_or_res->dlrx_size-total, 0);
				DLOGTR2(PRIO_LOW,
				    "\tRead %d characters; expected %d\n",
				    bytes_read, req_or_res->dlrx_size);
				total += bytes_read;
			}

			for (int b = 0; b < req_or_res->dlrx_size; b++) {
				DLOGTR1(PRIO_LOW, "<0x%02X>", buffer[b]);
			}
			DLOGTR0(PRIO_LOW, "\n");
		}
	} else {
		client->eventNotifier.on_client_closed(
		    client->eventNotifier.server, client);
	}

	dlog_free(buffer);
}

static dl_event_handler_handle
dl_accept_client_connection(int server_handle)
{
	struct sockaddr_in clientAddress = {0};
	socklen_t addressSize = sizeof clientAddress;

	const dl_event_handler_handle client_handle =
		accept(server_handle, (struct sockaddr*) &clientAddress,
				&addressSize);
	if(0 > client_handle) {
		/* NOTE: In the real world, this function should be more forgiving.
		*       For example, the client should be allowed to abort the connection request. */
		printf("Failed to accept client connection");
	}
		       
	(void) printf("Client: New connection created on IP-address %X\n",
			ntohl(clientAddress.sin_addr.s_addr));
		          
	return client_handle;
}

struct dl_response *
dlog_broker_handle(struct dl_request * const request)
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
	
/*
	DL_ASSERT(req_msg != NULL, "FetchRequest cannot be NULL");
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

       	// TODO: Currently the only supported mode, this is nonsense
	// that again needs fixing
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

	if (bytes_so_far < curfreq->dlfr_min_bytes) {
		// Do not send anything
		return 0;
	}
*/

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
	// Get the index from the segments being managed by the broker
	return NULL;
}

/*
static void
dl_processor(struct dl_processor_argument *pa)
{
	struct dl_buffer *buffer;
	struct thread_to_proc_pool_element *element;
	struct request_pool_element *temp;
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
		//pthread_mutex_lock(&thread_to_proc_pool_mtx[pa->index]);
		//LIST_FOREACH(element,
		//    &thread_to_proc_pools[pa->index], entries) {
		//	ufds[connection].fd = element->fd;
		//	ufds[connection].events = POLLIN;
		//	max_connection++;
		//}
		//pthread_mutex_unlock(&thread_to_proc_pool_mtx[pa->index]);
			
		/* Poll the connections assigned to this processor 
		//dl_transport_poll
		//rv = poll(ufds, connection, POLL_TIMEOUT_MS);
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
					//msg_size = read_msg(
					//    ufds[connection].fd, pbuf);

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
						//pthread_mutex_lock(
						//    &thread_to_proc_pool_mtx[pa->index]);
						//LIST_REMOVE(element, entries);
						//dlog_free(element);
						//pthread_mutex_unlock(
						//    &thread_to_proc_pool_mtx[pa->index]);
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
			
			response->rsp_msg = dlog_broker_handle(req_msg);
			if (response != NULL) {
				if (rmsg->dlrqm_api_key == DL_PRODUCE_REQUEST ) { //&&
				    //(!dl_produce_request_get_required_acks(rmsg->dlrqm_message.dlrqmt_produce_request))) {

					/* Allocate and initialise a buffer to encode the request. 
					buffer = (struct dl_buffer *) dlog_alloc(
						sizeof(struct dl_buffer_hdr) + (sizeof(char) * MTU));
					DL_ASSERT(buffer != NULL, "Buffer to encode request cannot be NULL");
					buffer->dlb_hdr.dlbh_data = buffer->dlb_databuf;
					buffer->dlb_hdr.dlbh_len = MTU;

					/* Encode the request the request. *
					//buffer_len = dl_response_encode(rmsg, buffer);
					//dl_transport_send(transport, buffer, buffer_len);
					
					dl_debug(PRIO_NORMAL, "Returned the request object into the pool %p\n", temp);
				}

				if(pa->config->val & BROKER_FSYNC_ALWAYS) {
					/* TODO *
					dl_debug(PRIO_LOW, "Adding responsse to the unfsynced list\n");

					/* Fsync the segment. *
					dl_lock_seg(ptr_seg);
					fsync(ptr_seg->_log);
					fsync(ptr_seg->_index);
					dl_unlock_seg(ptr_seg);
				} else {
					/* TODO *
					dl_debug(PRIO_LOW, "Adding responsse to the unfsynced list\n");

					// TODO: this is makes no sense;
					// remove it
					//pthread_mutex_lock(&unfsynced_responses_mtx);
					//STAILQ_INSERT_TAIL(&unfsynced_responses, response, entries);
					//pthread_cond_signal(&unfsynced_responses_cond);
					//pthread_mutex_unlock(&unfsynced_responses_mtx);

					/* Finished processing the request. *
					//dlog_free(rq_temp);
				}

				/* Finished processing the request. *
				dlog_free(response);
			} else {
				/* Failed processing the request. *
				dlog_free(rq_temp);
			}
		}
		
		// TODO: totally not convinced about this	
		// isn't the poll doing?
		sleep(pa->config->processor_thread_sleep_length);
	}
}
*/

struct dl_broker_client *
dl_broker_client_new(dl_event_handler_handle server_handle,
    struct ServerEventNotifier *event_notifier)
{
	struct dl_broker_client *client;

	DL_ASSERT(event_notifier != NULL,
	    "Server event notifier cannot be NULL\n");

 	client = (struct dl_broker_client *) dlog_alloc(
	    sizeof(struct dl_broker_client));
	if(NULL != client) {
		client->client_socket = dl_accept_client_connection(
		    server_handle);
		       
		/* Successfully created -> register the client with Reactor. */
		client->eventHandler.dleh_instance = client;
		client->eventHandler.dleh_get_handle = dl_get_client_socket;
		client->eventHandler.dleh_handle_event = dl_handle_read_event;

		dl_poll_reactor_register(&client->eventHandler);
					       
		client->eventNotifier = *event_notifier;
	}
   
	return client;
}

void
dl_broker_client_free(struct dl_broker_client *client)
{
	DL_ASSERT(client != NULL, "Client instance cannot be NULL\n");

	/* Before deleting the client we have to unregister at the Reactor. */
	dl_poll_reactor_unregister(&client->eventHandler);
	      
	(void) close(client->client_socket);
	dlog_free(client);
}
