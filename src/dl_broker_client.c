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
#include "dl_broker_partition.h"
#include "dl_broker_topic.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_produce_request.h"
#include "dl_request.h"
#include "dl_request_or_response.h"
#include "dl_utils.h"

static dl_event_handler_handle dl_accept_client_connection(const int);
static dl_event_handler_handle dl_get_client_socket(void *instance);
static void dl_handle_read_event(void *instance);

static struct dl_response * dlog_broker_handle(struct dl_request * const,
    struct broker_configuration const * const conf);
static struct dl_response * dl_handle_fetch_request(struct dl_request *);
static struct dl_response * dl_handle_produce_request(struct dl_request *,
    struct broker_configuration const * const conf);
static struct dl_response * dl_handle_list_offset_request(struct dl_request *);

static
dl_event_handler_handle dl_get_client_socket(void *instance)
{
	const struct dl_broker_client *client = instance;

	DL_ASSERT(instance != NULL, ("Broker client instance cannot be NULL"));

	return client->client_socket;
}

static void
dl_handle_read_event(void *instance)
{
	struct dl_request *request;
	struct dl_request *response;
	const struct dl_broker_client *client = instance;
	struct dl_request_or_response *req_or_res;
	int rc;
	size_t bytes_read = 0, total = 0;
	char *buffer = (char *) dlog_alloc(1024);
	int32_t buffer_len = 0;

	DL_ASSERT(instance != NULL, ("Broker client instance cannot be NULL"));

	/* Read the size of the request to process. */
	rc = recv(client->client_socket, buffer,
	    sizeof(req_or_res->dlrx_size), 0);
	if (rc == 0) {
		/* Peer has closed connection */
	} else if (rc > 0) {

		DLOGTR2(PRIO_LOW, "Read %d bytes (%p)...\n", rc, buffer);
		req_or_res = dl_decode_request_or_response(buffer);
		if (NULL != req_or_res) {
			DLOGTR1(PRIO_LOW, "\tNumber of bytes: %d\n",
			    req_or_res->dlrx_size);

			total += sizeof(int32_t);

			while (bytes_read < req_or_res->dlrx_size) {
				bytes_read = recv(client->client_socket,
				    &buffer[total],
				    req_or_res->dlrx_size-bytes_read, 0);
				DLOGTR2(PRIO_LOW,
				    "\tRead %d characters; expected %d\n",
				    bytes_read, req_or_res->dlrx_size);
				total += bytes_read;
			}

			for (int b = 0; b < req_or_res->dlrx_size; b++) {
				DLOGTR1(PRIO_LOW, "<0x%02hX>", buffer[b]);
			}
			DLOGTR0(PRIO_LOW, "\n");
	
			/* Decode the request from the received buffer. */	
			request = dl_request_decode(buffer);
			if (request != NULL) {
				/* If the request TODO */
				response = dlog_broker_handle(request,
				    client->event_notifier.dlben_conf);
				if (response != NULL) {

					/* Encode and send the response. */
					buffer_len = dl_response_encode(
					    response, buffer);
					if (buffer_len > 0) {

						printf("Sending %d\n", buffer_len);
						send(client->client_socket,
						    buffer, buffer_len, 0);
					}
				} else {
					DLOGTR0(PRIO_HIGH,
					    "Error handling request\n");
				}
			} else {
				DLOGTR0(PRIO_HIGH, "Error decoding request\n");
			}
		}
	} else {
		client->event_notifier.on_client_closed(
		    client->event_notifier.server, client);
	}

	dlog_free(buffer);
}

static dl_event_handler_handle
dl_accept_client_connection(const int server_handle)
{
	struct sockaddr_in client_address = {0};
	socklen_t address_size = sizeof client_address;
	dl_event_handler_handle client_handle;
       
	client_handle = accept(server_handle,
	    (struct sockaddr *) &client_address, &address_size);
	if (0 > client_handle) {
		/* NOTE: In the real world, this function should be more forgiving.
		*       For example, the client should be allowed to abort the connection request. */
		DLOGTR0(PRIO_HIGH, "Failed to accept client connection");
	}
		       
	DLOGTR1(PRIO_NORMAL, "Client: New connection created on IP-address %X\n",
	    ntohl(client_address.sin_addr.s_addr));
		          
	return client_handle;
}

static struct dl_response *
dlog_broker_handle(struct dl_request * const request,
    struct broker_configuration const * const conf)
{
	DL_ASSERT(request != NULL, "Request message cannot be NULL");
	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");

	switch (request->dlrqm_api_key) {
	case DL_FETCH_API_KEY:
		return dl_handle_fetch_request(request);
		break;
	case DL_OFFSET_API_KEY:
		DLOGTR2(PRIO_LOW, "Processing OffsetRequest "
		    "(client: %s, id: %d)\n", request->dlrqm_client_id,
		    request->dlrqm_correlation_id);
		return dl_handle_list_offset_request(request);
		break;
	case DL_PRODUCE_API_KEY:;
		DLOGTR2(PRIO_LOW, "Processing ProduceRequest "
		    "(client: %s, id: %d)\n", request->dlrqm_client_id,
		    request->dlrqm_correlation_id);
		return dl_handle_produce_request(request, conf);
		break;
	default:
		DLOGTR1(PRIO_HIGH, "Unsupported Request %d\n",
		    request->dlrqm_api_key);
		return NULL;
	}
}

struct dl_response *
dl_handle_fetch_request(struct dl_request *request)
{
	struct dl_fetch_request *fetch_request;
	struct dl_fetch_request_partition *fetch_partition;
	struct dl_fetch_request_topic *fetch_topic;
	struct dl_response *fetch_response = NULL;
	
	DL_ASSERT(request!= NULL, "FetchRequest cannot be NULL");
	
	fetch_request = request->dlrqm_message.dlrqmt_offset_request;
	DL_ASSERT(fetch_request != NULL, "FetchRequest cannot be NULL");
	
	DLOGTR2(PRIO_LOW, "Processing FetchRequest (client: %s, id: %d)\n",
	    request->dlrqm_client_id, request->dlrqm_correlation_id);
	
	SLIST_FOREACH(fetch_topic, &fetch_request->dlfr_topics,
	    dlfrt_entries) {
		DLOGTR1(PRIO_NORMAL,
		    "Fetch request for the topicname '%s'\n",
		    fetch_topic->dlfrt_topic_name);

		SLIST_FOREACH(fetch_partition, &fetch_topic->dlfrt_partitions,
		    dlfrp_entries) {

			struct dl_partition *partition =
			    SLIST_FIRST(&topic->dlt_partitions);
			//partition->dlp_active_segment, "Hello", 5);

		};
	};

	return fetch_response;
}

// TODO: construct response
static struct dl_response *
dl_handle_produce_request(struct dl_request *request,
    struct broker_configuration const * const conf)
{
	struct dl_response *produce_response = NULL;
	struct dl_produce_request *produce_request;
	struct dl_produce_request_topic *produce_request_topic;
	struct dl_produce_request_partition *produce_request_partition;

	DL_ASSERT(request != NULL, "ProduceRequest cannot be NULL");
	
	produce_request = request->dlrqm_message.dlrqmt_produce_request;
	DL_ASSERT(produce_request != NULL, "ProduceRequest cannot be NULL");

	DLOGTR1(PRIO_LOW, "ProduceRequest id = %d\n",
	    request->dlrqm_correlation_id);

	SLIST_FOREACH(produce_request_topic, &produce_request->dlpr_topics,
	    dlprt_entries) {

		DLOGTR1(PRIO_NORMAL,
		    "Inserting messages into the topicname '%s'\n",
		    produce_request_topic->dlprt_topic_name);

		SLIST_FOREACH(produce_request_partition,
		    &produce_request_topic->dlprt_partitions,
		    dlprp_entries) {

			// Insert the message
			struct dl_partition *partition =
			    SLIST_FIRST(&topic->dlt_partitions);
			dl_insert_message(partition->dlp_active_segment, "Hello", 5);

			if (conf->val & BROKER_FSYNC_ALWAYS) {
				/* Fsync the segment. */
				dl_lock_seg(partition->dlp_active_segment);
				fsync(partition->dlp_active_segment->_log);
				fsync(partition->dlp_active_segment->_index);
				dl_unlock_seg(partition->dlp_active_segment);
			}
		}
	}
	return produce_response;
}

static struct dl_response *
dl_handle_list_offset_request(struct dl_request *request)
{
	struct dl_list_offset_request *offset_request;
	struct dl_list_offset_request_partition *request_partition;
	struct dl_list_offset_request_topic *request_topic;
	struct dl_response *response;
	struct dl_list_offset_response *offset_response;
	struct dl_list_offset_response_partition *response_partition;
	struct dl_list_offset_response_topic *response_topic;

	DL_ASSERT(request!= NULL, "ListOffsetRequest cannot be NULL");

	offset_request = request->dlrqm_message.dlrqmt_offset_request;
	DL_ASSERT(offset_request != NULL, "ListOffsetRequest cannot be NULL");

	DLOGTR1(PRIO_LOW, "ListOffsetRequest id = %d\n",
	    request->dlrqm_correlation_id);
	
	response = (struct dl_response *) dlog_alloc(
		sizeof(struct dl_response));
      	response->dlrs_api_key = DL_OFFSET_API_KEY;

	offset_response	= response->dlrs_message.dlrs_offset_message=
	    (struct dl_list_offset_response *) dlog_alloc(
		sizeof(struct dl_list_offset_response));
	if (offset_response != NULL) {	

		printf("ntopics = %d\n", offset_request->dlor_ntopics);

		offset_response->dlor_ntopics = offset_request->dlor_ntopics;
		SLIST_INIT(&offset_response->dlor_topics);

		SLIST_FOREACH(request_topic, &offset_request->dlor_topics,
		    dlort_entries) {

			DLOGTR1(PRIO_NORMAL,
			    "Listing offset for the topicname '%s'\n",
			    request_topic->dlort_topic_name);

			response_topic = (struct dl_list_offset_response_topic *)
			    dlog_alloc(sizeof(struct dl_list_offset_response_topic));
			if (response_topic != NULL) {	

				response_topic->dlort_npartitions = 
				    request_topic->dlort_npartitions;
				SLIST_INIT(&response_topic->dlort_partitions);
				strlcpy(response_topic->dlort_topic_name,
				    request_topic->dlort_topic_name,
				    DL_MAX_TOPIC_NAME_LEN);

				SLIST_FOREACH(request_partition,
				    &request_topic->dlort_partitions,
				    dlorp_entries) {

					response_partition = (struct dl_list_offset_response_partition *)
					    dlog_alloc(sizeof(struct dl_list_offset_response_partition));
					if (response_partition != NULL) {	

						response_partition->dlorp_partition =
						    request_partition->dlorp_partition;

						if (request_partition->dlorp_time == -1) {
							/* TODO: Earliest */

							response_partition->dlorp_error_code = -1;
						} else if (request_partition->dlorp_time == -2) {
							/* Latest */

							response_partition->dlorp_error_code = 0;
							response_partition->dlorp_offset = topic->dlt_offset;
							/* TODO: Time index */
							response_partition->dlorp_timestamp = 0;
						} else {
							/* TODO: Time index */
							response_partition->dlorp_error_code = -1;
						}

						SLIST_INSERT_HEAD(&response_topic->dlort_partitions,
						    response_partition,
						    dlorp_entries);
					}
				};
			}
			SLIST_INSERT_HEAD(&offset_response->dlor_topics,
			    response_topic, dlort_entries);
		};
	}
	return response;
}

struct dl_broker_client *
dl_broker_client_new(dl_event_handler_handle server_handle,
    struct dl_broker_event_notifier *event_notifier)
{
	struct dl_broker_client *client;

	DL_ASSERT(event_notifier != NULL,
	    "Server event notifier cannot be NULL\n");

 	client = (struct dl_broker_client *) dlog_alloc(
	    sizeof(struct dl_broker_client));
	if (client != NULL) {
		client->client_socket = dl_accept_client_connection(
		    server_handle);
		       
		/* Successfully created -> register the client with Reactor. */
		client->event_handler.dleh_instance = client;
		client->event_handler.dleh_get_handle = dl_get_client_socket;
		client->event_handler.dleh_handle_event = dl_handle_read_event;

		dl_poll_reactor_register(&client->event_handler);
					       
		client->event_notifier = *event_notifier;
	}
	return client;
}

void
dl_broker_client_free(struct dl_broker_client *client)
{

	DL_ASSERT(client != NULL, ("Broker client instance cannot be NULL\n"));

	/* Before deleting the client we have to unregister at the Reactor. */
	dl_poll_reactor_unregister(&client->event_handler);
	      
	(void) close(client->client_socket);
	dlog_free(client);
}
