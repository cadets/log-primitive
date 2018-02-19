/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/queue.h>

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
#include "dl_broker_client.h"
#include "dl_config.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_response.h"
#include "dl_transport.h"
#include "dl_utils.h"

#define MAX_NO_OF_CLIENTS 10

struct dlog_broker_handle {
	struct dl_event_handler event_handler;
	dl_event_handler_handle socket;
	struct dl_broker_client *clients[MAX_NO_OF_CLIENTS];
};

/* Record statistics for the broker */
struct dl_broker_statistics {
	// TODO
};

static void * dl_fsync_thread(void *);
static void dl_siginfo_handler(int);
static void dl_sigint_handler(int);
static int dl_init_listening_socket(int);
static int dl_start_fsync_thread(struct broker_configuration *);

struct response_pool_element {
	struct dl_response *rsp_msg;
	STAILQ_ENTRY(response_pool_element) entries;
	int fd;
};

STAILQ_HEAD(unfsynced_response, response_pool_element);
static struct unfsynced_response unfsynced_responses; 
static pthread_mutex_t unfsynced_responses_mtx;
static pthread_cond_t unfsynced_responses_cond;

struct dl_fsync_argument {
	int index;
	pthread_t const *tid;
	struct broker_configuration const *config;
};

static pthread_t fsy_thread;
static struct dl_fsync_argument fsy_args;

static struct segment *ptr_seg;

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

/* TODO: Fix up coarse locking and multithreading */
static void *
dl_fsync_thread(void *vargp)
{
	char *pbuf;
        char *send_out_buf;
	struct dl_fsync_argument *pa =
	    (struct dl_fsync_argument *) vargp;
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


		/* Syncboth the log and the index to the disk. */
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
	fsy_args.config = conf;
	return pthread_create(&fsy_thread, NULL, dl_fsync_thread, &fsy_args);
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

/**
 * Returns the index where a client matching the given pointer is found.
 * Returns -1 if no match was found. 
 */ 
static int
dl_match_controlled_client_by_pointer(const struct dlog_broker_handle *server,
    const struct dl_broker_client *clientToMatch)
{
	int clientSlot = -1;
	int slotFound = 0;
	int i = 0;
		       
	for (i = 0; (i < MAX_NO_OF_CLIENTS) && (0 == slotFound); ++i) {
			          
		if (clientToMatch == server->clients[i]) {
			clientSlot = i;
			slotFound = 1;
		}
	}
		       
	return clientSlot;
}

static int
dl_find_free_client_slot(const struct dlog_broker_handle *server)
{
	return dl_match_controlled_client_by_pointer(server, NULL);
}

static int
dl_find_matching_client_slot(const struct dlog_broker_handle *server,
    const struct dl_broker_client *client)
{  
	return dl_match_controlled_client_by_pointer(server, client);
}

static dl_event_handler_handle
dl_get_server_socket(void* instance)
{
	const struct dlog_broker_handle *handle = instance;
	return handle->socket;
}

static void
dl_on_client_closed(void *server, void *closedClient)
{
	struct dlog_broker_handle *serverInstance = server;
	struct dl_broker_client *clientInstance = closedClient;
	int clientSlot;
	
	clientSlot = dl_find_matching_client_slot(serverInstance, clientInstance);
	if (0 > clientSlot) {
		printf("Phantom client detected");
	}
		       
	dl_broker_client_free(clientInstance);
		          
	serverInstance->clients[clientSlot] = NULL;
}

static void
dl_handle_read_event(void *instance)
{
	struct dlog_broker_handle *server = instance;
    	int free_slot;
       
	DLOGTR0(PRIO_LOW, "Client request\n");

	free_slot = dl_find_free_client_slot(server);
       	if (0 <= free_slot) {
		/* Define a callback for events requiring the actions of the
		 * server (for example a closed connection). */
	        struct ServerEventNotifier event_notifier = {0};
		event_notifier.server = server;
		event_notifier.on_client_closed = dl_on_client_closed;
				       
		server->clients[free_slot] = dl_broker_client_new(
		    server->socket, &event_notifier);
				               
		DLOGTR0(PRIO_LOW,
		    "Server: Incoming connect request accepted\n");
	} else {
		DLOGTR0(PRIO_HIGH, "Server: Not space for more clients\n");
	}
}

void
dlog_broker_init(const char *partition_name, struct broker_configuration *conf)
{

	DL_ASSERT(partition_name != NULL, "Partition name cannot be NULL");
	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");

	/* Install signal handler to terminate broker cleanly. */	
	signal(SIGINT, dl_sigint_handler);

	/* Install signal handler to report broker statistics. */
	signal(SIGINFO, dl_siginfo_handler);

	/* Create the specified partition; deleting if already present. */
	dl_del_folder(partition_name);
	dl_make_folder(partition_name);

	/* Preallocate 1024*1024 segement file. */
	ptr_seg = dl_make_segment(0, 1024*1024, partition_name);

	/* If the broker isn't configured to immediately fsync log entries,
	 * create the a queue used to asynchronously fsync requests.
	 */
	print_configuration(conf);
	if (!(conf->val & BROKER_FSYNC_ALWAYS)) {
		STAILQ_INIT(&unfsynced_responses);
		pthread_mutex_init(&unfsynced_responses_mtx, NULL);
		pthread_cond_init(&unfsynced_responses_cond, NULL);
		
		dl_start_fsync_thread(conf);
	}
}

/* TODO allow specifying which network interface to bind to */
struct dlog_broker_handle *
dlog_broker_create_server(int portnumber)
{
	struct dlog_broker_handle *handle;

	handle = (struct dlog_broker_handle *) dlog_alloc(
	    sizeof(struct dlog_broker_handle));
	if (handle != NULL ) {

		handle->socket = dl_init_listening_socket(portnumber);
        	handle->event_handler.dleh_instance = handle;
	        handle->event_handler.dleh_get_handle = dl_get_server_socket;
		handle->event_handler.dleh_handle_event = dl_handle_read_event;

		dl_poll_reactor_register(&handle->event_handler);
	}

	return handle;
}

void
dlog_broker_fini()
{
}
