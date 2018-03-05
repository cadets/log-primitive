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
 *
 */

#include <sbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dlog_client.h"
#include "dl_memory.h"
#include "dl_utils.h"

static void dlp_siginfo_handler(int);
static void dlp_sigint_handler(int);
static void dlp_on_response(struct dl_response const * const);

/* Configure the distributed log logging level. */
unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const USAGE =
    "%s: [-p port number] [-t topic] [-h hostname] [-v]\n";

static char const * const DLC_DEFAULT_CLIENT_ID = "dlog_console_producer";
static char const * const DLC_DEFAULT_TOPIC  = "default";
static char const * const DLC_DEFAULT_HOSTNAME  = "localhost";
static const int DLC_DEFAULT_PORT = 9092;
static const int DLC_DISTLOG_RECORD_SIZE_BYTES = 4096;

static void
dlp_siginfo_handler(int sig)
{

	dl_debug(PRIO_LOW, "Caught SIGIFO[%d]\n", sig);
}

static void
dlp_sigint_handler(int sig)
{

	dl_debug(PRIO_LOW, "Caught SIGINT[%d]\n", sig);
	
	/* Deallocate the buffer used to store the user input. */
	//free(line);

	/* Finalise the distributed log client before finishing. */
	//dlog_client_fini();

	exit(EXIT_SUCCESS);
}

static void
dlp_on_response(struct dl_response const * const response)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_partition *produce_partition;
	struct dl_produce_response_topic *produce_topic;
	int partition;

	dl_debug(PRIO_LOW, "response size = %d\n", response->dlrs_size);
	dl_debug(PRIO_LOW, "correlation id = %d\n", response->dlrs_correlation_id);
	dl_debug(PRIO_LOW, "api key= %d\n", response->dlrs_api_key);

	switch (response->dlrs_api_key) {
	case DL_PRODUCE_API_KEY:
		produce_response = response->dlrs_message.dlrs_produce_message;

		dl_debug(PRIO_LOW, "ntopics= %d\n", produce_response->dlpr_ntopics);

		SLIST_FOREACH(produce_topic,
			&produce_response->dlpr_topics, dlprt_entries) {

			dl_debug(PRIO_LOW, "Topic: %s\n",
				produce_topic->dlprt_topic_name);

			for (partition = 0;
			    partition < produce_topic->dlprt_npartitions;
			    partition++) {

				dl_debug(PRIO_LOW, "Partition: %d\n",
				    produce_topic->dlprt_partitions[partition].dlprp_partition);

				dl_debug(PRIO_LOW, "ErrorCode: %d\n",
				    produce_topic->dlprt_partitions[partition].dlprp_error_code);

				dl_debug(PRIO_LOW, "Base offset: %d\n",
					produce_topic->dlprt_partitions[partition].dlprp_offset);
			};
		};
		break;
	default:
		dl_debug(PRIO_HIGH, "Unexcepted Response %d\n",
		    response->dlrs_api_key);
		break;
	}

}

/**
 * Utility for writing to the distributed log from the console.
 */
int
main(int argc, char **argv)
{
	struct dlog_handle *handle;
	struct dl_client_configuration cc;
	struct sbuf *client_id = NULL;
	struct sbuf *hostname = NULL;
	struct sbuf *topic = NULL;
	char * line;
	int port = DLC_DEFAULT_PORT;
	int resend_timeout = 40;
	int opt, rc;
	size_t len = 0;
	size_t read = 0;

	/* Configure the default values. */
	sbuf_cpy(client_id, DLC_DEFAULT_CLIENT_ID);
	sbuf_cpy(hostname, DLC_DEFAULT_HOSTNAME);
	sbuf_cpy(topic, DLC_DEFAULT_TOPIC);

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "c::t::h::p::v")) != -1) {
		switch (opt) {
		case 'c':
			sbuf_cpy(client_id, optarg);
			break;
		case 't':
			sbuf_cpy(topic, optarg);
			break;
		case 'h':
			sbuf_cpy(hostname, optarg);
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			PRIO_LOG = PRIO_LOW;
			break;
		default:
			fprintf(stderr, USAGE, argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

	/* Install signal handler to terminate broker cleanly on SIGINT. */	
	signal(SIGINT, dlp_sigint_handler);

	/* Install signal handler to report broker statistics. */
	signal(SIGINFO, dlp_siginfo_handler);

	/* Configure and initialise the distributed log client. */
	cc.dlcc_on_response = dlp_on_response;
	cc.dlcc_client_id = client_id;
	cc.to_resend = true;
	cc.resend_timeout = resend_timeout;
	cc.resender_thread_sleep_length = 10;
	cc.request_notifier_thread_sleep_length = 3;
	cc.reconn_timeout = 5;
	cc.poll_timeout = 3000;

	handle = dlog_client_open(hostname, port, &cc);
        if (handle == NULL) {
		fprintf(stderr,
		    "Error initialising the distributed log client.\n");
		exit(EXIT_FAILURE);
	}
  
       	/* Allocate memory for the user input. */	
	len = DLC_DISTLOG_RECORD_SIZE_BYTES; 
	line = malloc(len * sizeof(char));

       	/* Echo from the command line to the distributed log. */	
	while ((read = getline(&line, &len, stdin) > 0)) {

		if (strcmp(line, "") != 0) {
			/* If the line is not empty, strip the newline and
			 * write to the distributed log.
			 */
			line[strlen(line) - 1] = '\0';

			rc = dlog_produce(handle, topic,
			    "key", strlen("key"), line, strlen(line));
			if (rc != 0) {
				fprintf(stderr,
				    "Failed writing to the log %d\n", rc); 
				break;
			}
		}
	}

	/* Deallocate the buffer used to store the user input. */
	free(line);

	/* Close the distributed log before finishing. */
	dlog_client_close(handle);

	sbuf_delete(topic);
	sbuf_delete(hostname);
	sbuf_delete(client_id);

	return 0;
}
