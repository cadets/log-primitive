/*-
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
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "distlog_client.h"
#include "dl_utils.h"

/* Configure the distributed log logging level. */
unsigned short PRIO_LOG = PRIO_HIGH;

static char const * const USAGE =
    "%s: [-p port number] [-t topic] [-h hostname]\n";

static char const * const DEFAULT_CLIENT_ID = "distlog_console_producer";
static char const * const DEFAULT_TOPIC  = "test";
static char const * const DEFAULT_HOSTNAME  = "localhost";
static const int DEFAULT_PORT = 9092;
static const int DISTLOG_RECORD_SIZE_BYTES = 4096;

static void on_ack(unsigned long);
// TODO: why isn't this dl_request_message and dl_response_message?
static void on_response(struct request_message *, struct response_message *);

static void
on_ack(unsigned long correlation_id)
{
}

static void
on_response(struct request_message *rm, struct response_message *rs)
{
}

/**
 * Utility for writing to the distributed log from the console.
 */
int
main(int argc, char **argv)
{
	struct client_configuration cc;
	char * client_id = DEFAULT_CLIENT_ID;
	char * topic = DEFAULT_TOPIC;
	char * hostname = DEFAULT_HOSTNAME;
	char * line;
	int port = DEFAULT_PORT;
	int resend_timeout = 40;
	int opt, rc;
	size_t len = 0;
	size_t read = 0;

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "c::t::h::p::")) != -1) {
		switch (opt) {
		case 'c':
			client_id = optarg;
			break;
		case 't':
			topic = optarg;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		default:
			fprintf(stderr, USAGE, argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

	/* Configure and initialise the distributed log client. */
	cc.to_resend = true;
	cc.resender_thread_sleep_length = 10;
	cc.request_notifier_thread_sleep_length = 3;
	cc.reconn_timeout = 5;
	cc.poll_timeout = 3000;
	cc.on_ack = on_ack;
	cc.on_response = on_response;

	rc = distlog_client_init(hostname, port, &cc);
        if (rc != 0) {

		fprintf(stderr,
		    "Error initialising the distributed log client %d.\n",
		    rc);
		exit(EXIT_FAILURE);
	}
  
       	/* Allocate memory for the user input. */	
	len = DISTLOG_RECORD_SIZE_BYTES; 
	line = malloc(len * sizeof(char));

       	/* Echo from the command line to the distributed log. */	
	while ((read = getline(&line, &len, stdin) > 0)) {

		if (strcmp(line, "") != 0) {
			/* If the line is not empty, strip the newline and
			 * write to the distributed log.
			 */
			line[strlen(line) - 1] = '\0';

			rc = distlog_send_request(0, REQUEST_PRODUCE,
			    client_id, cc.to_resend, resend_timeout, topic,
			    1, "key", line);
			if (rc != 0) {
				fprintf(stderr,
				    "Failed writing to the log %d\n", rc); 
				break;
			}
		}
	}

	/* Deallocate the buffer used to store the user input. */
	free(line);

	/* Finalise the distributed log before finishing. */
	distlog_client_fini();

	return 0;
}
