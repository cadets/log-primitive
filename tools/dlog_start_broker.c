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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dlog_broker.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_utils.h"

/* Configure the distributed log logging level. */
unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const USAGE =
    "%s: [-t topic_name] [-h hostname] [-p port number] [-v]\n";

static char const * const DLB_DEFAULT_HOSTNAME  = "localhost";
static char const * const DLB_DEFAULT_TOPIC  = "default";
static const int DLB_DEFAULT_PORT = 9092;

static void dlb_siginfo_handler(int);
static void dlb_sigint_handler(int);

extern struct dlog_broker_statistics dlog_broker_stats;

static void
dlb_siginfo_handler(int sig)
{

	/* Report the broker statistics. */
	DLOGTR0(PRIO_HIGH, "Broker statistics:\n");
	DLOGTR1(PRIO_HIGH, "bytes read = %ld\n",
	    dlog_broker_stats.dlbs_bytes_read);
}

static void
dlb_sigint_handler(int sig)
{
	dl_debug(PRIO_LOW, "Caught SIGINT[%d]\n", sig);
	
	/* Deallocate the buffer used to store the user input. */
	//free(line);

	/* Finalise the distributed log client before finishing. */
	//dlog_broker_fini();

	exit(EXIT_SUCCESS);
}


/**
 * TODO
 */
int
main(int argc, char **argv)
{
	struct dlog_broker_handle *handle;
	struct broker_configuration bc;
	char const * hostname = DLB_DEFAULT_HOSTNAME;
	char const * topic = DLB_DEFAULT_TOPIC;
	int port = DLB_DEFAULT_PORT;
	int opt;
	
	dl_debug(PRIO_LOW, "Starting DLog broker...\n");

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "t::h::p::v")) != -1) {
		switch (opt) {
		case 't':
			topic = optarg;
			break;
		case 'h':
			hostname = optarg;
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
	signal(SIGINT, dlb_sigint_handler);

	/* Install signal handler to report broker statistics. */
	signal(SIGINFO, dlb_siginfo_handler);

	/* Configure and initialise the distributed log broker. */
	bc.fsync_thread_sleep_length = 1000;
	bc.processor_thread_sleep_length = 1000;
	bc.val = BROKER_FSYNC_ALWAYS;

	dlog_broker_init(topic, &bc);

	handle = dlog_broker_create_server(port, &bc);
	if (handle == NULL) {
		fprintf(stderr,
		    "Error initialising the distributed log client.\n");
		exit(EXIT_FAILURE);
	}
 
	for (;;) {

		dl_poll_reactor_handle_events();
	}

	/* Close the distributed log before finishing. */
	//dlog_broker_close(handle);

	//dlog_broker_fini(handle);

	return EXIT_SUCCESS;
}
