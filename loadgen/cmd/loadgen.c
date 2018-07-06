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

#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "dl_config.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_response.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

#define DLOGIOC_PRODUCER _IOWR('d', 1, struct dl_client_config)
#define DLOGIOC_ADDTOPICPART _IOWR('d', 2, struct dl_client_config)
#define DLOGIOC_DELTOPICPART _IOWR('d', 3, struct dl_client_config)
#define DLOGIOC_ADDSEG _IOWR('d', 4, struct dl_client_config)
#define DLOGIOC_DELSEG _IOWR('d', 5, struct dl_client_config)

#define HARNESSIOC_REGDLOG _IOWR('d', 1, struct dl_client_config)

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const DLC_DEFAULT_CLIENT_ID = "loadgen";
static char const * const DLOG = "/dev/dlog";
static char const * const HARNESS = "/dev/harness";
static char const * const USAGE = "%s: [-c client id] [-t topic] [-v]\n";

unsigned short PRIO_LOG = PRIO_LOW;

static int stop  = 0;

unsigned long topic_hashmask2;
LIST_HEAD(dld_parts, dld_part) *topic_hashmap2;

int
main(int argc, char **argv)
{
	struct dl_broker_topic *t;
	struct dl_client_config_desc *conf;
	struct dl_topic_desc *tp_desc;
	struct dl_transport *trans;
	struct dl_producer *producer;
	struct iovec iov[2];
	nvlist_t *props;
	struct sbuf *tname;
	char *client_id = (char *) DLC_DEFAULT_CLIENT_ID;
	char *line, *sep;
	int *harg;
	int dlog, harness, iocnt, opt, rc;
	size_t len = 0, packed_len;
	ssize_t read;

	/* Parse the utilities command line arguments. */
	while ((opt = getopt(argc, argv, "c:t:h:p:v")) != -1) {
		switch (opt) {
		case 'c':
			client_id = optarg;
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
	
	DLOGTR0(PRIO_LOW, "Dlog daemon starting...\n");

	dlog = open(DLOG, O_RDWR);
	if (dlog == -1)
		goto harness_exit;
	DLOGTR2(PRIO_LOW, "Opened the %s device (%d)\n", DLOG, dlog);

	props = nvlist_create(0);
	if (props == NULL)
		goto close_dlog;

	nvlist_add_string(props, DL_CONF_CLIENTID, client_id);
	nvlist_add_string(props, DL_CONF_TOPIC, "cadets-trace-0");

	conf = (struct dl_client_config_desc *) malloc(
	    sizeof(struct dl_client_config_desc));
	if (conf == NULL)
		goto close_producer;

	conf->dlcc_packed_nvlist = nvlist_pack(props, &packed_len); 
	conf->dlcc_packed_nvlist_len = packed_len;

	rc = ioctl(dlog, DLOGIOC_PRODUCER, &conf);	
	if (rc != 0)
		goto close_producer;
	DLOGTR0(PRIO_LOW, "Created DLog producer\n");

	harness = open(HARNESS, O_RDWR);
	if (harness == -1)
		goto close_harness;
	DLOGTR2(PRIO_LOW, "Opened the %s device (%d)\n", HARNESS, harness);

	/* Configure the test harness with the DLog device fd. */	
	harg = &dlog;	
	rc = ioctl(harness, HARNESSIOC_REGDLOG, &harg);	
	if (rc != 0)
		goto close_harness;

	/* Allocate memory for the user input. */	
	len = 1024;
	line = malloc(1024 * sizeof(char));
	if (line == NULL)
		goto close_harness;
	
       	/* Echo from the command line to the distributed log. */	
	while ((read = getline(&line, &len, stdin)) > 0) {

		if (read > 1) {
			/* Parse the input either a value or key=value */
			sep = strchrnul(line, '=');
		
			if ((sep - line) == read ) {
				iocnt = 1;

				iov[0].iov_base = line;
				iov[0].iov_len = read - 1;
			} else {
				iocnt = 2;

				iov[0].iov_base = line;
				iov[0].iov_len = sep - line;

				iov[1].iov_base = ++sep;
				iov[1].iov_len = (read - 1) - (sep - line);
			}

			/* Write to the distributed log. */
			rc = writev(harness, &iov[0], iocnt);
			if (rc != 0) {
				DLOGTR1(PRIO_HIGH,
				    "Failed writing to the log %d\n", rc); 
				break;
			}
		}
	}

	/* Deallocate the buffer used to store the user input. */
	free(line);

close_harness:
	/* Close the load generator harness.  */	
	DLOGTR0(PRIO_LOW, "Closing load generator harness.\n");
	close(harness);
		
close_producer:
	nvlist_destroy(props);
 
close_dlog:
	/* Close the distibuted log. */	
	DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	close(dlog);

harness_exit:	
	DLOGTR0(PRIO_LOW, "Dlog daemon stopped.\n");

	return 0;
}
