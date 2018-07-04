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

static char const * const DLOG = "/dev/dlog";
static char const * const HARNESS = "/dev/harness";

unsigned short PRIO_LOG = PRIO_LOW;

static int stop  = 0;

unsigned long topic_hashmask2;
LIST_HEAD(dld_parts, dld_part) *topic_hashmap2;

static void dlogd_stop(int);

static void
dlogd_stop(int sig)
{
	stop = 1;
}

int
main(void)
{
	struct dl_broker_topic *t;
	struct dl_client_config_desc *conf;
	struct dl_topic_desc *tp_desc;
	struct dl_transport *trans;
	struct dl_producer *producer;
	struct iovec iov[2];
	nvlist_t *props;
	struct sbuf *tname;
	char *line;
	int * tmp;
	int dlog, harness, rc;
	size_t len = 0, read = 0, packed_len;

	DLOGTR0(PRIO_LOW, "Dlog daemon starting...\n");

	//signal(SIGINT, dlogd_stop);

	/* Create the hashmap to store the names of the topics managed by the
	 * broker and their segments.
	 */
	//topic_hashmap2 = dl_topic_hashmap_new(10, &topic_hashmask2);

	/* Preallocate an initial segement file for the topic and add to the
	 * hashmap.
	 */
	/*
	tname = sbuf_new_auto();
	sbuf_cpy(tname, "cadets-trace");
	rc = dl_topic_new(&t, tname);
	rc = dl_transport_new(&trans);
	if (rc != 0)
		exit(EXIT_FAILURE);

	rc = dl_transport_connect(trans, "127.0.0.1", 9090);
	if (rc != 0)
		exit(EXIT_FAILURE);
	DLOGTR2(PRIO_LOW, "%d (%d)...\n", rc, errno);
	
	rc = dl_producer_new(&producer, t, trans);
	if (rc != 0)
		exit(EXIT_FAILURE);

	dl_topic_as_desc(t, &tp_desc);	
	rc = ioctl(dlog, DLOGIOC_ADDTOPICPART, &tp_desc);	
	if (rc != 0)
		exit(EXIT_FAILURE);
	DLOGTR3(PRIO_LOW, "%s %d (%d)...\n", DLOG, rc, errno);
*/
	dlog = open(DLOG, O_RDWR);
	if (dlog == -1)
		exit(EXIT_FAILURE);
	DLOGTR2(PRIO_LOW, "Successfully opened the %s device (%d)\n",
	    DLOG, dlog);


	props = nvlist_create(0);
	if (props == NULL)
		goto harness_exit;

	nvlist_add_string(props, DL_CONF_CLIENTID, "harness");
	nvlist_add_string(props, DL_CONF_TOPIC, "cadets-trace-0");

	conf = (struct dl_client_config_desc *) malloc(
	    sizeof(struct dl_client_config_desc));
	if (conf == NULL)
		goto err1;

	conf->dlcc_packed_nvlist = nvlist_pack(props, &packed_len); 
	conf->dlcc_packed_nvlist_len = packed_len;
	DLOGTR1(PRIO_LOW, "packed nvlist length = %d", packed_len);

	rc = ioctl(dlog, DLOGIOC_PRODUCER, &conf);	
	DLOGTR2(PRIO_LOW, "/dev/dlog %d (%d)...\n", rc, errno);
	if (rc != 0)
		exit(EXIT_FAILURE);

	harness = open(HARNESS, O_RDWR);
	if (harness == -1)
		exit(EXIT_FAILURE);
	DLOGTR2(PRIO_LOW, "Successfully opened the %s device (%d)\n",
	    HARNESS, harness);
	
	tmp = &dlog;	
	rc = ioctl(harness, HARNESSIOC_REGDLOG, &tmp);	
	if (rc != 0) {
		DLOGTR2(PRIO_LOW, "%d (%d)...\n", rc, errno);
		exit(EXIT_FAILURE);
	}
	DLOGTR2(PRIO_LOW, "%d (%d)...\n", rc, errno);

	/* Allocate memory for the user input. */	
	len = 1024; 
	line = malloc(1024* sizeof(char));
	if (line == NULL)
		exit(EXIT_FAILURE);
	
       	/* Echo from the command line to the distributed log. */	
	while ((read = getline(&line, &len, stdin) > 0)) {

		if (strcmp(line, "") != 0) {
			/* If the line is not empty, strip the newline and
			 * write to the distributed log.
			 */
			line[strlen(line) - 1] = '\0';

			iov[0].iov_base = "key";
			iov[0].iov_len = 3;

			iov[1].iov_base = line;
			iov[1].iov_len = strlen(line);

			rc = writev(harness, &iov[0], 2);
			if (rc != 0) {
				fprintf(stderr,
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
 
close_dlog:
	/* Close the distibuted log. */	
	DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	close(dlog);
		
err1:
	nvlist_destroy(props);

harness_exit:	
	DLOGTR0(PRIO_LOW, "Dlog daemon stopped.\n");

	return 0;
}
