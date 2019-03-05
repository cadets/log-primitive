/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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
#include <sys/dnv.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libutil.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <malloc_np.h>

#include "dlog.h"
#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_response.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

extern uint32_t hashlittle(const void *, size_t, uint32_t);

static char const * const DLOGD_PIDFILE = "/var/run/dlogd.pid";
static char const * const DLOGD_DEFAULT_CONFIG = "/etc/dlogd/dlogd.cfg";
static char const * const DLOG_DEV = "/dev/dlog";

struct dl_producer_elem {
	LIST_ENTRY(dl_producer_elem) dlp_entries;
	struct dl_producer *dlp_inst;
};

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

/* Global singleton dlogd configuration */
extern nvlist_t *dlogd_props;
nvlist_t *dlogd_props;

static int stop  = 0;
static char const* dlogd_name;
static LIST_HEAD(dl_producers, dl_producer_elem) *producers;
static unsigned long hashmask;
static int dlog;

static void
dlogd_stop(int sig __attribute__((unused)))
{

	stop = 1;
}

static void
dlogd_ignore_sigpipe(int sig __attribute__((unused)))
{

	DLOGTR0(PRIO_LOW, "Kafka closed read end of connection\n");
}

static int 
setup_daemon(void)
{
	long hashsize;
	int nelements;

	/* Open the DLog device */
	dlog = open(DLOG_DEV, O_RDWR);
	if (dlog == -1)  {

		DLOGTR2(PRIO_LOW, "Error opening %s (%d)\n", DLOG_DEV,
		    errno);
		return -1;
	}

	/* Create the hashmap to store producers for the topics managed by the
	 * dlog daemon.
	 */
	nelements = dnvlist_get_number(dlogd_props,
		DL_CONF_NELEMENTS, DL_DEFAULT_NELEMENTS);
	for (hashsize = 1; hashsize <= nelements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	producers = dlog_alloc(
	    (unsigned long) hashsize * sizeof(*producers));
	if (producers == NULL) {

		DLOGTR2(PRIO_LOW, "Error opening %s (%d)\n", DLOG_DEV,
		    errno);
		return -1;
	}

	for (int i = 0; i < hashsize; i++)
		LIST_INIT(&producers[i]);
	hashmask = hashsize -1;

	return 0;
}

static int
dlogd_manage_topic(char * topic_name, char *hostname, int64_t port)
{
	struct dl_producer *producer;
	struct dl_producer_elem *elem;
	struct dl_topic_desc *topic_desc;
	struct dl_topic *topic;
	char *log_path;
	uint32_t h;
	int rc;

	/* Get the comnfigured log path from the properties. */
	log_path = dnvlist_get_string(dlogd_props, DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

	/* Preallocate an initial segment file for the topic and add
	 * to the hashmap.
	 */
	rc = dl_topic_new(&topic, topic_name, log_path);
	if (rc == 0) {

		rc = dl_topic_as_desc(topic, &topic_desc);	
		if (rc == 0) {
			rc = ioctl(dlog, DLOGIOC_ADDTOPICPART,
				&topic_desc);	
			if (rc == 0) {
				rc = dl_producer_new(&producer, topic,
					log_path, hostname, port, dlogd_props); 
				if (rc == 0) {
					elem = (struct dl_producer_elem *) dlog_alloc(sizeof(struct dl_producer_elem));
					elem->dlp_inst = producer;

					h = hashlittle(topic_name,
						strlen(topic_name), 0);
					LIST_INSERT_HEAD(
					    &producers[h & hashmask],
					    elem, dlp_entries); 
				} else {
					ioctl(dlog, DLOGIOC_DELTOPICPART,
					    &topic_desc);	
				}
			
				dlog_free(topic_desc);
			} else {
				DLOGTR1(PRIO_HIGH,
					"Failed to configure topic %s\n",
					topic_name);
				dlog_free(topic_desc);
				dl_topic_delete(topic);
				return -1;
			}
		} else {
			DLOGTR1(PRIO_HIGH,
				"Failed to create topic %s\n", topic_name);
			dl_topic_delete(topic);
			return -1;
		}
	} else {
		DLOGTR1(PRIO_HIGH, "Failed to create topic %s\n",
		    topic_name);
		return -1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	char const *conf_file = DLOGD_DEFAULT_CONFIG;
	char *topic_name, *hostname;
	struct dl_producer_elem *p, *p_tmp;	
	struct dl_topic *topic_tmp;
	nvlist_t *topics, *topic;
	void *cookie = NULL;
	int64_t port;
	struct pidfh *pfh;
	pid_t pid;
	int c, rc, type, dlogd_debug = 0;

	dlogd_name = basename(argv[0]); 	

	/* Parse the dlogd command line arguments */
	opterr = 0;
	while ((c = getopt(argc, argv, "dc:")) != -1) {
		switch(c) {
		case 'c':
			/* Configuration file option */
			conf_file = optarg;
			break;
		case 'd':
			/* Debug option */
			dlogd_debug++;
			break;
		case '?':
		default:
			errx(EXIT_FAILURE,
			    "Usage: %s [-d] [-c config_file]\n", dlogd_name);
		}
	}

	/* Create a pid file for the dlogd daemon. */
	pfh = pidfile_open(DLOGD_PIDFILE, 0600, &pid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			errx(EXIT_FAILURE,
			    "Daemon already running, pid: %d", pid);
		}
		DLOGTR0(PRIO_HIGH, "Cannot open or create pid file\n");
	}

	if (dlogd_debug > 0) {

		/* Configure syslog to copy error messages to stderr. */
		openlog(dlogd_name, LOG_PERROR, LOG_USER);
	} else { 
		if (daemon(0, 0) == -1) {

			pidfile_remove(pfh);
			errx(EXIT_FAILURE,
			    "Failed registering dlogd as daemon\n");
		}
	}

	/* Write the pid */
	pidfile_write(pfh);

	DLOGTR1(PRIO_LOW, "%s daemon starting...\n", dlogd_name);

	/* Parse the configuration file. */
	rc = dl_config_new(conf_file, dlogd_debug);
	if (rc != 0) {

		pidfile_remove(pfh);
		errx(EXIT_FAILURE, "Failed parsing dlogd configuration file\n");
	}
	
	if (setup_daemon() != 0) {

		pidfile_remove(pfh);
		errx(EXIT_FAILURE, "Failed setting up dlogd as daemon\n");
	}

	/* Iterate over the configured topics. */
	topics = nvlist_take_nvlist(dlogd_props, DL_CONF_TOPICS);
	while ((topic_name = nvlist_next(topics, &type, &cookie)) != NULL) {
				
		switch (type) {
		case NV_TYPE_NVLIST: 
	
			if (nvlist_exists_nvlist(topics, topic_name)) {
				topic = nvlist_get_nvlist(topics, topic_name);

				hostname = dnvlist_get_string(topic, DL_CONF_BROKER,
				    DL_DEFAULT_BROKER);

				port = dnvlist_get_number(topic,
				    DL_CONF_BROKER_PORT, DL_DEFAULT_BROKER_PORT);

				rc = dlogd_manage_topic(topic_name, hostname, port);
				if (rc != 0)
					DLOGTR1(PRIO_HIGH,
					    "Failed configuring topic %s\n", topic_name);
			} else {
				DLOGTR1(PRIO_HIGH,
			    	    "Topic %s details missing\n", topic_name);
			}
			break;
		default:
			DLOGTR1(PRIO_HIGH,
			    "Invalid nvlist type for topic %s\n", topic_name);
			break;
		}
	}

	/* Register signal handler to terminate dlogd */
	signal(SIGINT, dlogd_stop);

	/* Register signal handler to ignore sigpipe */
	signal(SIGPIPE, dlogd_ignore_sigpipe);
	
	/* Handle any events registered for the configured topics/producers. */
	while (stop == 0) {

		dl_poll_reactor_handle_events();
	}

	/* Destroy the nvlist used to store producer configuration. */
	nvlist_destroy(dlogd_props);

	/* Delete all of the producers */
	DLOGTR0(PRIO_LOW, "Deleting the producers.\n");
	for (unsigned int p_it = 0; p_it < hashmask + 1 ; p_it++) {
		LIST_FOREACH_SAFE(p, &producers[p_it], dlp_entries, p_tmp) {

			LIST_REMOVE(p, dlp_entries);

			topic_tmp = dl_producer_get_topic(p->dlp_inst);
			DL_ASSERT(topic_tmp != NULL,
			    ("Producer topic cannot be NULL"));
			
			DLOGTR1(PRIO_LOW,
			    "Deleting the topic %s producer.\n",
			    sbuf_data(dl_topic_get_name(topic_tmp)));
				
			/* Destroy the nvlist used to store the topic details. */
			if (nvlist_exists_nvlist(topics,
			    sbuf_data(dl_topic_get_name(topic_tmp)))) {
				    topic = nvlist_take_nvlist(topics,
			    		sbuf_data(dl_topic_get_name(topic_tmp)));
				nvlist_destroy(topic);
			}
	
			/* Delete the topic producer */
			dl_producer_delete(p->dlp_inst);
	
			/* Delete the producer element */
			dlog_free(p);
		}
	}
	
	/* Destroy the nvlist used to store configured topics. */
	nvlist_destroy(topics);

	/* Delete the producer hashmap */
	DLOGTR0(PRIO_LOW, "Deleting the producer hashmap.\n");
	dlog_free(producers);

	/* Close the distibuted log. */	
	DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	rc = close(dlog);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error closing distributed log %d\n",
		    errno);

	if (dlogd_debug > 0)
		closelog();

	pidfile_remove(pfh);

	DLOGTR1(PRIO_LOW, "%s daemon stopped.\n", dlogd_name);
	
	return 0;
}
