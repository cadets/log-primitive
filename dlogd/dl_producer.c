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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_config.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_request.h"
#include "dl_request_queue.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

typedef enum dl_producer_state {
	DLP_INITIAL,
	DLP_IDLE,
	DLP_SYNCING,
	DLP_OFFLINE,
	DLP_CONNECTING} dl_producer_state;

struct dl_producer {
	LIST_ENTRY(dl_prodcuer) dlp_entries;
	struct dl_correlation_id *dlp_cid;
	struct dl_event_handler dlp_trans_hdlr;
	struct dl_event_handler dlp_kq_hdlr;
	struct dl_event_handler dlp_ktimer_hdlr;
	struct dl_request_q *dlp_request_q;
	struct dl_topic *dlp_topic;
	struct dl_transport *dlp_transport;
	dl_producer_state dlp_state;
	pthread_t dlp_produce_tid;
	pthread_t dlp_resender_tid;
	pthread_cond_t dlp_suspend_cond;
	pthread_mutex_t dlp_mtx;
	struct sbuf *dlp_broker_hostname;
	struct sbuf *dlp_name;
	int dlp_broker_port;
	int dlp_exit;
	int dlp_suspend;
	int dlp_ktimer;
	int dlp_reconn_ms;
	int offset;
	int resend_timeout;
	int resend_period;
};

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_syncing(struct dl_producer * const self);
static void dl_producer_offline(struct dl_producer * const self);
static void dl_producer_connecting(struct dl_producer * const self);

static dl_event_handler_handle dlp_get_transport_fd(void *);
static void dlp_transport_hdlr(void *, int, int);
static dl_event_handler_handle dl_producer_get_kq_fd(void *);
static void dl_producer_kq_handler(void *, int, int);
static dl_event_handler_handle dl_producer_get_timer_fd(void *);
static void dl_producer_timer_handler(void *instance, int, int);

static void *dlp_produce_thread(void *vargp);
static void *dlp_resender_thread(void *vargp);

static const off_t DL_FSYNC_DEFAULT_CHARS = 1024*1024;
static const int NOTIFY_IDENT = 1337;
static const int DLP_MINRECONN_MS = 1000;
static const int DLP_MAXRECONN_MS = 60000;

static inline void 
dl_producer_check_integrity(struct dl_producer const * const self)
{

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(self->dlp_cid != NULL,
	    ("Producer correlation id cannot be NULL."));
	DL_ASSERT(self->dlp_request_q != NULL,
	    ("Producer request queue cannot be NULL."));
	DL_ASSERT(self->dlp_topic != NULL,
	    ("Producer topic cannot be NULL."));
	DL_ASSERT(self->dlp_name != NULL,
	    ("Producer instance cannot be NULL."));
}

static dl_event_handler_handle
dlp_get_transport_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	return dl_transport_get_fd(p->dlp_transport);
}

static void 
dlp_transport_hdlr(void *instance, int fd, int revents)
{
	struct dl_producer * const self = instance;
	struct dl_request_element *request, *request_temp;
	struct dl_response *response;
	struct dl_response_header *header;
	struct dl_bbuf *buffer;
	struct kevent kev;
	socklen_t len;
	int rc, err;
	
	dl_producer_check_integrity(self);

	if (revents & (POLLHUP | POLLERR)) {

		len = sizeof(int);
		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (err == ECONNREFUSED) {
			DLOGTR0(PRIO_LOW, "Connection refused\n");
		}
		
		dl_producer_down(self);
		return;
	}

	if (revents & POLLIN) {

		if (dl_transport_read_msg(self->dlp_transport, &buffer) == 0) {

			DLOGTR0(PRIO_LOW, "Response\n");
			unsigned char *bufval = dl_bbuf_data(buffer);
			for (int i = 0; i < dl_bbuf_len(buffer); i++) {
				DLOGTR1(PRIO_LOW, "<0x%02hhX>", bufval[i]);
			};
			DLOGTR0(PRIO_LOW, "\n");

			/* Flip the buffer as we are now reading values from
			 * it.
			 */
			dl_bbuf_flip(buffer);

			/* Deserialise the response header. */
			if (dl_response_header_decode(&header, buffer) == 0) {

				DLOGTR1(PRIO_LOW, "Got response id = : %d\n",
				    header->dlrsh_correlation_id);

				/* Acknowledge the request message based
				 * on the CorrelationId returned in the response.
				 */
				dl_request_q_lock(self->dlp_request_q);
				request = STAILQ_FIRST(
				    &self->dlp_request_q->dlrq_unackd_requests);

				if (request->dlrq_correlation_id ==
				    header->dlrsh_correlation_id) {

					DLOGTR1(PRIO_HIGH,
					    "Found unack'd request id: %d\n",
					    header->dlrsh_correlation_id);
					switch (request->dlrq_api_key) {
					case DL_PRODUCE_API_KEY:
						dl_produce_response_decode(
						    &response, buffer);
						break;
					case DL_FETCH_API_KEY:
						dl_fetch_response_decode(
						    &response, buffer);
						break;
					case DL_OFFSET_API_KEY:
						dl_list_offset_response_decode(
						    &response, buffer);
						break;
					default:
						DLOGTR1(PRIO_HIGH,
						    "Request ApiKey is invalid (%d)\n",
						    request->dlrq_api_key);
						break;
					}

					/* The request has been acknowleded
					 * and can now be freed.
					 */
					STAILQ_REMOVE_HEAD(
					    &self->dlp_request_q->dlrq_unackd_requests,
					    dlrq_entries);
					self->dlp_request_q->dlrq_len--;
					dlog_free(request);

					/* Invoke the client callback. */
					//if (response != NULL) { // &&
					    //handle->dlh_config->dlcc_on_response != NULL) {
					//	handle->dlh_config->dlcc_on_response(
					//	    response);
					//	dlog_free(response);
					//}
				} else {
					/* The log's response doesn't
					 * correspond to the client's most
					 * recent request.
					 */
					DLOGTR1(PRIO_HIGH,
					    "Couldn't find unack'd request id: "
					    "%d\n",
					    header->dlrsh_correlation_id);	

					//STAILQ_FOREACH_SAFE(request,

					//    &self->dlp_request_q->dlrq_unackd_requests,
					//    dlrq_entries, request_temp) {
					//    }

;
				}
				dl_request_q_unlock(self->dlp_request_q);
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Error decoding response header.\n");
			}

			// TODO: Free the dl_bbuf instance
			// dl_bbuf_delete(buffer);
			// dl_response
		} else {
			/* Server disconnected. */
			dl_producer_down(self);
			return;

		}
	}

	if (revents & POLLOUT) {

		len = sizeof(int);
		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (rc == 0) {
			if (err == 0) {
				DLOGTR0(PRIO_LOW, "Connected\n");

				self->dlp_reconn_ms = DLP_MINRECONN_MS;	
				dl_poll_reactor_unregister(
				    &self->dlp_trans_hdlr);
				dl_poll_reactor_register(&self->dlp_trans_hdlr,
				    POLLIN|POLLHUP|POLLERR);
				dl_producer_up(self);
			} 
		} else {
			dl_producer_down(self);
		}
	}
}

static dl_event_handler_handle
dl_producer_get_kq_fd(void *instance)
{
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;

	dl_producer_check_integrity(p);

	seg = dl_topic_get_active_segment(p->dlp_topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));
	return seg->_klog;
}

static void 
dl_producer_kq_handler(void *instance, int fd, int revents)
{
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;
	struct kevent event;
	off_t log_position;
	int rc;
	
	dl_producer_check_integrity(p);
	
	seg = dl_topic_get_active_segment(p->dlp_topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));

	rc = kevent(seg->_klog, 0, 0, &event, 1, 0);
	if (rc == -1)
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.", rc,
		    errno);
	else {
		dl_segment_lock(seg);
		log_position = lseek(seg->_log, 0, SEEK_END);
		dl_segment_unlock(seg);
		if (log_position - seg->last_sync_pos >
		    DL_FSYNC_DEFAULT_CHARS) {

			dl_segment_lock(seg);
			dl_index_update(seg->dls_idx);
			fsync(seg->_log);
			dl_segment_set_last_sync_pos(seg, log_position);
			dl_segment_unlock(seg);

			dl_producer_produce(p);
		}
	}
}

static dl_event_handler_handle
dl_producer_get_timer_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	return p->dlp_ktimer;
}

static void 
dl_producer_timer_handler(void *instance, int fd, int revents)
{
	struct dl_producer const * const p = instance;
	struct kevent event;
	off_t log_position;
	int rc;
	
	dl_producer_check_integrity(p);
	
	rc = kevent(p->dlp_ktimer, 0, 0, &event, 1, 0);
	if (rc == -1) {
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	} else {

		DLOGTR0(PRIO_LOW, "Re-connect timeout\n");
		dl_producer_reconnect(p);
	}
}

static void *
dlp_resender_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *) vargp;
	struct dl_request_element *request, *request_temp;
	time_t now;
	int old_cancel_state;

	dl_producer_check_integrity(self);

	DLOGTR0(PRIO_LOW, "Resender thread started\n");

	for (;;) {
		pthread_mutex_lock(&self->dlp_mtx);
		while (self->dlp_suspend != 0) {
			DLOGTR0(PRIO_LOW, "Resender thread suspended.\n");
			pthread_cond_wait(&self->dlp_suspend_cond,
			    &self->dlp_mtx);
		}
		pthread_mutex_unlock(&self->dlp_mtx);
		pthread_cond_broadcast(&self->dlp_suspend_cond);

		//dlrq_unackd_it_new()
		//while (dlrq_it_has_next(unackd_it) != 0) {
		//    //request = dlrq_it_next)unackd_it);
		//}
		//dlrq_unackd_it_delete()
		dl_request_q_lock(self->dlp_request_q);
		STAILQ_FOREACH_SAFE(request,
		    &self->dlp_request_q->dlrq_unackd_requests,
		    dlrq_entries, request_temp) {

			now = time(NULL);

			DLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
			    "Resend when the difference is %d. "
			    "Current: %lu\n",
			    request->dlrq_last_sent, now,
			    self->resend_timeout, 
			    now - request->dlrq_last_sent);

			if ((now - request->dlrq_last_sent) >
			    self->resend_timeout) {
				request->dlrq_last_sent = time(NULL);

				STAILQ_REMOVE(
				    &self->dlp_request_q->dlrq_unackd_requests,
				    request, dl_request_element, dlrq_entries);

				/* Resend the request. */
				dl_request_q_enqueue(
				    self->dlp_request_q, request);
				
				DLOGTR0(PRIO_LOW, "Resending request.\n");
			}
		}
		dl_request_q_unlock(self->dlp_request_q);

		pthread_mutex_lock(&self->dlp_mtx);
		if (self->dlp_exit != 0) {
			pthread_mutex_unlock(&self->dlp_mtx);
			break;
		}
		pthread_mutex_unlock(&self->dlp_mtx);
		
		sleep(self->resend_period);
	}

	DLOGTR0(PRIO_LOW, "Resender thread stopped.\n");
	pthread_exit(NULL);
}

static void *
dlp_produce_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *) vargp;
	struct dl_request_element *request, *request_temp;
	int rv, msg_size, old_cancel_state, port;
	ssize_t nbytes;

	dl_producer_check_integrity(self);
	
	DLOGTR0(PRIO_LOW, "Producer thread started...\n");

	DLOGTR0(PRIO_LOW, "Dequeuing requests...\n");

	for (;;) {

		pthread_mutex_lock(&self->dlp_mtx);
		while (self->dlp_suspend != 0) {
			DLOGTR0(PRIO_LOW, "Produce thread suspended.\n");
			pthread_cond_wait(&self->dlp_suspend_cond,
			    &self->dlp_mtx);
		}
		pthread_mutex_unlock(&self->dlp_mtx);
		pthread_cond_broadcast(&self->dlp_suspend_cond);
	
		if (dl_request_q_dequeue(self->dlp_request_q, &request) == 0) {

			nbytes = dl_transport_send_request(
			    self->dlp_transport, request->dlrq_buffer);
			if (nbytes != -1) {

				DLOGTR2(PRIO_LOW,
				    "Successfully sent request "
				    "(nbytes = %zu, bytes = %zu)\n",
				    nbytes, dl_bbuf_pos(request->dlrq_buffer));

				DLOGTR1(PRIO_LOW,
				    "Successfully sent request (id = %d)\n",
				    request->dlrq_correlation_id);

				/* The request must be acknowledged, store
				 * the request until an acknowledgment is
				 * received from the broker.
				 */

				/* Successfuly send the request,
				 * record the last send time.
				 */
				request->dlrq_last_sent = time(NULL);

				DLOGTR1(PRIO_NORMAL, "Processed request %d\n",
				    request->dlrq_correlation_id);

			} else {
				// TODO: proper errro handling is necessary
				DLOGTR1(PRIO_NORMAL,
				    "Transport send error (%d)\n", errno);

				// TODO: Don't think I need to do this
				// as the poll reactor is handling errors?
				dl_producer_down(self);
			}
		} else {
			pthread_mutex_lock(&self->dlp_mtx);
			if (self->dlp_exit != 0) {
				pthread_mutex_unlock(&self->dlp_mtx);
				break;
			}
			pthread_mutex_unlock(&self->dlp_mtx);
		}
	}

	DLOGTR0(PRIO_LOW, "Produce thread stopped.\n");
	pthread_exit(NULL);
}

static void
dl_producer_connecting(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_CONNECTING;
	DLOGTR1(PRIO_LOW, "Producer state = CONNECTING (%d)\n",
	    self->dlp_state);

	rc = dl_transport_new(&self->dlp_transport);
	if (rc == 0) {

		dl_transport_connect(self->dlp_transport,
		    sbuf_data(self->dlp_broker_hostname),
		    self->dlp_broker_port);

		self->dlp_trans_hdlr.dleh_instance = self;
		self->dlp_trans_hdlr.dleh_get_handle =
		    dlp_get_transport_fd;
		self->dlp_trans_hdlr.dleh_handle_event =
		    dlp_transport_hdlr;

		dl_poll_reactor_register(&self->dlp_trans_hdlr,
		    POLLERR | POLLOUT | POLLHUP);
	} else {
		DLOGTR2(PRIO_HIGH, "Failed connecting to %s:%d\n",
		    sbuf_data(self->dlp_broker_hostname),
		    self->dlp_broker_port);

		dl_producer_down(self);
	}
}

static void
dl_producer_idle(struct dl_producer * const self)
{
	struct dl_bbuf *idx_buf, *t;
	struct dl_segment *seg;
	off_t log_position;
	int32_t roffset, poffset, tmp_buf[2];
	int rc;

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_IDLE;
	DLOGTR1(PRIO_LOW, "Producer state = IDLE (%d)\n", self->dlp_state);
}

static void
dl_producer_syncing(struct dl_producer * const self)
{
	struct dl_topic *topic = self->dlp_topic;
	uint32_t h;
	struct dl_bbuf *buffer, *msg_buffer;
	struct dl_request *message;
	struct dl_transport *transport;
	struct timespec ts;
	struct timeval now;
	int rv, msg_size, old_cancel_state, port;
	int rc;

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_SYNCING;
	DLOGTR1(PRIO_LOW, "Producer state = SYNCING (%d)\n", self->dlp_state);
	
	pthread_mutex_lock(&self->dlp_mtx);
    	self->dlp_suspend = 0;
	pthread_mutex_unlock(&self->dlp_mtx);
	pthread_cond_broadcast(&self->dlp_suspend_cond);
 
	while (dl_segment_get_message_by_offset(
	    dl_topic_get_active_segment(topic),
	    self->offset, &msg_buffer) == 0) {

		self->offset++;
		
		/* Instantiate a new ProduceRequest */
		if (dl_produce_request_new_nomsg(&message,
		    dl_correlation_id_val(self->dlp_cid),
		    self->dlp_name, 1, 2000,
		    dl_topic_get_name(self->dlp_topic)) == 0) {

			rc = dl_request_encode(message, &buffer);
			if (rc != 0) {
				// TODO
			}
#ifdef DEBUG
			DLOGTR1(PRIO_LOW, "MessageSet (%zu bytes)\n",
			    dl_bbuf_pos(msg_buffer));
			unsigned char *bufval = dl_bbuf_data(msg_buffer);
			for (int i = 0; i < dl_bbuf_pos(msg_buffer); i++) {
				DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
			};
			DLOGTR0(PRIO_LOW, "\n");
#endif

			// Concat the buffers together?
			rc = dl_bbuf_concat(buffer, msg_buffer);
			if (rc != 0) {
				// TODO
			}
#ifdef DEBUG
			DLOGTR1(PRIO_LOW, "ProduceRequest (%zu bytes)\n",
			    dl_bbuf_pos(buffer));
			bufval = dl_bbuf_data(buffer);
			for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
				DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
			};
			DLOGTR0(PRIO_LOW, "\n");
#endif
			rc = dl_request_q_enqueue_new(self->dlp_request_q,
			    buffer, dl_correlation_id_val(self->dlp_cid),
			    DL_PRODUCE_API_KEY);
			if (rc != 0) {
				// TODO: Error handling when enqueing enqueue
			}

			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(self->dlp_cid);
		} else {

			DLOGTR0(PRIO_HIGH, "Failed creating ProduceRequest\n");
			// what to do?
		}
	}
	
	/* Self-trigger syncd() event. */
	dl_producer_syncd(self);
}

static void
dl_producer_offline(struct dl_producer * const self)
{
	struct kevent kev;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_OFFLINE;
	DLOGTR1(PRIO_LOW, "Producer state = OFFLINE (%d)\n", self->dlp_state);

        /* Suspend the produce and resender threads */	
	pthread_mutex_lock(&self->dlp_mtx);
    	self->dlp_suspend = 1;
	pthread_mutex_unlock(&self->dlp_mtx);
	
	/* The transport connection with the broker is offline, thus unregister
	 * the transport file descriptor.
	 */
	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);
	dl_transport_delete(self->dlp_transport);
	self->dlp_transport = NULL;

	/* Trigger reconnect event after timeout  period. */	
	EV_SET(&kev, NOTIFY_IDENT, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, 0, self->dlp_reconn_ms, NULL);
	kevent(self->dlp_ktimer, &kev, 1, NULL, 0, NULL);

	/* Exponential backoff of the retry timer. */
	if (self->dlp_reconn_ms < DLP_MAXRECONN_MS)
		self->dlp_reconn_ms *= 2;
	else
		self->dlp_reconn_ms += DLP_MAXRECONN_MS;
	return;
}

int
dl_producer_new(struct dl_producer **self, struct dl_topic *topic,
    char *hostname, int port, nvlist_t *props)
{
	struct dl_producer *producer;
	int rc;
	char *client_id;
	bool to_resend;

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(topic != NULL, ("Producer instance cannot be NULL."));
		
	producer = (struct dl_producer *) dlog_alloc(
	    sizeof(struct dl_producer));
	if (producer== NULL)
		goto err_producer;

	bzero(producer, sizeof(struct dl_producer));

	producer->dlp_exit = 0;
	producer->dlp_suspend = 1;
	producer->offset = 0;
	producer->dlp_state = DLP_INITIAL;
	producer->dlp_topic = topic;
	producer->dlp_transport = NULL;
	producer->dlp_name = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		client_id = nvlist_get_string(props, DL_CONF_CLIENTID);
	} else {
		client_id = DL_DEFAULT_CLIENTID;
	}
	sbuf_cpy(producer->dlp_name, client_id);
	sbuf_finish(producer->dlp_name);

	if (nvlist_exists_string(props, DL_CONF_RESENDTIMEOUT)) {
		producer->resend_timeout = nvlist_get_number(props,
		    DL_CONF_RESENDTIMEOUT);
	} else {
		producer->resend_timeout = DL_DEFAULT_RESENDTIMEOUT;
	}

	if (nvlist_exists_string(props, DL_CONF_RESENDPERIOD)) {
		producer->resend_period = nvlist_get_number(props,
		    DL_CONF_RESENDPERIOD);
	} else {
		producer->resend_period = DL_DEFAULT_RESENDPERIOD;
	}

	producer->dlp_broker_hostname = sbuf_new_auto();
	sbuf_cpy(producer->dlp_broker_hostname, hostname);
	sbuf_finish(producer->dlp_broker_hostname);
	producer->dlp_broker_port = port;

	rc = dl_request_q_new(&producer->dlp_request_q, 20);
	if (rc != 0) {
		goto err_producer;
	}

	rc = dl_correlation_id_new(&producer->dlp_cid);
	if (rc != 0) {
		goto err_producer;
	}

	rc = pthread_mutex_init(&producer->dlp_mtx, NULL);
	if (rc != 0) {
		goto err_producer;
	}

	rc = pthread_cond_init(&producer->dlp_suspend_cond, NULL);
	if (rc != 0) {
		goto err_producer;
	}

	rc = pthread_create(&producer->dlp_produce_tid, NULL,
	    dlp_produce_thread, producer);
	if (rc != 0) {
		goto err_producer;
	}

	if (nvlist_exists_bool(props, DL_CONF_TORESEND)) {
		to_resend = nvlist_get_number(props, DL_CONF_TORESEND);
	} else {
		to_resend = DL_DEFAULT_TORESEND;
	}
	if (to_resend) {
		rc = pthread_create(&producer->dlp_resender_tid, NULL,
		    dlp_resender_thread, producer);
		if (rc != 0) {
			goto err_producer;
		}
	}

	producer->dlp_kq_hdlr.dleh_instance = producer;
	producer->dlp_kq_hdlr.dleh_get_handle = dl_producer_get_kq_fd;
	producer->dlp_kq_hdlr.dleh_handle_event = dl_producer_kq_handler;

	dl_poll_reactor_register(&producer->dlp_kq_hdlr, POLLIN | POLLERR);
				
	producer->dlp_ktimer = kqueue();
		
	producer->dlp_reconn_ms = DLP_MINRECONN_MS;	
	producer->dlp_ktimer_hdlr.dleh_instance = producer;
	producer->dlp_ktimer_hdlr.dleh_get_handle = dl_producer_get_timer_fd;
	producer->dlp_ktimer_hdlr.dleh_handle_event = dl_producer_timer_handler;

	dl_poll_reactor_register(&producer->dlp_ktimer_hdlr,
	    POLLIN | POLLOUT | POLLERR);
	
	/* Synchnronously create the Producer in the connecting state. */
	dl_producer_connecting(producer);

	*self = producer;
	dl_producer_check_integrity(*self);
	return 0;

err_producer:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Producer instance\n");
	*self = NULL;
	return -1;
}

void
dl_producer_delete(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	
	/* Resume and exit the produce and resend threads. */
	pthread_mutex_lock(&self->dlp_mtx);
	self->dlp_suspend = 0;
	self->dlp_exit = 1;
	pthread_mutex_unlock(&self->dlp_mtx);
	pthread_cond_broadcast(&self->dlp_suspend_cond);
		
	pthread_join(self->dlp_resender_tid, NULL);
	pthread_join(self->dlp_produce_tid, NULL);
	
	pthread_mutex_destroy(&self->dlp_mtx);
	pthread_cond_destroy(&self->dlp_suspend_cond);
	
	/* Unregister any poll reeactor handlers */
	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);
	dl_poll_reactor_unregister(&self->dlp_kq_hdlr);
	dl_poll_reactor_unregister(&self->dlp_ktimer_hdlr);

	/* Delete the topic managed by the producer. */
	dl_topic_delete(self->dlp_topic);

	/* Destroy the correlation id */
	dl_correlation_id_delete(self->dlp_cid);

	/* Delete the request queue */
	dl_request_q_delete(self->dlp_request_q);

	/* Delete the producer name */
	sbuf_delete(self->dlp_name);

	/* Delete the producer transport */
	if (self->dlp_transport != NULL)
		 dl_transport_delete(self->dlp_transport);

	dlog_free(self);
}

struct dl_topic *
dl_producer_get_topic(struct dl_producer *self)
{

	dl_producer_check_integrity(self);

	return self->dlp_topic;
}

void
dl_producer_produce(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
	DLOGTR0(PRIO_LOW, "Producer event = produce()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* idle -> recovery */
		dl_producer_syncing(self);
		break;
	case DLP_OFFLINE:
		/* IGNORE */
		break;
	case DLP_INITIAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_up(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
	DLOGTR0(PRIO_LOW, "Producer event = up()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* connecting -> syncing */
		dl_producer_syncing(self);
		break;
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* IGNORE */
		break;
	case DLP_INITIAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_down(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	DLOGTR0(PRIO_LOW, "Producer event = down()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* connecting|idle|recovery -> offline */
		dl_producer_offline(self);
		break;
	case DLP_OFFLINE:
		/* IGNORE */
		break;
	case DLP_INITIAL:
		/* FALLTHROUGH */
	default:
		DLOGTR1(PRIO_LOW, "Producer state = %d\n", self->dlp_state);
		DL_ASSERT(0, ("Invalid topic state"));
		break;
	}
}

void
dl_producer_syncd(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
	DLOGTR0(PRIO_LOW, "Producer event = sync()\n");

	switch(self->dlp_state) {
	case DLP_SYNCING:
		/* recover->idle */
		dl_producer_idle(self);
	case DLP_OFFLINE:
		/* IGNORE */ /* NEed to fix up the suspending of threads */
		break;
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* CANNOT HAPPEN */
		break;
	case DLP_INITIAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid topic state"));
		break;
	}
}

void
dl_producer_reconnect(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
	DLOGTR0(PRIO_LOW, "Producer event = reconnect()\n");

	switch(self->dlp_state) {
	case DLP_SYNCING:
		/* recover -> idle */
		dl_producer_idle(self);
		break;
	case DLP_OFFLINE:
		/* offline -> connecting */
		dl_producer_connecting(self);
		break;
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* CANNOT HAPPEN */
		break;
	default:
		DL_ASSERT(0, ("Invalid topic state"));
		break;
	}
}
