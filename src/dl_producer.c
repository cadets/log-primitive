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
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_resender.h"
#include "dl_request.h"
#include "dl_request_queue.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

typedef enum dl_producer_state {
	DLP_INITIAL,
	DLP_IDLE,
	DLP_RECOVERY,
	DLP_OFFLINE} dl_producer_state;

struct dl_producer {
	struct dl_correlation_id *dlp_cid;
	struct dl_resender *dlp_resender;
	struct dl_request_q *dlp_request_q;
	struct dl_topic *dlp_topic;
	struct dl_transport *dlp_transport;
	struct dl_event_handler dlp_trans_hdlr;
	struct dl_event_handler dlp_kq_hdlr;
	pthread_t dlp_tid;
	pthread_mutex_t dlp_mtx;
	dl_producer_state dlp_state;
	struct sbuf *dlp_name;
	int dlp_exit;
};

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_recovery(struct dl_producer * const self);
static void dl_producer_offline(struct dl_producer * const self);

static void *dl_producer_thread(void *vargp);

static const off_t DL_FSYNC_DEFAULT_CHARS = 100;

static inline void 
dl_producer_check_integrity(struct dl_producer const * const self)
{
	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(self->dlp_cid != NULL,
	    ("Producer correlation id cannot be NULL."));
	//DL_ASSERT(self->dlp_resender != NULL,
	//    ("Producer resender cannot be NULL."));
	DL_ASSERT(self->dlp_request_q != NULL,
	    ("Producer request queue cannot be NULL."));
	DL_ASSERT(self->dlp_topic != NULL,
	    ("Producer topic cannot be NULL."));
	//DL_ASSERT(self->dlp_name != NULL,
	//    ("Producer instance cannot be NULL."));
}

static dl_event_handler_handle
dl_producer_get_trans_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	printf("here get_trans_fd\n");

	return dl_transport_get_fd(p->dlp_transport);
}

static void 
dl_producer_trans_handler(void *instance, int revents)
{
	struct dl_producer const * const p = instance;
	socklen_t len;
	int rc , fd, err;

	dl_producer_check_integrity(p);

	fd = dl_transport_get_fd(p->dlp_transport);
	len = sizeof(int);
	rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
	if (rc == 0) {
		if (revents & POLLHUP) {
			if (err == ECONNREFUSED) {
				printf("connection refuesed\n");
				dl_poll_reactor_unregister(&p->dlp_trans_hdlr);
			}
		}
		
		if (revents & POLLOUT) {
			if (err == 0) {
				printf("connected\n");

				dl_producer_up(p);
			} else {
				printf("not connected %d\n",err);
			}
		}
	} else {
		// TODO
		// DLOGTR0(PRIO_HIGH, "");
		dl_poll_reactor_unregister(&p->dlp_trans_hdlr);
	}
}

static void 
dl_producer_hup_hdlr(void *instance, int revents)
{
	struct dl_producer const * const self = instance;
	struct dl_response_header *header;
	struct dl_bbuf *buffer;

	DLOGTR0(PRIO_LOW, "dlog_client_handle_read_event\n");

	if (dl_transport_read_msg(self->dlp_transport, &buffer) == 0) {

		unsigned char *bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_len(buffer); i++) {
			DLOGTR1(PRIO_LOW, "<0x%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		/* Flip the buffer as we are now reading values from it. */
		dl_bbuf_flip(buffer);

		/* Deserialise the response header. */
		if (dl_response_header_decode(&header, buffer) == 0) {

			DLOGTR1(PRIO_LOW, "Got response id = : %d\n",
			    header->dlrsh_correlation_id);

			/* Acknowledge the request message based
			 * on the CorrelationId returned in the response.
			 */
			/*
			request = dl_resender_ackd_request(
			    handle->dlh_resender,
			    header->dlrsh_correlation_id);
			if (request != NULL) {
				switch (request->dlrq_api_key) {
				case DL_PRODUCE_API_KEY:
					dl_produce_response_decode(&response,
					    buffer);
					break;
				case DL_FETCH_API_KEY:
					dl_fetch_response_decode(&response,
					    buffer);
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
				
				* The request has been acknowleded and can
				* now be freed.
				*
				dlog_free(request);

				* Invoke the client callback. *
				if (response != NULL &&
				    handle->dlh_config->dlcc_on_response != NULL) {
					handle->dlh_config->dlcc_on_response(
					    response);
					dlog_free(response);
				}
			} else {
				DLOGTR1(PRIO_HIGH,
				    "Couldn't find the unack'd request id: "
				    "%d\n", header->dlrsh_correlation_id);
			}
		*/
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Error decoding response header.\n");
		}

		// TODO: Free the dl_bbuf instance
	} else {
		/* Server disconnected. */
		//dl_poll_reactor_unregister(&handle->dlh_event_handler);

		/* Reconnect and register */
		// TODO: What about the request?
	}

}

static dl_event_handler_handle
dl_producer_get_kq_fd(void *instance)
{
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;

	dl_producer_check_integrity(p);

	seg = dl_topic_get_active_segment(p->dlp_topic);
	return seg->_klog;
}

static void 
dl_producer_kq_handler(void *instance, int revents)
{
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;
	struct iovec index_bufs[2];
	struct kevent event;
	off_t log_position;
	int rc;
	
	dl_producer_check_integrity(p);
	
	seg = dl_topic_get_active_segment(p->dlp_topic);

	rc = kevent(seg->_klog, 0, 0, &event, 1, 0);
	if (rc == -1)
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.", rc,
		    errno);
	else {

		dl_segment_lock(seg);

		/* Create the index. */
		log_position = lseek(seg->_log, 0, SEEK_CUR);
		lseek(seg->_index, seg->offset * 2 * sizeof(int32_t), SEEK_SET);

		index_bufs[0].iov_base = &seg->offset;
		index_bufs[0].iov_len = sizeof(uint32_t);

		index_bufs[1].iov_base = &log_position;
		index_bufs[1].iov_len = sizeof(uint32_t);

		writev(seg->_index, index_bufs, 2);	

		log_position = lseek(seg->_log, 0, SEEK_END);
		DLOGTR2(PRIO_LOW, "log_position = %d, last_sync_pos = %d\n",
		    log_position, seg->last_sync_pos);
		if (log_position - seg->last_sync_pos >
		    DL_FSYNC_DEFAULT_CHARS) {

			DLOGTR0(PRIO_NORMAL, "Syncing the index and log...\n");

			seg->last_sync_pos = log_position;
			fsync(seg->_log);
			fsync(seg->_index);
		}
		dl_segment_unlock(seg);
		
		dl_producer_produce(p);
	}
}

int
dl_producer_new(struct dl_producer **self, struct dl_topic *topic)
{
	struct dl_producer *producer;
	int rc;

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(topic != NULL, ("Producer instance cannot be NULL."));
		
	producer = (struct dl_producer *) dlog_alloc(
	    sizeof(struct dl_producer));
	if (producer== NULL)
		goto err_producer;

	bzero(producer, sizeof(struct dl_producer));

	producer->dlp_state = DLP_INITIAL;
	producer->dlp_topic = topic;
	//producer->dlp_name = TODO;

	rc = dl_request_q_new(&producer->dlp_request_q);
	if (rc != 0) {
		goto err_producer;
	}

	//rc = dl_resender_new(&producer->dlp_resender);
	//if (rc != 0) {
	//	goto err_producer;
	//}
	
	rc = dl_correlation_id_new(&producer->dlp_cid);
	if (rc != 0) {
		goto err_producer;
	}

	rc = pthread_create(&producer->dlp_tid, NULL, dl_producer_thread,
	    producer);
	if (rc != 0) {
		goto err_producer;
	}
	
	/* Synchnronously create the Producer in the offline state. */
	dl_producer_offline(producer);

	producer->dlp_kq_hdlr.dleh_instance = producer;
	producer->dlp_kq_hdlr.dleh_get_handle = dl_producer_get_kq_fd;
	producer->dlp_kq_hdlr.dleh_handle_event = dl_producer_kq_handler;
	dl_poll_reactor_register(&producer->dlp_kq_hdlr, POLLIN | POLLERR);

	*self = producer;
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

	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);
	dl_poll_reactor_unregister(&self->dlp_kq_hdlr);

	dlog_free(self);
}

static void
dl_producer_idle(struct dl_producer * const self)
{

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_IDLE;
	DLOGTR0(PRIO_LOW, "Producer state = IDLE\n");
}

static void
dl_producer_recovery(struct dl_producer * const self)
{
	struct dl_topic *topic = self->dlp_topic;
	uint32_t h;
	struct dl_bbuf *buffer, *msg_buffer;
	struct dl_request *message;
	struct dl_transport *transport;
	struct timespec ts;
	struct timeval now;
	int rv, msg_size, old_cancel_state, port;
#ifdef __APPLE__
	int32_t secs, msecs;
#else
	//struct timeval tv;
#endif
	int offset = 0, rc;

	dl_producer_check_integrity(self);
	//DL_ASSERT(self->dlp_transport != NULL,
	//    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_RECOVERY;
	DLOGTR0(PRIO_LOW, "Producer state = RECOVERY\n");
				
	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);

	self->dlp_trans_hdlr.dleh_instance = self;
	self->dlp_trans_hdlr.dleh_get_handle = dl_producer_get_trans_fd;
	self->dlp_trans_hdlr.dleh_handle_event = dl_producer_hup_hdlr;
	dl_poll_reactor_register(&self->dlp_trans_hdlr, POLLIN|POLLHUP|POLLERR);

	//struct dl_partition *request_partition =
	//    SLIST_FIRST(&self->dlp_topic->dlt_partitions);

	while (dl_segment_get_message_by_offset(
	    dl_topic_get_active_segment(topic),
	    offset++, &msg_buffer) == 0) {
		
		/* Instantiate a new ProduceRequest */
		if (dl_produce_request_new_nomsg(&message,
		    dl_correlation_id_val(self->dlp_cid),
		    self->dlp_name, 1, 2000,
		    dl_topic_get_name(self->dlp_topic)) != 0) {
			DLOGTR0(PRIO_HIGH, "Failed creating ProduceRequest\n");

			// TODO: obviously can't return -1 here
			// what to do?
		}

		rc = dl_request_encode(message, &buffer);

		unsigned char *bufval = dl_bbuf_data(msg_buffer);
		for (int i = 0; i < dl_bbuf_pos(msg_buffer); i++) {
		DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		// Concat the buffers together?
		rc = dl_bbuf_concat(buffer, msg_buffer);

		bufval = dl_bbuf_data(buffer);
		for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
		DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		// enqueue
		struct dl_request_element *request;
		request = (struct dl_request_element *) dlog_alloc(
		    sizeof(struct dl_request_element));
		request->dlrq_buffer = buffer;
		request->dlrq_correlation_id =
		    dl_correlation_id_val(self->dlp_cid),
		request->dlrq_api_key = DL_PRODUCE_API_KEY;
		dl_request_q_enqueue(self->dlp_request_q, request);
	}
	
	/* Self-trigger syncd() event. */
	dl_producer_syncd(self);
}

static void
dl_producer_offline(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_OFFLINE;
	DLOGTR0(PRIO_LOW, "Producer state = OFFLINE\n");

	rc = dl_transport_new(&self->dlp_transport);
	rc = dl_transport_connect(self->dlp_transport, "127.0.0.1", 9090);
	
	self->dlp_trans_hdlr.dleh_instance = self;
	self->dlp_trans_hdlr.dleh_get_handle = dl_producer_get_trans_fd;
	self->dlp_trans_hdlr.dleh_handle_event = dl_producer_trans_handler;

	dl_poll_reactor_register(&self->dlp_trans_hdlr, POLLOUT | POLLHUP);
}

void
dl_producer_produce(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_OFFLINE:
		/* offline -> offline */
		dl_producer_offline(self);
		break;
	case DLP_RECOVERY:
		/* IGNORE */
		break;
	case DLP_IDLE:
		/* idle -> recovery */
		dl_producer_recovery(self);
		break;
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_up(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_OFFLINE:
		/* offline -> recovery */
		dl_producer_recovery(self);
		break;
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_RECOVERY:
		/* IGNORE */
		break;
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_down(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_IDLE:
		/* idle -> offline */
		dl_producer_offline(self);
		break;
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_RECOVERY:
		/* recovery -> idle */
		dl_producer_idle(self);
		break;
	default:
		DL_ASSERT(0, ("Invalid topic state"));
		break;
	}
}

void
dl_producer_syncd(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_RECOVERY:
		/* recover -> idle */
		dl_producer_idle(self);
		break;
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* CANNOT HAPPEN */
		break;
	default:
		DL_ASSERT(0, ("Invalid topic state"));
		break;
	}
}

static void *
dl_producer_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *) vargp;
	struct dl_request_queue local_request_queue;
	struct dl_request_element *request, *request_temp;
	int rv, msg_size, old_cancel_state, port;
	ssize_t nbytes;

	DL_ASSERT(vargp != NULL, "Request thread arguments cannot be NULL");
	
	DLOGTR0(PRIO_LOW, "Producer thread started...\n");

	/* Defer cancellation of the thread until the cancellation point 
	 * This ensures that thread isn't cancelled until outstanding requests
	 * have been processed.
	 */	
	pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, &old_cancel_state);

	/* Initialize a local queue, used to enqueue requests from the
	 * request queue prior to processing.
	 */
	STAILQ_INIT(&local_request_queue);

	DLOGTR0(PRIO_LOW, "Dequeuing requests...\n");
	for (;;) {

		if (dl_request_q_dequeue(self->dlp_request_q,
			&local_request_queue) == 0) {

			STAILQ_FOREACH_SAFE(request, &local_request_queue,
			    dlrq_entries, request_temp) {

				STAILQ_REMOVE_HEAD(&local_request_queue,
				    dlrq_entries);

			
				nbytes = dl_transport_send_request(self->dlp_transport, request->dlrq_buffer);
				if (nbytes != -1) {
					DLOGTR1(PRIO_LOW,
					    "Successfully sent request (id = %d)\n",
					    dl_correlation_id_val(self->dlp_cid));

					/* The request must be acknowledged, store
					 * the request until an acknowledgment is
					 * received from the broker.
					 */

					/* Successfuly send the request,
					 * record the last send time.
					 */
					/*
#ifdef _KERNEL
#ifdef __APPLE__
					clock_get_calendar_microtime(&secs,
						&msecs);
					request->dlrq_last_sent =
						(secs * 1000) + msecs;
#else
					getmicrotime(&tv);
					request->dlrq_last_sent =
						(tv.tv_sec *1000) +
						(tv.tv_usec/1000);
#endif
#else
					request->dlrq_last_sent = time(NULL);
#endif
					*/
					//DLOGTR1(PRIO_LOW,
					//"Inserting into the tree with key %d\n",
					//request->dlrq_correlation_id);

					// TODO: Add error handling
					//dl_resender_unackd_request(handle->dlh_resender, request);
					//DLOGTR1(PRIO_NORMAL, "Processed request %d\n",
					  //  request->dlrq_correlation_id);

					/* Increment the monotonic correlation id. */
					dl_correlation_id_inc(self->dlp_cid);
				} else {
					// TODO: proper errro handling is necessary
					DLOGTR0(PRIO_NORMAL, "socket send error\n");

					dl_producer_down(self);
				}
			}
		} else {
			DLOGTR0(PRIO_HIGH,
			    "Checking request thread supsend...");
			pthread_mutex_lock(&self->dlp_mtx);
			if (self->dlp_exit) {
				pthread_mutex_unlock(&self->dlp_mtx);
				break;
			}
			pthread_mutex_unlock(&self->dlp_mtx);

			pthread_testcancel();
		}
	}

	DLOGTR0(PRIO_LOW, "Request thread stopped.\n");
	pthread_exit(NULL);
}

int
dl_producer_produce_to(struct dl_producer *self, struct dl_bbuf *buffer)
{
	struct dl_partition *request_partition;

	dl_producer_check_integrity(self);
	DL_ASSERT(buffer != NULL, ("Buffer to produce cannot be NULL."));

	/* Produce the Message into the topic. */
	//request_partition = SLIST_FIRST(&self->dlp_topic->dlt_partitions);
	
	if (dl_segment_insert_message(
	    dl_topic_get_active_segment(self->dlp_topic),
	    dl_bbuf_data(buffer), dl_bbuf_pos(buffer)) == 0) {

		dl_producer_produce(self);

		return 0;
	}
	return -1;
}	
