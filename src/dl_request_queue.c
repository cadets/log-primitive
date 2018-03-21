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
#ifdef _KERNEL
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/sbuf.h>
#else
#include <pthread.h>
#include <sys/sbuf.h>
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_request_queue.h"
#include "dl_utils.h"

struct dl_request_q {
	struct dl_request_queue dlrq_requests;
#ifdef _KERNEL
	struct mtx dlrq_mtx;
	struct cv dlrq_cond;
#else
	pthread_mutex_t dlrq_mtx;
	pthread_cond_t dlrq_cond;
#endif
	struct sbuf *dlrq_name;
};

static char const * const DL_REQUEST_Q_TYPE = "dlog request_q lock";

int 
dl_request_q_dequeue(struct dl_request_q *self, struct dl_request_queue *local_request_queue)
{
#ifndef _KERNEL
	struct timespec ts;
	struct timeval now;
#endif
	struct dl_request_element *request;

	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));
	DL_ASSERT(local_request_queue != NULL, ("Target queue cannot be NULL."));

#ifdef _KERNEL
	//mtx_assert(&self->dlrq_mtx, MA_NOTOWNED);
	mtx_lock(&self->dlrq_mtx);		
#else
	pthread_mutex_lock(&self->dlrq_mtx);		
#endif
	while (STAILQ_EMPTY(&self->dlrq_requests) != 0 ) {
		/* There are no elements in the reader's
		 * queue check whether the thread has been
		 * canceled.
		 */
#ifdef _KERNEL
		kthread_suspend_check();
#else
		pthread_testcancel();
#endif	
		/* Wait for elements to be added to the
		 * reader's queue, whilst also periodically checking
		 * the thread's cancellation state.
		 */
#ifdef _KERNEL
		// TODO: In-kernel timing
		mtx_assert(&self->dlrq_mtx, MA_OWNED);
		cv_timedwait(&self->dlrq_cond, &self->dlrq_mtx, 10 * hz / 9);
#else
		gettimeofday(&now, NULL);
		ts.tv_sec = now.tv_sec + 1;
		ts.tv_nsec = 0;

		pthread_cond_timedwait(&self->dlrq_cond, &self->dlrq_mtx, &ts);
#endif
	}

	while (STAILQ_EMPTY(&self->dlrq_requests) == 0 ) {
		request = STAILQ_FIRST(&self->dlrq_requests);
		STAILQ_REMOVE_HEAD(&self->dlrq_requests,
			dlrq_entries);

		STAILQ_INSERT_TAIL(local_request_queue,
			request, dlrq_entries);
	}
#ifdef _KERNEL
	mtx_unlock(&self->dlrq_mtx);
#else
	pthread_mutex_unlock(&self->dlrq_mtx);
#endif
	return 0;
}

int 
dl_request_q_enqueue(struct dl_request_q *self, struct dl_request_element *request)
{

	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));
	DL_ASSERT(request != NULL, ("Request instance cannot be NULL."));

#ifdef _KERNEL
	mtx_assert(&self->dlrq_mtx, MA_NOTOWNED);
	mtx_lock(&self->dlrq_mtx);
#else
	pthread_mutex_lock(&self->dlrq_mtx);
#endif
	STAILQ_INSERT_TAIL(&self->dlrq_requests, request, dlrq_entries);
#ifdef _KERNEL
	cv_signal(&self->dlrq_cond);
	mtx_unlock(&self->dlrq_mtx);
#else
	pthread_cond_signal(&self->dlrq_cond);
	pthread_mutex_unlock(&self->dlrq_mtx);
#endif
	return 0;
}

int 
dl_request_q_enqueue_new(struct dl_request_q *self, struct dl_bbuf *buffer,
    int32_t correlation_id, int16_t api_key)
{
	struct dl_request_element *request;
	
	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));
	DL_ASSERT(buffer != NULL, ("Buffer cannot be NULL."));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
	 * and responses.
	 */
	request = (struct dl_request_element *) dlog_alloc(
	    sizeof(struct dl_request_element));
#ifdef _KERNEL
	DL_ASSERT(request != NULL, ("Failed allocating request."));
	{
#else
	if (request != NULL) {
#endif
		/* Construct the request */
		bzero(request, sizeof(struct dl_request_element));
		request->dlrq_buffer = buffer;
		request->dlrq_correlation_id = correlation_id;
		request->dlrq_api_key = api_key;

		if (dl_request_q_enqueue(self, request) == 0) {

			DLOGTR0(PRIO_LOW, "Enqueued request message..\n");
			return 0;
		}
		dlog_free(request);
		return -1;
	} 

	DLOGTR0(PRIO_HIGH, "Failed allocating request.\n");
	return -1;
}

int
dl_request_q_new(struct dl_request_q **self)
{
	struct dl_request_q *request_q;
	
	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));

	request_q = (struct dl_request_q *) dlog_alloc(
		    	sizeof(struct dl_request_q));
#ifdef _KERNEL
	DL_ASSERT(request_q != NULL, ("Failed allocating request queue."));
	{
#else
	if (request_q != NULL) {
#endif
		bzero(request_q, sizeof(struct dl_request_q));

		STAILQ_INIT(&request_q->dlrq_requests);
		request_q->dlrq_name = sbuf_new_auto();
		sbuf_cat(request_q->dlrq_name, "request_q"); //%d", ?);
		sbuf_finish(request_q->dlrq_name);
#ifdef _KERNEL
		// TODO MTX_RECURSE?
		mtx_init(&request_q->dlrq_mtx,sbuf_data(request_q->dlrq_name),
		    DL_REQUEST_Q_TYPE, MTX_DEF|MTX_RECURSE);
		cv_init(&request_q->dlrq_cond, sbuf_data(request_q->dlrq_name));
#else
		pthread_mutex_init(&request_q->dlrq_mtx, NULL);
		pthread_cond_init(&request_q->dlrq_cond, NULL);
#endif
		*self = request_q;
		return 0;
	}

	DLOGTR0(PRIO_HIGH, "Failed allocating request queue.\n");
	*self = NULL;
	return -1;
}

void
dl_request_q_delete(struct dl_request_q *self)
{
	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));
	DL_ASSERT(STAILQ_EMPTY(&self->dlrq_requests) == 0,
	    ("Rquest queue is not emprty!"));

	sbuf_delete(self->dlrq_name);
#ifdef _KERNEL
	//mtx_destroy(&self->dlrq_mtx);
	//cv_destroy(&self->dlrq_cond);
#else
	pthread_mutex_destory(&self->dlrq_mtx);
	pthread_cond_destroy(&self->dlrq_cond);
#endif
	dlog_free(self);
}
