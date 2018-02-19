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
 */

#include <sys/queue.h>

#include <poll.h>
#include <stddef.h>

#include "dl_assert.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_utils.h"

static STAILQ_HEAD(dl_handlers, dl_handler_registration) handlers =
    STAILQ_HEAD_INITIALIZER(handlers);

struct dl_handler_registration {
	STAILQ_ENTRY(dl_handler_registration) entries;
	struct dl_event_handler *handler;
	struct pollfd fd;
};

static size_t dl_build_poll_array(struct pollfd *);
static void dl_dispatch_signalled_handles(const struct pollfd *, size_t);
static struct dl_event_handler * dl_find_handler(int fd);
static void dl_add_to_registry(struct dl_event_handler *handler);
static void dl_remove_from_registry(struct dl_event_handler *handler);

// TODO: Limit number of hadles correctly
static const size_t MAX_NO_OF_HANDLES = 10;

/* Add a copy of all registered handlers to the given array. */
static size_t
dl_build_poll_array(struct pollfd *fds)
{
	struct dl_handler_registration *registration;
	size_t nhandles = 0;

	STAILQ_FOREACH(registration, &handlers, entries) {

		fds->fd = registration->fd.fd;
		fds->events = registration->fd.events;

		fds++;
		nhandles++;
	}

	return nhandles;
}

/**
 * Identify the event handler corresponding to the given descriptor in the
 * registeredHandlers.
 */
static struct dl_event_handler *
dl_find_handler(int fd)
{
	struct dl_handler_registration *registration;

	STAILQ_FOREACH(registration, &handlers, entries) {

		if (registration->fd.fd == fd) {
			return registration->handler;
		}
	}
	return NULL;
}

/* Add a copy of the given handler to the first free position in
* registeredHandlers. */
static void
dl_add_to_registry(struct dl_event_handler *handler)
{
	struct dl_handler_registration *registration;

	DL_ASSERT(NULL != handler, "dl_event_handlerr cannot be NULL\n");

	registration = (struct dl_handler_registration *) dlog_alloc(
	    sizeof(struct dl_handler_registration));
	if (registration != NULL ) {
		registration->handler = handler;
		registration->fd.fd = handler->dleh_get_handle(
		    handler->dleh_instance);
		registration->fd.events = POLLRDNORM;

		STAILQ_INSERT_TAIL(&handlers, registration, entries);
	}
}

/* Identify the event handler in the registeredHandlers and remove it. */
static void
dl_remove_from_registry(struct dl_event_handler *handler)
{
	struct dl_handler_registration *registration;

	DL_ASSERT(NULL != handler, "dl_event_handlerr cannot be NULL\n");
	
	STAILQ_FOREACH(registration, &handlers, entries) {

		if (registration->handler == handler) {

			STAILQ_REMOVE(&handlers, registration,
			    dl_handler_registration, entries);
			break;
		}
	}
}

/* Implementation of the Reactor interface used for registrations. */

void
dl_poll_reactor_register(struct dl_event_handler *handler)
{

	DL_ASSERT(NULL != handler, "dl_event_handlerr cannot be NULL\n");

        dl_add_to_registry(handler);
}

void
dl_poll_reactor_unregister(struct dl_event_handler *handler)
{

	DL_ASSERT(NULL != handler, "dl_event_handlerr cannot be NULL\n");
	
	dl_remove_from_registry(handler);
}

void
dl_dispatch_signalled_handles(const struct pollfd *fds, size_t nhandles)
{
	struct dl_event_handler *signalled_handler;
	size_t handle;

	/**
	 * Loop through all handles. Upon detection of a handle signalled by
	 * poll, its corresponding event handler is fetched and invoked.
	 */
	for (handle = 0; handle < nhandles; ++handle) {
		/**
		 * Detect all signalled handles and invoke their corresponding
		 * event handlers.
		 */
		if ((POLLRDNORM | POLLERR) & fds[handle].revents) {

			signalled_handler = dl_find_handler(fds[handle].fd);
			if (NULL != signalled_handler){
				signalled_handler->dleh_handle_event(
				    signalled_handler->dleh_instance);
			}
		}
	}
}

void
dl_poll_reactor_handle_events(void)
{
	struct pollfd fds[MAX_NO_OF_HANDLES] = {0};
	size_t nhandles;
       
	nhandles = dl_build_poll_array(fds);
        
	/* Invoke the synchronous event demultiplexer. */
	if (0 < poll(fds, nhandles, -1)){
		/** 
		 * Identify all signalled handles and invoke the event handler
		 * associated with each one.
		 */
		dl_dispatch_signalled_handles(fds, nhandles);
	} else {
		DLOGTR0(PRIO_LOW, "Poll failure");
	}
}
