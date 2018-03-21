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

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

static int32_t dl_encode_response_header(struct dl_response const * const,
    struct dl_bbuf * const);

#define DL_ENCODE_SIZE(buffer, value) dl_encode_int32(buffer, value)

int
dl_response_header_decode(struct dl_response_header **header,
    struct dl_bbuf *source)
{
	struct dl_response_header *self;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL\n");

	self = *header = (struct dl_response_header *) dlog_alloc(
	    sizeof(struct dl_response_header));
#ifdef KERNEL
	DL_ASSERT(header != NULL, ("Failed allocateding Response header.\n"));
	{
#else
	if (self != NULL) {
#endif
		/* Decode the CorrelationId */	
		dl_bbuf_get_int32(source, &self->dlrsh_correlation_id);
		return 0;
	}
	return -1;
}

int32_t
dl_response_encode(struct dl_response *response, struct dl_bbuf *target)
{

	DL_ASSERT(response != NULL, "Response message cannot be NULL\n");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL\n");

	if (dl_encode_response_header(response, target) == 0) {

		switch (response->dlrs_api_key) {
		case DL_OFFSET_API_KEY:
			DLOGTR0(PRIO_LOW, "Encoding ListOffsetResponse...\n");

			 dl_list_offset_response_encode(
				response->dlrs_message.dlrs_offset_message,
				target);
			break;
		case DL_PRODUCE_API_KEY:
			DLOGTR0(PRIO_LOW, "Encoding ProduceResponse...\n");

			dl_produce_response_encode(
				response->dlrs_message.dlrs_produce_message,
				target);
			break;
		default:
			// TODO
			break;
		}

		return 0;
	} else {
		return -1;
	}
}

/**
 * Encode the ResponseHeader.
 *
 * ResponseHeader = CorrelationId
 *  
 * CorrelationId
 */
static int32_t 
dl_encode_response_header(struct dl_response const * const response,
    struct dl_bbuf * const target)
{

	DL_ASSERT(response != NULL, "Response cannot be NULL");
	DL_ASSERT(target != NULL, "Target buffer cannot be NULL");

	/* Encode the Response CorrelationId into the buffer. */
	return DL_ENCODE_CORRELATION_ID(target, response->dlrs_correlation_id);
}
