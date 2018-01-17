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

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#include "dl_assert.h"
#include "dl_primitive_types.h"
#include "dl_list_offset_request.h"

#define DL_ENCODE_PARTITION(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_TOPIC_NAME(buffer, value) \
    dl_encode_string(buffer, value, DL_MAX_TOPIC_NAME_LEN)
#define DL_ENCODE_REPLICAID(buffer, value) dl_encode_int32(buffer, value)
#define DL_ENCODE_TIMESTAMP(buffer, value) dl_encode_int64(buffer, value)

/**
 * Encode the ListOffsetRequest.
 *
 * ListOffsetRequest = ReplicaId [Topics]
 * Topics = Topic [Partitions]
 * Topic
 * Partitions = Partition Timestamp
 * Partition
 * Timestamp
 */
int
dl_encode_listoffset_request(struct dl_offset_request *request, char *buffer)
{
	int32_t request_size = 0;

	DL_ASSERT(request != NULL, "Offset request cannot be NULL");
	DL_ASSERT(buffer != NULL, "Buffer used for encoding cannot be NULL");

	/* Encode the ListOffsetRequest ReplicaId into the buffer. */
	request_size += DL_ENCODE_REPLICAID(&buffer[request_size],
	    request->dlor_replica_id);
	
	// TODO: topics
	request_size += dl_encode_int32(&buffer[request_size], 1);
	
	/* Encode the ListOffsetRequest Topic Name into the buffer. */
	request_size += DL_ENCODE_TOPIC_NAME(&buffer[request_size],
	    request->dlor_topic_name);

	// TODO: partitions
	request_size += dl_encode_int32(&buffer[request_size], 1);

	// TODO: Fixed 12 bytes
	
	/* Encode the ListOffsetRequest Partition into the buffer. */
	request_size += DL_ENCODE_PARTITION(&buffer[request_size],
	    request->dlor_partition);
	
	/* Encode the ListOffsetRequest Timestamp into the buffer. */
	// TODO: Earliest
	request_size += DL_ENCODE_TIMESTAMP(&buffer[request_size],
	    request->dlor_time);
	
	return request_size;
}
