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

#include <stdarg.h>
#include <string.h>

#include "dl_assert.h"
#include "dl_list_offset_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"

int
dl_decode_offset_response(struct dl_offset_response *response,
    char *buffer)
{
	int32_t npartitions, partition_response, response_it;
	int16_t topic_name_len;
      
        // TODO: Number of responses	
	dl_decode_int32(buffer);
	buffer += sizeof(int32_t);

	/* Decode the TopicName */
	topic_name_len = DL_DECODE_TOPIC_NAME(buffer,
	    response->dlors_topic_name);
	buffer += topic_name_len;
	printf("topic name = %s\n", response->dlors_topic_name);

	// No. partition offsets	
	npartitions = dl_decode_int32(buffer);
	buffer += sizeof(int32_t);
	
	/* Decode the Partition */
	dl_decode_int32(buffer);
	buffer += sizeof(int32_t);
	
	/* Decode the ErrorCode */
	printf("ec = %d\n", dl_decode_int16(buffer));
	buffer += sizeof(int16_t);
	
	/* Decode the Timestamp */
	printf("ts = %d\n", dl_decode_int64(buffer));
	buffer += sizeof(int64_t);

	/* Decode the Offset*/
	response->dlors_offset = dl_decode_int64(buffer);
	printf("off = %d\n", response->dlors_offset);
	buffer += sizeof(int64_t);

	return 0;
}
