/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * Copyright (c) 2017 (Graeme Jenkinson)
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

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
// TODO: endian.h?
#endif

#include <string.h>
// TODO: Remove this?
#include <stdio.h>

#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_protocol_parser.h"
#include "dl_request.h"
#include "dl_utils.h"

int8_t
dl_decode_int8(char const * buffer)
{
	return *((int8_t *) buffer);
}

int16_t
dl_decode_int16(char const * buffer)
{
	return be16toh(*((int16_t *) buffer));
}

int32_t
dl_decode_int32(char const * buffer)
{
	return be32toh(*((int32_t *) buffer));
}

int64_t
dl_decode_int64(char const * buffer)
{
	return be64toh(*((int64_t *) buffer));
}

// TODO: Strings can be nullable?
int
dl_decode_string(char *buffer, char *string)
{
	int string_len, decoded_len = 0;

	/* Strings NULLABLE, therefore first check whether there is a value
	 * to decode.
	 */
	if (dl_decode_int32(&buffer[sizeof(int16_t)]) == -1) {
		decoded_len += sizeof(int32_t);
	} else {
		/* Decode the string length */
		string_len = dl_decode_int16(buffer);
		decoded_len += sizeof(int16_t);

		strlcpy(string, &buffer[sizeof(int16_t)], string_len+1);
		decoded_len += string_len;
	}

	return decoded_len;
}

// TODO: bytes can be nullable?
int
dl_decode_bytes(char *buffer, char *bytes)
{
	int bytes_len, decoded_len = 0;

	/* Bytes NULLABLE, therefore first check whether there is a value
	 * to decode.
	 */
	if (dl_decode_int32(&buffer[sizeof(int32_t)]) == -1) {

		decoded_len += sizeof(int32_t);
	} else {
		/* Decode the bytes length */
		bytes_len = dl_decode_int32(buffer);
		decoded_len += sizeof(int16_t);

		memcpy(bytes, &buffer[sizeof(int32_t)], bytes_len);
		decoded_len += bytes_len;
	}

	return decoded_len;
}

int
dl_decode_request_or_response(struct dl_request_or_response *req_or_res,
    char *buffer)
{
        /* Decode the Size */	
	req_or_res->dlrx_size = dl_decode_int32(buffer);
	buffer += sizeof(int32_t);

	return sizeof(int32_t);
}
