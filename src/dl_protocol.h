/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DL_PROTOCOL_H
#define _DL_PROTOCOL_H

#include <sys/types.h>

#define DLOG_API_V1 1
#define DLOG_API_VERSION DLOG_API_V1

#define DLOG_MESSAGE_V0 0
#define DLOG_MESSAGE_V1 1

// Topic names should have a maximum length
// so that when persisted to the filesystem they
// don't exceed the maximum allowable path length
#define DL_MAX_TOPIC_NAME_LEN 249
#define DL_MAX_CLIENT_ID_LEN 249
#define MTU 2048

#define DL_DECODE_ERROR_CODE(source) dl_decode_int16(source);
#define DL_DECODE_MAX_WAIT_TIME(source) dl_decode_int32(source)
#define DL_DECODE_MIN_BYTES(source) dl_decode_int32(source)
#define DL_DECODE_OFFSET(source) dl_decode_int64(source);
#define DL_DECODE_PARTITION(source) dl_decode_int32(source)
#define DL_DECODE_REPLICA_ID(source) dl_decode_int32(source)
#define DL_DECODE_REQUIRED_ACKS(source) dl_decode_int16(source);
#define DL_DECODE_TIMEOUT(source) dl_decode_int32(source);
#define DL_DECODE_TIMESTAMP(source) dl_decode_int64(source);
#define DL_DECODE_THROTTLE_TIME(source) dl_decode_int32(source)
#define DL_DECODE_TOPIC_NAME(source, target) dl_decode_string(source, target)

#define DL_ENCODE_ERROR_CODE(target, source) dl_encode_int16(target, source)
#define DL_ENCODE_MAX_WAIT_TIME(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_MIN_BYTES(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_OFFSET(target, source) dl_encode_int64(target, source)
#define DL_ENCODE_PARTITION(target, source) dl_encode_int32(target, source)
#define DL_ENCODE_REPLICA_ID(target, value) dl_encode_int32(target, value)
#define DL_ENCODE_REQUIRED_ACKS(buffer, value) dl_encode_int16(buffer, value);
#define DL_ENCODE_TIMEOUT(buffer, value) dl_encode_int32(buffer, value);
#define DL_ENCODE_TIMESTAMP(buffer, value) dl_encode_int64(buffer, value);
#define DL_ENCODE_THROTTLE_TIME(target, source) dl_encode_int32(target, source)
#define DL_ENCODE_TOPIC_NAME(target, source) \
    dl_encode_string(target, source, DL_MAX_TOPIC_NAME_LEN)

// TODO: simplified mbuf like structure for encoding and decoding
// messages
struct dl_buffer_hdr {
	char * dlbh_data;
	int dlbh_len;
};

struct dl_buffer {
	struct dl_buffer_hdr dlb_hdr;
	char dlb_databuf[1];
};

/* ApiKey
 * Note: Only the Produce, Fetch and Offset APIs are currently implemented.
 */
enum dl_api_key {
	DL_PRODUCE_API_KEY = 0,
	DL_FETCH_API_KEY = 1,
	DL_OFFSET_API_KEY = 2,
};
typedef enum dl_api_key dl_api_key;

#endif
