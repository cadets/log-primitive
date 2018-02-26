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

#ifndef _DL_PROTOCOL_H
#define _DL_PROTOCOL_H

#include <sys/types.h>

#define DLOG_API_V1 1
#define DLOG_API_VERSION DLOG_API_V1

// Topic names should have a maximum length
// so that when persisted to the filesystem they
// don't exceed the maximum allowable path length
#define DL_MAX_TOPIC_NAME_LEN 249
#define DL_MAX_CLIENT_ID_LEN 249

#define CLIENT_ID_SIZE 12
#define KEY_SIZE 12
#define VALUE_SIZE 12
#define MAX_SET_SIZE 8
#define METADATA_REQUEST_MAX_TOPICS 64
#define CONSUMER_GROUP_ID_SIZE 16
#define CONSUMER_ID_SIZE 16
#define METADATA_SIZE 16
#define HOST_SIZE 16
#define MAX_REPLICAS 16
#define MAX_ISR 16
#define METADATAS_SIZE 16
#define MAX_SUB_SUB_SIZE 16
#define MAX_SUB_SIZE 16
#define MAX_SUB_FETCH_SIZE 16
#define MAX_OFFSETS 16
#define MAX_SUB_SUB_FETCH_SIZE 16
#define MAX_PART_OFFSETS 16
#define MAX_SOR 16
#define GROUP_ID_SIZE 16
#define CONSUMER_ID_SIZE 16
#define MAX_SUB_OCR 16
#define MAX_SUB_SUB_OCR 16
#define MAX_SUB_OFR 16
#define MAX_SUB_SUB_OFR 16
#define MAX_BROKERS 16

#define MTU 2048


// TODO: It's a string in the protocol
#define DL_MAX_CLIENT_ID 12
// TODO: improve key/value handling
#define DL_MESSAGE_KEY_SIZE 256
#define DL_MESSAGE_VALUE_SIZE 256


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
	DL_PRODUCE_REQUEST = 0,
	DL_FETCH_REQUEST = 1,
	DL_OFFSET_REQUEST = 2,
	DL_METADATA_REQUEST = 3,
	DL_OFFSET_COMMIT_REQUEST = 8,
	DL_OFFSET_FETCH_REQUEST = 9,
	DL_COORDINATOR_REQUEST = 10
};
typedef enum dl_api_key dl_api_key;

#endif
