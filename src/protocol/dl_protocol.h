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

#define DISTLOG_API_V1 1
#define DISTLOG_API_VERSION DISTLOG_API_V1

// Topic names should have a maximum length
// so that when persisted to the filesystem they
// don't exceed the maximum allowable path length
#define DL_MAX_TOPIC_NAME_LEN 249

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

/* Requests. */

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

struct dl_message {
	int32_t dlm_crc;
	int8_t dlm_magic_byte;
	int8_t dlm_attributes;
	int64_t dlm_timestamp;
	char dlm_key[DL_MESSAGE_KEY_SIZE];
	char dlm_value[DL_MESSAGE_VALUE_SIZE];
	//int32_t *dlm_nkey;
	//int8_t *dlm_key;
	//int32_t *dlm_nvalue;
	//int8_t *dlm_value;
};

struct dl_message_set {
	int64_t dlms_offset;
	int32_t dlms_message_size;
	struct dl_message dlms_message;
};

struct dl_topic_data_data {
	int32_t dlpr_partition;
	int32_t dlpr_message_set_size; // This is the size in bytes of the message sent
	int32_t dl_nmessage_set;
	struct dl_message_set dlpr_message_set[1];
};

struct dl_topic_data {
	char dltd_topic_name[DL_MAX_TOPIC_NAME_LEN];
	int32_t dltd_ndata;
	struct dl_topic_data_data dltd_data[1];
};

struct dl_metadata_request {
	char dlmr_topic_name[DL_MAX_TOPIC_NAME_LEN];
};

struct dl_offset_commit_request {
	char consumer_group_id[CONSUMER_GROUP_ID_SIZE];
	int32_t consumer_group_generation_id;
	char consumer_id[CONSUMER_ID_SIZE];
	int64_t retention_time;
	char dlocr_topic_name[DL_MAX_TOPIC_NAME_LEN];
	int32_t partition;
	int64_t offset;
	char metadata[METADATA_SIZE];
};

struct dl_offset_fetch_request {
	char dlofr_topic_name[DL_MAX_TOPIC_NAME_LEN];
	char dlofr_consumer_group_id[CONSUMER_GROUP_ID_SIZE];
	int32_t dlofr_partition;
};

struct dl_group_coordinator_request {
	char dlgcr_group_id[GROUP_ID_SIZE];
};

/* Responses. */

struct dl_pr_partition_response {
	int32_t dlpr_partition;
	int16_t dlpr_error_code;
	int64_t dlpr_base_offset;
};

struct dl_pr_response {
	char dl_pr_topic_name[DL_MAX_TOPIC_NAME_LEN];
	int32_t dlr_num_partition_responses;
	struct dl_pr_partition_response *dlr_partition_responses;
	//struct dl_pr_partition_response dlr_partition_responses[1];
};	

struct dl_fr_partition_response {
	int32_t dlfrpr_partition;
	int16_t dlfrpr_error_code;
	int64_t dlfrpr_high_watermark;
};

struct dl_fr_response {
	char dl_fr_topic_name[DL_MAX_TOPIC_NAME_LEN];
	int32_t dl_fr_num_partition_responses;
	struct dl_fr_partition_response *dl_fr_partition_responses;
	//struct dl_pr_partition_response dlr_partition_responses[1];
};	

struct dl_request_or_response {
	int32_t dlrx_size;
};

#endif
