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

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

#define CLIENT_ID_SIZE 12
#define KEY_SIZE 12
#define VALUE_SIZE 12
#define MAX_SET_SIZE 8
#define METADATA_REQUEST_MAX_TOPICS 64
#define TOPIC_NAME_SIZE 16
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

/* ApiKey - TODO */
enum dl_api_key {
	DL_PRODUCE_REQUEST = 0,
	DL_FETCH_REQUEST = 1,
	DL_OFFSET_REQUEST = 2,
	DL_OFFSET_COMMIT_REQUEST,
	DL_OFFSET_FETCH_REQUEST,
	DL_METADATA_REQUEST,
	DL_COORDINATOR_REQUEST
};
typedef enum dl_api_key dl_api_key;

struct dl_message {
	int32_t dlm_crc;
	int8_t dlm_magic_byte;
	int8_t dlm_attributes;
	int64_t dlm_timestamp;
	char dlm_key[DL_MESSAGE_KEY_SIZE];
	char dlm_value[DL_MESSAGE_VALUE_SIZE];
};

struct dl_message_set {
	int64_t dlms_offset;
	int32_t dlms_message_size;
	struct dl_message dlms_message;
};

struct dl_produce_request {
	int16_t dlpr_required_acks;
	int32_t dlpr_timeout;
	char dlpr_topic_name[TOPIC_NAME_SIZE]; // DL_
	int32_t dlpr_partition;
	int32_t dlpr_message_set_size; // This is the size in bytes of the message set
	struct dl_message_set dlpr_message_set[1];
};

struct dl_fetch_request {
	int32_t dlfr_replica_id;
	int32_t dlfr_max_wait_time;
	int32_t dlfr_min_bytes;
	char dlfr_topic_name[TOPIC_NAME_SIZE];
	int32_t dlfr_partition;
	int64_t dlfr_fetch_offset;
	int32_t dlfr_max_bytes;
};
struct dl_offset_request {
	int32_t dlor_replica_id;
	// List of values	
	// topics
	// ntopics
	char dlor_topic_name[TOPIC_NAME_SIZE];
	// List of values
	// partitions
	// npartitions
	int32_t dlor_partition;
	int64_t dlor_time;
};

struct dl_metadata_request {
	char dlmr_topic_name[TOPIC_NAME_SIZE];
};

struct dl_offset_commit_request {
	char consumer_group_id[CONSUMER_GROUP_ID_SIZE];
	int32_t consumer_group_generation_id;
	char consumer_id[CONSUMER_ID_SIZE];
	int64_t retention_time;
	char dlocr_topic_name[TOPIC_NAME_SIZE];
	int32_t partition;
	int64_t offset;
	char metadata[METADATA_SIZE];
};

struct dl_offset_fetch_request {
	char dlofr_topic_name[TOPIC_NAME_SIZE];
	char dlofr_consumer_group_id[CONSUMER_GROUP_ID_SIZE];
	int32_t dlofr_partition;
};

struct dl_group_coordinator_request {
	char dlgcr_group_id[GROUP_ID_SIZE];
};

union dl_request_message {
	struct dl_produce_request dlrqmt_produce_request;
	struct dl_fetch_request dlrqmt_fetch_request;
	struct dl_offset_request dlrqmt_offset_request;
	struct dl_metadata_request dlrqmt_metadata_request[1];
	struct dl_offset_commit_request dlrqmt_offset_commit_request;
	struct dl_offset_fetch_request dlrqmt_offset_fetch_request;
	struct dl_group_coordinator_request dlrqmt_group_coordinator_request;
};

struct dl_request {
	int32_t dlrqm_size;
	int16_t dlrqm_api_key;
	int16_t dlrqm_api_version;
	int32_t dlrqm_correlation_id;
	char dlrqm_client_id[DL_MAX_CLIENT_ID];
	union dl_request_message dlrqm_message;
};

// Responses now

/*
struct broker {
	int node_id;
	int port;
	char host[HOST_SIZE];
};

struct replica {
	int replica;
};

struct isr {
	int isr;
};

struct partition_metadata {
	struct isr isr[MAX_ISR];
	struct replica replicas[MAX_REPLICAS];
	int leader;
	int num_isrs; // Isr
	int num_replicas; // Replicas
	int partition_error_code;
	int partition_id;
};

struct topic_metadata {
	struct partition_metadata partition_metadatas[METADATAS_SIZE];
	struct topic_name topic_name;
	int num_partitions; // PartitionMetadatas
	int topic_error_code;
};

struct metadata_response {
	struct broker brokers[MAX_BROKERS];
	int num_brokers; // Brokers
};

struct sub_sub_produce_response {
	long offset;
	long timestamp;
	int error_code;
	int partition;
};

struct sub_produce_response {
	struct sub_sub_produce_response sspr[MAX_SUB_SUB_SIZE];
	struct topic_name topic_name;
	int num_subsub; // sspr
};

struct produce_response {
	struct sub_produce_response spr[MAX_SUB_SIZE];
	int num_sub; //spr
	int throttle_time;
};

struct sub_sub_fetch_response {
	struct message_set message_set;
	long highway_mark_offset;
	int partition;
	int error_code;
	int message_set_size;
};

struct sub_fetch_response {
	struct sub_sub_fetch_response ssfr[MAX_SUB_SUB_FETCH_SIZE];
	struct topic_name topic_name;
	int num_ssfr; // ssfr
};

struct fetch_response {
	struct sub_fetch_response sfr[MAX_SUB_FETCH_SIZE];
	int num_sfr; // sfr
	int throttle_time;
};

struct offset{
	long offset;
};

struct partition_offsets {
	struct offset offsets[MAX_OFFSETS];
	int partition;
	int error_code;
	int num_offsets;// Offsets
	long timestamp;
};

struct sub_offset_response {
	struct topic_name topic_name;
	struct partition_offsets partition_offsets[MAX_PART_OFFSETS];
	int num_parts; // PartitionOffsets
};

struct offset_response {
	struct sub_offset_response sor[MAX_SOR];
	int num_sor; // sor
};

struct group_coordinator_response {
	int corrdinator_id;
	int corrdinator_port;
	int error_code;
	char corrdinator_host[HOST_SIZE];
};

struct sub_sub_offset_commit_response{
	int partition;
	int error_code;
};

struct sub_offset_commit_response{
	struct topic_name topic_name;
	struct sub_sub_offset_commit_response ssocr[MAX_SUB_SUB_OCR];
	int num_ssocr; // ssocr
};

struct offset_commit_response{
	struct sub_offset_commit_response socr[MAX_SUB_OCR];
	int num_sub_ocr; // socr
};

struct sub_sub_offset_fetch_response{
	long offset;
	int error_code;
	int partition;
	char metadata[METADATA_SIZE];
};

struct sub_offset_fetch_response{
	struct sub_sub_offset_fetch_response ssofr[MAX_SUB_SUB_OFR];
	struct topic_name topic_name;
	int num_ssofr; // ssofr
};

struct offset_fetch_response {
	struct sub_offset_fetch_response sofr[MAX_SUB_OFR];
	int num_sub_ofr; // sofr
};

union res_message {
	struct metadata_response metadata_response;
	struct produce_response produce_response;
	struct fetch_response fetch_response;
	struct offset_response offset_response;
	struct offset_commit_response offset_commit_response;
	struct offset_fetch_response offset_fetch_response;
	struct group_coordinator_response group_coordinator_response;
};

struct response_message {
	union res_message rm;
	int correlation_id;
};
*/

struct dl_pr_partition_response {
	int32_t dlpr_partition;
	int16_t dlpr_error_code;
	int64_t dlpr_base_offset;
};

struct dl_pr_response {
	char dl_pr_topic_name[TOPIC_NAME_SIZE];
	int32_t dlr_num_partition_responses;
	struct dl_pr_partition_response *dlr_partition_responses;
	//struct dl_pr_partition_response dlr_partition_responses[1];
};	

struct dl_produce_response {
	int32_t dlprs_num_responses;
	struct dl_pr_response *dlprs_responses;
	//struct dl_pr_response dlprs_responses[1];
	int32_t dlprs_throttle_time;
};

struct dl_fr_partition_response {
	int32_t dlfrpr_partition;
	int16_t dlfrpr_error_code;
	int64_t dlfrpr_high_watermark;
};

struct dl_fr_response {
	char dl_fr_topic_name[TOPIC_NAME_SIZE];
	int32_t dl_fr_num_partition_responses;
	struct dl_fr_partition_response *dl_fr_partition_responses;
	//struct dl_pr_partition_response dlr_partition_responses[1];
};	

struct dl_fetch_response {
	struct dl_fr_response *dlfrs_responses;
	int32_t dlfrs_throttle_time;
	int32_t dlfrs_num_responses;
};

struct dl_offset_response {
	char dlors_topic_name[TOPIC_NAME_SIZE];
	int64_t dlors_offset;
};

union dl_response_message {
	//struct metadata_response metadata_response;
	struct dl_produce_response dlrs_produce_response;
	struct dl_fetch_response dlrs_fetch_response;
	struct dl_offset_response dlrs_offset_response;
	//struct offset_commit_response offset_commit_response;
	//struct offset_fetch_response offset_fetch_response;
	//struct group_coordinator_response group_coordinator_response;
};

struct dl_response {
	int32_t dlrs_size;
	int32_t dlrs_correlation_id;
	union dl_response_message dlrs_message;
};

struct dl_request_or_response {
	int32_t dlrx_size;
};

//extern enum response_type match_requesttype(enum request_type);
//extern void clear_responsemessage(struct response_message *, enum request_type);
//extern void clear_requestmessage(struct request_message *, enum request_type);
extern int read_msg(int, char *);

// TODO: its possible that these functions aren't even required
extern void dl_build_fetch_request(struct dl_request *, int32_t,
    char *, va_list);
extern void dl_build_produce_request(struct dl_request *, int32_t,
    char *, va_list);

#endif
