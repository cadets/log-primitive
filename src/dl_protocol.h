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

#include "dl_message.h"

#define CLIENT_ID_SIZE 12
#define KEY_SIZE 12
#define VALUE_SIZE 12
#define MAX_SET_SIZE 8
#define METADATA_REQUEST_MAX_TOPICS 64
#define TOPIC_NAME_SIZE 16
#define CONSUMER_GROUP_ID_SIZE 16
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

static int OVERALL_MSG_FIELD_SIZE = 4;

// TODO: prefix DL_
enum reply_error_codes {
	CRC_NOT_MATCH	= 1 << 0,
	CRC_MATCH	= 1 << 2,
	INSERT_ERROR	= 1 << 3,
	INSERT_SUCCESS	= 1 << 4
};
typedef enum reply_error_codes reply_error_codes;

// TODO: prefix DL_
enum request_type {
	REQUEST_PRODUCE,
	REQUEST_OFFSET_COMMIT,
	REQUEST_OFFSET,
	REQUEST_FETCH,
	REQUEST_OFFSET_FETCH,
	REQUEST_METADATA,
	REQUEST_GROUP_COORDINATOR
};
typedef enum request_type request_type;

// TODO: prefix DL_
enum response_type {
 	RESPONSE_METADATA,
	RESPONSE_PRODUCE,
	RESPONSE_FETCH,
	RESPONSE_OFFSET,
	RESPONSE_OFFSET_COMMIT,
	RESPONSE_OFFSET_FETCH,
	RESPONSE_GROUP_COORDINATOR
};
typedef enum response_type response_type;

struct message_set_element {
	struct dl_message message;
	long offset;
	int message_size;
};

struct message_set {
	struct message_set_element elems[MAX_SET_SIZE];
	int num_elems; // Elems
};

struct topic_name {
	char topic_name[TOPIC_NAME_SIZE];
};

struct group_coordinator_request {
	char group_id[GROUP_ID_SIZE];
};

struct metadata_request {
	struct topic_name topic_names[METADATA_REQUEST_MAX_TOPICS];
	int num_topics; // TopicNames
};

struct sub_sub_produce_request {
	struct message_set mset;
	int message_set_size;
	int partition;
};

struct sub_produce_request {
	struct sub_sub_produce_request sspr;
	struct topic_name topic_name;
};

struct produce_request {
	struct sub_produce_request spr;
	int required_acks;
	int timeout;
};

struct fetch_request {
	struct topic_name topic_name;
	long fetch_offset;
	int replica_id;
	int max_wait_time;
	int min_bytes;
	int partition;
	int max_bytes;
};

struct offset_request {
	struct topic_name topic_name;
	long time;
	int repolica_id; 
	int partition;
};

struct offset_commit_request {
	struct topic_name topic_name;
	long offset;
	long timestamp;
	int consumer_group_generation_id;
	int consumer_id;
	int partition;
	char consumer_group_id[CONSUMER_GROUP_ID_SIZE];
	char metadata[METADATA_SIZE];
};

struct offset_fetch_request {
	struct topic_name topic_name;
	int partition;
	char consumer_group_id[CONSUMER_GROUP_ID_SIZE];
};

union req_message {
	struct metadata_request metadata_request;
	struct produce_request produce_request;
	struct fetch_request fetch_request;
	struct offset_request offset_request;
	struct offset_commit_request offset_commit_request;
	struct offset_fetch_request offset_fetch_request;
	struct group_coordinator_request group_coordinator_request;
};

struct request_message {
	union req_message rm; // ! APIKEY
	enum request_type api_key;
	int api_version;
	int correlation_id;
	char client_id[CLIENT_ID_SIZE];
};

// Responses now

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

extern enum response_type match_requesttype(enum request_type);
extern void clear_responsemessage(struct response_message *, enum request_type);
extern void clear_requestmessage(struct request_message *, enum request_type);

#endif
