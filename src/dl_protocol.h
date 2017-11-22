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

enum reply_error_codes {
	CRC_NOT_MATCH	= 1 << 0,
	CRC_MATCH	= 1 << 2,
	INSERT_ERROR	= 1 << 3,
	INSERT_SUCCESS	= 1 << 4
};
typedef enum reply_error_codes reply_error_codes;

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
	struct message_set_element Elems[MAX_SET_SIZE];
	int NUM_ELEMS; // Elems
};

struct TopicName {
	char TopicName[TOPIC_NAME_SIZE];
};

struct GroupCoordinatorRequest {
	char GroupId[GROUP_ID_SIZE];
};

struct MetadataRequest {
	struct TopicName TopicNames[METADATA_REQUEST_MAX_TOPICS];
	int NUM_TOPICS; // TopicNames
};

struct SubSubProduceRequest {
	struct message_set mset;
	int MessageSetSize;
	int Partition;
};

struct SubProduceRequest {
	struct SubSubProduceRequest sspr;
	struct TopicName TopicName;
};

struct ProduceRequest {
	struct SubProduceRequest spr;
	int RequiredAcks;
	int Timeout;
};

struct FetchRequest {
	struct TopicName TopicName;
	long FetchOffset;
	int ReplicaId;
	int MaxWaitTime;
	int MinBytes;
	int Partition;
	int MaxBytes;
};

struct OffsetRequest {
	struct TopicName TopicName;
	long Time;
	int RepolicaId;
	int Partition;
};

struct OffsetCommitRequest {
	struct TopicName TopicName;
	long Offset;
	long Timestamp;
	int ConsumerGroupGenerationId;
	int ConsumerId;
	int Partition;
	char ConsumerGroupId[CONSUMER_GROUP_ID_SIZE];
	char Metadata[METADATA_SIZE];
};

struct OffsetFetchRequest {
	struct TopicName TopicName;
	int Partition;
	char ConsumerGroupId[CONSUMER_GROUP_ID_SIZE];
};

union ReqMessage {
	struct MetadataRequest     metadata_request;
	struct ProduceRequest      produce_request;
	struct FetchRequest        fetch_request;
	struct OffsetRequest       offset_request;
	struct OffsetCommitRequest offset_commit_request;
	struct OffsetFetchRequest  offset_fetch_request;
	struct GroupCoordinatorRequest group_coordinator_request;
};

struct RequestMessage {
	union ReqMessage rm; // ! APIKEY
	enum request_type APIKey;
	int APIVersion;
	int CorrelationId;
	char ClientId[CLIENT_ID_SIZE];
};

// Responses now

struct Broker {
	int NodeId;
	int Port;
	char Host[HOST_SIZE];
};

struct Replica {
	int Replica;
};

struct Isr {
	int Isr;
};

struct PartitionMetadata {
	struct Isr Isr[MAX_ISR];
	struct Replica Replicas[MAX_REPLICAS];
	int Leader;
	int NUM_Isrs; // Isr
	int NUM_REPLICAS; // Replicas
	int PartitionErrorCode;
	int PartitionId;
};

struct TopicMetadata {
	struct PartitionMetadata PartitionMetadatas[METADATAS_SIZE];
	struct TopicName TopicName;
	int NUM_PARTITIONS; // PartitionMetadatas
	int TopicErrorCode;
};

struct MetadataResponse {
	struct Broker Brokers[MAX_BROKERS];
	int NUM_BROKERS; // Brokers
};

struct SubSubProduceResponse {
	long Offset;
	long Timestamp;
	int ErrorCode;
	int Partition;
};

struct SubProduceResponse {
	struct SubSubProduceResponse sspr[MAX_SUB_SUB_SIZE];
	struct TopicName TopicName;
	int NUM_SUBSUB; // sspr
};

struct ProduceResponse {
	struct SubProduceResponse spr[MAX_SUB_SIZE];
	int NUM_SUB; //spr
	int ThrottleTime;
};

struct subSubFetchResponse {
	struct message_set MessageSet;
	long HighwayMarkOffset;
	int Partition;
	int ErrorCode;
	int MessageSetSize;
};

struct subFetchResponse {
	struct subSubFetchResponse ssfr[MAX_SUB_SUB_FETCH_SIZE];
	struct TopicName TopicName;
	int NUM_SSFR; // ssfr
};

struct FetchResponse {
	struct subFetchResponse sfr[MAX_SUB_FETCH_SIZE];
	int NUM_SFR; // sfr
	int ThrottleTime;
};

struct Offset{
	long Offset;
};

struct PartitionOffsets {
	struct Offset Offsets[MAX_OFFSETS];
	int Partition;
	int ErrorCode;
	int NUM_OFFSETS;// Offsets
	long Timestamp;
};

struct subOffsetResponse {
	struct TopicName TopicName;
	struct PartitionOffsets PartitionOffsets[MAX_PART_OFFSETS];
	int NUM_PARTS; // PartitionOffsets
};

struct OffsetResponse {
	struct subOffsetResponse sor[MAX_SOR];
	int NUM_SOR; // sor
};

struct GroupCoordinatorResponse {
	int CorrdinatorId;
	int CorrdinatorPort;
	int ErrorCode;
	char CorrdinatorHost[HOST_SIZE];
};

struct subSubOffsetCommitResponse{
	int Partition;
	int ErrorCode;
};

struct subOffsetCommitResponse{
	struct TopicName TopicName;
	struct subSubOffsetCommitResponse ssocr[MAX_SUB_SUB_OCR];
	int NUM_SSOCR; // ssocr
};

struct OffsetCommitResponse{
	struct subOffsetCommitResponse socr[MAX_SUB_OCR];
	int NUM_SUB_OCR; // socr
};

struct subSubOffsetFetchResponse{
	long Offset;
	int ErrorCode;
	int Partition;
	char Metadata[METADATA_SIZE];
};

struct subOffsetFetchResponse{
	struct subSubOffsetFetchResponse ssofr[MAX_SUB_SUB_OFR];
	struct TopicName TopicName;
	int NUM_SSOFR; // ssofr
};

struct OffsetFetchResponse {
	struct subOffsetFetchResponse sofr[MAX_SUB_OFR];
	int NUM_SUB_OFR; // sofr
};

union ResMessage {
	struct MetadataResponse metadata_response;
	struct ProduceResponse produce_response;
	struct FetchResponse fetch_response;
	struct OffsetResponse offset_response;
	struct OffsetCommitResponse offset_commit_response;
	struct OffsetFetchResponse offset_fetch_response;
	struct GroupCoordinatorResponse group_coordinator_response;
};

struct ResponseMessage {
	union ResMessage rm;
	int CorrelationId;
};

extern enum response_type match_requesttype(enum request_type);
extern void clear_responsemessage(struct ResponseMessage *,
    enum request_type);
extern void clear_requestmessage(struct RequestMessage *,
    enum request_type);

#endif
