/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#define CLIENT_ID_SIZE 12
#define KEY_SIZE 12
#define VALUE_SIZE 12
#define MAX_SET_SIZE 8
#define METADATA_REQUEST_MAX_TOPICS 64
#define TopicNameSize 16
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

enum reply_error_codes{
    CRC_NOT_MATCH = 1 << 0,
    CRC_MATCH = 1 << 2,
    INSERT_ERROR  = 1 << 3,
    INSERT_SUCCESS = 1 << 4
};

enum request_type {
    REQUEST_PRODUCE,
    REQUEST_OFFSET_COMMIT,
    REQUEST_OFFSET,
    REQUEST_FETCH,
    REQUEST_OFFSET_FETCH,
    REQUEST_METADATA,
    REQUEST_GROUP_COORDINATOR
};

enum response_type {
    RESPONSE_METADATA,
    RESPONSE_PRODUCE,
    RESPONSE_FETCH,
    RESPONSE_OFFSET,
    RESPONSE_OFFSET_COMMIT,
    RESPONSE_OFFSET_FETCH,
    RESPONSE_GROUP_COORDINATOR
};

struct Message{
    unsigned long CRC;
    unsigned long Timestamp;
    int Attributes;
    char key[KEY_SIZE];
    char value[VALUE_SIZE];
};

struct MessageSetElement{
    long Offset;
    int MessageSize;
    struct Message Message;
};

struct MessageSet{
    int NUM_ELEMS; // Elems
    struct MessageSetElement Elems[MAX_SET_SIZE];
};

struct TopicName{
    char TopicName[TopicNameSize];
};

struct GroupCoordinatorRequest{
    char GroupId[GROUP_ID_SIZE];
};

struct MetadataRequest{
    int NUM_TOPICS; // TopicNames
    struct TopicName TopicNames[METADATA_REQUEST_MAX_TOPICS];
};

struct SubSubProduceRequest{
    int Partition;
    int MessageSetSize;
    struct MessageSet mset;
};

struct SubProduceRequest{
    struct TopicName TopicName;
    struct SubSubProduceRequest sspr;
};

struct ProduceRequest{
    int RequiredAcks;
    int Timeout;
    struct SubProduceRequest spr;
};


struct FetchRequest{
    int ReplicaId;
    int MaxWaitTime;
    int MinBytes;
    struct TopicName TopicName;
    int Partition;
    long FetchOffset;
    int MaxBytes;
};

struct OffsetRequest{
    int RepolicaId;
    struct TopicName TopicName;
    int Partition;
    long Time;
};

struct OffsetCommitRequest{
    char ConsumerGroupId[CONSUMER_GROUP_ID_SIZE];
    int ConsumerGroupGenerationId;
    int ConsumerId;

    struct TopicName TopicName;

    int Partition;
    long Offset;
    long Timestamp;
    char Metadata[METADATA_SIZE];
};

struct OffsetFetchRequest{
    char ConsumerGroupId[CONSUMER_GROUP_ID_SIZE];
    struct TopicName TopicName;
    int Partition;
};

union ReqMessage{
    struct MetadataRequest     metadata_request;
    struct ProduceRequest      produce_request;
    struct FetchRequest        fetch_request;
    struct OffsetRequest       offset_request;
    struct OffsetCommitRequest offset_commit_request;
    struct OffsetFetchRequest  offset_fetch_request;
    struct GroupCoordinatorRequest group_coordinator_request;
};


struct RequestMessage{
    enum request_type APIKey;
    int APIVersion;
    int CorrelationId;
    char ClientId[CLIENT_ID_SIZE];

    union ReqMessage rm; // ! APIKEY
};

// Responses now


struct Broker{
    int NodeId;
    char Host[HOST_SIZE];
    int Port;
};

struct Replica{
  int Replica;
};

struct Isr{
    int Isr;
};
struct PartitionMetadata{
    int PartitionErrorCode;
    int PartitionId;
    int Leader;
    int NUM_REPLICAS; // Replicas
    struct Replica Replicas[MAX_REPLICAS];
    int NUM_Isrs; // Isr
    struct Isr Isr[MAX_ISR];
};

struct TopicMetadata{
    int TopicErrorCode;
    struct TopicName TopicName;
    int NUM_PARTITIONS; // PartitionMetadatas
    struct PartitionMetadata PartitionMetadatas[METADATAS_SIZE];
};

struct MetadataResponse{
    int NUM_BROKERS; // Brokers
    struct Broker Brokers[MAX_BROKERS];
};

struct SubSubProduceResponse{
    int Partition;
    int ErrorCode;
    long Offset;
    long Timestamp;
};

struct SubProduceResponse{
    struct TopicName TopicName;
    int NUM_SUBSUB; // sspr
    struct SubSubProduceResponse sspr[MAX_SUB_SUB_SIZE];
};

struct ProduceResponse{
    int NUM_SUB; //spr
    struct SubProduceResponse spr[MAX_SUB_SIZE];
    int ThrottleTime;
};

struct subSubFetchResponse{
    int Partition;
    int ErrorCode;
    long HighwayMarkOffset;
    int MessageSetSize;
    struct MessageSet MessageSet;
};

struct subFetchResponse{
    struct TopicName TopicName;
    int NUM_SSFR; // ssfr
    struct subSubFetchResponse ssfr[MAX_SUB_SUB_FETCH_SIZE];
};

struct FetchResponse{
    int NUM_SFR; // sfr
    struct subFetchResponse sfr[MAX_SUB_FETCH_SIZE];
    int ThrottleTime;
};

struct Offset{
    long Offset;
};

struct PartitionOffsets{
    int Partition;
    int ErrorCode;
    long Timestamp;
    int NUM_OFFSETS;// Offsets
    struct Offset Offsets[MAX_OFFSETS];
};

struct subOffsetResponse{
    struct TopicName TopicName;
    int NUM_PARTS; // PartitionOffsets
    struct PartitionOffsets PartitionOffsets[MAX_PART_OFFSETS];
};

struct OffsetResponse{
    int NUM_SOR; // sor
    struct subOffsetResponse sor[MAX_SOR];
};

struct GroupCoordinatorResponse{
    int ErrorCode;
    int CorrdinatorId;
    char CorrdinatorHost[HOST_SIZE];
    int CorrdinatorPort;
};

struct subSubOffsetCommitResponse{
    int Partition;
    int ErrorCode;
};

struct subOffsetCommitResponse{
    struct TopicName TopicName;
    int NUM_SSOCR; // ssocr
    struct subSubOffsetCommitResponse ssocr[MAX_SUB_SUB_OCR];
};

struct OffsetCommitResponse{
    int NUM_SUB_OCR; // socr
    struct subOffsetCommitResponse socr[MAX_SUB_OCR];
};

struct subSubOffsetFetchResponse{
    int Partition;
    long Offset;
    char Metadata[METADATA_SIZE];
    int ErrorCode;
};

struct subOffsetFetchResponse{
    struct TopicName TopicName;
    int NUM_SSOFR; // ssofr
    struct subSubOffsetFetchResponse ssofr[MAX_SUB_SUB_OFR];
};

struct OffsetFetchResponse{
    int NUM_SUB_OFR; // sofr
    struct subOffsetFetchResponse sofr[MAX_SUB_OFR];
};


union ResMessage{
    struct MetadataResponse metadata_response;
    struct ProduceResponse  produce_response;
    struct FetchResponse    fetch_response;
    struct OffsetResponse   offset_response;
    struct OffsetCommitResponse offset_commit_response;
    struct OffsetFetchResponse  offset_fetch_response;
    struct GroupCoordinatorResponse group_coordinator_response;
};

struct ResponseMessage{
    int CorrelationId;
    union ResMessage rm;
};

enum response_type match_requesttype(enum request_type rt);
void clear_responsemessage(struct ResponseMessage* rm, enum request_type rt);
void clear_requestmessage(struct RequestMessage* rm, enum request_type rt);

#endif
