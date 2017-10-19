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

#include "../headers/message.h"
#include "../headers/protocol.h"
#include "../headers/protocol_common.h"
#include <string.h>
#include <stdio.h>

extern int MESSAGESETSIZE_FIELD_SIZE;
extern int NUM_SOR_FIELD_SIZE;
extern int NUM_PARTITIONS_FIELD_SIZE;
extern int NUM_PARTS_FIELD_SIZE;
extern int GROUP_COORDINATOR_REQUEST_SIZE_FIELD_SIZE;
extern int SSPR_SIZE_FIELD_SIZE;
extern int METADATA_SIZE_FIELD_SIZE;
extern int APIKEY_FIELD_SIZE;
extern int TOPICERRORCODE_FIELD_SIZE;
extern int REPLICAS_SIZE_FIELD_SIZE;
extern int CONSUMERGROUPGENERATIONID_FIELD_SIZE;
extern int HOST_SIZE_FIELD_SIZE;
extern int THROTTLETIME_FIELD_SIZE;
extern int NUM_SUB_OFR_FIELD_SIZE;
extern int NUM_SUBSUB_FIELD_SIZE;
extern int CORRDINATORID_FIELD_SIZE;
extern int NUM_REPLICAS_FIELD_SIZE;
extern int NUM_BROKERS_FIELD_SIZE;
extern int ATTRIBUTES_FIELD_SIZE;
extern int NUM_SFR_FIELD_SIZE;
extern int FETCHOFFSET_FIELD_SIZE;
extern int MAXBYTES_FIELD_SIZE;
extern int REPLICA_FIELD_SIZE;
extern int SOFR_SIZE_FIELD_SIZE;
extern int FETCH_RESPONSE_SIZE_FIELD_SIZE;
extern int NUM_SUB_FIELD_SIZE;
extern int APIVERSION_FIELD_SIZE;
extern int CRC_FIELD_SIZE;
extern int VALUE_SIZE_FIELD_SIZE;
extern int NUM_ISRS_FIELD_SIZE;
extern int RM_SIZE_FIELD_SIZE;
extern int CORRELATIONID_FIELD_SIZE;
extern int NUM_TOPICS_FIELD_SIZE;
extern int REPOLICAID_FIELD_SIZE;
extern int OFFSET_COMMIT_RESPONSE_SIZE_FIELD_SIZE;
extern int PARTITION_FIELD_SIZE;
extern int OFFSET_REQUEST_SIZE_FIELD_SIZE;
extern int KEY_SIZE_FIELD_SIZE;
extern int MESSAGESIZE_FIELD_SIZE;
extern int OFFSET_RESPONSE_SIZE_FIELD_SIZE;
extern int MESSAGE_SIZE_FIELD_SIZE;
extern int TOPICNAME_SIZE_FIELD_SIZE;
extern int PARTITIONID_FIELD_SIZE;
extern int REPLICAID_FIELD_SIZE;
extern int SOR_SIZE_FIELD_SIZE;
extern int OFFSET_COMMIT_REQUEST_SIZE_FIELD_SIZE;
extern int LEADER_FIELD_SIZE;
extern int OFFSET_FETCH_REQUEST_SIZE_FIELD_SIZE;
extern int PARTITIONMETADATAS_SIZE_FIELD_SIZE;
extern int TIMESTAMP_FIELD_SIZE;
extern int NUM_OFFSETS_FIELD_SIZE;
extern int ERRORCODE_FIELD_SIZE;
extern int CONSUMERID_FIELD_SIZE;
extern int BROKERS_SIZE_FIELD_SIZE;
extern int OFFSET_FIELD_SIZE;
extern int SOCR_SIZE_FIELD_SIZE;
extern int CORRDINATORPORT_FIELD_SIZE;
extern int NUM_SSOCR_FIELD_SIZE;
extern int SSOFR_SIZE_FIELD_SIZE;
extern int METADATA_RESPONSE_SIZE_FIELD_SIZE;
extern int MAXWAITTIME_FIELD_SIZE;
extern int TIMEOUT_FIELD_SIZE;
extern int TIME_FIELD_SIZE;
extern int CONSUMERGROUPID_SIZE_FIELD_SIZE;
extern int MESSAGESET_SIZE_FIELD_SIZE;
extern int ELEMS_SIZE_FIELD_SIZE;
extern int NUM_SUB_OCR_FIELD_SIZE;
extern int PARTITIONOFFSETS_SIZE_FIELD_SIZE;
extern int PRODUCE_RESPONSE_SIZE_FIELD_SIZE;
extern int SSFR_SIZE_FIELD_SIZE;
extern int PRODUCE_REQUEST_SIZE_FIELD_SIZE;
extern int SSOCR_SIZE_FIELD_SIZE;
extern int NUM_ELEMS_FIELD_SIZE;
extern int SPR_SIZE_FIELD_SIZE;
extern int CLIENTID_SIZE_FIELD_SIZE;
extern int METADATA_REQUEST_SIZE_FIELD_SIZE;
extern int NUM_SSOFR_FIELD_SIZE;
extern int MSET_SIZE_FIELD_SIZE;
extern int HIGHWAYMARKOFFSET_FIELD_SIZE;
extern int TOPICNAMES_SIZE_FIELD_SIZE;
extern int OFFSETS_SIZE_FIELD_SIZE;
extern int REQUIREDACKS_FIELD_SIZE;
extern int FETCH_REQUEST_SIZE_FIELD_SIZE;
extern int CORRDINATORHOST_SIZE_FIELD_SIZE;
extern int GROUP_COORDINATOR_RESPONSE_SIZE_FIELD_SIZE;
extern int ISR_FIELD_SIZE;
extern int SFR_SIZE_FIELD_SIZE;
extern int NODEID_FIELD_SIZE;
extern int GROUPID_SIZE_FIELD_SIZE;
extern int NUM_SSFR_FIELD_SIZE;
extern int MINBYTES_FIELD_SIZE;
extern int OFFSET_FETCH_RESPONSE_SIZE_FIELD_SIZE;
extern int PARTITIONERRORCODE_FIELD_SIZE;
extern int PORT_FIELD_SIZE;

int parse_message(struct Message* inp, char *beg){
	unsigned long temp_var_crc = get_long(beg, CRC_FIELD_SIZE);
	inp->CRC = temp_var_crc;
	unsigned long temp_var_timestamp = get_long(beg+CRC_FIELD_SIZE, TIMESTAMP_FIELD_SIZE);
	inp->Timestamp = temp_var_timestamp;
	int temp_var_attributes = get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE, ATTRIBUTES_FIELD_SIZE);
	inp->Attributes = temp_var_attributes;
	int read_var_key = get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE, KEY_SIZE_FIELD_SIZE);
	char* krya_key = inp->key;
	get_val(&krya_key, beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE, read_var_key);
	krya_key[read_var_key] = '\0';
	int read_var_value = get_int(beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE+read_var_key, VALUE_SIZE_FIELD_SIZE);
	char* krya_value = inp->value;
	get_val(&krya_value, beg+CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE+read_var_key+VALUE_SIZE_FIELD_SIZE, read_var_value);
	krya_value[read_var_value] = '\0';
	return CRC_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+ATTRIBUTES_FIELD_SIZE+KEY_SIZE_FIELD_SIZE+read_var_key+VALUE_SIZE_FIELD_SIZE+read_var_value;
}
int parse_messagesetelement(struct MessageSetElement* inp, char *beg){
	long temp_var_offset = get_long(beg, OFFSET_FIELD_SIZE);
	inp->Offset = temp_var_offset;
	int temp_var_messagesize = get_int(beg+OFFSET_FIELD_SIZE, MESSAGESIZE_FIELD_SIZE);
	inp->MessageSize = temp_var_messagesize;
	int parsed_size_message = parse_message(&inp->Message, beg+OFFSET_FIELD_SIZE+MESSAGESIZE_FIELD_SIZE);
	return OFFSET_FIELD_SIZE+MESSAGESIZE_FIELD_SIZE+parsed_size_message;
}
int parse_messageset(struct MessageSet* inp, char *beg){
	int read_var_elems = get_int(beg, ELEMS_SIZE_FIELD_SIZE);
	struct MessageSetElement* krya_elems = inp->Elems;
	int temp_elems = 0;
	for(int i=0; i<read_var_elems; i++){
		temp_elems = temp_elems + parse_messagesetelement(&krya_elems[i], beg+ELEMS_SIZE_FIELD_SIZE + temp_elems);
	}
	inp->NUM_ELEMS = read_var_elems;
	return ELEMS_SIZE_FIELD_SIZE+temp_elems;
}
int parse_topicname(struct TopicName* inp, char *beg){
	int read_var_topicname = get_int(beg, TOPICNAME_SIZE_FIELD_SIZE);
	char* krya_topicname = inp->TopicName;
	get_val(&krya_topicname, beg+TOPICNAME_SIZE_FIELD_SIZE, read_var_topicname);
	krya_topicname[read_var_topicname] = '\0';
	return TOPICNAME_SIZE_FIELD_SIZE+read_var_topicname;
}
int parse_groupcoordinatorrequest(struct GroupCoordinatorRequest* inp, char *beg){
	int read_var_groupid = get_int(beg, GROUPID_SIZE_FIELD_SIZE);
	char* krya_groupid = inp->GroupId;
	get_val(&krya_groupid, beg+GROUPID_SIZE_FIELD_SIZE, read_var_groupid);
	krya_groupid[read_var_groupid] = '\0';
	return GROUPID_SIZE_FIELD_SIZE+read_var_groupid;
}
int parse_metadatarequest(struct MetadataRequest* inp, char *beg){
	int read_var_topicnames = get_int(beg, TOPICNAMES_SIZE_FIELD_SIZE);
	struct TopicName* krya_topicnames = inp->TopicNames;
	int temp_topicnames = 0;
	for(int i=0; i<read_var_topicnames; i++){
		temp_topicnames = temp_topicnames + parse_topicname(&krya_topicnames[i], beg+TOPICNAMES_SIZE_FIELD_SIZE + temp_topicnames);
	}
	inp->NUM_TOPICS = read_var_topicnames;
	return TOPICNAMES_SIZE_FIELD_SIZE+temp_topicnames;
}
int parse_subsubproducerequest(struct SubSubProduceRequest* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	int temp_var_messagesetsize = get_int(beg+PARTITION_FIELD_SIZE, MESSAGESETSIZE_FIELD_SIZE);
	inp->MessageSetSize = temp_var_messagesetsize;
	int parsed_size_messageset = parse_messageset(&inp->mset, beg+PARTITION_FIELD_SIZE+MESSAGESETSIZE_FIELD_SIZE);
	return PARTITION_FIELD_SIZE+MESSAGESETSIZE_FIELD_SIZE+parsed_size_messageset;
}
int parse_subproducerequest(struct SubProduceRequest* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int parsed_size_subsubproducerequest = parse_subsubproducerequest(&inp->sspr, beg+parsed_size_topicname);
	return parsed_size_topicname+parsed_size_subsubproducerequest;
}
int parse_producerequest(struct ProduceRequest* inp, char *beg){
	int temp_var_requiredacks = get_int(beg, REQUIREDACKS_FIELD_SIZE);
	inp->RequiredAcks = temp_var_requiredacks;
	int temp_var_timeout = get_int(beg+REQUIREDACKS_FIELD_SIZE, TIMEOUT_FIELD_SIZE);
	inp->Timeout = temp_var_timeout;
	int parsed_size_subproducerequest = parse_subproducerequest(&inp->spr, beg+REQUIREDACKS_FIELD_SIZE+TIMEOUT_FIELD_SIZE);
	return REQUIREDACKS_FIELD_SIZE+TIMEOUT_FIELD_SIZE+parsed_size_subproducerequest;
}
int parse_fetchrequest(struct FetchRequest* inp, char *beg){
	int temp_var_replicaid = get_int(beg, REPLICAID_FIELD_SIZE);
	inp->ReplicaId = temp_var_replicaid;
	int temp_var_maxwaittime = get_int(beg+REPLICAID_FIELD_SIZE, MAXWAITTIME_FIELD_SIZE);
	inp->MaxWaitTime = temp_var_maxwaittime;
	int temp_var_minbytes = get_int(beg+REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE, MINBYTES_FIELD_SIZE);
	inp->MinBytes = temp_var_minbytes;
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg+REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE+MINBYTES_FIELD_SIZE);
	int temp_var_partition = get_int(beg+REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE+MINBYTES_FIELD_SIZE+parsed_size_topicname, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	long temp_var_fetchoffset = get_long(beg+REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE+MINBYTES_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE, FETCHOFFSET_FIELD_SIZE);
	inp->FetchOffset = temp_var_fetchoffset;
	int temp_var_maxbytes = get_int(beg+REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE+MINBYTES_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+FETCHOFFSET_FIELD_SIZE, MAXBYTES_FIELD_SIZE);
	inp->MaxBytes = temp_var_maxbytes;
	return REPLICAID_FIELD_SIZE+MAXWAITTIME_FIELD_SIZE+MINBYTES_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+FETCHOFFSET_FIELD_SIZE+MAXBYTES_FIELD_SIZE;
}
int parse_offsetrequest(struct OffsetRequest* inp, char *beg){
	int temp_var_repolicaid = get_int(beg, REPOLICAID_FIELD_SIZE);
	inp->RepolicaId = temp_var_repolicaid;
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg+REPOLICAID_FIELD_SIZE);
	int temp_var_partition = get_int(beg+REPOLICAID_FIELD_SIZE+parsed_size_topicname, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	long temp_var_time = get_long(beg+REPOLICAID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE, TIME_FIELD_SIZE);
	inp->Time = temp_var_time;
	return REPOLICAID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+TIME_FIELD_SIZE;
}
int parse_offsetcommitrequest(struct OffsetCommitRequest* inp, char *beg){
	int read_var_consumergroupid = get_int(beg, CONSUMERGROUPID_SIZE_FIELD_SIZE);
	char* krya_consumergroupid = inp->ConsumerGroupId;
	get_val(&krya_consumergroupid, beg+CONSUMERGROUPID_SIZE_FIELD_SIZE, read_var_consumergroupid);
	krya_consumergroupid[read_var_consumergroupid] = '\0';
	int temp_var_consumergroupgenerationid = get_int(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid, CONSUMERGROUPGENERATIONID_FIELD_SIZE);
	inp->ConsumerGroupGenerationId = temp_var_consumergroupgenerationid;
	int temp_var_consumerid = get_int(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE, CONSUMERID_FIELD_SIZE);
	inp->ConsumerId = temp_var_consumerid;
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE);
	int temp_var_partition = get_int(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	long temp_var_offset = get_long(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE, OFFSET_FIELD_SIZE);
	inp->Offset = temp_var_offset;
	long temp_var_timestamp = get_long(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE, TIMESTAMP_FIELD_SIZE);
	inp->Timestamp = temp_var_timestamp;
	int read_var_metadata = get_int(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+TIMESTAMP_FIELD_SIZE, METADATA_SIZE_FIELD_SIZE);
	char* krya_metadata = inp->Metadata;
	get_val(&krya_metadata, beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+METADATA_SIZE_FIELD_SIZE, read_var_metadata);
	krya_metadata[read_var_metadata] = '\0';
	return CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+CONSUMERGROUPGENERATIONID_FIELD_SIZE+CONSUMERID_FIELD_SIZE+parsed_size_topicname+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+METADATA_SIZE_FIELD_SIZE+read_var_metadata;
}
int parse_offsetfetchrequest(struct OffsetFetchRequest* inp, char *beg){
	int read_var_consumergroupid = get_int(beg, CONSUMERGROUPID_SIZE_FIELD_SIZE);
	char* krya_consumergroupid = inp->ConsumerGroupId;
	get_val(&krya_consumergroupid, beg+CONSUMERGROUPID_SIZE_FIELD_SIZE, read_var_consumergroupid);
	krya_consumergroupid[read_var_consumergroupid] = '\0';
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid);
	int temp_var_partition = get_int(beg+CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+parsed_size_topicname, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	return CONSUMERGROUPID_SIZE_FIELD_SIZE+read_var_consumergroupid+parsed_size_topicname+PARTITION_FIELD_SIZE;
}
int parse_reqmessage(union ReqMessage* inp, char *beg, enum request_type rt){
	int siz = 0;

	switch(rt){
		case REQUEST_METADATA: siz =  parse_metadatarequest(&inp->metadata_request, beg); break;
		case REQUEST_PRODUCE: siz =  parse_producerequest(&inp->produce_request, beg); break;
		case REQUEST_FETCH: siz = parse_fetchrequest(&inp->fetch_request, beg); break;
		case REQUEST_OFFSET: siz = parse_offsetrequest(&inp->offset_request, beg); break;
		case REQUEST_OFFSET_COMMIT: siz = parse_offsetcommitrequest(&inp->offset_commit_request, beg); break;
		case REQUEST_OFFSET_FETCH: siz = parse_offsetfetchrequest(&inp->offset_fetch_request, beg); break;
		case REQUEST_GROUP_COORDINATOR: siz = parse_groupcoordinatorrequest(&inp->group_coordinator_request, beg); break;
	}

	return siz;
}

enum request_type get_apikey(char* beg){
    return (enum request_type) get_int(beg, APIKEY_FIELD_SIZE);
}

int parse_requestmessage(struct RequestMessage* inp, char *beg){
	int temp_var_apikey = get_int(beg, APIKEY_FIELD_SIZE);
	inp->APIKey = (enum request_type)temp_var_apikey;
	int temp_var_apiversion = get_int(beg+APIKEY_FIELD_SIZE, APIVERSION_FIELD_SIZE);
	inp->APIVersion = temp_var_apiversion;
	int temp_var_correlationid = get_int(beg+APIKEY_FIELD_SIZE+APIVERSION_FIELD_SIZE, CORRELATIONID_FIELD_SIZE);
	inp->CorrelationId = temp_var_correlationid;
	int read_var_clientid = get_int(beg+APIKEY_FIELD_SIZE+APIVERSION_FIELD_SIZE+CORRELATIONID_FIELD_SIZE, CLIENTID_SIZE_FIELD_SIZE);
	char* krya_clientid = inp->ClientId;
	get_val(&krya_clientid, beg+APIKEY_FIELD_SIZE+APIVERSION_FIELD_SIZE+CORRELATIONID_FIELD_SIZE+CLIENTID_SIZE_FIELD_SIZE, read_var_clientid);
	krya_clientid[read_var_clientid] = '\0';
		int msiz = parse_reqmessage(&inp->rm, beg+APIKEY_FIELD_SIZE+APIVERSION_FIELD_SIZE+CORRELATIONID_FIELD_SIZE+CLIENTID_SIZE_FIELD_SIZE+read_var_clientid, inp->APIKey);
	return APIKEY_FIELD_SIZE+APIVERSION_FIELD_SIZE+CORRELATIONID_FIELD_SIZE+CLIENTID_SIZE_FIELD_SIZE+read_var_clientid+msiz;
}

int parse_broker(struct Broker* inp, char *beg){
	int temp_var_nodeid = get_int(beg, NODEID_FIELD_SIZE);
	inp->NodeId = temp_var_nodeid;
	int read_var_host = get_int(beg+NODEID_FIELD_SIZE, HOST_SIZE_FIELD_SIZE);
	char* krya_host = inp->Host;
	get_val(&krya_host, beg+NODEID_FIELD_SIZE+HOST_SIZE_FIELD_SIZE, read_var_host);
	krya_host[read_var_host] = '\0';
	int temp_var_port = get_int(beg+NODEID_FIELD_SIZE+HOST_SIZE_FIELD_SIZE+read_var_host, PORT_FIELD_SIZE);
	inp->Port = temp_var_port;
	return NODEID_FIELD_SIZE+HOST_SIZE_FIELD_SIZE+read_var_host+PORT_FIELD_SIZE;
}
int parse_replica(struct Replica* inp, char *beg){
	int temp_var_replica = get_int(beg, REPLICA_FIELD_SIZE);
	inp->Replica = temp_var_replica;
	return REPLICA_FIELD_SIZE;
}
int parse_isr(struct Isr* inp, char *beg){
	int temp_var_isr = get_int(beg, ISR_FIELD_SIZE);
	inp->Isr = temp_var_isr;
	return ISR_FIELD_SIZE;
}
int parse_partitionmetadata(struct PartitionMetadata* inp, char *beg){
	int temp_var_partitionerrorcode = get_int(beg, PARTITIONERRORCODE_FIELD_SIZE);
	inp->PartitionErrorCode = temp_var_partitionerrorcode;
	int temp_var_partitionid = get_int(beg+PARTITIONERRORCODE_FIELD_SIZE, PARTITIONID_FIELD_SIZE);
	inp->PartitionId = temp_var_partitionid;
	int temp_var_leader = get_int(beg+PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE, LEADER_FIELD_SIZE);
	inp->Leader = temp_var_leader;
	int read_var_replicas = get_int(beg+PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE+LEADER_FIELD_SIZE, REPLICAS_SIZE_FIELD_SIZE);
	struct Replica* krya_replicas = inp->Replicas;
	int temp_replicas = 0;
	for(int i=0; i<read_var_replicas; i++){
		temp_replicas = temp_replicas + parse_replica(&krya_replicas[i], beg+PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE+LEADER_FIELD_SIZE+REPLICAS_SIZE_FIELD_SIZE + temp_replicas);
	}
	inp->NUM_REPLICAS = read_var_replicas;
	int read_var_isr = get_int(beg+PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE+LEADER_FIELD_SIZE+REPLICAS_SIZE_FIELD_SIZE+temp_replicas, ISR_FIELD_SIZE);
	struct Isr* krya_isr = inp->Isr;
	int temp_isr = 0;
	for(int i=0; i<read_var_isr; i++){
		temp_isr = temp_isr + parse_isr(&krya_isr[i], beg+PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE+LEADER_FIELD_SIZE+REPLICAS_SIZE_FIELD_SIZE+temp_replicas+ISR_FIELD_SIZE + temp_isr);
	}
	inp->NUM_Isrs = read_var_isr;
	return PARTITIONERRORCODE_FIELD_SIZE+PARTITIONID_FIELD_SIZE+LEADER_FIELD_SIZE+REPLICAS_SIZE_FIELD_SIZE+temp_replicas+ISR_FIELD_SIZE+temp_isr;
}
int parse_topicmetadata(struct TopicMetadata* inp, char *beg){
	int temp_var_topicerrorcode = get_int(beg, TOPICERRORCODE_FIELD_SIZE);
	inp->TopicErrorCode = temp_var_topicerrorcode;
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg+TOPICERRORCODE_FIELD_SIZE);
	int read_var_partitionmetadatas = get_int(beg+TOPICERRORCODE_FIELD_SIZE+parsed_size_topicname, PARTITIONMETADATAS_SIZE_FIELD_SIZE);
	struct PartitionMetadata* krya_partitionmetadatas = inp->PartitionMetadatas;
	int temp_partitionmetadatas = 0;
	for(int i=0; i<read_var_partitionmetadatas; i++){
		temp_partitionmetadatas = temp_partitionmetadatas + parse_partitionmetadata(&krya_partitionmetadatas[i], beg+TOPICERRORCODE_FIELD_SIZE+parsed_size_topicname+PARTITIONMETADATAS_SIZE_FIELD_SIZE + temp_partitionmetadatas);
	}
	inp->NUM_PARTITIONS = read_var_partitionmetadatas;
	return TOPICERRORCODE_FIELD_SIZE+parsed_size_topicname+PARTITIONMETADATAS_SIZE_FIELD_SIZE+temp_partitionmetadatas;
}
int parse_metadataresponse(struct MetadataResponse* inp, char *beg){
	int read_var_brokers = get_int(beg, BROKERS_SIZE_FIELD_SIZE);
	struct Broker* krya_brokers = inp->Brokers;
	int temp_brokers = 0;
	for(int i=0; i<read_var_brokers; i++){
		temp_brokers = temp_brokers + parse_broker(&krya_brokers[i], beg+BROKERS_SIZE_FIELD_SIZE + temp_brokers);
	}
	inp->NUM_BROKERS = read_var_brokers;
	return BROKERS_SIZE_FIELD_SIZE+temp_brokers;
}
int parse_subsubproduceresponse(struct SubSubProduceResponse* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	int temp_var_errorcode = get_int(beg+PARTITION_FIELD_SIZE, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	long temp_var_offset = get_long(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE, OFFSET_FIELD_SIZE);
	inp->Offset = temp_var_offset;
	long temp_var_timestamp = get_long(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+OFFSET_FIELD_SIZE, TIMESTAMP_FIELD_SIZE);
	inp->Timestamp = temp_var_timestamp;
	return PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+OFFSET_FIELD_SIZE+TIMESTAMP_FIELD_SIZE;
}
int parse_subproduceresponse(struct SubProduceResponse* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int read_var_sspr = get_int(beg+parsed_size_topicname, SSPR_SIZE_FIELD_SIZE);
	struct SubSubProduceResponse* krya_sspr = inp->sspr;
	int temp_sspr = 0;
	for(int i=0; i<read_var_sspr; i++){
		temp_sspr = temp_sspr + parse_subsubproduceresponse(&krya_sspr[i], beg+parsed_size_topicname+SSPR_SIZE_FIELD_SIZE + temp_sspr);
	}
	inp->NUM_SUBSUB = read_var_sspr;
	return parsed_size_topicname+SSPR_SIZE_FIELD_SIZE+temp_sspr;
}
int parse_produceresponse(struct ProduceResponse* inp, char *beg){
	int read_var_spr = get_int(beg, SPR_SIZE_FIELD_SIZE);
	struct SubProduceResponse* krya_spr = inp->spr;
	int temp_spr = 0;
	for(int i=0; i<read_var_spr; i++){
		temp_spr = temp_spr + parse_subproduceresponse(&krya_spr[i], beg+SPR_SIZE_FIELD_SIZE + temp_spr);
	}
	inp->NUM_SUB = read_var_spr;
	int temp_var_throttletime = get_int(beg+SPR_SIZE_FIELD_SIZE+temp_spr, THROTTLETIME_FIELD_SIZE);
	inp->ThrottleTime = temp_var_throttletime;
	return SPR_SIZE_FIELD_SIZE+temp_spr+THROTTLETIME_FIELD_SIZE;
}
int parse_subsubfetchresponse(struct subSubFetchResponse* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	int temp_var_errorcode = get_int(beg+PARTITION_FIELD_SIZE, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	long temp_var_highwaymarkoffset = get_long(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE, HIGHWAYMARKOFFSET_FIELD_SIZE);
	inp->HighwayMarkOffset = temp_var_highwaymarkoffset;
	int temp_var_messagesetsize = get_int(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+HIGHWAYMARKOFFSET_FIELD_SIZE, MESSAGESETSIZE_FIELD_SIZE);
	inp->MessageSetSize = temp_var_messagesetsize;
	int parsed_size_messageset = parse_messageset(&inp->MessageSet, beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+HIGHWAYMARKOFFSET_FIELD_SIZE+MESSAGESETSIZE_FIELD_SIZE);
	return PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+HIGHWAYMARKOFFSET_FIELD_SIZE+MESSAGESETSIZE_FIELD_SIZE+parsed_size_messageset;
}
int parse_subfetchresponse(struct subFetchResponse* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int read_var_ssfr = get_int(beg+parsed_size_topicname, SSFR_SIZE_FIELD_SIZE);
	struct subSubFetchResponse* krya_ssfr = inp->ssfr;
	int temp_ssfr = 0;
	for(int i=0; i<read_var_ssfr; i++){
		temp_ssfr = temp_ssfr + parse_subsubfetchresponse(&krya_ssfr[i], beg+parsed_size_topicname+SSFR_SIZE_FIELD_SIZE + temp_ssfr);
	}
	inp->NUM_SSFR = read_var_ssfr;
	return parsed_size_topicname+SSFR_SIZE_FIELD_SIZE+temp_ssfr;
}
int parse_fetchresponse(struct FetchResponse* inp, char *beg){
	int read_var_sfr = get_int(beg, SFR_SIZE_FIELD_SIZE);
	struct subFetchResponse* krya_sfr = inp->sfr;
	int temp_sfr = 0;
	for(int i=0; i<read_var_sfr; i++){
		temp_sfr = temp_sfr + parse_subfetchresponse(&krya_sfr[i], beg+SFR_SIZE_FIELD_SIZE + temp_sfr);
	}
	inp->NUM_SFR = read_var_sfr;
	int temp_var_throttletime = get_int(beg+SFR_SIZE_FIELD_SIZE+temp_sfr, THROTTLETIME_FIELD_SIZE);
	inp->ThrottleTime = temp_var_throttletime;
	return SFR_SIZE_FIELD_SIZE+temp_sfr+THROTTLETIME_FIELD_SIZE;
}
int parse_offset(struct Offset* inp, char *beg){
	long temp_var_offset = get_long(beg, OFFSET_FIELD_SIZE);
	inp->Offset = temp_var_offset;
	return OFFSET_FIELD_SIZE;
}
int parse_partitionoffsets(struct PartitionOffsets* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	int temp_var_errorcode = get_int(beg+PARTITION_FIELD_SIZE, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	long temp_var_timestamp = get_long(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE, TIMESTAMP_FIELD_SIZE);
	inp->Timestamp = temp_var_timestamp;
	int read_var_offsets = get_int(beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+TIMESTAMP_FIELD_SIZE, OFFSETS_SIZE_FIELD_SIZE);
	struct Offset* krya_offsets = inp->Offsets;
	int temp_offsets = 0;
	for(int i=0; i<read_var_offsets; i++){
		temp_offsets = temp_offsets + parse_offset(&krya_offsets[i], beg+PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+OFFSETS_SIZE_FIELD_SIZE + temp_offsets);
	}
	inp->NUM_OFFSETS = read_var_offsets;
	return PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE+TIMESTAMP_FIELD_SIZE+OFFSETS_SIZE_FIELD_SIZE+temp_offsets;
}
int parse_suboffsetresponse(struct subOffsetResponse* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int read_var_partitionoffsets = get_int(beg+parsed_size_topicname, PARTITIONOFFSETS_SIZE_FIELD_SIZE);
	struct PartitionOffsets* krya_partitionoffsets = inp->PartitionOffsets;
	int temp_partitionoffsets = 0;
	for(int i=0; i<read_var_partitionoffsets; i++){
		temp_partitionoffsets = temp_partitionoffsets + parse_partitionoffsets(&krya_partitionoffsets[i], beg+parsed_size_topicname+PARTITIONOFFSETS_SIZE_FIELD_SIZE + temp_partitionoffsets);
	}
	inp->NUM_PARTS = read_var_partitionoffsets;
	return parsed_size_topicname+PARTITIONOFFSETS_SIZE_FIELD_SIZE+temp_partitionoffsets;
}
int parse_offsetresponse(struct OffsetResponse* inp, char *beg){
	int read_var_sor = get_int(beg, SOR_SIZE_FIELD_SIZE);
	struct subOffsetResponse* krya_sor = inp->sor;
	int temp_sor = 0;
	for(int i=0; i<read_var_sor; i++){
		temp_sor = temp_sor + parse_suboffsetresponse(&krya_sor[i], beg+SOR_SIZE_FIELD_SIZE + temp_sor);
	}
	inp->NUM_SOR = read_var_sor;
	return SOR_SIZE_FIELD_SIZE+temp_sor;
}
int parse_groupcoordinatorresponse(struct GroupCoordinatorResponse* inp, char *beg){
	int temp_var_errorcode = get_int(beg, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	int temp_var_corrdinatorid = get_int(beg+ERRORCODE_FIELD_SIZE, CORRDINATORID_FIELD_SIZE);
	inp->CorrdinatorId = temp_var_corrdinatorid;
	int read_var_corrdinatorhost = get_int(beg+ERRORCODE_FIELD_SIZE+CORRDINATORID_FIELD_SIZE, CORRDINATORHOST_SIZE_FIELD_SIZE);
	char* krya_corrdinatorhost = inp->CorrdinatorHost;
	get_val(&krya_corrdinatorhost, beg+ERRORCODE_FIELD_SIZE+CORRDINATORID_FIELD_SIZE+CORRDINATORHOST_SIZE_FIELD_SIZE, read_var_corrdinatorhost);
	krya_corrdinatorhost[read_var_corrdinatorhost] = '\0';
	int temp_var_corrdinatorport = get_int(beg+ERRORCODE_FIELD_SIZE+CORRDINATORID_FIELD_SIZE+CORRDINATORHOST_SIZE_FIELD_SIZE+read_var_corrdinatorhost, CORRDINATORPORT_FIELD_SIZE);
	inp->CorrdinatorPort = temp_var_corrdinatorport;
	return ERRORCODE_FIELD_SIZE+CORRDINATORID_FIELD_SIZE+CORRDINATORHOST_SIZE_FIELD_SIZE+read_var_corrdinatorhost+CORRDINATORPORT_FIELD_SIZE;
}
int parse_subsuboffsetcommitresponse(struct subSubOffsetCommitResponse* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	int temp_var_errorcode = get_int(beg+PARTITION_FIELD_SIZE, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	return PARTITION_FIELD_SIZE+ERRORCODE_FIELD_SIZE;
}
int parse_suboffsetcommitresponse(struct subOffsetCommitResponse* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int read_var_ssocr = get_int(beg+parsed_size_topicname, SSOCR_SIZE_FIELD_SIZE);
	struct subSubOffsetCommitResponse* krya_ssocr = inp->ssocr;
	int temp_ssocr = 0;
	for(int i=0; i<read_var_ssocr; i++){
		temp_ssocr = temp_ssocr + parse_subsuboffsetcommitresponse(&krya_ssocr[i], beg+parsed_size_topicname+SSOCR_SIZE_FIELD_SIZE + temp_ssocr);
	}
	inp->NUM_SSOCR = read_var_ssocr;
	return parsed_size_topicname+SSOCR_SIZE_FIELD_SIZE+temp_ssocr;
}
int parse_offsetcommitresponse(struct OffsetCommitResponse* inp, char *beg){
	int read_var_socr = get_int(beg, SOCR_SIZE_FIELD_SIZE);
	struct subOffsetCommitResponse* krya_socr = inp->socr;
	int temp_socr = 0;
	for(int i=0; i<read_var_socr; i++){
		temp_socr = temp_socr + parse_suboffsetcommitresponse(&krya_socr[i], beg+SOCR_SIZE_FIELD_SIZE + temp_socr);
	}
	inp->NUM_SUB_OCR = read_var_socr;
	return SOCR_SIZE_FIELD_SIZE+temp_socr;
}
int parse_subsuboffsetfetchresponse(struct subSubOffsetFetchResponse* inp, char *beg){
	int temp_var_partition = get_int(beg, PARTITION_FIELD_SIZE);
	inp->Partition = temp_var_partition;
	long temp_var_offset = get_long(beg+PARTITION_FIELD_SIZE, OFFSET_FIELD_SIZE);
	inp->Offset = temp_var_offset;
	int read_var_metadata = get_int(beg+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE, METADATA_SIZE_FIELD_SIZE);
	char* krya_metadata = inp->Metadata;
	get_val(&krya_metadata, beg+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+METADATA_SIZE_FIELD_SIZE, read_var_metadata);
	krya_metadata[read_var_metadata] = '\0';
	int temp_var_errorcode = get_int(beg+PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+METADATA_SIZE_FIELD_SIZE+read_var_metadata, ERRORCODE_FIELD_SIZE);
	inp->ErrorCode = temp_var_errorcode;
	return PARTITION_FIELD_SIZE+OFFSET_FIELD_SIZE+METADATA_SIZE_FIELD_SIZE+read_var_metadata+ERRORCODE_FIELD_SIZE;
}
int parse_suboffsetfetchresponse(struct subOffsetFetchResponse* inp, char *beg){
	int parsed_size_topicname = parse_topicname(&inp->TopicName, beg);
	int read_var_ssofr = get_int(beg+parsed_size_topicname, SSOFR_SIZE_FIELD_SIZE);
	struct subSubOffsetFetchResponse* krya_ssofr = inp->ssofr;
	int temp_ssofr = 0;
	for(int i=0; i<read_var_ssofr; i++){
		temp_ssofr = temp_ssofr + parse_subsuboffsetfetchresponse(&krya_ssofr[i], beg+parsed_size_topicname+SSOFR_SIZE_FIELD_SIZE + temp_ssofr);
	}
	inp->NUM_SSOFR = read_var_ssofr;
	return parsed_size_topicname+SSOFR_SIZE_FIELD_SIZE+temp_ssofr;
}
int parse_offsetfetchresponse(struct OffsetFetchResponse* inp, char *beg){
	int read_var_sofr = get_int(beg, SOFR_SIZE_FIELD_SIZE);
	struct subOffsetFetchResponse* krya_sofr = inp->sofr;
	int temp_sofr = 0;
	for(int i=0; i<read_var_sofr; i++){
		temp_sofr = temp_sofr + parse_suboffsetfetchresponse(&krya_sofr[i], beg+SOFR_SIZE_FIELD_SIZE + temp_sofr);
	}
	inp->NUM_SUB_OFR = read_var_sofr;
	return SOFR_SIZE_FIELD_SIZE+temp_sofr;
}
int parse_resmessage(union ResMessage* inp, char *beg, enum response_type rt){
	int siz = 0;

	switch(rt){
		case REQUEST_METADATA: siz =  parse_metadataresponse(&inp->metadata_response, beg); break;
		case REQUEST_PRODUCE: siz =  parse_produceresponse(&inp->produce_response, beg); break;
		case REQUEST_FETCH: siz = parse_fetchresponse(&inp->fetch_response, beg); break;
		case REQUEST_OFFSET: siz = parse_offsetresponse(&inp->offset_response, beg); break;
		case REQUEST_OFFSET_COMMIT: siz = parse_offsetcommitresponse(&inp->offset_commit_response, beg); break;
		case REQUEST_OFFSET_FETCH: siz = parse_offsetfetchresponse(&inp->offset_fetch_response, beg); break;
		case REQUEST_GROUP_COORDINATOR: siz = parse_groupcoordinatorresponse(&inp->group_coordinator_response, beg); break;
	}

	return siz;
}
int parse_responsemessage(struct ResponseMessage* inp, char *beg, enum response_type rt){
	int temp_var_correlationid = get_int(beg, CORRELATIONID_FIELD_SIZE);
	inp->CorrelationId = temp_var_correlationid;
	int parsed_size_resmessage = parse_resmessage(&inp->rm, beg+CORRELATIONID_FIELD_SIZE, rt);
	return CORRELATIONID_FIELD_SIZE+parsed_size_resmessage;
}

