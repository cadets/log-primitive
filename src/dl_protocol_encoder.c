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

#include <string.h>
#include <stdio.h>

#include "message.h"
#include "dl_protocol.h"
#include "dl_protocol_common.h"

//static int encode_message(struct message *, char **);
static int dl_encode_messagesetelement(struct message_set_element *, char **);
static int dl_encode_messageset(struct message_set *, char **);
static int dl_encode_topicname(struct topic_name *, char **);
static int dl_encode_groupcoordinatorrequest(
    struct group_coordinator_request *, char **);
static int dl_encode_metadatarequest(struct metadata_request *, char **);
static int dl_encode_subsubproducerequest(struct sub_sub_produce_request *,
    char **);
static int dl_encode_subproducerequest(struct sub_produce_request *, char **);
static int dl_encode_producerequest(struct produce_request *, char **);
static int dl_encode_fetchrequest(struct fetch_request *, char **);
static int dl_encode_offsetrequest(struct offset_request *, char **);
static int dl_encode_offsetcommitrequest(struct offset_commit_request *,
    char **);
static int dl_encode_offsetfetchrequest(struct offset_fetch_request *,
    char **);
static int dl_encode_reqmessage(union req_message *, char **,
    enum request_type);
static int dl_encode_broker(struct broker *, char **);
static int dl_encode_replica(struct replica *, char **);
static int dl_encode_isr(struct isr *, char **);
static int dl_encode_partitionmetadata(struct partition_metadata *, char **);
static int dl_encode_topicmetadata(struct topic_metadata *, char **);
static int dl_encode_metadataresponse(struct metadata_response *, char **);
static int dl_encode_subsubproduceresponse(struct sub_sub_produce_response *,
    char **);
static int dl_encode_subproduceresponse(struct sub_produce_response *,
    char **);
static int dl_encode_produceresponse(struct produce_response *, char **);
static int dl_encode_subsubfetchresponse(struct sub_sub_fetch_response *,
    char **);
static int dl_encode_subfetchresponse(struct sub_fetch_response *, char **);
static int dl_encode_fetchresponse(struct fetch_response *, char **);
static int dl_encode_offset(struct offset *, char **);
static int dl_encode_partitionoffsets(struct partition_offsets *, char **);
static int dl_encode_suboffsetresponse(struct sub_offset_response *, char **);
static int dl_encode_offsetresponse(struct offset_response *, char **);
static int dl_encode_groupcoordinatorresponse(
    struct group_coordinator_response *, char **);
static int dl_encode_subsuboffsetcommitresponse(
    struct sub_sub_offset_commit_response *, char **);
static int dl_encode_suboffsetcommitresponse(struct sub_offset_commit_response *,
    char **);
static int dl_encode_offsetcommitresponse(struct offset_commit_response *,
    char **);
static int dl_encode_subsuboffsetfetchresponse(
    struct sub_sub_offset_fetch_response *, char **);
static int dl_encode_suboffsetfetchresponse(struct sub_offset_fetch_response *,
    char **);
static int dl_encode_offsetfetchresponse(struct offset_fetch_response *,
    char **);

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

/*
static int
dl_encode_message(struct message *inp, char **st)
{
	char *saveto = *st;
	const char *format="%.*lu%.*lu%.*d%.*d%s%.*d%s";

	return sprintf(saveto, format, CRC_FIELD_SIZE, inp->crc,
	    TIMESTAMP_FIELD_SIZE,inp->timestamp,
	    inp->attributes < 0 ? ATTRIBUTES_FIELD_SIZE-1 : ATTRIBUTES_FIELD_SIZE,
	    inp->attributes, KEY_SIZE_FIELD_SIZE, strlen(inp->key), inp->key,
	    VALUE_SIZE_FIELD_SIZE, strlen(inp->value), inp->value);
}
*/

static int
dl_encode_messagesetelement(struct message_set_element *inp, char **st)
{
	char *saveto = *st;
	char temp_message[MTU], *temp_message_ptr=temp_message;
	bzero(temp_message, MTU);
	int temp_len_message = dl_encode_message(&inp->message, &temp_message_ptr);
	const char* format="%.*ld%.*d%s";
	return sprintf(saveto, format,
	    inp->offset < 0 ? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE,
	    inp->offset,
	    inp->message_size < 0 ? MESSAGESIZE_FIELD_SIZE-1 : MESSAGESIZE_FIELD_SIZE,
	    inp->message_size, temp_message);
}

static int
dl_encode_messageset(struct message_set* inp, char** st)
{
	char *saveto = *st;
	char temp_elems[MTU];
	char final_var_elems[MTU];
	bzero(final_var_elems, MTU);
	for(int i=0; i < inp->num_elems; i++){
		bzero(temp_elems, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_elems = dl_encode_messagesetelement(&inp->elems[i], &innertemp_ptr);
		sprintf(temp_elems, "%s", innertemp_ptr);
		strcat(final_var_elems, temp_elems);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, ELEMS_SIZE_FIELD_SIZE,
	    inp->num_elems, final_var_elems);
}

static int
dl_encode_topicname(struct topic_name* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d%s";
	return sprintf(saveto, format, TOPICNAME_SIZE_FIELD_SIZE,
	    strlen(inp->topic_name), inp->topic_name);
}

static int
dl_encode_groupcoordinatorrequest(struct group_coordinator_request *inp,
    char** st)
{
	char *saveto = *st;
	const char* format="%.*d%s";
	return sprintf(saveto, format, GROUPID_SIZE_FIELD_SIZE,
	    strlen(inp->group_id), inp->group_id);
}

static int
dl_encode_metadatarequest(struct metadata_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicnames[MTU];
	char final_var_topicnames[MTU];
	bzero(final_var_topicnames, MTU);
	for(int i=0; i < inp->num_topics; i++){
		bzero(temp_topicnames, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_topicnames = dl_encode_topicname(&inp->topic_names[i], &innertemp_ptr);
		sprintf(temp_topicnames, "%s", innertemp_ptr);
		strcat(final_var_topicnames, temp_topicnames);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, TOPICNAMES_SIZE_FIELD_SIZE,
	    inp->num_topics, final_var_topicnames);
}

static int
dl_encode_subsubproducerequest(struct sub_sub_produce_request* inp, char** st)
{
	char *saveto = *st;
	char temp_mset[MTU], *temp_mset_ptr=temp_mset;
	bzero(temp_mset, MTU);
	int temp_len_mset = dl_encode_messageset(&inp->mset, &temp_mset_ptr);
	const char* format="%.*d%.*d%s";
	return sprintf(saveto, format,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->message_set_size < 0 ? MESSAGESETSIZE_FIELD_SIZE-1 : MESSAGESETSIZE_FIELD_SIZE,
	    inp->message_set_size, temp_mset);
}

static int
dl_encode_subproducerequest(struct sub_produce_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_sspr[MTU], *temp_sspr_ptr=temp_sspr;
	bzero(temp_sspr, MTU);
	int temp_len_sspr = dl_encode_subsubproducerequest(&inp->sspr, &temp_sspr_ptr);
	const char* format="%s%s";
	return sprintf(saveto, format, temp_topicname, temp_sspr);
}

static int
dl_encode_producerequest(struct produce_request* inp, char** st)
{
	char *saveto = *st;
	char temp_spr[MTU], *temp_spr_ptr=temp_spr;
	bzero(temp_spr, MTU);
	int temp_len_spr = dl_encode_subproducerequest(&inp->spr, &temp_spr_ptr);
	const char* format="%.*d%.*d%s";
	return sprintf(saveto, format,
	    inp->required_acks < 0 ? REQUIREDACKS_FIELD_SIZE-1 : REQUIREDACKS_FIELD_SIZE,
	    inp->required_acks,
	    inp->timeout < 0 ? TIMEOUT_FIELD_SIZE-1 : TIMEOUT_FIELD_SIZE,
	    inp->timeout, temp_spr);
}

static int
dl_encode_fetchrequest(struct fetch_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	const char* format="%.*d%.*d%.*d%s%.*d%.*ld%.*d";
	return sprintf(saveto, format,
	    inp->replica_id < 0 ? REPLICAID_FIELD_SIZE-1 : REPLICAID_FIELD_SIZE,
	    inp->replica_id,
	    inp->max_wait_time < 0 ? MAXWAITTIME_FIELD_SIZE-1 : MAXWAITTIME_FIELD_SIZE,
	    inp->max_wait_time,
	    inp->min_bytes < 0 ? MINBYTES_FIELD_SIZE-1 : MINBYTES_FIELD_SIZE,
	    inp->min_bytes, temp_topicname,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->fetch_offset < 0 ? FETCHOFFSET_FIELD_SIZE-1 : FETCHOFFSET_FIELD_SIZE,
	    inp->fetch_offset,
	    inp->max_bytes < 0 ? MAXBYTES_FIELD_SIZE-1 : MAXBYTES_FIELD_SIZE,
	    inp->max_bytes);
}

static int
dl_encode_offsetrequest(struct offset_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	const char* format="%.*d%s%.*d%.*ld";
	return sprintf(saveto, format,
	    inp->repolica_id < 0 ? REPOLICAID_FIELD_SIZE-1 : REPOLICAID_FIELD_SIZE,
	    inp->repolica_id, temp_topicname,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->time < 0 ? TIME_FIELD_SIZE-1 : TIME_FIELD_SIZE, inp->time);
}

static int
dl_encode_offsetcommitrequest(struct offset_commit_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	const char* format="%.*d%s%.*d%.*d%s%.*d%.*ld%.*ld%.*d%s";
	return sprintf(saveto, format, CONSUMERGROUPID_SIZE_FIELD_SIZE,
	    strlen(inp->consumer_group_id), inp->consumer_group_id,
	    inp->consumer_group_generation_id < 0 ? CONSUMERGROUPGENERATIONID_FIELD_SIZE-1 : CONSUMERGROUPGENERATIONID_FIELD_SIZE,
	    inp->consumer_group_generation_id,
	    inp->consumer_id < 0 ? CONSUMERID_FIELD_SIZE-1 : CONSUMERID_FIELD_SIZE,
	    inp->consumer_id, temp_topicname,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->offset < 0 ? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE,
	    inp->offset,
	    inp->timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE,
	    inp->timestamp, METADATA_SIZE_FIELD_SIZE, strlen(inp->metadata),
	    inp->metadata);
}

static int
dl_encode_offsetfetchrequest(struct offset_fetch_request* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	const char* format="%.*d%s%s%.*d";
	return sprintf(saveto, format, CONSUMERGROUPID_SIZE_FIELD_SIZE,
	    strlen(inp->consumer_group_id), inp->consumer_group_id,
	    temp_topicname,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition);
}

static int
dl_encode_reqmessage(union req_message* inp, char** st, enum request_type rt)
{
	char *saveto = *st;
	char temp [MTU], *temp_ptr = temp;
	bzero(temp, MTU);

	switch (rt){
		case REQUEST_METADATA:
			dl_encode_metadatarequest(&inp->metadata_request, &temp_ptr);
			break;
		case REQUEST_PRODUCE:
			dl_encode_producerequest(&inp->produce_request, &temp_ptr);
			break;
		case REQUEST_FETCH:
			dl_encode_fetchrequest(&inp->fetch_request, &temp_ptr);
			break;
		case REQUEST_OFFSET:
			dl_encode_offsetrequest(&inp->offset_request, &temp_ptr);
			break;
		case REQUEST_OFFSET_COMMIT:
			dl_encode_offsetcommitrequest(&inp->offset_commit_request, &temp_ptr);
			break;
		case REQUEST_OFFSET_FETCH:
			dl_encode_offsetfetchrequest(&inp->offset_fetch_request, &temp_ptr);
			break;
		case REQUEST_GROUP_COORDINATOR:
			dl_encode_groupcoordinatorrequest(&inp->group_coordinator_request, &temp_ptr);
			break;
	}
	const char* format = "%s";
	return sprintf(saveto, format, temp);
}

int
dl_encode_requestmessage(struct request_message* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*d%.*d%.*d%s%s";
    	char temp[MTU], *t = temp;
    	int tt = dl_encode_reqmessage(&inp->rm, &t, inp->api_key);

	return sprintf(saveto, format,
	    inp->api_key < 0 ? APIKEY_FIELD_SIZE-1 : APIKEY_FIELD_SIZE,
	    inp->api_key,
	    inp->api_version < 0 ? APIVERSION_FIELD_SIZE-1 : APIVERSION_FIELD_SIZE,
	    inp->api_version,
	    inp->correlation_id < 0 ? CORRELATIONID_FIELD_SIZE-1 : CORRELATIONID_FIELD_SIZE,
	    inp->correlation_id, CLIENTID_SIZE_FIELD_SIZE,
	    strlen(inp->client_id),
	    inp->client_id, temp);
}

static int
dl_encode_broker(struct broker* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*d%s%.*d";
	return sprintf(saveto, format,
	    inp->node_id < 0 ? NODEID_FIELD_SIZE-1 : NODEID_FIELD_SIZE,
	    inp->node_id, HOST_SIZE_FIELD_SIZE, strlen(inp->host), inp->host,
	    inp->port < 0 ? PORT_FIELD_SIZE-1 : PORT_FIELD_SIZE, inp->port);
}

static int
dl_encode_replica(struct replica* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d";
	return sprintf(saveto, format,
	    inp->replica < 0 ? REPLICA_FIELD_SIZE-1 : REPLICA_FIELD_SIZE,
	    inp->replica);
}

static int
dl_encode_isr(struct isr* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d";
	return sprintf(saveto, format,
	    inp->isr < 0 ? ISR_FIELD_SIZE-1 : ISR_FIELD_SIZE, inp->isr);
}

static int
dl_encode_partitionmetadata(struct partition_metadata* inp, char** st)
{
	char *saveto = *st;
	char temp_replicas[MTU];
	char final_var_replicas[MTU];
	bzero(final_var_replicas, MTU);
	for(int i=0; i < inp->num_replicas; i++){
		bzero(temp_replicas, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_replicas = dl_encode_replica(&inp->replicas[i], &innertemp_ptr);
		sprintf(temp_replicas, "%s", innertemp_ptr);
		strcat(final_var_replicas, temp_replicas);
	}
	char temp_isr[MTU];
	char final_var_isr[MTU];
	bzero(final_var_isr, MTU);
	for(int i=0; i < inp->num_isrs; i++){
		bzero(temp_isr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_isr = dl_encode_isr(&inp->isr[i], &innertemp_ptr);
		sprintf(temp_isr, "%s", innertemp_ptr);
		strcat(final_var_isr, temp_isr);
	}
	const char* format="%.*d%.*d%.*d%.*d%s%.*d%s";
	return sprintf(saveto, format,
	    inp->partition_error_code < 0? PARTITIONERRORCODE_FIELD_SIZE-1 : PARTITIONERRORCODE_FIELD_SIZE,
	    inp->partition_error_code,
	    inp->partition_id < 0 ? PARTITIONID_FIELD_SIZE-1 : PARTITIONID_FIELD_SIZE,
	    inp->partition_id,
	    inp->leader < 0 ? LEADER_FIELD_SIZE-1 : LEADER_FIELD_SIZE,
	    inp->leader, REPLICAS_SIZE_FIELD_SIZE, inp->num_replicas,
	    final_var_replicas, ISR_FIELD_SIZE, inp->num_isrs, final_var_isr);
}

static int
dl_encode_topicmetadata(struct topic_metadata* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_partitionmetadatas[MTU];
	char final_var_partitionmetadatas[MTU];
	bzero(final_var_partitionmetadatas, MTU);
	for(int i=0; i < inp->num_partitions; i++){
		bzero(temp_partitionmetadatas, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_partitionmetadatas = dl_encode_partitionmetadata(&inp->partition_metadatas[i], &innertemp_ptr);
		sprintf(temp_partitionmetadatas, "%s", innertemp_ptr);
		strcat(final_var_partitionmetadatas, temp_partitionmetadatas);
	}
	const char* format="%.*d%s%.*d%s";
	return sprintf(saveto, format,
	    inp->topic_error_code < 0 ? TOPICERRORCODE_FIELD_SIZE-1 : TOPICERRORCODE_FIELD_SIZE,
	    inp->topic_error_code, temp_topicname,
	    PARTITIONMETADATAS_SIZE_FIELD_SIZE, inp->num_partitions,
	    final_var_partitionmetadatas);
}

static int
dl_encode_metadataresponse(struct metadata_response* inp, char** st)
{
	char *saveto = *st;
	char temp_brokers[MTU];
	char final_var_brokers[MTU];
	bzero(final_var_brokers, MTU);
	for(int i=0; i < inp->num_brokers; i++){
		bzero(temp_brokers, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_brokers = dl_encode_broker(&inp->brokers[i], &innertemp_ptr);
		sprintf(temp_brokers, "%s", innertemp_ptr);
		strcat(final_var_brokers, temp_brokers);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, BROKERS_SIZE_FIELD_SIZE,
	    inp->num_brokers, final_var_brokers);
}

static int
dl_encode_subsubproduceresponse(struct sub_sub_produce_response *inp,
    char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*d%.*ld%.*ld";
	return sprintf(saveto, format,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->error_code < 0 ? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code,
	    inp->offset < 0 ? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE,
	    inp->offset,
	    inp->timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE,
	    inp->timestamp);
}

static int
dl_encode_subproduceresponse(struct sub_produce_response* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_sspr[MTU];
	char final_var_sspr[MTU];
	bzero(final_var_sspr, MTU);
	for(int i=0; i < inp->num_subsub; i++){
		bzero(temp_sspr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sspr = dl_encode_subsubproduceresponse(&inp->sspr[i], &innertemp_ptr);
		sprintf(temp_sspr, "%s", innertemp_ptr);
		strcat(final_var_sspr, temp_sspr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSPR_SIZE_FIELD_SIZE,
	    inp->num_subsub, final_var_sspr);
}


static int
dl_encode_produceresponse(struct produce_response* inp, char** st)
{
	char *saveto = *st;
	char temp_spr[MTU];
	char final_var_spr[MTU];
	bzero(final_var_spr, MTU);
	for(int i=0; i < inp->num_sub; i++){
		bzero(temp_spr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_spr = dl_encode_subproduceresponse(&inp->spr[i], &innertemp_ptr);
		sprintf(temp_spr, "%s", innertemp_ptr);
		strcat(final_var_spr, temp_spr);
	}
	const char* format="%.*d%s%.*d";
	return sprintf(saveto, format, SPR_SIZE_FIELD_SIZE, inp->num_sub,
	    final_var_spr,
	    inp->throttle_time < 0 ? THROTTLETIME_FIELD_SIZE-1 : THROTTLETIME_FIELD_SIZE,
	    inp->throttle_time);
}

static int
dl_encode_subsubfetchresponse(struct sub_sub_fetch_response* inp, char** st)
{
	char *saveto = *st;
	char temp_messageset[MTU], *temp_messageset_ptr=temp_messageset;
	bzero(temp_messageset, MTU);
	int temp_len_messageset = dl_encode_messageset(&inp->message_set, &temp_messageset_ptr);
	const char* format="%.*d%.*d%.*ld%.*d%s";
	return sprintf(saveto, format,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->error_code < 0 ? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code,
	    inp->highway_mark_offset < 0 ? HIGHWAYMARKOFFSET_FIELD_SIZE-1 : HIGHWAYMARKOFFSET_FIELD_SIZE,
	    inp->highway_mark_offset,
	    inp->message_set_size < 0 ? MESSAGESETSIZE_FIELD_SIZE-1 : MESSAGESETSIZE_FIELD_SIZE,
	    inp->message_set_size, temp_messageset);
}

static int
dl_encode_subfetchresponse(struct sub_fetch_response* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_ssfr[MTU];
	char final_var_ssfr[MTU];
	bzero(final_var_ssfr, MTU);
	for(int i=0; i < inp->num_ssfr; i++){
		bzero(temp_ssfr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssfr = dl_encode_subsubfetchresponse(&inp->ssfr[i], &innertemp_ptr);
		sprintf(temp_ssfr, "%s", innertemp_ptr);
		strcat(final_var_ssfr, temp_ssfr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSFR_SIZE_FIELD_SIZE,
	    inp->num_ssfr, final_var_ssfr);
}

static int
dl_encode_fetchresponse(struct fetch_response* inp, char** st)
{
	char *saveto = *st;
	char temp_sfr[MTU];
	char final_var_sfr[MTU];
	bzero(final_var_sfr, MTU);
	for(int i=0; i < inp->num_sfr; i++){
		bzero(temp_sfr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sfr = dl_encode_subfetchresponse(&inp->sfr[i], &innertemp_ptr);
		sprintf(temp_sfr, "%s", innertemp_ptr);
		strcat(final_var_sfr, temp_sfr);
	}
	const char* format="%.*d%s%.*d";
	return sprintf(saveto, format, SFR_SIZE_FIELD_SIZE, inp->num_sfr,
	    final_var_sfr,
	    inp->throttle_time < 0? THROTTLETIME_FIELD_SIZE-1 : THROTTLETIME_FIELD_SIZE,
	    inp->throttle_time);
}

static int
dl_encode_offset(struct offset* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*ld";
	return sprintf(saveto, format,
	    inp->offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE,
	    inp->offset);
}


static int
dl_encode_partitionoffsets(struct partition_offsets* inp, char** st)
{
	char *saveto = *st;
	char temp_offsets[MTU];
	char final_var_offsets[MTU];
	bzero(final_var_offsets, MTU);
	for(int i=0; i < inp->num_offsets; i++){
		bzero(temp_offsets, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_offsets = dl_encode_offset(&inp->offsets[i], &innertemp_ptr);
		sprintf(temp_offsets, "%s", innertemp_ptr);
		strcat(final_var_offsets, temp_offsets);
	}
	const char* format="%.*d%.*d%.*ld%.*d%s";
	return sprintf(saveto, format,
	    inp->partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->error_code < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code,
	    inp->timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE,
	    inp->timestamp, OFFSETS_SIZE_FIELD_SIZE, inp->num_offsets,
	    final_var_offsets);
}

static int
dl_encode_suboffsetresponse(struct sub_offset_response* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_partitionoffsets[MTU];
	char final_var_partitionoffsets[MTU];
	bzero(final_var_partitionoffsets, MTU);
	for(int i=0; i < inp->num_parts; i++){
		bzero(temp_partitionoffsets, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_partitionoffsets = dl_encode_partitionoffsets(&inp->partition_offsets[i], &innertemp_ptr);
		sprintf(temp_partitionoffsets, "%s", innertemp_ptr);
		strcat(final_var_partitionoffsets, temp_partitionoffsets);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname,
	    PARTITIONOFFSETS_SIZE_FIELD_SIZE, inp->num_parts,
	    final_var_partitionoffsets);
}


static int
dl_encode_offsetresponse(struct offset_response* inp, char** st)
{
	char *saveto = *st;
	char temp_sor[MTU];
	char final_var_sor[MTU];
	bzero(final_var_sor, MTU);
	for(int i=0; i < inp->num_sor; i++){
		bzero(temp_sor, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sor = dl_encode_suboffsetresponse(&inp->sor[i], &innertemp_ptr);
		sprintf(temp_sor, "%s", innertemp_ptr);
		strcat(final_var_sor, temp_sor);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOR_SIZE_FIELD_SIZE, inp->num_sor,
	    final_var_sor);
}


static int
dl_encode_groupcoordinatorresponse(struct group_coordinator_response* inp,
	char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*d%.*d%s%.*d";
	return sprintf(saveto, format,
	    inp->error_code < 0 ? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code,
	    inp->corrdinator_id < 0 ? CORRDINATORID_FIELD_SIZE-1 : CORRDINATORID_FIELD_SIZE,
	    inp->corrdinator_id, CORRDINATORHOST_SIZE_FIELD_SIZE,
	    strlen(inp->corrdinator_host), inp->corrdinator_host,
	    inp->corrdinator_port < 0 ? CORRDINATORPORT_FIELD_SIZE-1 : CORRDINATORPORT_FIELD_SIZE,
	    inp->corrdinator_port);
}

static int
dl_encode_subsuboffsetcommitresponse(
    struct sub_sub_offset_commit_response* inp, char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*d";
	return sprintf(saveto, format,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition,
	    inp->error_code < 0 ? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code);
}

static int
dl_encode_suboffsetcommitresponse(struct sub_offset_commit_response* inp, char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name, &temp_topicname_ptr);
	char temp_ssocr[MTU];
	char final_var_ssocr[MTU];
	bzero(final_var_ssocr, MTU);
	for(int i=0; i < inp->num_ssocr; i++){
		bzero(temp_ssocr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssocr = dl_encode_subsuboffsetcommitresponse(&inp->ssocr[i], &innertemp_ptr);
		sprintf(temp_ssocr, "%s", innertemp_ptr);
		strcat(final_var_ssocr, temp_ssocr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSOCR_SIZE_FIELD_SIZE,
	    inp->num_ssocr, final_var_ssocr);
}

static int
dl_encode_offsetcommitresponse(struct offset_commit_response* inp, char** st)
{
	char *saveto = *st;
	char temp_socr[MTU];
	char final_var_socr[MTU];
	bzero(final_var_socr, MTU);
	for(int i=0; i < inp->num_sub_ocr; i++){
		bzero(temp_socr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_socr = dl_encode_suboffsetcommitresponse(&inp->socr[i], &innertemp_ptr);
		sprintf(temp_socr, "%s", innertemp_ptr);
		strcat(final_var_socr, temp_socr);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOCR_SIZE_FIELD_SIZE,
	    inp->num_sub_ocr, final_var_socr);
}

static int
dl_encode_subsuboffsetfetchresponse(struct sub_sub_offset_fetch_response *inp,
	char** st)
{
	char *saveto = *st;
	const char* format="%.*d%.*ld%.*d%s%.*d";
	return sprintf(saveto, format,
	    inp->partition < 0 ? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE,
	    inp->partition, inp->offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE,
	    inp->offset, METADATA_SIZE_FIELD_SIZE, strlen(inp->metadata),
	    inp->metadata,
	    inp->error_code < 0 ? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE,
	    inp->error_code);
}

static int
dl_encode_suboffsetfetchresponse(struct sub_offset_fetch_response *inp,
    char** st)
{
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = dl_encode_topicname(&inp->topic_name,
	    &temp_topicname_ptr);
	char temp_ssofr[MTU];
	char final_var_ssofr[MTU];
	bzero(final_var_ssofr, MTU);
	for(int i=0; i < inp->num_ssofr; i++){
		bzero(temp_ssofr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssofr = dl_encode_subsuboffsetfetchresponse(
		    &inp->ssofr[i], &innertemp_ptr);
		sprintf(temp_ssofr, "%s", innertemp_ptr);
		strcat(final_var_ssofr, temp_ssofr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSOFR_SIZE_FIELD_SIZE,
	    inp->num_ssofr, final_var_ssofr);
}

static int
dl_encode_offsetfetchresponse(struct offset_fetch_response *inp, char **st)
{
	char *saveto = *st;
	char temp_sofr[MTU];
	char final_var_sofr[MTU];
	bzero(final_var_sofr, MTU);
	for(int i=0; i < inp->num_sub_ofr; i++){
		bzero(temp_sofr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sofr = dl_encode_suboffsetfetchresponse(
		    &inp->sofr[i], &innertemp_ptr);
		sprintf(temp_sofr, "%s", innertemp_ptr);
		strcat(final_var_sofr, temp_sofr);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOFR_SIZE_FIELD_SIZE,
	    inp->num_sub_ofr, final_var_sofr);
}

static int
dl_encode_resmessage(union res_message *inp, char** st, enum response_type rt)
{
	char *saveto = *st;
	char temp [MTU], *temp_ptr = temp;
	bzero(temp, MTU);

	switch (rt) {
		case RESPONSE_METADATA:
		       	dl_encode_metadataresponse(
			    &inp->metadata_response, &temp_ptr);
			break;
		case RESPONSE_PRODUCE:
			dl_encode_produceresponse(&inp->produce_response,
			    &temp_ptr);
			break;
		case RESPONSE_FETCH:
			dl_encode_fetchresponse(&inp->fetch_response,
			    &temp_ptr);
			break;
		case RESPONSE_OFFSET:
			dl_encode_offsetresponse(&inp->offset_response,
			    &temp_ptr);
			break;
		case RESPONSE_OFFSET_COMMIT:
			dl_encode_offsetcommitresponse(
			    &inp->offset_commit_response, &temp_ptr);
			break;
		case RESPONSE_OFFSET_FETCH:
			dl_encode_offsetfetchresponse(
			    &inp->offset_fetch_response, &temp_ptr);
			break;
		case RESPONSE_GROUP_COORDINATOR:
			dl_encode_groupcoordinatorresponse(
			    &inp->group_coordinator_response, &temp_ptr);
			break;
	}
	const char* format = "%s";
	return sprintf(saveto, format, temp);
}

int
dl_encode_responsemessage(struct response_message* inp, char **st,
	enum response_type rt)
{
	char *saveto = *st;
	char temp_rm[MTU], *temp_rm_ptr=temp_rm;
	bzero(temp_rm, MTU);

	int temp_len_rm = dl_encode_resmessage(&inp->rm, &temp_rm_ptr, rt);

	const char* format="%.*d%s";

	return sprintf(saveto, format,
	    inp->correlation_id < 0 ? CORRELATIONID_FIELD_SIZE-1 : CORRELATIONID_FIELD_SIZE,
	    inp->correlation_id, temp_rm);
}
