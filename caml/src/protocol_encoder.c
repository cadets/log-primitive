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

int encode_message(struct Message* inp, char** st){
	char *saveto = *st;
	const char* format="%.*lu%.*lu%.*d%.*d%s%.*d%s";
	return sprintf(saveto, format, CRC_FIELD_SIZE, inp->CRC, TIMESTAMP_FIELD_SIZE, inp->Timestamp, inp->Attributes < 0? ATTRIBUTES_FIELD_SIZE-1 : ATTRIBUTES_FIELD_SIZE, inp->Attributes, KEY_SIZE_FIELD_SIZE, strlen(inp->key), inp->key, VALUE_SIZE_FIELD_SIZE, strlen(inp->value), inp->value);
}


int encode_messagesetelement(struct MessageSetElement* inp, char** st){
	char *saveto = *st;
	char temp_message[MTU], *temp_message_ptr=temp_message;
	bzero(temp_message, MTU);
	int temp_len_message = encode_message(&inp->Message, &temp_message_ptr);
	const char* format="%.*ld%.*d%s";
	return sprintf(saveto, format, inp->Offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE, inp->Offset, inp->MessageSize < 0? MESSAGESIZE_FIELD_SIZE-1 : MESSAGESIZE_FIELD_SIZE, inp->MessageSize, temp_message);
}


int encode_messageset(struct MessageSet* inp, char** st){
	char *saveto = *st;
	char temp_elems[MTU];
	char final_var_elems[MTU];
	bzero(final_var_elems, MTU);
	for(int i=0; i < inp->NUM_ELEMS; i++){
		bzero(temp_elems, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_elems = encode_messagesetelement(&inp->Elems[i], &innertemp_ptr);
		sprintf(temp_elems, "%s", innertemp_ptr);
		strcat(final_var_elems, temp_elems);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, ELEMS_SIZE_FIELD_SIZE, inp->NUM_ELEMS, final_var_elems);
}


int encode_topicname(struct TopicName* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%s";
	return sprintf(saveto, format, TOPICNAME_SIZE_FIELD_SIZE, strlen(inp->TopicName), inp->TopicName);
}


int encode_groupcoordinatorrequest(struct GroupCoordinatorRequest* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%s";
	return sprintf(saveto, format, GROUPID_SIZE_FIELD_SIZE, strlen(inp->GroupId), inp->GroupId);
}


int encode_metadatarequest(struct MetadataRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicnames[MTU];
	char final_var_topicnames[MTU];
	bzero(final_var_topicnames, MTU);
	for(int i=0; i < inp->NUM_TOPICS; i++){
		bzero(temp_topicnames, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_topicnames = encode_topicname(&inp->TopicNames[i], &innertemp_ptr);
		sprintf(temp_topicnames, "%s", innertemp_ptr);
		strcat(final_var_topicnames, temp_topicnames);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, TOPICNAMES_SIZE_FIELD_SIZE, inp->NUM_TOPICS, final_var_topicnames);
}


int encode_subsubproducerequest(struct SubSubProduceRequest* inp, char** st){
	char *saveto = *st;
	char temp_mset[MTU], *temp_mset_ptr=temp_mset;
	bzero(temp_mset, MTU);
	int temp_len_mset = encode_messageset(&inp->mset, &temp_mset_ptr);
	const char* format="%.*d%.*d%s";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->MessageSetSize < 0? MESSAGESETSIZE_FIELD_SIZE-1 : MESSAGESETSIZE_FIELD_SIZE, inp->MessageSetSize, temp_mset);
}


int encode_subproducerequest(struct SubProduceRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_sspr[MTU], *temp_sspr_ptr=temp_sspr;
	bzero(temp_sspr, MTU);
	int temp_len_sspr = encode_subsubproducerequest(&inp->sspr, &temp_sspr_ptr);
	const char* format="%s%s";
	return sprintf(saveto, format, temp_topicname, temp_sspr);
}


int encode_producerequest(struct ProduceRequest* inp, char** st){
	char *saveto = *st;
	char temp_spr[MTU], *temp_spr_ptr=temp_spr;
	bzero(temp_spr, MTU);
	int temp_len_spr = encode_subproducerequest(&inp->spr, &temp_spr_ptr);
	const char* format="%.*d%.*d%s";
	return sprintf(saveto, format, inp->RequiredAcks < 0? REQUIREDACKS_FIELD_SIZE-1 : REQUIREDACKS_FIELD_SIZE, inp->RequiredAcks, inp->Timeout < 0? TIMEOUT_FIELD_SIZE-1 : TIMEOUT_FIELD_SIZE, inp->Timeout, temp_spr);
}


int encode_fetchrequest(struct FetchRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	const char* format="%.*d%.*d%.*d%s%.*d%.*ld%.*d";
	return sprintf(saveto, format, inp->ReplicaId < 0? REPLICAID_FIELD_SIZE-1 : REPLICAID_FIELD_SIZE, inp->ReplicaId, inp->MaxWaitTime < 0? MAXWAITTIME_FIELD_SIZE-1 : MAXWAITTIME_FIELD_SIZE, inp->MaxWaitTime, inp->MinBytes < 0? MINBYTES_FIELD_SIZE-1 : MINBYTES_FIELD_SIZE, inp->MinBytes, temp_topicname, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->FetchOffset < 0? FETCHOFFSET_FIELD_SIZE-1 : FETCHOFFSET_FIELD_SIZE, inp->FetchOffset, inp->MaxBytes < 0? MAXBYTES_FIELD_SIZE-1 : MAXBYTES_FIELD_SIZE, inp->MaxBytes);
}


int encode_offsetrequest(struct OffsetRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	const char* format="%.*d%s%.*d%.*ld";
	return sprintf(saveto, format, inp->RepolicaId < 0? REPOLICAID_FIELD_SIZE-1 : REPOLICAID_FIELD_SIZE, inp->RepolicaId, temp_topicname, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->Time < 0? TIME_FIELD_SIZE-1 : TIME_FIELD_SIZE, inp->Time);
}


int encode_offsetcommitrequest(struct OffsetCommitRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	const char* format="%.*d%s%.*d%.*d%s%.*d%.*ld%.*ld%.*d%s";
	return sprintf(saveto, format, CONSUMERGROUPID_SIZE_FIELD_SIZE, strlen(inp->ConsumerGroupId), inp->ConsumerGroupId, inp->ConsumerGroupGenerationId < 0? CONSUMERGROUPGENERATIONID_FIELD_SIZE-1 : CONSUMERGROUPGENERATIONID_FIELD_SIZE, inp->ConsumerGroupGenerationId, inp->ConsumerId < 0? CONSUMERID_FIELD_SIZE-1 : CONSUMERID_FIELD_SIZE, inp->ConsumerId, temp_topicname, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->Offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE, inp->Offset, inp->Timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE, inp->Timestamp, METADATA_SIZE_FIELD_SIZE, strlen(inp->Metadata), inp->Metadata);
}


int encode_offsetfetchrequest(struct OffsetFetchRequest* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	const char* format="%.*d%s%s%.*d";
	return sprintf(saveto, format, CONSUMERGROUPID_SIZE_FIELD_SIZE, strlen(inp->ConsumerGroupId), inp->ConsumerGroupId, temp_topicname, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition);
}


int encode_reqmessage(union ReqMessage* inp, char** st, enum request_type rt){
	char *saveto = *st;
	char temp [MTU], *temp_ptr = temp;
	bzero(temp, MTU);

	switch(rt){
		case REQUEST_METADATA: encode_metadatarequest(&inp->metadata_request, &temp_ptr); break;
		case REQUEST_PRODUCE:  encode_producerequest(&inp->produce_request, &temp_ptr); break;
		case REQUEST_FETCH:    encode_fetchrequest(&inp->fetch_request, &temp_ptr); break;
		case REQUEST_OFFSET: encode_offsetrequest(&inp->offset_request, &temp_ptr); break;
		case REQUEST_OFFSET_COMMIT: encode_offsetcommitrequest(&inp->offset_commit_request, &temp_ptr); break;
		case REQUEST_OFFSET_FETCH: encode_offsetfetchrequest(&inp->offset_fetch_request, &temp_ptr); break;
		case REQUEST_GROUP_COORDINATOR: encode_groupcoordinatorrequest(&inp->group_coordinator_request, &temp_ptr); break;
	}
	const char* format = "%s";
	return sprintf(saveto, format, temp);
}


int encode_requestmessage(struct RequestMessage* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*d%.*d%.*d%s%s";

    char temp[MTU], *t = temp;
    int tt = encode_reqmessage(&inp->rm, &t, inp->APIKey);

	return sprintf(saveto, format, inp->APIKey < 0? APIKEY_FIELD_SIZE-1 : APIKEY_FIELD_SIZE, inp->APIKey, inp->APIVersion < 0? APIVERSION_FIELD_SIZE-1 : APIVERSION_FIELD_SIZE, inp->APIVersion, inp->CorrelationId < 0? CORRELATIONID_FIELD_SIZE-1 : CORRELATIONID_FIELD_SIZE, inp->CorrelationId, CLIENTID_SIZE_FIELD_SIZE, strlen(inp->ClientId), inp->ClientId, temp);
}


int encode_broker(struct Broker* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*d%s%.*d";
	return sprintf(saveto, format, inp->NodeId < 0? NODEID_FIELD_SIZE-1 : NODEID_FIELD_SIZE, inp->NodeId, HOST_SIZE_FIELD_SIZE, strlen(inp->Host), inp->Host, inp->Port < 0? PORT_FIELD_SIZE-1 : PORT_FIELD_SIZE, inp->Port);
}


int encode_replica(struct Replica* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d";
	return sprintf(saveto, format, inp->Replica < 0? REPLICA_FIELD_SIZE-1 : REPLICA_FIELD_SIZE, inp->Replica);
}


int encode_isr(struct Isr* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d";
	return sprintf(saveto, format, inp->Isr < 0? ISR_FIELD_SIZE-1 : ISR_FIELD_SIZE, inp->Isr);
}


int encode_partitionmetadata(struct PartitionMetadata* inp, char** st){
	char *saveto = *st;
	char temp_replicas[MTU];
	char final_var_replicas[MTU];
	bzero(final_var_replicas, MTU);
	for(int i=0; i < inp->NUM_REPLICAS; i++){
		bzero(temp_replicas, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_replicas = encode_replica(&inp->Replicas[i], &innertemp_ptr);
		sprintf(temp_replicas, "%s", innertemp_ptr);
		strcat(final_var_replicas, temp_replicas);
	}
	char temp_isr[MTU];
	char final_var_isr[MTU];
	bzero(final_var_isr, MTU);
	for(int i=0; i < inp->NUM_Isrs; i++){
		bzero(temp_isr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_isr = encode_isr(&inp->Isr[i], &innertemp_ptr);
		sprintf(temp_isr, "%s", innertemp_ptr);
		strcat(final_var_isr, temp_isr);
	}
	const char* format="%.*d%.*d%.*d%.*d%s%.*d%s";
	return sprintf(saveto, format, inp->PartitionErrorCode < 0? PARTITIONERRORCODE_FIELD_SIZE-1 : PARTITIONERRORCODE_FIELD_SIZE, inp->PartitionErrorCode, inp->PartitionId < 0? PARTITIONID_FIELD_SIZE-1 : PARTITIONID_FIELD_SIZE, inp->PartitionId, inp->Leader < 0? LEADER_FIELD_SIZE-1 : LEADER_FIELD_SIZE, inp->Leader, REPLICAS_SIZE_FIELD_SIZE, inp->NUM_REPLICAS, final_var_replicas, ISR_FIELD_SIZE, inp->NUM_Isrs, final_var_isr);
}


int encode_topicmetadata(struct TopicMetadata* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_partitionmetadatas[MTU];
	char final_var_partitionmetadatas[MTU];
	bzero(final_var_partitionmetadatas, MTU);
	for(int i=0; i < inp->NUM_PARTITIONS; i++){
		bzero(temp_partitionmetadatas, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_partitionmetadatas = encode_partitionmetadata(&inp->PartitionMetadatas[i], &innertemp_ptr);
		sprintf(temp_partitionmetadatas, "%s", innertemp_ptr);
		strcat(final_var_partitionmetadatas, temp_partitionmetadatas);
	}
	const char* format="%.*d%s%.*d%s";
	return sprintf(saveto, format, inp->TopicErrorCode < 0? TOPICERRORCODE_FIELD_SIZE-1 : TOPICERRORCODE_FIELD_SIZE, inp->TopicErrorCode, temp_topicname, PARTITIONMETADATAS_SIZE_FIELD_SIZE, inp->NUM_PARTITIONS, final_var_partitionmetadatas);
}


int encode_metadataresponse(struct MetadataResponse* inp, char** st){
	char *saveto = *st;
	char temp_brokers[MTU];
	char final_var_brokers[MTU];
	bzero(final_var_brokers, MTU);
	for(int i=0; i < inp->NUM_BROKERS; i++){
		bzero(temp_brokers, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_brokers = encode_broker(&inp->Brokers[i], &innertemp_ptr);
		sprintf(temp_brokers, "%s", innertemp_ptr);
		strcat(final_var_brokers, temp_brokers);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, BROKERS_SIZE_FIELD_SIZE, inp->NUM_BROKERS, final_var_brokers);
}


int encode_subsubproduceresponse(struct SubSubProduceResponse* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*d%.*ld%.*ld";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode, inp->Offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE, inp->Offset, inp->Timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE, inp->Timestamp);
}


int encode_subproduceresponse(struct SubProduceResponse* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_sspr[MTU];
	char final_var_sspr[MTU];
	bzero(final_var_sspr, MTU);
	for(int i=0; i < inp->NUM_SUBSUB; i++){
		bzero(temp_sspr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sspr = encode_subsubproduceresponse(&inp->sspr[i], &innertemp_ptr);
		sprintf(temp_sspr, "%s", innertemp_ptr);
		strcat(final_var_sspr, temp_sspr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSPR_SIZE_FIELD_SIZE, inp->NUM_SUBSUB, final_var_sspr);
}


int encode_produceresponse(struct ProduceResponse* inp, char** st){
	char *saveto = *st;
	char temp_spr[MTU];
	char final_var_spr[MTU];
	bzero(final_var_spr, MTU);
	for(int i=0; i < inp->NUM_SUB; i++){
		bzero(temp_spr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_spr = encode_subproduceresponse(&inp->spr[i], &innertemp_ptr);
		sprintf(temp_spr, "%s", innertemp_ptr);
		strcat(final_var_spr, temp_spr);
	}
	const char* format="%.*d%s%.*d";
	return sprintf(saveto, format, SPR_SIZE_FIELD_SIZE, inp->NUM_SUB, final_var_spr, inp->ThrottleTime < 0? THROTTLETIME_FIELD_SIZE-1 : THROTTLETIME_FIELD_SIZE, inp->ThrottleTime);
}


int encode_subsubfetchresponse(struct subSubFetchResponse* inp, char** st){
	char *saveto = *st;
	char temp_messageset[MTU], *temp_messageset_ptr=temp_messageset;
	bzero(temp_messageset, MTU);
	int temp_len_messageset = encode_messageset(&inp->MessageSet, &temp_messageset_ptr);
	const char* format="%.*d%.*d%.*ld%.*d%s";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode, inp->HighwayMarkOffset < 0? HIGHWAYMARKOFFSET_FIELD_SIZE-1 : HIGHWAYMARKOFFSET_FIELD_SIZE, inp->HighwayMarkOffset, inp->MessageSetSize < 0? MESSAGESETSIZE_FIELD_SIZE-1 : MESSAGESETSIZE_FIELD_SIZE, inp->MessageSetSize, temp_messageset);
}


int encode_subfetchresponse(struct subFetchResponse* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_ssfr[MTU];
	char final_var_ssfr[MTU];
	bzero(final_var_ssfr, MTU);
	for(int i=0; i < inp->NUM_SSFR; i++){
		bzero(temp_ssfr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssfr = encode_subsubfetchresponse(&inp->ssfr[i], &innertemp_ptr);
		sprintf(temp_ssfr, "%s", innertemp_ptr);
		strcat(final_var_ssfr, temp_ssfr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSFR_SIZE_FIELD_SIZE, inp->NUM_SSFR, final_var_ssfr);
}


int encode_fetchresponse(struct FetchResponse* inp, char** st){
	char *saveto = *st;
	char temp_sfr[MTU];
	char final_var_sfr[MTU];
	bzero(final_var_sfr, MTU);
	for(int i=0; i < inp->NUM_SFR; i++){
		bzero(temp_sfr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sfr = encode_subfetchresponse(&inp->sfr[i], &innertemp_ptr);
		sprintf(temp_sfr, "%s", innertemp_ptr);
		strcat(final_var_sfr, temp_sfr);
	}
	const char* format="%.*d%s%.*d";
	return sprintf(saveto, format, SFR_SIZE_FIELD_SIZE, inp->NUM_SFR, final_var_sfr, inp->ThrottleTime < 0? THROTTLETIME_FIELD_SIZE-1 : THROTTLETIME_FIELD_SIZE, inp->ThrottleTime);
}


int encode_offset(struct Offset* inp, char** st){
	char *saveto = *st;
	const char* format="%.*ld";
	return sprintf(saveto, format, inp->Offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE, inp->Offset);
}


int encode_partitionoffsets(struct PartitionOffsets* inp, char** st){
	char *saveto = *st;
	char temp_offsets[MTU];
	char final_var_offsets[MTU];
	bzero(final_var_offsets, MTU);
	for(int i=0; i < inp->NUM_OFFSETS; i++){
		bzero(temp_offsets, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_offsets = encode_offset(&inp->Offsets[i], &innertemp_ptr);
		sprintf(temp_offsets, "%s", innertemp_ptr);
		strcat(final_var_offsets, temp_offsets);
	}
	const char* format="%.*d%.*d%.*ld%.*d%s";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode, inp->Timestamp < 0? TIMESTAMP_FIELD_SIZE-1 : TIMESTAMP_FIELD_SIZE, inp->Timestamp, OFFSETS_SIZE_FIELD_SIZE, inp->NUM_OFFSETS, final_var_offsets);
}


int encode_suboffsetresponse(struct subOffsetResponse* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_partitionoffsets[MTU];
	char final_var_partitionoffsets[MTU];
	bzero(final_var_partitionoffsets, MTU);
	for(int i=0; i < inp->NUM_PARTS; i++){
		bzero(temp_partitionoffsets, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_partitionoffsets = encode_partitionoffsets(&inp->PartitionOffsets[i], &innertemp_ptr);
		sprintf(temp_partitionoffsets, "%s", innertemp_ptr);
		strcat(final_var_partitionoffsets, temp_partitionoffsets);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, PARTITIONOFFSETS_SIZE_FIELD_SIZE, inp->NUM_PARTS, final_var_partitionoffsets);
}


int encode_offsetresponse(struct OffsetResponse* inp, char** st){
	char *saveto = *st;
	char temp_sor[MTU];
	char final_var_sor[MTU];
	bzero(final_var_sor, MTU);
	for(int i=0; i < inp->NUM_SOR; i++){
		bzero(temp_sor, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sor = encode_suboffsetresponse(&inp->sor[i], &innertemp_ptr);
		sprintf(temp_sor, "%s", innertemp_ptr);
		strcat(final_var_sor, temp_sor);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOR_SIZE_FIELD_SIZE, inp->NUM_SOR, final_var_sor);
}


int encode_groupcoordinatorresponse(struct GroupCoordinatorResponse* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*d%.*d%s%.*d";
	return sprintf(saveto, format, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode, inp->CorrdinatorId < 0? CORRDINATORID_FIELD_SIZE-1 : CORRDINATORID_FIELD_SIZE, inp->CorrdinatorId, CORRDINATORHOST_SIZE_FIELD_SIZE, strlen(inp->CorrdinatorHost), inp->CorrdinatorHost, inp->CorrdinatorPort < 0? CORRDINATORPORT_FIELD_SIZE-1 : CORRDINATORPORT_FIELD_SIZE, inp->CorrdinatorPort);
}


int encode_subsuboffsetcommitresponse(struct subSubOffsetCommitResponse* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*d";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode);
}


int encode_suboffsetcommitresponse(struct subOffsetCommitResponse* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_ssocr[MTU];
	char final_var_ssocr[MTU];
	bzero(final_var_ssocr, MTU);
	for(int i=0; i < inp->NUM_SSOCR; i++){
		bzero(temp_ssocr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssocr = encode_subsuboffsetcommitresponse(&inp->ssocr[i], &innertemp_ptr);
		sprintf(temp_ssocr, "%s", innertemp_ptr);
		strcat(final_var_ssocr, temp_ssocr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSOCR_SIZE_FIELD_SIZE, inp->NUM_SSOCR, final_var_ssocr);
}


int encode_offsetcommitresponse(struct OffsetCommitResponse* inp, char** st){
	char *saveto = *st;
	char temp_socr[MTU];
	char final_var_socr[MTU];
	bzero(final_var_socr, MTU);
	for(int i=0; i < inp->NUM_SUB_OCR; i++){
		bzero(temp_socr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_socr = encode_suboffsetcommitresponse(&inp->socr[i], &innertemp_ptr);
		sprintf(temp_socr, "%s", innertemp_ptr);
		strcat(final_var_socr, temp_socr);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOCR_SIZE_FIELD_SIZE, inp->NUM_SUB_OCR, final_var_socr);
}


int encode_subsuboffsetfetchresponse(struct subSubOffsetFetchResponse* inp, char** st){
	char *saveto = *st;
	const char* format="%.*d%.*ld%.*d%s%.*d";
	return sprintf(saveto, format, inp->Partition < 0? PARTITION_FIELD_SIZE-1 : PARTITION_FIELD_SIZE, inp->Partition, inp->Offset < 0? OFFSET_FIELD_SIZE-1 : OFFSET_FIELD_SIZE, inp->Offset, METADATA_SIZE_FIELD_SIZE, strlen(inp->Metadata), inp->Metadata, inp->ErrorCode < 0? ERRORCODE_FIELD_SIZE-1 : ERRORCODE_FIELD_SIZE, inp->ErrorCode);
}


int encode_suboffsetfetchresponse(struct subOffsetFetchResponse* inp, char** st){
	char *saveto = *st;
	char temp_topicname[MTU], *temp_topicname_ptr=temp_topicname;
	bzero(temp_topicname, MTU);
	int temp_len_topicname = encode_topicname(&inp->TopicName, &temp_topicname_ptr);
	char temp_ssofr[MTU];
	char final_var_ssofr[MTU];
	bzero(final_var_ssofr, MTU);
	for(int i=0; i < inp->NUM_SSOFR; i++){
		bzero(temp_ssofr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_ssofr = encode_subsuboffsetfetchresponse(&inp->ssofr[i], &innertemp_ptr);
		sprintf(temp_ssofr, "%s", innertemp_ptr);
		strcat(final_var_ssofr, temp_ssofr);
	}
	const char* format="%s%.*d%s";
	return sprintf(saveto, format, temp_topicname, SSOFR_SIZE_FIELD_SIZE, inp->NUM_SSOFR, final_var_ssofr);
}


int encode_offsetfetchresponse(struct OffsetFetchResponse* inp, char** st){
	char *saveto = *st;
	char temp_sofr[MTU];
	char final_var_sofr[MTU];
	bzero(final_var_sofr, MTU);
	for(int i=0; i < inp->NUM_SUB_OFR; i++){
		bzero(temp_sofr, MTU);
		char innertemp[MTU], *innertemp_ptr=innertemp;
		bzero(innertemp_ptr, MTU);
		int temp_len_sofr = encode_suboffsetfetchresponse(&inp->sofr[i], &innertemp_ptr);
		sprintf(temp_sofr, "%s", innertemp_ptr);
		strcat(final_var_sofr, temp_sofr);
	}
	const char* format="%.*d%s";
	return sprintf(saveto, format, SOFR_SIZE_FIELD_SIZE, inp->NUM_SUB_OFR, final_var_sofr);
}

int encode_resmessage(union ResMessage* inp, char** st, enum response_type rt){
	char *saveto = *st;
	char temp [MTU], *temp_ptr = temp;
	bzero(temp, MTU);

	switch(rt){
		case RESPONSE_METADATA: encode_metadataresponse(&inp->metadata_response, &temp_ptr); break;
		case RESPONSE_PRODUCE:  encode_produceresponse(&inp->produce_response, &temp_ptr); break;
		case RESPONSE_FETCH:    encode_fetchresponse(&inp->fetch_response, &temp_ptr); break;
		case RESPONSE_OFFSET: encode_offsetresponse(&inp->offset_response, &temp_ptr); break;
		case RESPONSE_OFFSET_COMMIT: encode_offsetcommitresponse(&inp->offset_commit_response, &temp_ptr); break;
		case RESPONSE_OFFSET_FETCH: encode_offsetfetchresponse(&inp->offset_fetch_response, &temp_ptr); break;
		case RESPONSE_GROUP_COORDINATOR: encode_groupcoordinatorresponse(&inp->group_coordinator_response, &temp_ptr); break;
	}
	const char* format = "%s";
	return sprintf(saveto, format, temp);
}


int encode_responsemessage(struct ResponseMessage* inp, char** st, enum response_type rt){
	char *saveto = *st;
	char temp_rm[MTU], *temp_rm_ptr=temp_rm;
	bzero(temp_rm, MTU);
	int temp_len_rm = encode_resmessage(&inp->rm, &temp_rm_ptr, rt);
	const char* format="%.*d%s";
	return sprintf(saveto, format, inp->CorrelationId < 0? CORRELATIONID_FIELD_SIZE-1 : CORRELATIONID_FIELD_SIZE, inp->CorrelationId, temp_rm);
}
