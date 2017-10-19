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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <strings.h>
#include <sys/poll.h>

#include "../headers/utils.h"
#include "../headers/message.h"
#include "../headers/processor.h"
#include "../headers/protocol.h"
#include "../headers/circular_queue.h"
#include "../headers/doubly_linked_list.h"
#include "../headers/caml_common.h"
#include "../headers/caml_broker.h"
#include "../headers/protocol.h"
#include "../headers/protocol_parser.h"
#include "../headers/protocol_encoder.h"

extern int MAX_NUM_REQUESTS_PER_PROCESSOR; // Maximum outstanding requests per processor.
extern int NUM_PROCESSORS; // Number of processors.
extern int MAX_NUM_RESPONSES_PER_PROCESSOR; // Maximum outstanding responses per processor.
extern int CONNECTIONS_PER_PROCESSOR; // Number of connections per processor.
extern int MAX_NUM_UNFSYNCED; // Maximum number of unfsynced inserts

extern mallocfunctiontype ilia_alloc;
extern freefunctiontype ilia_free;

static DLL* threadid_to_array_of_connections;
static DLL* request_pool;
static DLL* response_pool;
static DLL* un_fsynced; // responses which are unsynced

static pthread_t *created_threads, *fsy_thread;
static processor_argument *pas, *fsy;

static CircularQueue* threadid_to_array_of_requests;

static int running = 0;

unsigned short PRIO_LOG = PRIO_NORMAL;

static segment* ptr_seg;

void msend(int fd, char* buf, int buf_size){

    debug(PRIO_NORMAL, "Sending: '%s'\n", buf);
    send(fd, buf, buf_size, 0);
}

int server_handle(DLLNode *req_p, DLLNode *res_p, int thread_index){

    struct ResponseMessage *res_ph;
    struct RequestMessage  *req_ph = (struct RequestMessage*) req_p->val;

    if(res_p){
        res_ph = (struct ResponseMessage*) res_p->val;
        res_p->fd = req_p->fd;
        clear_responsemessage(res_ph, req_ph->APIKey);
        res_ph->CorrelationId = req_ph->CorrelationId;
    }

    debug(PRIO_NORMAL, "CorrelationId: %d ClientID: %s\n", req_ph->CorrelationId, req_ph->ClientId);
    switch(req_ph->APIKey){
        case REQUEST_PRODUCE:;
            char* current_topic_name = req_ph->rm.produce_request.spr.TopicName.TopicName;
            debug(PRIO_NORMAL, "Inserting messages into the topicname '%s'\n", current_topic_name);

            if(res_p){
                int topic_name_len = strlen(current_topic_name);
                debug(PRIO_NORMAL, "There is a response needed [%d]\n", req_ph->CorrelationId);

                int current_subreply = res_ph->rm.produce_response.NUM_SUB; // Get the current subproduce

                struct SubProduceResponse *current_spr = &(res_ph->rm.produce_response.spr[current_subreply]);
                res_ph->rm.produce_response.NUM_SUB++; // Say that you have occupied a cell in the subproduce
                char* ttn = current_spr->TopicName.TopicName;
                debug(PRIO_LOW, "starting copying...\n");
                memcpy(ttn, current_topic_name, topic_name_len);
                debug(PRIO_LOW, "Done...\n");
                current_spr->NUM_SUBSUB = req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS;

                for(int i=0; i< req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS; i++){
                    struct Message *tmsg = &req_ph->rm.produce_request.spr.sspr.mset.Elems[i].Message;
                    debug(PRIO_LOW, "\tMessage: '%s'\n", tmsg->value);
                    int slen = strlen(tmsg->value);

                    struct SubSubProduceResponse* curr_sspr = &current_spr->sspr[i];
                    curr_sspr->Timestamp = time(NULL);
                    int curr_repl = 0;
                    unsigned long mycrc = get_crc(tmsg->value, slen);

                    if (tmsg->CRC == mycrc){ // Checking to see if the crcs match
                        lock_seg(ptr_seg);
                        int ret = insert_message(ptr_seg, tmsg->value, slen);
                        ulock_seg(ptr_seg);
                        curr_repl |= CRC_MATCH;
                        if(ret > 0){
                            curr_repl |= INSERT_SUCCESS;
                            curr_sspr->Offset = ret;
                        }else{
                            curr_repl |= INSERT_ERROR;
                        }
                    }else{
                        curr_repl |= CRC_NOT_MATCH;
                        debug(PRIO_LOW, "The CRCs do not match for msg: '%s'\n", tmsg->value);
                    }

                    curr_sspr->ErrorCode = curr_repl;
                    curr_sspr->Partition = 1; // TODO: implement the proper partitions
                }
            }else{
                debug(PRIO_LOW, "There is no response needed\n");
                for(int i=0; i< req_ph->rm.produce_request.spr.sspr.mset.NUM_ELEMS; i++){
                    struct Message *tmsg = &req_ph->rm.produce_request.spr.sspr.mset.Elems[i].Message;
                    int slen = strlen(tmsg->value);

                    unsigned long mycrc = get_crc(tmsg->value, slen);

                    if (tmsg->CRC == mycrc){ // Checking to see if the crcs match
                        lock_seg(ptr_seg);
                        insert_message(ptr_seg, tmsg->value, slen);
                        ulock_seg(ptr_seg);
                    }
                }
            }
           break;
        case REQUEST_OFFSET_COMMIT: break;
        case REQUEST_OFFSET: break;
        case REQUEST_FETCH:
            debug(PRIO_NORMAL, "Got a request_fetch message\n");

            res_ph = (struct ResponseMessage*) res_p->val;

            struct FetchResponse* curfres = &res_ph->rm.fetch_response;
            struct FetchRequest* curfreq = &req_ph->rm.fetch_request;

            debug(PRIO_NORMAL, "Request: %p Response: %p\n", req_ph, res_ph);

            current_topic_name = curfreq->TopicName.TopicName;
            int topic_name_len = strlen(current_topic_name);
            debug(PRIO_NORMAL, "The associated topic name is: %s\n", current_topic_name);

            debug(PRIO_NORMAL, "Fetching messages from %s starting at offset %ld\n", curfreq->TopicName.TopicName, curfreq->FetchOffset);

            long handle_start = time(NULL);

            int bytes_so_far = 0;
            long current_offset = curfreq->FetchOffset;

            curfres->NUM_SFR = 0; //Currently the only supported mode
            int csfr = 0, cssfr = 0, curm = 0, first_time = 1;
            while((time(NULL) - handle_start)<curfreq->MaxWaitTime){
                if(first_time){
                    debug(PRIO_NORMAL, "The first time for the given configuration:\n\tcsfr: %d\n\tcssfr: %d\n\tcurm: %d\n", csfr, cssfr, curm);
                    memcpy(curfres->sfr[csfr].TopicName.TopicName, current_topic_name, topic_name_len);
                    curfres->ThrottleTime = 0; //TODO: IMPLEMENT IF NEEDED
                    curfres->sfr[csfr].ssfr[cssfr].HighwayMarkOffset = 0;//TODO: implement getting the last possible offset
                    curfres->sfr[csfr].ssfr[cssfr].Partition = 0;
                    first_time = 0;
                }

                if(curm == MAX_SET_SIZE){
                    debug(PRIO_NORMAL, "The current message has reached the upper boundary of %d\n", MAX_SET_SIZE);
                    cssfr += 1;
                    curm = 0;
                    first_time = 1;
                    continue;
                }

                if(cssfr == MAX_SUB_SUB_FETCH_SIZE){
                    cssfr = 0;
                    curm  = 0;
                    csfr  += 1;
                    first_time = 1;
                    continue;
                }

                if(csfr == MAX_SUB_FETCH_SIZE){
                    debug(PRIO_HIGH, "Fetch response has reached its maximum size\n");
                    break;
                }
                struct MessageSetElement *mse = &curfres->sfr[csfr].ssfr[cssfr].MessageSet.Elems[curm];
                mse->Message.Attributes = 0;

                int msglen = get_message_by_offset(ptr_seg, current_offset, mse->Message.value);

                if(msglen < 0){
                    mse->Message.Attributes = msglen;
                }
                
                if(msglen == 0){
                    debug(PRIO_NORMAL, "No message for a given offset(%lu) found. Stopping here meaning it is the end\n", current_offset); 
                    break;
                }
    
                debug(PRIO_NORMAL, "Found a message %s for offset %d\n", mse->Message.value, current_offset);
                curfres->NUM_SFR = csfr+1;
                curfres->sfr[csfr].NUM_SSFR = cssfr+1;
                curfres->sfr[csfr].ssfr[cssfr].MessageSet.NUM_ELEMS = curm+1;

                mse->Offset = current_offset;
                mse->Message.Timestamp = time(NULL);
                mse->Message.CRC = get_crc(mse->Message.value, msglen);

                bytes_so_far += msglen >= 0 ? msglen : 0;
                curm += 1;
                current_offset += 1;

                if(bytes_so_far >=curfreq->MaxBytes){
                    break;
                }
            }

            if(bytes_so_far < curfreq->MinBytes){
                // Do not send anything
                return 0;
            }

            break;
        case REQUEST_OFFSET_FETCH: break;
        case REQUEST_METADATA: break;
        case REQUEST_GROUP_COORDINATOR: break;
    }
    debug(PRIO_LOW, "Finished server_handle\n");
    return 1;
}

int assign_to_processor(int processorid, int conn_fd){

    DLLNode* pcn = lboru_dll(&threadid_to_array_of_connections[processorid]);
    if(pcn){
        memcpy(pcn->val, &conn_fd, sizeof(int));
        debug(PRIO_LOW, "Enqueued %d fd into the connections queue\n", *((int*)pcn->val));
        print_dll(&threadid_to_array_of_connections[processorid]);
        return 1;
    }
    return -1;
}

int free_datastructures(){

    for(int i = 0; i< NUM_PROCESSORS; i++){
        ilia_free(threadid_to_array_of_connections[i].head);
    }
    ilia_free(threadid_to_array_of_connections);

    ilia_free(pas);
    ilia_free(created_threads);
    // TODO: clean the req/res
    // TODO: clean&join the threads

    return 1;
}

int allocate_broker_datastructures(struct broker_configuration* conf){

    pas = (processor_argument*) ilia_alloc(sizeof(processor_argument)*NUM_PROCESSORS);
    created_threads = (pthread_t*) ilia_alloc(sizeof(pthread_t)*NUM_PROCESSORS);

    threadid_to_array_of_connections = allocate_dlls_per_num_processors(NUM_PROCESSORS, CONNECTIONS_PER_PROCESSOR);
    preallocate_with(threadid_to_array_of_connections, NUM_PROCESSORS, CONNECTIONS_PER_PROCESSOR, sizeof(int));

    request_pool = allocate_dlls_per_num_processors(NUM_PROCESSORS, MAX_NUM_REQUESTS_PER_PROCESSOR);
    preallocate_with(request_pool, NUM_PROCESSORS, MAX_NUM_REQUESTS_PER_PROCESSOR, sizeof(struct RequestMessage));

    response_pool = allocate_dlls_per_num_processors(NUM_PROCESSORS, MAX_NUM_RESPONSES_PER_PROCESSOR);
    preallocate_with(response_pool, NUM_PROCESSORS, MAX_NUM_RESPONSES_PER_PROCESSOR, sizeof(struct ResponseMessage));

    threadid_to_array_of_requests = allocate_circ_queue_per_num_processors( NUM_PROCESSORS,
                                                                            MAX_NUM_REQUESTS_PER_PROCESSOR,
                                                                            sizeof(DLLNode*));
    //threadid_to_array_of_responses = allocate_circ_queue_per_num_processors(NUM_PROCESSORS,
    //                                                                        MAX_NUM_RESPONSES_PER_PROCESSOR,
    //                                                                        sizeof(DLLNode*));


    if(!(conf->val & BROKER_FSYNC_ALWAYS)){
        fsy = (processor_argument*) ilia_alloc(sizeof(struct processor_argument));
        fsy_thread = (pthread_t*) ilia_alloc(sizeof(pthread_t));

        un_fsynced = allocate_dlls_per_num_processors(1, MAX_NUM_UNFSYNCED);
        preallocate_with(un_fsynced, 1, MAX_NUM_UNFSYNCED, sizeof(DLLNode**));
    }

    return 0;
}

int init_listening_socket(int portnumber){
    int sockfd;
    struct sockaddr_in self;

	/*---Create streaming socket---*/
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) return -1;

	/*---Initialize address/port structure---*/
	bzero(&self, sizeof(self));
	self.sin_family = AF_INET;
	self.sin_port = htons(portnumber);
	self.sin_addr.s_addr = INADDR_ANY;

	/*---Assign a port number to the socket---*/
    if ( bind(sockfd, (struct sockaddr*)&self, sizeof(self)) != 0 ) return -2;

	/*---Make it a "listening socket"---*/
	if ( listen(sockfd, 20) != 0 ) return -3;

    return sockfd;
}

void accept_loop(int sockfd, struct broker_configuration* conf){
    int current_processor_id = 0;
    running = 1;

	while (running){
		int clientfd, ret;
		struct sockaddr_in client_addr;
		socklen_t addrlen=sizeof(client_addr);
		clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
        if(clientfd < 0){
            running=0;
            return;
        }
        ret = assign_to_processor(current_processor_id, clientfd);
		debug(PRIO_NORMAL, "%s:%d connected and assigned to processor number %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), current_processor_id);
        if(ret > 0){
            current_processor_id = (current_processor_id+1) % NUM_PROCESSORS;
        }
	}
}

void* processorThread(void *vargp){
    processor_argument* pa = (processor_argument*) vargp;

    sleep(1);
    debug(PRIO_LOW, "Processor thread with id %d started...\n", pa->index);

    char buffer[MTU], *pbuf = buffer, send_out_buf[MTU];

    DLLNode* temp;

    int rv, msg_size;

    DLL* mydll = &threadid_to_array_of_connections[pa->index];

    while(running){
        int mynum = mydll->cur_num;

        if(mynum > 0){
            struct pollfd ufds[mynum];

            DLLNode* cur = mydll->head;
            for(int i=0; i < mynum; i++){
                ufds[i].fd = *((int*)cur->val);
                ufds[i].events = POLLIN;// | POLLPRI;
                cur = cur->next;
            }

            rv = poll(ufds, mynum, 3000);
            debug(PRIO_NORMAL, "[%d] Polling... %d\n", pa->index, rv);

            if (rv == -1){
                debug(PRIO_HIGH, "POLL ERROR\n");
                exit(-1);
            }

            if (rv != 0){
                cur = mydll->head;
                DLLNode* next = NULL;
                for(int i=0;(i < mynum) && (i != mydll->cur_num); i++){
                    next = cur->next;
                    if (ufds[i].revents & POLLIN) {
                        DLLNode* rm = lboru_dll(request_pool);

                        if(!rm){
                            //TODO it is actually a very good q what to do here. Either
                            //ignore, or send back a message saying there is a problem
                            //For now it just ignores it as the client policy just resends it.
                            //Meaning that potentially one may starve
                            debug(PRIO_NORMAL, "Cant borrow any more requests.\n");
                            continue;
                        }

                        msg_size = read_msg(ufds[i].fd, &pbuf);
                        if(msg_size > 0){
                            debug(PRIO_LOW, "Enqueuing: '%s'\n", pbuf);

                            struct RequestMessage *trq = (struct RequestMessage*) rm->val;

                            clear_requestmessage(trq, get_apikey(pbuf));
                            parse_requestmessage(trq , pbuf);
                            rm->fd = ufds[i].fd;

                            lock_cq(&threadid_to_array_of_requests[pa->index]);
                            enqueue(&threadid_to_array_of_requests[pa->index], &rm, sizeof(DLLNode*));
                            ulock_cq(&threadid_to_array_of_requests[pa->index]);
                        }else{
                            //This is the disconnect. Maybe need to clean the
                            //responses to this guy. Not sure how to do that
                            //yet. TODO: decide
                            lretu_dll(&threadid_to_array_of_connections[pa->index], cur);
                            lretu_dll(request_pool, rm);
                        }
                    }
                    cur = next;
                }
            }
        }

		if(threadid_to_array_of_requests[pa->index].front != -1){
            int bnodes_size = 2;
            DLLNode* bnodes[bnodes_size];
            int ret = lboru_dlls(bnodes, bnodes_size, un_fsynced, response_pool);
            if(!ret) continue;
            DLLNode **unfs  = &bnodes[0], **res_p = &bnodes[1];

            debug(PRIO_LOW, "Successfully borrowed %p %p %p\n", *unfs, *res_p, (*res_p)->val);

            lock_cq(&threadid_to_array_of_requests[pa->index]);
            int ind = dequeue(&threadid_to_array_of_requests[pa->index], (void**) &temp, sizeof(DLLNode*));
            ulock_cq(&threadid_to_array_of_requests[pa->index]);

            if (ind != -1){
                struct RequestMessage* rmsg = ((struct RequestMessage* )temp->val);
                if(pa->config->val&BROKER_FSYNC_ALWAYS){lretu_dll(un_fsynced,*unfs);unfs=NULL;}
                if((rmsg->APIKey == REQUEST_PRODUCE) && (!rmsg->rm.produce_request.RequiredAcks)){lretu_dll(response_pool,*res_p);res_p=NULL;}

                int sh = server_handle(temp, *res_p, pa->index);
                debug(PRIO_NORMAL, "Server handle finished with code %d\n", sh);
                debug(PRIO_NORMAL, "Response %p\n", res_p);
                if (sh > 0){
                    if(pa->config->val & BROKER_FSYNC_ALWAYS){
                        lock_seg(ptr_seg);
                        fsync(ptr_seg->_log);
                        fsync(ptr_seg->_index);
                        ulock_seg(ptr_seg);

                        if(res_p){
                            struct ResponseMessage* myres = (struct ResponseMessage*) (*res_p)->val;
                            int fi = wrap_with_size(myres, &pbuf, send_out_buf, rmsg->APIKey);
                            msend((*res_p)->fd, send_out_buf, fi);

                            lretu_dll(response_pool, *res_p);
                            lretu_dll(request_pool, temp);
                        }
                        if(unfs) lretu_dll(un_fsynced, *unfs);
                    }else{
                        if(res_p){
                            debug(PRIO_NORMAL, "Setting the unfsynched node %p\n", unfs);
                            (*unfs)->fd = rmsg->APIKey;
                            memcpy(&((*unfs)->val), res_p, sizeof(DLLNode*));
                            debug(PRIO_NORMAL, "Copied into the unfs: %p %p\n", (*unfs)->val, *res_p);
                            debug(PRIO_NORMAL, "Done\n");
                        }
                        lretu_dll(request_pool, temp);
                        debug(PRIO_NORMAL, "Returned the request object into the pool %p\n", temp);
                    }
                }else{
                    if(res_p) lretu_dll(response_pool, *res_p);
                    if(unfs) lretu_dll(un_fsynced, *unfs);
                    if(temp) lretu_dll(request_pool, temp);
                }
            }
		}else{
            sleep(pa->config->processor_thread_sleep_length);
        }
    }

    return NULL;
}

void start_processor_threads(struct broker_configuration* conf){
    for(int i=0; i < NUM_PROCESSORS; i++){
        pas[i].index = i;
        pas[i].tid   = NULL;
        pas[i].config = conf;

        pthread_create(&created_threads[i], NULL, processorThread, &pas[i]);
        pas[i].tid = &created_threads[i];
    }
}

void* fsyncThread(void* vargp){
    processor_argument* pa = (processor_argument*) vargp;

    sleep(1);

    debug(PRIO_LOW, "FSync thread started... %d\n", pa->index);
    char *pbuf = (char*) ilia_alloc(MTU*sizeof(char)), *send_out_buf = (char*) ilia_alloc(MTU*sizeof(char));

    while(running){
        debug(PRIO_LOW, "Checking if there are any elements un-fsynched...\n");

        if(un_fsynced->cur_num > 0){
            lock_dll(un_fsynced);
            debug(PRIO_LOW, "un-fsynched queue has some elements in it [%d]. Time to ack them.\n", un_fsynced->cur_num);

            lock_seg(ptr_seg);
            fsync(ptr_seg->_log);
            fsync(ptr_seg->_index);

            DLLNode* cur = un_fsynced->last_valid;
            while (cur){
                DLLNode* res_p = (DLLNode*) cur->val;
                struct ResponseMessage *rm = (struct ResponseMessage*)res_p->val;

                debug(PRIO_LOW, "Unfsynching: %d\n", rm->CorrelationId);
                int fi = wrap_with_size(rm, &pbuf, send_out_buf, (enum request_type)cur->fd);

                msend(res_p->fd, send_out_buf, fi);
                //send(res_p->fd, send_out_buf, fi, 0);


                lretu_dll(response_pool, res_p);
                returnObj(un_fsynced, cur);

                cur = un_fsynced->last_valid;
            }
            ulock_dll(un_fsynced);
            ulock_seg(ptr_seg);

            debug(PRIO_LOW, "Finished fsynching the elems for now. Sleeping....\n");
        }else{
            debug(PRIO_LOW, "No elements that are not fsynched\n");
        }
        debug(PRIO_LOW, "Fsynch thread is going to sleep for %d seconds\n", pa->config->fsync_thread_sleep_length);
        sleep(pa->config->fsync_thread_sleep_length);
    }
    return NULL;
}


void start_fsync_thread(struct broker_configuration *conf){
    fsy->tid   = NULL;
    fsy->config = conf;
    fsy->index = 0;

    pthread_create(fsy_thread, NULL, fsyncThread, fsy);
    fsy->tid = fsy_thread;
}

void close_listening_socket(int sockfd){
    close(sockfd);
}

void sigintHandler(int dummy) {
    debug(PRIO_NORMAL, "Caught SIGINT[%d]\n", dummy);
    running = 0;

    for(int i=0; i<NUM_PROCESSORS; i++){
        pthread_join(created_threads[i], NULL);
    }

    free_datastructures();
    exit(0);
}


void broker_busyloop(int portnumber, const char* p_name, struct broker_configuration* conf){

    print_configuration(conf);
    allocate_broker_datastructures(conf);
    start_processor_threads(conf);

    // TODO: NEED TO MOVE IT SOMEWHERE
    del_folder(p_name);
    make_folder(p_name);
    ptr_seg = make_segment(0, 1024*1024, p_name);

    signal(SIGINT, sigintHandler);

    if(!(conf->val & BROKER_FSYNC_ALWAYS)){
        start_fsync_thread(conf);
    }

    int sockfd = init_listening_socket(portnumber);
    accept_loop(sockfd, conf);
}
