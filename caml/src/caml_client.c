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
#include <stdarg.h>

#include "../headers/utils.h"
#include "../headers/message.h"
#include "../headers/circular_queue.h"
#include "../headers/doubly_linked_list.h"
#include "../headers/binary_tree.h"
#include "../headers/caml_common.h"
#include "../headers/caml_client.h"

#include "../headers/protocol.h"
#include "../headers/protocol_parser.h"
#include "../headers/protocol_encoder.h"

extern int NUM_NOTIFIERS; // Number of notifiers for the client.
extern int NUM_READERS; // Number of readers for the client.
extern int REQUESTS_PER_NOTIFIER; // Number of the requests in notifiers.
extern int NODE_POOL_SIZE; // number of maximum outstanding un-acked messages
extern int MSG_POOL_SIZE; // number of avalibale MEssage size elemets

extern int MAX_NUM_REQUESTS_PER_PROCESSOR;
extern int NUM_PROCESSORS;
extern int MAX_NUM_RESPONSES_PER_PROCESSOR;
extern int CONNECTIONS_PER_PROCESSOR;

static CircularQueue* request_notifiers;
static CircularQueue* send_out_queue;
static DLL* request_pool;
static DLL* node_pool;
static DLL* response_pool;

static pthread_t* notifiers;
static pthread_t* readers;
static pthread_t* resender;

static int current_request_notifier = 0;
static int running = 0;

static notifier_argument *nas; // Array containing arguments to the notifier threads
static reader_argument *resender_arg;
static reader_argument *ras; //Array containing arguments to the reader threads

static bt_holder *un_ack_holder;
static int num_readers;

int connect_to_server(const char *hostname, int portnumber){
    int sockfd;
    struct sockaddr_in dest;

    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) return -1;

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(portnumber);

    if ( inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0 ) return -2;
    if ( connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0 ) return -3;

    return sockfd;
}

void* resender_thread(void *vargp){
    reader_argument *ra = (reader_argument*) vargp;

    sleep(1);
    debug(PRIO_LOW, "Resender thread started\n");

    unsigned long now;

    int server_id_assign = 0;
    while(running){

        lock_dll(node_pool);

        if(node_pool->last_valid){
            debug(PRIO_LOW, "There is a node borrowed from the node pool. Need to check if needs resend.\n");
            lock_bth(un_ack_holder);
            lock_dll(request_pool);

            //DLLNode *cur = node_pool->last_valid;
            //while (cur){
            DLLNode* cur = node_pool->last_valid;
            while(cur){
            //for(int i = 0; i < node_pool->cur_num; i++){
                struct bt_node *btn = (struct bt_node*) cur->val;
                debug(PRIO_NORMAL, "Checking the node with corr id: %d(%d) [%d in the node pool]\n", btn->key, ((struct RequestMessage*) ((DLLNode*) btn->val)->val)->CorrelationId, node_pool->cur_num);
                debug(PRIO_NORMAL, "The request %p\n", btn->val);

                if(btn->should_resend){
                    now = time(NULL);
                    debug(PRIO_LOW, "Was sent %lu now is %lu. Resend when the difference is %lu. Current: %lu\n", btn->last_sent, now, btn->resend_timeout, now-btn->last_sent);

                    if((now - btn->last_sent) > btn->resend_timeout){
                        debug(PRIO_NORMAL, "Resending....\n");
                        btn->last_sent = time(NULL);
                        DLLNode* rq = (DLLNode*)btn->val;

                        lock_cq(&send_out_queue[server_id_assign]);
                        enqueue(&send_out_queue[server_id_assign], &rq, sizeof(DLLNode*));
                        ulock_cq(&send_out_queue[server_id_assign]);

                        server_id_assign = (server_id_assign + 1) % num_readers;
                        debug(PRIO_LOW, "Done.\n");
                    }
                }
                debug(PRIO_LOW, "From cur %p to prev %p\n", cur, cur->prev);
                cur = cur->prev;
            }

            ulock_bth(un_ack_holder);
            ulock_dll(request_pool);
        }
        ulock_dll(node_pool);
        debug(PRIO_NORMAL, "Resender thread is going to sleep for %d seconds\n", ra->config->resender_thread_sleep_length);
        sleep(ra->config->resender_thread_sleep_length);
    }

    return NULL;
}


void* reader_thread(void *vargp){

    reader_argument* ra = (reader_argument*) vargp;

    int server_conn = -1, rv, msg_size;
    char* pbuf = (char*) ilia_alloc(sizeof(char)*MTU);
    char* send_out_buffer = (char*) ilia_alloc(sizeof(char)*MTU);

    DLLNode *rm;

    while(running){
        if (server_conn < 0){
            debug(PRIO_NORMAL, "No connection to server. Attempting to connect to '%s:%d'\n", ra->hostname, ra->portnumber);
            server_conn = connect_to_server(ra->hostname, ra->portnumber);
            if(server_conn < 0){
                debug(PRIO_NORMAL, "Error connecting...\n");
            }

            sleep(ra->config->reconn_timeout);
            continue;
        }
        struct pollfd ufd;
        ufd.fd = server_conn;
        ufd.events = POLLIN;

        rv = poll(&ufd, 1, ra->config->poll_timeout);
        debug(PRIO_NORMAL, "Reader thread polling ... %d\n", rv);
        if(rv == -1){ debug(PRIO_HIGH, "Poll error..."); continue; }
        if(rv){
            msg_size = read_msg(ufd.fd, &pbuf);

            if (msg_size > 0){
                int mnotif = (current_request_notifier + 1) % NUM_NOTIFIERS;
                lock_cq(&request_notifiers[mnotif]);

                enqueue(&request_notifiers[mnotif], pbuf, sizeof(char)*MTU);

                current_request_notifier = mnotif;
                ulock_cq(&request_notifiers[mnotif]);
            }else{
                server_conn = -1;
            }
        }

		while(send_out_queue[ra->index].num_elems > 0){
            lock_cq(&send_out_queue[ra->index]);
            int ind = dequeue(&send_out_queue[ra->index], (void*) &rm, sizeof(DLLNode*));
            ulock_cq(&send_out_queue[ra->index]);

            if(ind != -1){
                struct RequestMessage* mimi = (struct RequestMessage*) rm->val;
                debug(PRIO_LOW, "[%d]Dequeued request with address %p\n", ind, mimi);
                int req_size = encode_requestmessage(mimi, &pbuf);
                int fi = sprintf(send_out_buffer, "%.*d%s", OVERALL_MSG_FIELD_SIZE, req_size+OVERALL_MSG_FIELD_SIZE, pbuf);

                debug(PRIO_NORMAL, "[%d]Sending: '%s'\n", ind, send_out_buffer);
                send(server_conn, send_out_buffer, fi, 0);
            }
        }
    }
    return NULL;
}


void parse_server_answer(struct RequestMessage* req_m, struct ResponseMessage* res_m, char* pbuf){
    clear_responsemessage(res_m, req_m->APIKey);
    parse_responsemessage(res_m, pbuf, match_requesttype(req_m->APIKey));
}

void* request_notifier_thread(void *vargp){
    notifier_argument* na = (notifier_argument*) vargp;
    char* pbuf = (char*) ilia_alloc(sizeof(char)*MTU); //TODO move this guy to the allocations

    debug(PRIO_LOW, "Requester thread with id %d started...\n", na->index);

    while(running){
        if(request_notifiers[na->index].num_elems > 0){
            DLLNode* rt = lboru_dll(response_pool);
            debug(PRIO_LOW, "The pool[%d] last valid after %p was borrowed: %p\n", response_pool->cur_num, rt, response_pool->last_valid);

            if(rt){
                lock_cq(&request_notifiers[na->index]);
                int ind = dequeue(&request_notifiers[na->index], (void*) pbuf, sizeof(char)*MTU);
                ulock_cq(&request_notifiers[na->index]);

                if(ind != -1){
                    lock_bth(un_ack_holder);
                    lock_dll(node_pool);

                    debug(PRIO_NORMAL, "Requester[%d] got the following message '%s'\n", na->index, pbuf);
                    correlationId_t message_corr_id = get_corrid(pbuf);

                    print_bt(un_ack_holder->bt);
                    bt_node *bn = search(un_ack_holder->bt, message_corr_id);
                    debug(PRIO_NORMAL, "Requested: %d Gotten: %d\n", message_corr_id, bn->key);
                    debug(PRIO_LOW, "CorrId of the message: %d\n", message_corr_id);

                    if(bn){
                        debug(PRIO_NORMAL, "Found the un_acked node\n");
                        DLLNode* req_n = (DLLNode*) bn->val;
                        struct RequestMessage  *req_m = (struct RequestMessage*)  req_n->val;
                        struct ResponseMessage *res_m = (struct ResponseMessage*) rt->val;

                        parse_server_answer(req_m, res_m, pbuf);
                        
                        na->on_ack(res_m->CorrelationId);
                        na->on_response(req_m, res_m);
                        debug(PRIO_NORMAL, "Got acknowledged: %d\n", res_m->CorrelationId);
                        debug(PRIO_NORMAL, "Returning Binary Tree object %p\n", bn->me);

                        lretu_dll(request_pool, (DLLNode*) bn->val);
                        returnObj(node_pool, (DLLNode*) bn->me);
                        lretu_dll(response_pool, rt);
                        bn->me = NULL;
                        bn->val = NULL;

                        un_ack_holder->bt = delete_node(un_ack_holder->bt, message_corr_id);
                        printf("After deleting\n");
                        print_bt(un_ack_holder->bt);
                    }else{
                        debug(PRIO_LOW, "Not found the un_acked node\n");
                        print_bt(un_ack_holder->bt);
                        lretu_dll(response_pool, rt);
                    }
                    ulock_dll(node_pool);
                    ulock_bth(un_ack_holder);
                }else{
                    lretu_dll(response_pool, rt);
                }
            }else{
                debug(PRIO_HIGH, "Cant borrow a response to send stuff off\n");
            }
        }
        sleep(na->config->request_notifier_thread_sleep_length);
    }
    return NULL;
}

void start_notifiers(struct client_configuration *cc){
    for(int i=0; i < NUM_NOTIFIERS; i++){
        nas[i].index = i;
        nas[i].tid   = NULL;
        nas[i].config = cc;
        nas[i].on_ack = cc->on_ack;
        nas[i].on_response = cc->on_response;

        pthread_create(&notifiers[i], NULL, request_notifier_thread, &nas[i]);
        nas[i].tid = &notifiers[i];
    }
}

void start_resender(struct client_configuration *cc){
    resender_arg->index=0;
    resender_arg->tid = NULL;
    resender_arg->config = cc;
    pthread_create(resender, NULL, resender_thread, resender_arg);
    resender_arg->tid = resender;
}

int allocate_client_datastructures(struct client_configuration* cc){
    //TODO: need to add the error checking somewhere here
    un_ack_holder = (struct bt_holder*) ilia_alloc(sizeof(struct bt_holder));
    un_ack_holder->bt = NULL;
    init_bt_holder(un_ack_holder);

    nas = (notifier_argument*) ilia_alloc(sizeof(notifier_argument)*NUM_NOTIFIERS);
    ras = (reader_argument*) ilia_alloc(sizeof(reader_argument)*NUM_READERS);
    notifiers = (pthread_t*) ilia_alloc(sizeof(pthread_t)*NUM_NOTIFIERS);
    readers = (pthread_t*) ilia_alloc(sizeof(pthread_t)*NUM_READERS);

    request_notifiers = allocate_circ_queue_per_num_processors(NUM_NOTIFIERS, REQUESTS_PER_NOTIFIER, sizeof(char)*MTU);
    send_out_queue = allocate_circ_queue_per_num_processors(NUM_NOTIFIERS, REQUESTS_PER_NOTIFIER, sizeof(DLLNode*));

    request_pool = allocate_dlls_per_num_processors(1, MAX_NUM_REQUESTS_PER_PROCESSOR);
    preallocate_with(request_pool, 1, MAX_NUM_REQUESTS_PER_PROCESSOR, sizeof(struct RequestMessage));

    if(cc->to_resend){
        node_pool = allocate_dlls_per_num_processors(1, NODE_POOL_SIZE);
        preallocate_with(node_pool, 1, NODE_POOL_SIZE, sizeof(struct bt_node));
        resender_arg = (reader_argument*) ilia_alloc(sizeof(reader_argument));
        resender = (pthread_t*) ilia_alloc(sizeof(pthread_t));
    }

    response_pool = allocate_dlls_per_num_processors(1, MAX_NUM_RESPONSES_PER_PROCESSOR);
    preallocate_with(response_pool, 1, MAX_NUM_RESPONSES_PER_PROCESSOR, sizeof(struct ResponseMessage));

    return 1;
}

void start_reader_threads(struct client_configuration *cc, int num, ...){

     va_list argvars;
     va_start(argvars, num);
     num_readers = MIN(NUM_READERS, num);

     for(int i=0; i < num_readers; i++){
        ras[i].index = i;
        ras[i].tid   = NULL;
        ras[i].config = cc;

        char* thost = va_arg(argvars, char*);
        memcpy(ras[i].hostname, thost, strlen(thost));
        ras[i].portnumber = va_arg(argvars, int);

        pthread_create(&readers[i], NULL, reader_thread, &ras[i]);
        nas[i].tid = &readers[i];
    }
    va_end(argvars);
}

void client_busyloop(const char *hostname, int portnumber, struct client_configuration* cc){

    int ret = allocate_client_datastructures(cc);
    if(ret > 0){
        debug(PRIO_NORMAL, "Finished allocation...\n");
        running = 1;

        start_notifiers(cc);
        start_reader_threads(cc, 1, hostname, portnumber);
        start_resender(cc);
    }
}

int send_request(int server_id, enum request_type rt, correlationId_t correlationId, char* clientId, int should_resend, int resend_timeout, ...){

    debug(PRIO_LOW, "User requested to send a message with correlation id of %d\n", correlationId);
    va_list ap;
    va_start(ap, resend_timeout);

    DLLNode *rq = lboru_dll(request_pool);

    int result = 0;

    if(rq){
        lock_dll(node_pool);
        DLLNode *dnode = borrow(node_pool);
        if(dnode){
            lock_bth(un_ack_holder);
            lock_cq(&send_out_queue[server_id]);

            struct RequestMessage *trq = (struct RequestMessage*) rq->val;
            debug(PRIO_LOW, "Requested rm (DLL: %p) (RequestMessage: %p)\n", rq, trq);
            debug(PRIO_LOW, "Building req \n");

            clear_requestmessage(trq, rt);
            build_req(trq, rt, correlationId, clientId, ap);
            debug(PRIO_LOW, "Done\n");

            if( (trq->APIKey == REQUEST_FETCH) || ((trq->APIKey == REQUEST_PRODUCE) && (trq->rm.produce_request.RequiredAcks))){
                struct bt_node *btn = (struct bt_node*) dnode->val;
                btn->should_resend = should_resend;
                btn->resend_timeout = resend_timeout;
                btn->last_sent = time(NULL);

                debug(PRIO_NORMAL, "Inserting into the tree with key %d\n", correlationId);
                un_ack_holder->bt = insert(un_ack_holder->bt, correlationId, &dnode, rq);
				debug(PRIO_NORMAL, "Key of the request %d when the user submitted is %d\n", ((struct RequestMessage*) rq->val)->CorrelationId, correlationId);
				debug(PRIO_NORMAL, "The key recorded: %d\n", ((struct bt_node*)dnode->val)->key);
                debug(PRIO_NORMAL, "Done\n");
            }else{
				returnObj(node_pool, dnode);
			}

            enqueue(&send_out_queue[server_id], &rq, sizeof(DLLNode*));
            result = 1;

            ulock_cq(&send_out_queue[server_id]);
            ulock_dll(node_pool);
            ulock_bth(un_ack_holder);
        }else{
            lretu_dll(request_pool, rq);
            ulock_dll(node_pool);
        }
    }else{
        debug(PRIO_LOW, "Error borrowing the request to perform user send\n");
    }

    debug(PRIO_LOW, "User request finished\n");
    va_end(ap);
    return result;
}
