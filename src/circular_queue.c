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

// The implementation of the circular queue

#include <string.h>
#include <stdio.h>

#include "circular_queue.h"
#include "caml_common.h"
#include "utils.h"

extern mallocfunctiontype ilia_alloc;
extern freefunctiontype ilia_free;

void create_circular_queue(CircularQueue* cq, int size){
    cq->front = -1;
    cq->rear  = -1;
    cq->size  = size;
    cq->num_elems = 0;
    if (pthread_mutex_init(&cq->mtx, NULL) != 0){
        debug(PRIO_HIGH, "Queue mutex init failed\n");
    }
}

void lock_cq(CircularQueue* cq){
    pthread_mutex_lock(&cq->mtx);
}

void ulock_cq(CircularQueue* cq){
    pthread_mutex_unlock(&cq->mtx);
}


int enqueue(CircularQueue* cq, void* elem, size_t elem_size){
    //If returns -1 means it has no space
    if((cq->front == 0 && cq->rear == cq->size-1) || (cq->rear == cq->front -1)){
        return -1;
    }

    cq->num_elems++;
    if(cq->front == -1){
        cq->front = 0;
        cq->rear  = 0;
        void* mm = cq->arr[cq->rear];
        memcpy(mm, elem, elem_size);

        return cq->rear;
    }
	if((cq->rear == cq->size-1) && (cq->front != 0)){
		cq->rear = 0;
        void* mm = cq->arr[cq->rear];
        memcpy(mm, elem, elem_size);

		return cq->rear;
	}

    cq->rear++;

    void* mm = cq->arr[cq->rear];
    memcpy(mm, elem, elem_size);

	return cq->rear;
}

int dequeue(CircularQueue* cq, void* saveto, size_t elem_size){

    if (cq->front == -1){
        return -1;
    }

    cq->num_elems--;
    void *krya = cq->arr[cq->front];
    memcpy(saveto, krya, elem_size);

    int ret = cq->front;

	if(cq->front == cq->rear){
		cq->front = -1;
		cq->rear  = -1;
	} else if (cq->front == cq->size-1)
        cq->front = 0;
    else
        cq->front++;

    return ret;
}

void display_queue(CircularQueue* cq){
    if (cq->front == -1){
        printf("Queue is Empty\n");
        return;
    }

    printf("Elements in Circular Queue are: ");
    if (cq->rear >= cq->front){
        for (int i = cq->front; i <= cq->rear; i++)
            printf("%s ",(char*)cq->arr[i]);
    }else{
        for (int i = cq->front; i < cq->size; i++)
            printf("%s ", (char*)cq->arr[i]);

        for (int i = 0; i <= cq->rear; i++)
            printf("%s ", (char*)cq->arr[i]);
    }
	printf("\n");
}

CircularQueue* allocate_circ_queue_per_num_processors(int top_arr_size, int low_arr_size, int arr_elem_size){
    CircularQueue* circ = (CircularQueue*) ilia_alloc(sizeof(CircularQueue)*top_arr_size);

    for(int i=0; i < top_arr_size; i++){
        create_circular_queue(&circ[i], low_arr_size);

        circ[i].arr = (void**) ilia_alloc(sizeof(void*) * low_arr_size);

        for(int j=0; j< low_arr_size; j++){
            circ[i].arr[j] = (void*) ilia_alloc(arr_elem_size);
        }
    }
    return circ;
}

