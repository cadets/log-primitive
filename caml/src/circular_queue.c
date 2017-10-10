// The implementation of the circular queue

#include <string.h>
#include <stdio.h>
#include "../headers/circular_queue.h"
#include "../headers/caml_common.h"
#include "../headers/utils.h"

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

