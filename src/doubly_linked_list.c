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

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "../headers/doubly_linked_list.h"
#include "../headers/caml_common.h"
#include "../headers/utils.h"

extern mallocfunctiontype ilia_alloc;
extern freefunctiontype ilia_free;

DLLNode* append_to_dll(DLL* pdll, void* val, int val_size){
   
    DLLNode* mnode = borrow(pdll);
    if(!mnode){
        debug(PRIO_NORMAL, "Could not borrow :(\n");
        return NULL;
    }

    memcpy(&mnode->val, &val, val_size);

    return mnode;
}

void print_dll(DLL* dll){
    printf("Contents of dll[%d %p]: ", dll->cur_num, dll->last_valid);
    if(dll->head && dll->last_valid){
        DLLNode* cur = dll->head;
        while(cur!=dll->last_valid){
            printf("%p, ", cur);
            cur = cur->next;
        }
    }
    printf("\n");
}

DLL* allocate_dlls_per_num_processors(int top_arr_size, int low_arr_size){
    DLL* dll_ptr       = (DLL*)      ilia_alloc(sizeof(DLL)      * top_arr_size);
    DLLNode** dlls_ptr = (DLLNode**) ilia_alloc(sizeof(DLLNode*) * top_arr_size);
    for(int i = 0; i< top_arr_size; i++)
           dlls_ptr[i] = (DLLNode*) ilia_alloc(sizeof(DLLNode)*low_arr_size);

    for(int i = 0; i < top_arr_size; i++){
        dll_ptr[i].head = &dlls_ptr[i][0];
        dll_ptr[i].last_valid = NULL;
        dll_ptr[i].cur_num = 0;

        if (pthread_mutex_init(&dll_ptr[i].mtx, NULL) != 0){
            debug(PRIO_HIGH, "DLL mutex init failed\n");
        }

        for(int j = 0; j < low_arr_size; j++){
            if(j > 0){
                dlls_ptr[i][j].prev = &dlls_ptr[i][j-1];
            }else{
                dlls_ptr[i][j].prev = NULL;
            }

            if(j <= low_arr_size-1){
                dlls_ptr[i][j].next = &dlls_ptr[i][j+1];
            }else{
                dlls_ptr[i][j].next = NULL;
            }
        }
    }
    return dll_ptr;
}

void preallocate_with(DLL* mdll, int top_arr_size, int low_arr_size, size_t alloc_size){
    mdll->elem_size = alloc_size;
    for(int i =0; i < top_arr_size; i++){
        for(int j =0; j < low_arr_size; j++){
            mdll[i].head[j].val = ilia_alloc(alloc_size);
            bzero(mdll[i].head[j].val, alloc_size);
        }
    }
}

void lock_dll(DLL* pdll){
    pthread_mutex_lock(&pdll->mtx);
}

void ulock_dll(DLL* pdll){
    pthread_mutex_unlock(&pdll->mtx);
}

void lretu_dll(DLL* pool, DLLNode* obj){
    lock_dll(pool);
    returnObj(pool, obj);
    ulock_dll(pool);
}

DLLNode* lboru_dll(DLL* pool){
    DLLNode* dln;
    lock_dll(pool);
    dln = borrow(pool);
    ulock_dll(pool);
    return dln;
}

DLLNode* borrow(DLL* pdll){

    if(!pdll->last_valid){
        pdll->cur_num = 1;
        pdll->last_valid = pdll->head;

        return pdll->head;
    }

    if(!pdll->last_valid->next){
        // means no more space
        debug(PRIO_NORMAL, "No more space in the dll. Currently in the pool %d objects\n", pdll->cur_num);
        return NULL;
    }

    pdll->cur_num += 1;
    pdll->last_valid = pdll->last_valid->next;

    return pdll->last_valid;
}

void removeNode(DLLNode* pcn){
    if(pcn->prev){
        pcn->prev->next = pcn->next;
    }
    pcn->next->prev = pcn->prev;
}

void insert_after(DLLNode* pcn, DLLNode* after){
    if(after->next){
        DLLNode* after_next = after->next;
        
        after->next = pcn;
        after_next->prev = pcn;
        pcn->next = after_next;
        pcn->prev = after;
    }else{
        after->next = pcn;
        pcn->prev = after;
    }
}

void returnObj(DLL* pdll, DLLNode* pcn){

    if(!pdll->last_valid){ debug(PRIO_HIGH, "Attempting to return a node that was not borrowed\n"); return;}

    pdll->cur_num--;

    if(pdll->last_valid == pcn){
        debug(PRIO_NORMAL, "Deleting the last_valid\n");
        pdll->last_valid = pdll->last_valid->prev;
        debug(PRIO_LOW, "Last_valid now at : %p (%d)\n", pdll->last_valid, pdll->cur_num);
        return;
    }

    if(!pcn->prev){
        debug(PRIO_NORMAL, "Resetting the head\n");
		pdll->head = pcn->next;
        pdll->head->prev = NULL;
    }

    debug(PRIO_NORMAL, "Normal deletion and insert\n");
    removeNode(pcn);
    insert_after(pcn, pdll->last_valid);
    debug(PRIO_LOW, "Last_valid now at : %p (%d)\n", pdll->last_valid, pdll->cur_num);
}

int lboru_dlls(DLLNode** nodes, int num_nodes, ...){
    va_list argvars;
    va_start(argvars, num_nodes);

    DLL* pools[num_nodes];

    int stopped = -1;
    for(int i=0; i < num_nodes; i++){
        pools[i] = va_arg(argvars, DLL*);
        DLLNode* dn = lboru_dll(pools[i]);

        if(!dn){
           stopped = i;
           break;
        }else{
            nodes[i] = dn;
        }
    }

    if(stopped != -1){
        for(int i=0; i < stopped; i++){
            lretu_dll(pools[i], nodes[i]);
        }
        va_end(argvars);
        return 0;
    }

    va_end(argvars);
    return 1;
}

