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

#ifndef DDL_H
#define DDL_H

#include <stddef.h>
#include <pthread.h>

#include "../headers/utils.h"

struct DLLNode{
  void* val;
  struct DLLNode *next;
  struct DLLNode *prev;
  int fd;
};

typedef struct DLLNode DLLNode;

struct DLL{
    int cur_num;
    DLLNode *head;
    DLLNode *last_valid;
    size_t elem_size;
    pthread_mutex_t mtx;
};

typedef struct DLL DLL;

DLLNode* append_to_dll(DLL* dll, void* val, int val_size);
void remove_from_dll(DLL* dll, DLLNode* ppcn);
void print_dll(DLL* dll);
DLL* allocate_dlls_per_num_processors(int top_arr_size, int low_arr_size);

void preallocate_with(DLL* mdll, int top_arr_size, int low_arr_size, size_t alloc_size);
DLLNode* borrow(DLL* pdll);
void returnObj(DLL* pdll, DLLNode* pcn);
void ulock_dll(DLL* pdll);
void lock_dll(DLL* pdll);
void lretu_dll(DLL* pool, DLLNode* obj);
DLLNode* lboru_dll(DLL* pool);
int lboru_dlls(DLLNode** nodes, int num_nodes, ...);

#endif
