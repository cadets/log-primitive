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

#ifndef _BINARY_TREE_H
#define _BINARY_TREE_H

#include "caml_common.h"
#include "doubly_linked_list.h"

struct bt_node {
	void *val;
	DLLNode *me;
	int height;
	correlationId_t key;
	struct bt_node *left;
	struct bt_node *right;
	int should_resend;
	unsigned long last_sent;
	unsigned long resend_timeout;
};
typedef struct bt_node bt_node;

struct bt_holder{
	bt_node *bt;
	pthread_mutex_t mtx;
};
typedef struct bt_holder bt_holder;

extern void	init_bt_holder(struct bt_holder *);
extern bt_node *	new_node(correlationId_t, DLLNode **, void *);
extern bt_node *	insert(bt_node *, correlationId_t, DLLNode **, void *);
extern bt_node *	delete_node(bt_node *, correlationId_t);
extern void	print_bt(bt_node *);
extern int	height(bt_node *);
extern bt_node*	search(bt_node *, correlationId_t);
extern void	lock_bth(struct bt_holder*);
extern void 	ulock_bth(struct bt_holder*);

#endif
