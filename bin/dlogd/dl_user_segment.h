/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#ifndef _DL_USER_SEGMENT_H
#define _DL_USER_SEGMENT_H

#include "dl_index.h"
#include "dl_offset.h"
#include "dl_producer.h"
#include "dl_segment.h"

struct dl_user_segment;

extern int dl_user_segment_new(struct dl_user_segment **,
    uint64_t, long int, char *, char *);
extern int dl_user_segment_new_default(struct dl_user_segment **,
    char *);
extern int dl_user_segment_new_default_sized(struct dl_user_segment **,
    uint32_t, char *);
extern int dl_user_segment_new_default_base(struct dl_user_segment **,
    uint64_t, char *);
extern void dl_user_segment_delete(struct dl_user_segment *);

extern struct dl_index * dl_user_segment_get_index(struct dl_user_segment *);
extern void dl_user_segment_set_index(struct dl_user_segment *, struct dl_index *);
extern int dl_user_segment_get_log(struct dl_user_segment *);
extern struct dl_offset * dl_user_segment_get_offset(struct dl_user_segment *);
extern void dl_user_segment_indexed(struct dl_user_segment *);

#endif
