/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
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

#ifndef _DL_BUF_H
#define _DL_BUF_H

#include <sys/types.h>

enum dl_buf_flags {
	DL_BUF_AUTOEXTEND,
	DL_BUF_FIXEDLEN,
	DL_BUF_EXTERNBUF,
	DL_BUF_BIGENDIAN,
	DL_BUF_LITTLEENDIAN,
};
typedef enum dl_buf_flags dl_buf_flags;

struct dl_buf;

extern int dl_buf_new(struct dl_buf **, char *, int, int);
extern int dl_buf_new_auto(struct dl_buf **);
extern int dl_buf_bcat(struct dl_buf *, char *, int);
extern void dl_buf_clear(struct dl_buf *);
extern int dl_buf_concat(struct dl_buf *, struct dl_buf *);
extern char * dl_buf_data(struct dl_buf *);
extern int dl_buf_flip(struct dl_buf *);
extern int dl_buf_get_int8(struct dl_buf *, u_int8_t *);
extern int dl_buf_get_int16(struct dl_buf *, u_int16_t *);
extern int dl_buf_get_int32(struct dl_buf *, u_int32_t *);
extern int dl_buf_get_int64(struct dl_buf *, u_int64_t *);
extern int dl_buf_len(struct dl_buf *);
extern int dl_buf_pos(struct dl_buf *);
extern int dl_buf_put_int8(struct dl_buf *, u_int8_t);
extern int dl_buf_put_int8_at(struct dl_buf *, u_int8_t, int);
extern int dl_buf_put_int16(struct dl_buf *, u_int16_t);
extern int dl_buf_put_int16_at(struct dl_buf *, u_int16_t, int);
extern int dl_buf_put_int32(struct dl_buf *, u_int32_t);
extern int dl_buf_put_int32_at(struct dl_buf *, u_int32_t, int);
extern int dl_buf_put_int64(struct dl_buf *, u_int64_t);
extern int dl_buf_put_int64_at(struct dl_buf *, u_int64_t, int);

#endif