/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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

#ifndef _DL_UTILS_H
#define _DL_UTILS_H

#ifdef _KERNEL
#define DLOGTR0(event_mask, format) \
	CTR0(event_mask, format)
#define DLOGTR1(event_mask, format, p1) \
	CTR1(event_mask, format, p1)
#define DLOGTR2(event_mask, format, p1, p2) \
	CTR2(event_mask, format, p1, p2)
#define DLOGTR3(event_mask, format, p1, p2, p3) \
	CTR3(event_mask, format, p1, p2, p3)
#define DLOGTR4(event_mask, format, p1, p2, p3, p4) \
	CTR4(event_mask, format, p1, p2, p3, p4)
#define DLOGTR5(event_mask, format, p1, p2, p3, p4, p5) \
	CTR5(event_mask, format, p1, p2, p3, p4, p5)
#define DLOGTR6(event_mask, format, p1, p2, p3, p4, p5, p6) \
	CTR6(event_mask, format, p1, p2, p3, p4, p5, p6)
#else
#define DLOGTR0(event_mask, format) \
	dl_debug(event_mask, format)
#define DLOGTR1(event_mask, format, p1) \
	dl_debug(event_mask, format, p1)
#define DLOGTR2(event_mask, format, p1, p2) \
	dl_debug(event_mask, format, p1, p2)
#define DLOGTR3(event_mask, format, p1, p2, p3) \
	dl_debug(event_mask, format, p1, p2, p3)
#define DLOGTR4(event_mask, format, p1, p2, p3, p4) \
	dl_debug(event_mask, format, p1, p2, p3, p4)
#define DLOGTR5(event_mask, format, p1, p2, p3, p4, p5) \
	dl_debug(event_mask, format, p1, p2, p3, p4, p5)
#define DLOGTR6(event_mask, format, p1, p2, p3, p4, p5, p6) \
	dl_debug(event_mask, format, p1, p2, p3, p4, p5, p6)
#endif

#define PRIO_HIGH   1 << 1
#define PRIO_NORMAL 1 << 2
#define PRIO_LOW    1 << 3

extern int dl_make_folder(const char *);
extern int dl_del_folder(const char *);

extern void dl_debug(int, const char *, ...);

#endif
