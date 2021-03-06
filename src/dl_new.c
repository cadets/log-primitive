/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#ifndef _KERNEL
#include <stdlib.h>
#endif

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_new.h"

int
dl_new(void **self, const void *_class, ...)
{
	const struct dl_class *class = _class;
	void *inst;

	DL_ASSERT(self != NULL, ("Object to instatiate cannot be NULL"));

	inst = dlog_alloc(class->dl_size);
	DL_ASSERT(inst != NULL, ("Failed to allocate %u bytes", class->dl_size));
	if (inst == NULL )
		return -1;

	* (const struct dl_class **) inst = class;
	
	if (class->dl_ctor) {

		va_list ap;

		va_start(ap, _class);
		class->dl_ctor(inst, &ap);
		va_end(ap);
	}

	*self = inst;
	return 0;
}

void
dl_delete(void *self)
{
	const struct dl_class **class = self;
	
	if (self != NULL && *class != NULL && (*class)->dl_dtor != NULL)
		(* class)->dl_dtor(self);

	dlog_free(self);
}

void
dl_to_string(void *self)
{
	const struct dl_class **class = self;
		
	if (self != NULL && *class != NULL && (*class)->dl_to_string)
		(* class)->dl_to_string(self);
}
