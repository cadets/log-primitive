#-
# Copyright (c) 2018 (Graeme Jenkinson)
# All rights reserved.
#
# This software was developed by BAE Systems, the University of Cambridge
# Computer Laboratory, and Memorial University under DARPA/AFRL contract
# FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
# (TC) research program.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

.PATH : ../../src ../dlogd

.OBJDIR:= obj
MK_AUTO_OBJ:= yes

PROGS= dlogconf
BINDIR= bin

SRCS.dlogconf = \
	dlogconf.c \
	dl_config.c

MAN.dlogconf =

LDADD+=-lucl
LDADD+=-lnv
LDADD+=-lsbuf
LDADD+=-lz

CFLAGS+=-DNDEBUG
CFLAGS+=-g
CFLAGS+=-Werror
CFLAGS+=-Wunused-variable
CFLAGS+=-Wno-incompatible-pointer-types-discards-qualifiers
CFLAGS+=-L/usr/local/lib
CFLAGS+=-I/usr/local/include
CFLAGS+=-I../dlogd
CFLAGS+=-I../../src
CFLAGS+=-I.
CFLAGS+=-O3
CFLAGS+=-fsanitize=address
CFLAGS+=-fno-omit-frame-pointer
CFLAGS+=-fsanitize=undefined

.include <bsd.progs.mk>
