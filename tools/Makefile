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

.PATH : ../libdlog
#.PATH : ../src

.OBJDIR:= obj
MK_AUTO_OBJ:= yes

DLOG_SRCS= dlog_client.c \
	dl_bbuf.c \
	dl_correlation_id.c \
	dl_resender.c \
	dl_utils.c \
	dl_thread.c \
	dl_fetch_request.c \
	dl_fetch_response.c \
	dl_list_offset_request.c \
	dl_list_offset_response.c \
	dl_message_set.c \
	dl_partition.c \
	dl_primitive_types.c \
	dl_produce_request.c \
	dl_produce_response.c \
	dl_request.c \
	dl_request_queue.c \
	dl_response.c \
	dl_segment.c \
	dl_transport.c \
	dl_topic.c \
	lookup3.c

#PROGS= dlog_start_broker \
#       dlog_console_producer \
#       dlog_console_consumer
PROGS= dlog_console_producer \
       dlog_console_consumer
BINDIR= bin

#SRCS.dlog_start_broker= dlog_start_broker.c
#\
#	../src/dl_partition.c \
#	../src/dl_segment.c \
#	../src/dl_topic.c
#${DLOG_SRCS}
#MAN.dlog_start_broker=

SRCS.dlog_console_producer= dlog_console_producer.c
MAN.dlog_console_producer=

SRCS.dlog_console_consumer= dlog_console_consumer.c 
#${DLOG_SRCS}
MAN.dlog_console_consumer=

LDADD+= -lz
LDADD+= -lpthread
LDADD+= -lm
LDADD+= -lsbuf
LDADD+= -lnv
#LDADD+= -ldlog
LDADD+= ${SRCTOP}/../libdlog/libdlog.a

CFLAGS+= -I${SRCTOP}
CFLAGS+= -I${SRCTOP}/../bin/dlogd
CLFAGS+= -L${SRCTOP}/../libdlog

.include <bsd.progs.mk>
