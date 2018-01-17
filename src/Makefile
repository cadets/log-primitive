#
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

MK_AUTO_OBJ:= yes
.include <auto.obj.mk>
#.include <bsd.obj.mk>

LIB:= distlog
LIBDIR:= /usr/local/lib
SRCS= distlog_broker.c \
      distlog_client.c \
      distlog_consumer.c \
      distlog_producer.c \
      dl_common.c \
      dl_correlation_id.c \
      dl_resender.c \
      dl_utils.c \
      dl_transport.c \
      dl_memory.c \
      dl_thread.c \
      dl_primitive_types.c \
      dl_request.c \
      dl_fetch_request.c \
      dl_list_offset_request.c \
      dl_produce_request.c \
      dl_response.c \
      dl_fetch_response.c \
      dl_list_offset_response.c \
      dl_produce_response.c

.PATH: osal
.PATH: protocol
.PATH: transport

CFLAGS+= -Iprotocol
CFLAGS+= -Itransport
CFLAGS+= -Iosal

.include <bsd.lib.mk>
