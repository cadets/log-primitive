KMOD=konsumer
SRCS= ../src/dlog_client.c \
	../src/dl_broker_partition.c \
	../src/dl_broker_segment.c \
	../src/dl_broker_topic.c \
	../src/dl_bbuf.c \
	../src/dl_config.c \
	../src/dl_correlation_id.c \
	../src/dl_resender.c \
	../src/dl_utils.c \
	../src/dl_thread.c \
	../src/dl_fetch_request.c \
	../src/dl_fetch_response.c \
	../src/dl_list_offset_request.c \
	../src/dl_list_offset_response.c \
	../src/dl_message_set.c \
	../src/dl_primitive_types.c \
	../src/dl_produce_request.c \
	../src/dl_produce_response.c \
	../src/dl_request.c \
	../src/dl_request_queue.c \
	../src/dl_response.c \
	../src/dl_transport.c \
	../src/lookup3.c \
	konsumer.c

CFLAGS+=-D_KERNEL
CFLAGS+=-Wno-unused-variable
CFLAGS+=-Wno-incompatible-pointer-types-discards-qualifiers
CFLAGS+=-Wno-missing-prototypes
CFLAGS+=-I/usr/src/cddl/compat/opensolaris/include
CFLAGS+=-I/usr/src/sys/cddl/compat/opensolaris/
CFLAGS+=-I/usr/src/sys/cddl/contrib/opensolaris/uts/common/
CFLAGS+=-I/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys
CFLAGS+=-I${SRCTOP}

.include <bsd.kmod.mk>
