include $(PWD)/config.mk

SRC_NAME = src
OBJ_NAME = obj
BIN_NAME = bin

SRCS = $(wildcard $(SRC_NAME)/*.c)
OBJS = $(SRCS:$(SRC_NAME)/%.c=$(OBJ_NAME)/%.o)

BFLAGS = \
	$(OBJ_NAME)/dl_common.o \
	$(OBJ_NAME)/dl_memory.o \
	$(OBJ_NAME)/dl_protocol_encoder.o \
	$(OBJ_NAME)/dl_protocol_parser.o \
	$(OBJ_NAME)/dl_protocol.o \
	$(OBJ_NAME)/dl_utils.o \
	$(OBJ_NAME)/distlog_broker.o \
	$(OBJ_NAME)/distlog_client.o

INC=-Iinclude

default: mkdir part1

$(OBJ_NAME)/%.o: $(SRC_NAME)/%.c
	$(COMPILE) 

part1: $(OBJS)
		@echo "Building objects ..."
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/distlog_console_producer.o $(BFLAGS) -o $(BIN_NAME)/distlog_console_producer
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/distlog_console_consumer.o $(BFLAGS) -o $(BIN_NAME)/distlog_console_consumer
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/test_distlog_broker.o $(BFLAGS) -o $(BIN_NAME)/broker_cl

mkdir: rmdir
		@mkdir $(OBJ_NAME)
		@mkdir $(BIN_NAME)

rmdir:
		@rm -rf $(OBJ_NAME)
		@rm -rf $(BIN_NAME)

clean: rmdir
		@echo "Cleanup."
		rm -f foo
		rm -rf $(OBJ_NAME)
		rm -rf $(BIN_NAME)

done:
		@echo "Done."
