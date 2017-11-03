include $(PWD)/config.mk

SRC_NAME = src
OBJ_NAME = obj
BIN_NAME = bin

SRCS = $(wildcard $(SRC_NAME)/*.c)
OBJS = $(SRCS:$(SRC_NAME)/%.c=$(OBJ_NAME)/%.o)

BFLAGS = \
	$(OBJ_NAME)/caml_common.o \
	$(OBJ_NAME)/caml_memory.o \
	$(OBJ_NAME)/protocol_encoder.o \
	$(OBJ_NAME)/protocol_parser.o \
	$(OBJ_NAME)/protocol.o \
	$(OBJ_NAME)/message.o \
	$(OBJ_NAME)/utils.o \
	$(OBJ_NAME)/circular_queue.o \
	$(OBJ_NAME)/doubly_linked_list.o \
	$(OBJ_NAME)/caml_broker.o \
	$(OBJ_NAME)/caml_client.o \
	$(OBJ_NAME)/binary_tree.o

INC=-Iinclude

default: mkdir part1

$(OBJ_NAME)/%.o: $(SRC_NAME)/%.c
	$(COMPILE) 

part1: $(OBJS)
		@echo "Building objects ..."
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/test_2.o $(BFLAGS) -o $(BIN_NAME)/test_2
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/test_caml_broker.o $(BFLAGS) -o $(BIN_NAME)/broker_cl
	 	$(CC) $(FLAGS) -Iinclude $(OBJ_NAME)/test_caml_client.o $(BFLAGS) -o $(BIN_NAME)/client_cl

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
