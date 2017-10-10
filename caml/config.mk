# DIRS

OBJ_DIR = $(PWD)/obj
BIN_DIR = $(PWD)/bin

# C COMPILER
CC = gcc 
FLAGS = -g -Wextra -Wall -Wno-unused-variable -Wno-unused-parameter -Wno-unused-command-line-argument -lm -lz -lpthread 

COMPILE = \
$(CC) $(FLAGS) -c $(addprefix $(PWD)/, $<) -o $(addprefix $(PWD)/, $@) 
#echo "COMPILING [$<]"; \
#FOR mac add -D F_PREALLOCATE;

CREAT_EX = \
echo "BUILDING EXECUTABLE [$<]"; \
$(CC) $(FLAGS) $(addprefix $(PWD)/, $<) -o $(addprefix $(PWD)/$(BIN_NAME)/, $@);

