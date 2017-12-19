SRCDIR= $(.CURDIR)/../src

CFLAGS+= -g
CFLAGS+= -Wextra
CFLAGS+= -Wall
CFLAGS+= -Wno-unused-variable
CFLASG+= -Wno-unused-parameter
CFLAGS+= -Wno-unused-command-line-argument
CFLAGS+= -I$(SRCDIR)
