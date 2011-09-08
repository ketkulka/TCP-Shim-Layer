UTCP_SRC=./source
UTCP_INC= ./include
UTCP_LIB_FILE= libutcp.a
UTCP_OBJ_DIR= ./obj
UTCP_LIB_DIR= ./lib
UTCP_BIN_DIR= ./bin


CP = cp
RM = rm -f
MV = mv

CC        = gcc
OPT       = 
DEBUG     = -g 
DEFINES   =
INCLUDE   = -I$(UTCP_INC) 
CFLAGS    = $(DEBUG) $(OPT) $(DEFINES) $(INCLUDE)
AR        = ar
ARFLAGS   = -cru

all: utcp.o utcpio.o timer.o list.o uip.o utcp_csum.o
	@ $(AR) $(ARFLAGS) $(UTCP_LIB_DIR)/$(UTCP_LIB_FILE) $(UTCP_OBJ_DIR)/timer.o $(UTCP_OBJ_DIR)/list.o  $(UTCP_OBJ_DIR)/utcp_csum.o $(UTCP_OBJ_DIR)/utcp.o $(UTCP_OBJ_DIR)/utcpio.o

utcp_csum.o:
	@ $(CC) $(CFLAGS) -c -o  $(UTCP_OBJ_DIR)/utcp_csum.o $(UTCP_SRC)/utcp_csum.c

uip.o:
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/uip.o $(UTCP_SRC)/uip.c
	
utcp.o:
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/utcp.o $(UTCP_SRC)/utcp.c

utcpio.o:
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/utcpio.o $(UTCP_SRC)/utcpio.c


timer.o: list.o
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/timer.o $(UTCP_SRC)/timer.c 
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/test_timer.o $(UTCP_SRC)/test_timer.c
	@ $(CC) $(CFLAGS) $(UTCP_OBJ_DIR)/list.o $(UTCP_OBJ_DIR)/timer.o $(UTCP_OBJ_DIR)/test_timer.o -o $(UTCP_BIN_DIR)/testtimer.out

list.o:
	@ $(CC) $(CFLAGS) -c -o $(UTCP_OBJ_DIR)/list.o $(UTCP_SRC)/list.c

install:	
	@ cp -f $(UTCP_LIB_DIR)/$(UTCP_LIB_FILE) /usr/lib/
	@ cp -f $(UTCP_INC)/* /usr/include/

clean:
	@ $(RM) $(UTCP_OBJ_DIR)/*
	@ $(RM) $(UTCP_BIN_DIR)/*
	@ $(RM) $(UTCP_LIB_DIR)/*

