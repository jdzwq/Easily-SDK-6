#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xportm.so.mk test --if need to creating some directory or file-list
# 2. make -f xportm.so.mk clean
# 3. make -f xportm.so.mk
# 4. make -f xportm.so.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -D _DEBUG

MODULE = xportm
ARCH = aarch64

LIB_PATH = /usr/local/lib

INC_PATH = ../../../include
SRC_PATH = ../../../server

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/sbin

DIRS = $(wildcard \
	$(SRC_PATH)/xportm/*.cc \
	$(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xportm/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	$(CC) -o $(OBJ_PATH)/$(MODULE) $(OBJS) -L $(LIB_PATH) -lxdk -lxdg -lxdl

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(OUT_PATH); then \
	sudo mkdir $(OUT_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(OUT_PATH);
	sudo chmod +x $(OUT_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(OUT_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
