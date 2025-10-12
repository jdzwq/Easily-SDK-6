#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. nmake /f xtimers.so.mk test --if need to creating some directory or file-list
# 2. nmake /f xtimers.so.mk clean
# 3. nmake /f xtimers.so.mk
# 4. nmake /f xtimers.so.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -D _DEBUG

MODULE = xtimers
ARCH = aarch64

LIB_PATH = /usr/local/lib
SRV_PATH = /usr/local/Easily/sbin

INC_PATH = ../../../include
SRC_PATH = ../../../server

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)

DIRS = $(wildcard \
	$(SRC_PATH)/xtimers/*.cc \
	$(SRC_PATH)/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xtimers/%.cc
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
	if ! test -d $(SRV_PATH); then \
	sudo mkdir -p $(SRV_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(MODULE) $(SRV_PATH);
	sudo chmod +x $(SRV_PATH)/$(MODULE);

uninstall:
	sudo rm -f $(SRV_PATH)/$(MODULE)

.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(MODULE)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------
