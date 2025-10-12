#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f www_api.mk test --if need to creating some directory or file-list
# 2. make -f www_api.mk clean
# 3. make -f www_api.mk
# 4. make -f www_api.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = www_api
ARCH = aarch64

LIB_PATH = /usr/local/lib
API_PATH = /usr/local/Easily/api

INC_PATH = ../../../include
SRC_PATH = ../../../server

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so

LIBS = -L $(LIB_PATH) -lxdk -lxdl
DIRS = $(wildcard $(SRC_PATH)/www_api/*.cc)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.cc, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/www_api/%.cc
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) $(LFLAGS) -o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(API_PATH); then \
	sudo mkdir -p $(API_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(API_PATH);
	sudo chmod 755 $(API_PATH)/$(TARGET);

uninstall:
	sudo rm -f $(API_PATH)/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------