#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for release version:
# 1. make test
# 2. make clean
# 3. make all
# 4. make install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC
LFLAGS = -shared -fPIC -pthread

MODULE = xdb_pgsql
ARCH = aarch64
VER = 6

SRV_PATH = /usr/local/Easily/lib
LNK_PATH = /usr/local/lib

INC_POSTGRE = /usr/include
LIB_POSTGRE = /usr/lib64

INC_PATH = ../../include
SRC_PATH = ../../xdb

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -L $(LNK_PATH) -lxdk -lxdl -L $(LIB_POSTGRE) -lpq
DIRS = $(wildcard $(SRC_PATH)/xdb_pgsql.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/xdb_pgsql.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH) -I $(INC_POSTGRE)

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
	if ! test -d $(SRV_PATH); then \
	sudo mkdir -p $(SRV_PATH); \
	fi
	if ! test -d $(LNK_PATH); then \
	sudo mkdir $(LNK_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(SRV_PATH);
	sudo chmod 755 $(SRV_PATH)/$(TARGET);
	sudo rm -f $(LNK_PATH)/$(LINKIT);
	sudo ln -s $(SRV_PATH)/$(TARGET) $(LNK_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LNK_PATH)/$(LINKIT);
	sudo rm -f $(SRV_PATH)/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------