#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. nmake /f xdn.so.mk test --if need to creating some directory or file-list
# 2. nmake /f xdn.so.mk clean
# 3. nmake /f xdn.so.mk
# 4. nmake /f xdn.so.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdn
ARCH = aarch64
VER = 6.0

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdn
OUT_PATH = ../../../Easily-app-6/linux/sbin/api
OBJ_PATH = ../../../Easily-tmp/linux/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -lm -ldl -lutil -L $(LNK_PATH) -lxdk -lcrypt
DIRS = $(wildcard \
		$(SRC_PATH)/net/*.c \
		$(SRC_PATH)/stm/*.c \
		$(SRC_PATH)/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/net/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/stm/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) $(LFLAGS) -o $(OUT_PATH)/$(TARGET) $(OBJS) $(LIBS)

test:
	if ! test -d $(OBJ_PATH); then \
	mkdir -p $(OBJ_PATH); \
	chmod 755 $(OBJ_PATH); \
	fi
	@echo $(DIRS)
	@echo $(SRCS)
	@echo $(OBJS)

install:
	if ! test -d $(SRV_PATH)/api; then \
	sudo mkdir -p $(SRV_PATH)/api; \
	fi
	if ! test -d $(LNK_PATH); then \
	sudo mkdir $(LNK_PATH); \
	fi

	sudo cp -f $(OUT_PATH)/$(TARGET) $(SRV_PATH)/api;
	sudo chmod 755 $(SRV_PATH)/api/$(TARGET);
	sudo rm -f $(LNK_PATH)/$(LINKIT);
	sudo ln -s $(SRV_PATH)/api/$(TARGET) $(LNK_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LNK_PATH)/$(LINKIT);
	sudo rm -f $(SRV_PATH)/api/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OUT_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end microsoft NMAKE file
#-----------------------------------------------------------------------------