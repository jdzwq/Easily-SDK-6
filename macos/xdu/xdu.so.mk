#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order:
# 1. make -f xdu.so.mk test --if need to creating some directory or file-list
# 2. make -f xdu.so.mk clean
# 3. make -f xdu.so.mk
# 4. make -f xdu.so.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread
MFLAGS = -framework Cocoa -g

MODULE = xdu
ARCH = aarch64
VER = 6.0

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdu
OUT_PATH = ../../../Easily-app-6/macos/sbin/api
OBJ_PATH = ../../../Easily-tmp/macos/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -lm -ldl -lutil -lxdk -lxgc
DIRS = $(wildcard \
	$(SRC_PATH)/macos/*.m \
	$(SRC_PATH)/imp/*.c \
	$(SRC_PATH)/*.c)
SRCS = $(notdir $(DIRS))
COB1 = $(patsubst %.c, %.o, $(SRCS))
COB2 = $(patsubst %.m, %.o, $(COB1))
COBS = $(patsubst %.c, %.o, $(COB2))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/macos/%.m
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/imp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(MFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) $(LFLAGS) -framework Cocoa -o $(OUT_PATH)/$(TARGET) $(OBJS) $(LIBS)
#	rm -f $(OBJS)

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
	sudo mkdir -p $(SRV_PATH); \
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
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------