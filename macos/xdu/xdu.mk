#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdu.mk test --if need to creating some directory or file-list
# 2. make -f xdu.mk clean
# 3. make -f xdu.mk
# 4. make -f xdu.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG
MFLAGS = -framework Cocoa -g

MODULE = xdu
ARCH = aarch64
MAJ_VER = 6
CUR_VER = 6

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdu

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/lib

TARGET = lib$(MODULE).$(CUR_VER).dylib
LINKIT = lib$(MODULE).dylib

LIBS = -lm -lxdk -lxdg
DIRS = $(wildcard \
	$(SRC_PATH)/cocoa/*.m \
	$(SRC_PATH)/imp/*.c \
	$(SRC_PATH)/*.c)
SRCS = $(notdir $(DIRS))
COB1 = $(patsubst %.c, %.o, $(SRCS))
COB2 = $(patsubst %.m, %.o, $(COB1))
COBS = $(patsubst %.c, %.o, $(COB2))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/cocoa/%.m
	$(CC) $(MFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/imp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -dynamiclib -fPIC -pthread -framework Cocoa \
	-o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS) \
	-Wl,-install_name,@rpath/$(LINKIT) \
	-current_version $(CUR_VER) \
	-compatibility_version $(MAJ_VER)

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
	sudo mkdir -p $(OUT_PATH); \
	fi

	sudo cp -f $(OBJ_PATH)/$(TARGET) $(OUT_PATH);
	sudo chmod 755 $(OUT_PATH)/$(TARGET);
	sudo rm -f $(LIB_PATH)/$(LINKIT);
	sudo ln -s $(OUT_PATH)/$(TARGET) $(LIB_PATH)/$(LINKIT);

uninstall:
	sudo rm -r $(LIB_PATH)/$(LINKIT);
	sudo rm -f $(OUT_PATH)/$(TARGET)
	
.PHONY : clean
clean:
	rm -f $(OBJS)
	rm -f $(OBJ_PATH)/$(TARGET)
#-----------------------------------------------------------------------------
# end GNU MAKE file
#-----------------------------------------------------------------------------