#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdk.mk test --if need to creating some directory or file-list
# 2. make -f xdk.mk clean
# 3. make -f xdk.mk
# 4. make -f xdk.mk install
#-----------------------------------------------------------------------------
CC = clang
CFLAGS = -g -Wall -fPIC -D _DEBUG

MODULE = xdk
ARCH = aarch64
CUR_VER = 26
MAX_VER = 1
MIN_VER = 0

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdk

OBJ_PATH = ~/工程/Easily-temp/macos/$(MODULE)/$(ARCH)
OUT_PATH = ~/工程/Easily-app-6/macos/lib

TARGET = lib$(MODULE).$(CUR_VER).$(MAX_VER).$(MIN_VER).dylib
LINKIT = lib$(MODULE).dylib

LIBS = -lm -L $(LIB_PATH) -limg -lbar -lcrypt -lzlib
DIRS = $(wildcard \
		$(SRC_PATH)/macos/*.c \
		$(SRC_PATH)/acp/*.c \
		$(SRC_PATH)/aob/*.c \
		$(SRC_PATH)/bar/*.c \
		$(SRC_PATH)/dob/*.c \
		$(SRC_PATH)/imp/*.c \
		$(SRC_PATH)/str/*.c \
		$(SRC_PATH)/enc/*.c \
		$(SRC_PATH)/util/*.c \
		$(SRC_PATH)/zip/*.c \
		$(SRC_PATH)/mob/*.c \
		$(SRC_PATH)/vob/*.c \
		$(SRC_PATH)/net/*.c \
		$(SRC_PATH)/iop/*.c \
		$(SRC_PATH)/stm/*.c \
		$(SRC_PATH)/expr/*.c \
		$(SRC_PATH)/math/*.c \
		$(SRC_PATH)/*.c )

SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/macos/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/acp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/aob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/bar/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/dob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/imp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/str/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/enc/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/util/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/zip/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/mob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/vob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/net/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/iop/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/stm/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/expr/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/math/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

all : $(OBJS)
	rm -f $@
	$(CC) -dynamiclib -fPIC -pthread \
	-o $(OBJ_PATH)/$(TARGET) $(OBJS) $(LIBS) \
	-Wl,-install_name,@rpath/$(LINKIT) \
	-current_version $(CUR_VER) \
	-compatibility_version $(MAX_VER) 

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
	mkdir -p $(OUT_PATH); \
	fi

	cp -f $(OBJ_PATH)/$(TARGET) $(OUT_PATH);
	chmod 755 $(OUT_PATH)/$(TARGET);

	sudo rm -f $(LIB_PATH)/$(LINKIT);
	sudo ln -sf $(OUT_PATH)/$(TARGET) $(LIB_PATH)/$(LINKIT);

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