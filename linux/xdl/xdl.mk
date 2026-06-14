#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdl.mk test --if need to creating some directory or file-list
# 2. make -f xdl.mk clean
# 3. make -f xdl.mk
# 4. make -f xdl.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdl
ARCH = aarch64
MAX_VER = 6
MIN_VER = 0

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdl

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/lib

TARGET = lib$(MODULE).so.$(MAX_VER).$(MIN_VER).$(ARCH)
LINKIT = lib$(MODULE).so

LIBS = -L $(LIB_PATH) -lxdk -lxdg
DIRS = $(wildcard \
	$(SRC_PATH)/*.c \
	$(SRC_PATH)/linux/*.c \
	$(SRC_PATH)/bag/*.c \
	$(SRC_PATH)/bio/*.c \
	$(SRC_PATH)/doc/*.c \
	$(SRC_PATH)/sdi/*.c \
	$(SRC_PATH)/ing/*.c \
	$(SRC_PATH)/mis/*.c \
	$(SRC_PATH)/par/*.c \
	$(SRC_PATH)/scan/*.c \
	$(SRC_PATH)/tio/*.c \
	$(SRC_PATH)/view/*.c \
	$(SRC_PATH)/xdb/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/linux/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/bag/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/bio/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/doc/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/sdi/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/ing/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/mis/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/par/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/scan/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/tio/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/view/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/xdb/%.c
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
# end microsoft NMAKE file
#-----------------------------------------------------------------------------