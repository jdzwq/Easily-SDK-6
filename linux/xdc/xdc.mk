#-----------------------------------------------------------------------------
# begin GNU MAKE file
# making order for debug version:
# 1. make -f xdc.mk test --if need to creating some directory or file-list
# 2. make -f xdc.mk clean
# 3. make -f xdc.mk
# 4. make -f xdc.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdc
ARCH = aarch64
VER = 6

LIB_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdc

OBJ_PATH = ~/Easily-temp/linux/$(MODULE)/$(ARCH)
OUT_PATH = ~/Easily-app-6/linux/lib

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -lxdk -lxdg -lxdu -lxdl
DIRS = $(wildcard $(SRC_PATH)/*.c \
	$(SRC_PATH)/bag/*.c \
	$(SRC_PATH)/box/*.c \
	$(SRC_PATH)/ctrl/*.c \
	$(SRC_PATH)/dlg/*.c \
	$(SRC_PATH)/edit/*.c \
	$(SRC_PATH)/hand/*.c \
	$(SRC_PATH)/win/*.c \
	$(SRC_PATH)/menu/*.c \
	$(SRC_PATH)/linux/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/bag/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/box/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/ctrl/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/dlg/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/edit/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/hand/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/win/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/menu/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/linux/%.c
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