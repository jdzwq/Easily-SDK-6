#-----------------------------------------------------------------------------
# begin microsoft NMAKE file
# making order:
# 1. nmake /f xdk.so.mk test --if need to creating some directory or file-list
# 2. nmake /f xdk.so.mk clean
# 3. nmake /f xdk.so.mk
# 4. nmake /f xdk.so.mk install
#-----------------------------------------------------------------------------
CC = gcc
CFLAGS = -g -Wall -fPIC -D _DEBUG
LFLAGS = -shared -fPIC -pthread

MODULE = xdk
ARCH = aarch64
VER = 6.0.0

SRV_PATH = /usr/local/xService
LNK_PATH = /usr/local/lib

INC_PATH = ../../include
SRC_PATH = ../../xdk
OUT_PATH = ../../../Easily-app-6/linux/sbin/api
OBJ_PATH = ../../../Easily-tmp/linux/$(MODULE)/$(ARCH)

TARGET = lib$(MODULE).so.$(VER)
LINKIT = lib$(MODULE).so

LIBS = -lm -ldl -lutil -lrt -L $(LNK_PATH) -limg -lbar -lcrypt -lzlib
DIRS = $(wildcard \
		$(SRC_PATH)/linux/*.c \
		$(SRC_PATH)/imp/*.c \
		$(SRC_PATH)/acp/*.c \
		$(SRC_PATH)/str/*.c \
		$(SRC_PATH)/enc/*.c \
		$(SRC_PATH)/maa/*.c \
		$(SRC_PATH)/util/*.c \
		$(SRC_PATH)/bar/*.c \
		$(SRC_PATH)/zip/*.c \
		$(SRC_PATH)/mob/*.c \
		$(SRC_PATH)/dob/*.c \
		$(SRC_PATH)/expr/*.c \
		$(SRC_PATH)/*.c)
SRCS = $(notdir $(DIRS))
COBS = $(patsubst %.c, %.o, $(SRCS))
OBJS = $(addprefix $(OBJ_PATH)/,$(COBS))

$(OBJ_PATH)/%.o : $(SRC_PATH)/linux/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/imp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/acp/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/str/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/enc/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/maa/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/util/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/bar/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/zip/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/mob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/dob/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_PATH)

$(OBJ_PATH)/%.o : $(SRC_PATH)/expr/%.c
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